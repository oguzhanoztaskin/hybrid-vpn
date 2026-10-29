package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// Protocol is the transport protocol of a flow.
type Protocol uint8

const (
	ICMP   Protocol = 1
	TCP    Protocol = 6
	UDP    Protocol = 17
	ICMPv6 Protocol = 58
)

func (p Protocol) String() string {
	switch p {
	case ICMP:
		return "icmp"
	case ICMPv6:
		return "icmpv6"
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "unknown"
}

// Flow is one TCP connection or UDP association as seen from the app.
type Flow struct {
	Protocol Protocol
	Src      netip.AddrPort // the app's address in the tunnel
	Dst      netip.AddrPort // where the app wants to go
}

type Action uint8

const (
	ActionDrop Action = iota
	ActionDNS
	ActionForward
)

// Decision is the router's verdict for a flow.
type Decision struct {
	Action    Action
	Transport string // ActionForward: the transport to use
	OnFailure string // ActionForward: Block or an explicit fallback transport
	RuleID    string // policy rule that decided, empty for built-ins/default
	Reason    string // ActionDrop: why
}

// Capabilities describes what a transport can carry.
type Capabilities struct {
	TCP, UDP bool
}

// Transport delivers flows the Router assigned to it. A transport must refuse
// destinations it cannot deliver itself (e.g. an address outside its tailnet);
// it must never fall back to another path such as the host network, because
// that would bypass routing policy.
//
// Implementations: direct (here), tailnet (go/tailnet), openvpn (go/openvpn)
// and socks5 (go/socks); http proxies are planned. Kind is the policy's
// transport type.
type Transport interface {
	Name() string // unique id referenced by policy routes
	Kind() string // "direct", "tailnet", "socks5", "http", "openvpn"
	Capabilities() Capabilities
	Dial(ctx context.Context, f Flow) (net.Conn, error)
}

// Router is the single routing boundary: every flow is decided here, and
// Router.Dial is the only way routing code reaches a Transport.
type Router struct {
	tunnel     []netip.Prefix
	resolvers  map[netip.Addr]bool
	transports map[string]Transport
	policy     atomic.Pointer[Policy]
}

var errNotForwarded = errors.New("flow is not routed to a transport")

// NewRouter builds a router with the default policy (direct, block on
// failure). tunnel are the TUN's own prefixes, resolvers the virtual DNS
// addresses.
func NewRouter(tunnel []netip.Prefix, resolvers []netip.Addr, transports ...Transport) (*Router, error) {
	r := &Router{tunnel: tunnel, resolvers: map[netip.Addr]bool{}, transports: map[string]Transport{}}
	for _, a := range resolvers {
		r.resolvers[a.Unmap()] = true
	}
	for _, t := range transports {
		if t.Name() == Block {
			return nil, fmt.Errorf("transport id %q is reserved", Block)
		}
		if _, dup := r.transports[t.Name()]; dup {
			return nil, fmt.Errorf("duplicate transport %q", t.Name())
		}
		r.transports[t.Name()] = t
	}
	r.policy.Store(DefaultPolicy())
	return r, nil
}

// SetPolicy validates and atomically installs a policy. It applies to flows
// decided from now on; established flows keep their transport.
func (r *Router) SetPolicy(data []byte) error {
	p, err := ParsePolicy(data, r.transports)
	if err != nil {
		return err
	}
	r.policy.Store(p)
	return nil
}

// NeedsUID reports whether deciding a flow requires its owning app.
func (r *Router) NeedsUID() bool { return r.policy.Load().NeedsUID() }

// Builtin applies the guards no policy can override. ok is false when the
// flow is left to the policy.
func (r *Router) Builtin(f Flow) (d Decision, ok bool) {
	dst := f.Dst.Addr().Unmap()
	switch {
	case !dst.IsValid() || dst.IsUnspecified() || dst.IsLoopback() || dst.IsMulticast() || dst == broadcast4:
		return Decision{Action: ActionDrop, Reason: "non-unicast destination"}, true
	case f.Dst.Port() == 53:
		// Any resolver, not just ours: the DNS firewall sees every query.
		return Decision{Action: ActionDNS}, true
	case r.resolvers[dst]:
		return Decision{Action: ActionDrop, Reason: "virtual resolver serves only port 53"}, true
	case r.inTunnel(dst):
		return Decision{Action: ActionDrop, Reason: "tunnel address"}, true
	}
	return Decision{}, false
}

// Policy evaluates the per-flow rules for an already attributed flow
// (uid may be UnknownUID).
func (r *Router) Policy(f Flow, uid int) Decision {
	p := r.policy.Load()
	if rule := p.Match(f, uid); rule != nil {
		if rule.Block {
			return Decision{Action: ActionDrop, RuleID: rule.ID, Reason: "policy:" + rule.ID}
		}
		return Decision{Action: ActionForward, Transport: rule.Route.Transport, OnFailure: rule.Route.OnFailure, RuleID: rule.ID}
	}
	return Decision{Action: ActionForward, Transport: p.Default.Transport, OnFailure: p.Default.OnFailure}
}

// Decide is Builtin followed by Policy. uid is called at most once, and only
// when the policy needs the owning app.
func (r *Router) Decide(f Flow, uid func() int) Decision {
	if d, ok := r.Builtin(f); ok {
		return d
	}
	owner := UnknownUID
	if r.NeedsUID() && uid != nil {
		owner = uid()
	}
	return r.Policy(f, owner)
}

// Dial opens the outbound side of a forwarded flow. If the chosen transport
// cannot deliver, only the decision's explicit OnFailure transport is tried;
// with OnFailure == Block the flow fails. Unknown transports fail closed.
func (r *Router) Dial(ctx context.Context, f Flow, d Decision) (conn net.Conn, used string, err error) {
	if d.Action != ActionForward {
		return nil, "", errNotForwarded
	}
	conn, err = r.dialOne(ctx, f, d.Transport)
	if err == nil {
		return conn, d.Transport, nil
	}
	if d.OnFailure == "" || d.OnFailure == Block || d.OnFailure == d.Transport {
		return nil, "", err
	}
	conn, ferr := r.dialOne(ctx, f, d.OnFailure)
	if ferr != nil {
		return nil, "", fmt.Errorf("%v; fallback %s: %w", err, d.OnFailure, ferr)
	}
	return conn, d.OnFailure, nil
}

func (r *Router) dialOne(ctx context.Context, f Flow, id string) (net.Conn, error) {
	t, ok := r.transports[id]
	if !ok {
		return nil, fmt.Errorf("unknown transport %q", id)
	}
	caps := t.Capabilities()
	if (f.Protocol == TCP && !caps.TCP) || (f.Protocol == UDP && !caps.UDP) {
		return nil, fmt.Errorf("%s: %w", id, ErrUnsupportedProtocol)
	}
	return t.Dial(ctx, f)
}

func (r *Router) inTunnel(a netip.Addr) bool {
	for _, p := range r.tunnel {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// DirectName is the transport id used by policy for the physical network.
const DirectName = "direct"

// ErrProtectFailed means the socket could not be excluded from the VPN.
// Dialing anyway would loop the connection back into our own tunnel.
var ErrProtectFailed = errors.New("could not protect socket from the VPN")

// Direct reaches destinations over the physical network. Every socket is
// passed to VpnService.protect() before it connects; if that fails the dial
// fails (fail closed) instead of looping through the tunnel.
type Direct struct {
	protect func(fd int) bool
	timeout time.Duration
}

func NewDirect(protect func(fd int) bool) *Direct {
	return &Direct{protect: protect, timeout: 10 * time.Second}
}

func (d *Direct) Name() string               { return DirectName }
func (d *Direct) Kind() string               { return "direct" }
func (d *Direct) Capabilities() Capabilities { return Capabilities{TCP: true, UDP: true} }

func (d *Direct) Dial(ctx context.Context, f Flow) (net.Conn, error) {
	return d.DialAddress(ctx, f.Protocol.String(), f.Dst.String())
}

// DialAddress dials network ("tcp" or "udp") and address ("host:port") over
// the physical network with a protected socket. Transports use it to reach
// their servers (e.g. a SOCKS5 proxy); a host name is resolved by the system
// resolver, whose queries pass through the DNS firewall.
func (d *Direct) DialAddress(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout: d.timeout,
		// Our own keepalives only start after 5 idle minutes, to limit wake-ups;
		// apps' end-to-end keepalives are answered by the userspace stack.
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 5 * time.Minute, Interval: time.Minute, Count: 3},
		Control: func(_, _ string, c syscall.RawConn) error {
			ok := false
			if err := c.Control(func(fd uintptr) { ok = d.protect(int(fd)) }); err != nil {
				return err
			}
			if !ok {
				return ErrProtectFailed
			}
			return nil
		},
	}
	return dialer.DialContext(ctx, network, address)
}
