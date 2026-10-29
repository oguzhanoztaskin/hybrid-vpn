// Package socks routes flows through SOCKS5 proxies (RFC 1928, with
// username/password authentication from RFC 1929) as transports
// "socks5:<id>". TCP flows use CONNECT, UDP flows UDP ASSOCIATE.
//
// The proxy is reached over the physical network with protected sockets. A
// flow the proxy refuses, or a proxy that can't be reached, fails the dial:
// there is no fallback to the host network. Destinations are always IP
// addresses, because flows carry no host name.
//
// SOCKS5 itself is not encrypted: the proxy, and anyone between the device
// and the proxy, sees destinations, the credentials and any unencrypted
// payload.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"hybridvpn/netcore/engine"
)

// TransportPrefix prefixes SOCKS5 transport ids in routing decisions.
const TransportPrefix = "socks5:"

// ErrNoUDP means the proxy answered UDP ASSOCIATE with "command not
// supported", as mitmproxy does. Later UDP flows are refused locally, without
// contacting the proxy, until the next Check.
var ErrNoUDP = errors.New("socks5: the proxy does not support UDP; UDP sent here is blocked")

// handshakeTimeout bounds connecting to the proxy plus the SOCKS exchange.
const handshakeTimeout = 10 * time.Second

// Config describes one proxy.
type Config struct {
	ID       string
	Server   string // "host:port"; a host name is resolved when dialing
	Username string // empty: no authentication offered
	Password string
	// Dial reaches the proxy over the physical network with protected sockets
	// (engine.Direct.DialAddress). Required.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Proxy is one configured SOCKS5 proxy and its counters.
type Proxy struct {
	cfg Config

	// broken is set for a proxy whose configuration was rejected: every
	// flow fails with it.
	broken error

	mu       sync.Mutex
	state    string // StateIdle, StateReady or StateError
	lastErr  string
	lastSeen time.Time // last successful exchange

	tcpActive, udpActive, flows, failures atomic.Int64
	noUDP                                 atomic.Bool
}

// Proxy states, as shown to the user.
const (
	StateIdle  = "idle"  // not used or checked yet
	StateReady = "ready" // the last exchange with the proxy succeeded
	StateError = "error" // the last exchange failed; Error says why
)

// New validates cfg. It does not contact the proxy (see Check).
func New(cfg Config) (*Proxy, error) {
	if cfg.ID == "" {
		return nil, errors.New("socks5: empty id")
	}
	host, port, err := net.SplitHostPort(cfg.Server)
	if err != nil || host == "" {
		return nil, fmt.Errorf("socks5 %s: server must be host:port", cfg.ID)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("socks5 %s: invalid port %q", cfg.ID, port)
	}
	if len(cfg.Username) > 255 || len(cfg.Password) > 255 {
		return nil, fmt.Errorf("socks5 %s: username and password are limited to 255 bytes", cfg.ID)
	}
	if cfg.Username == "" && cfg.Password != "" {
		return nil, fmt.Errorf("socks5 %s: a password needs a username", cfg.ID)
	}
	if cfg.Dial == nil {
		return nil, fmt.Errorf("socks5 %s: no dialer", cfg.ID)
	}
	return &Proxy{cfg: cfg, state: StateIdle}, nil
}

// NewFailed returns a proxy that refuses every flow with err, so a bad
// configuration fails closed for its routes instead of stopping the engine.
func NewFailed(id, server string, err error) *Proxy {
	return &Proxy{cfg: Config{ID: id, Server: server}, broken: err, state: StateError, lastErr: err.Error()}
}

// ID is the proxy's id without the transport prefix.
func (p *Proxy) ID() string { return p.cfg.ID }

// Transport returns the routing transport "socks5:<id>".
func (p *Proxy) Transport() engine.Transport { return transport{p} }

type transport struct{ p *Proxy }

func (t transport) Name() string { return TransportPrefix + t.p.cfg.ID }
func (t transport) Kind() string { return "socks5" }
func (t transport) Capabilities() engine.Capabilities {
	return engine.Capabilities{TCP: true, UDP: true}
}
func (t transport) Dial(ctx context.Context, f engine.Flow) (net.Conn, error) {
	return t.p.dial(ctx, f)
}

// Check connects and authenticates without opening a flow, to report early
// whether the proxy is reachable and accepts the credentials.
func (p *Proxy) Check(ctx context.Context) error {
	if p.broken != nil {
		return p.broken
	}
	p.noUDP.Store(false) // the proxy may have changed (e.g. restarted in another mode)
	c, err := p.connect(ctx)
	if err != nil {
		p.record(err)
		return err
	}
	c.Close()
	p.record(nil)
	return nil
}

// Summary is the proxy's status for the UI.
type Summary struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Server    string `json:"server"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	LastSeen  int64  `json:"last_seen,omitempty"` // Unix milliseconds
	NoUDP     bool   `json:"no_udp,omitempty"`    // the proxy refused UDP ASSOCIATE
	TCPActive int64  `json:"tcp_active"`
	UDPActive int64  `json:"udp_active"`
	Flows     int64  `json:"flows"`
	Failures  int64  `json:"failures"`
}

func (p *Proxy) Summary() Summary {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Summary{
		Type: "socks5", ID: p.cfg.ID, Server: p.cfg.Server, State: p.state, Error: p.lastErr, NoUDP: p.noUDP.Load(),
		TCPActive: p.tcpActive.Load(), UDPActive: p.udpActive.Load(),
		Flows: p.flows.Load(), Failures: p.failures.Load(),
	}
	if !p.lastSeen.IsZero() {
		s.LastSeen = p.lastSeen.UnixMilli()
	}
	return s
}

func (p *Proxy) record(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		p.state, p.lastErr, p.lastSeen = StateReady, "", time.Now()
		return
	}
	p.state, p.lastErr = StateError, err.Error()
}

// recordFlow records a flow's outcome. A refusal for one destination
// (errRefused) proves the proxy works, so it doesn't mark the proxy broken.
func (p *Proxy) recordFlow(err error) {
	if err == nil {
		p.flows.Add(1)
		p.record(nil)
		return
	}
	p.failures.Add(1)
	var r *refusedError
	if errors.As(err, &r) || errors.Is(err, ErrNoUDP) {
		p.record(nil)
		return
	}
	p.record(err)
}

func (p *Proxy) dial(ctx context.Context, f engine.Flow) (conn net.Conn, err error) {
	if p.broken != nil {
		p.failures.Add(1)
		return nil, p.broken
	}
	if f.Protocol == engine.UDP && p.noUDP.Load() {
		p.failures.Add(1)
		return nil, ErrNoUDP
	}
	defer func() { p.recordFlow(err) }()
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	dst := netip.AddrPortFrom(f.Dst.Addr().Unmap(), f.Dst.Port())
	if f.Protocol == engine.TCP {
		if _, err := request(c, cmdConnect, dst); err != nil {
			c.Close()
			return nil, err
		}
		c.SetDeadline(time.Time{})
		p.tcpActive.Add(1)
		return &tcpConn{Conn: c, active: &p.tcpActive}, nil
	}

	// UDP: the association lives as long as this control connection.
	relay, err := request(c, cmdUDPAssociate, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		c.Close()
		var r *refusedError
		if errors.As(err, &r) && r.code == repCommandNotSupported {
			p.noUDP.Store(true)
			return nil, ErrNoUDP
		}
		return nil, err
	}
	proxyAddr, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("socks5: relay address: %w", err)
	}
	relay = relayAddress(relay, proxyAddr.Addr())
	u, err := p.cfg.Dial(ctx, "udp", relay.String())
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("socks5: UDP relay %s: %w", relay, err)
	}
	c.SetDeadline(time.Time{})
	p.udpActive.Add(1)
	uc := &udpConn{Conn: u, control: c, dst: dst, active: &p.udpActive}
	go uc.watchControl()
	return uc, nil
}

// relayAddress is where to send UDP datagrams. A proxy that names no
// interface (0.0.0.0 or ::) means its own address. One naming a loopback
// address is listening on loopback behind a port forward (or NAT), where only
// the address we connected to reaches it; for a proxy on this device the two
// are the same.
func relayAddress(bound netip.AddrPort, proxy netip.Addr) netip.AddrPort {
	if a := bound.Addr(); a.IsUnspecified() || a.IsLoopback() {
		return netip.AddrPortFrom(proxy.Unmap(), bound.Port())
	}
	return bound
}

// connect opens a control connection and completes method negotiation and
// authentication. The connection has the context's deadline set.
func (p *Proxy) connect(ctx context.Context) (net.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
	}
	c, err := p.cfg.Dial(ctx, "tcp", p.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("socks5: can't reach %s: %w", p.cfg.Server, err)
	}
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	if err := p.authenticate(c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

const (
	version5        = 5
	methodNone      = 0x00
	methodPassword  = 0x02
	methodNoneValid = 0xff

	cmdConnect      = 1
	cmdUDPAssociate = 3

	repCommandNotSupported = 7

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

func (p *Proxy) authenticate(c net.Conn) error {
	greeting := []byte{version5, 1, methodNone}
	if p.cfg.Username != "" {
		greeting = []byte{version5, 2, methodNone, methodPassword}
	}
	if _, err := c.Write(greeting); err != nil {
		return fmt.Errorf("socks5: greeting: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return fmt.Errorf("socks5: greeting reply: %w", err)
	}
	if reply[0] != version5 {
		return fmt.Errorf("socks5: %s is not a SOCKS5 proxy (version %d)", p.cfg.Server, reply[0])
	}
	switch reply[1] {
	case methodNone:
		return nil
	case methodPassword:
		if p.cfg.Username == "" {
			return errors.New("socks5: the proxy asked for a password, but none is configured")
		}
		msg := []byte{1, byte(len(p.cfg.Username))}
		msg = append(msg, p.cfg.Username...)
		msg = append(msg, byte(len(p.cfg.Password)))
		msg = append(msg, p.cfg.Password...)
		if _, err := c.Write(msg); err != nil {
			return fmt.Errorf("socks5: authentication: %w", err)
		}
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			return fmt.Errorf("socks5: authentication reply: %w", err)
		}
		if reply[1] != 0 {
			return errors.New("socks5: the proxy rejected the username or password")
		}
		return nil
	case methodNoneValid:
		if p.cfg.Username == "" {
			return errors.New("socks5: the proxy requires authentication; set a username and password")
		}
		return errors.New("socks5: the proxy accepts none of the offered authentication methods")
	default:
		return fmt.Errorf("socks5: the proxy chose an unsupported authentication method %d", reply[1])
	}
}

// refusedError is a request the proxy answered with a failure code: the proxy
// works, but won't serve this destination or command.
type refusedError struct{ code byte }

func (e *refusedError) Error() string {
	reasons := map[byte]string{
		1: "general failure", 2: "not allowed by its rules", 3: "network unreachable",
		4: "host unreachable", 5: "connection refused", 6: "TTL expired",
		7: "command not supported", 8: "address type not supported",
	}
	r, ok := reasons[e.code]
	if !ok {
		r = fmt.Sprintf("code %d", e.code)
	}
	return "socks5: the proxy refused: " + r
}

// request sends a CONNECT or UDP ASSOCIATE for addr and returns the bound
// address from the reply.
func request(c net.Conn, cmd byte, addr netip.AddrPort) (netip.AddrPort, error) {
	msg := []byte{version5, cmd, 0}
	msg = appendAddr(msg, addr)
	if _, err := c.Write(msg); err != nil {
		return netip.AddrPort{}, fmt.Errorf("socks5: request: %w", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("socks5: reply: %w", err)
	}
	if head[0] != version5 {
		return netip.AddrPort{}, fmt.Errorf("socks5: bad reply version %d", head[0])
	}
	bound, err := readAddr(c, head[3])
	if err != nil {
		return netip.AddrPort{}, err
	}
	if head[1] != 0 {
		return netip.AddrPort{}, &refusedError{head[1]}
	}
	return bound, nil
}

func appendAddr(b []byte, a netip.AddrPort) []byte {
	ip := a.Addr().Unmap()
	if ip.Is4() {
		b = append(b, atypIPv4)
	} else {
		b = append(b, atypIPv6)
	}
	b = append(b, ip.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, a.Port())
}

// readAddr reads ADDR and PORT of the given type. A domain (allowed in replies
// but useless for a relay address) is reported as an error.
func readAddr(r io.Reader, atyp byte) (netip.AddrPort, error) {
	var n int
	switch atyp {
	case atypIPv4:
		n = 4
	case atypIPv6:
		n = 16
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return netip.AddrPort{}, err
		}
		skip := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, skip); err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPort{}, errors.New("socks5: the proxy named its relay by host name, which is not supported")
	default:
		return netip.AddrPort{}, fmt.Errorf("socks5: unknown address type %d", atyp)
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return netip.AddrPort{}, fmt.Errorf("socks5: reply address: %w", err)
	}
	ip, _ := netip.AddrFromSlice(buf[:n])
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(buf[n:])), nil
}

// tcpConn counts an active CONNECT flow until it is closed.
type tcpConn struct {
	net.Conn
	active *atomic.Int64
	once   sync.Once
}

func (c *tcpConn) Close() error {
	c.once.Do(func() { c.active.Add(-1) })
	return c.Conn.Close()
}

// CloseWrite half-closes the proxied connection, if the underlying one can.
func (c *tcpConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// udpConn is one UDP association for one destination. Each Write is one
// datagram to dst; Read returns only datagrams from dst, unfragmented.
type udpConn struct {
	net.Conn          // the UDP socket connected to the relay
	control  net.Conn // closing it ends the association
	dst      netip.AddrPort
	active   *atomic.Int64
	once     sync.Once
}

// maxHeader is the largest SOCKS5 UDP header we send or accept (IPv6).
const maxHeader = 3 + 1 + 16 + 2

var writeBufs = sync.Pool{New: func() any { b := make([]byte, 0, 65535+maxHeader); return &b }}

func (c *udpConn) Write(p []byte) (int, error) {
	bp := writeBufs.Get().(*[]byte)
	defer writeBufs.Put(bp)
	b := appendAddr(append((*bp)[:0], 0, 0, 0), c.dst) // RSV, FRAG 0
	b = append(b, p...)
	if _, err := c.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil {
			return 0, err
		}
		// RSV(2) FRAG(1) ATYP(1) ADDR PORT DATA. Fragments and datagrams from
		// anyone but this flow's destination are dropped.
		if n < 4 || p[2] != 0 {
			continue
		}
		var addrLen int
		switch p[3] {
		case atypIPv4:
			addrLen = 4
		case atypIPv6:
			addrLen = 16
		default:
			continue
		}
		hdr := 4 + addrLen + 2
		if n < hdr {
			continue
		}
		ip, _ := netip.AddrFromSlice(p[4 : 4+addrLen])
		src := netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(p[4+addrLen:]))
		if src != c.dst {
			continue
		}
		return copy(p, p[hdr:n]), nil
	}
}

// watchControl ends the association when the proxy closes the control
// connection, as RFC 1928 requires.
func (c *udpConn) watchControl() {
	io.Copy(io.Discard, c.control)
	c.Close()
}

func (c *udpConn) Close() error {
	c.once.Do(func() {
		c.active.Add(-1)
		c.control.Close()
	})
	return c.Conn.Close()
}
