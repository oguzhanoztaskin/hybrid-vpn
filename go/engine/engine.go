// Package engine is the Go full-tunnel data plane (M2a, experimental): it
// reads IP packets from the VPN's TUN device, terminates TCP and UDP in gVisor
// netstack, and forwards each flow according to the Router.
//
// Ownership: Start takes ownership of Config.TUN and closes it in Stop.
// Packets never cross JNI; only DNS queries and socket protection call into
// the host (Kotlin), once per query or socket.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Host is implemented by the Android side.
type Host interface {
	// Protect excludes a socket from the VPN (VpnService.protect).
	Protect(fd int) bool
	// DNS answers one DNS message from an app; nil means no answer (drop).
	// It may block for the duration of an upstream query.
	DNS(query []byte, f Flow) []byte
	// OwnerUID returns the Android UID that owns the flow, or UnknownUID.
	// Called once per new flow, and only when the policy matches on apps.
	OwnerUID(f Flow) int
}

type Config struct {
	TUN       *os.File // ownership passes to the engine
	MTU       uint32
	Host      Host
	Tunnel    []netip.Prefix // the TUN interface's own prefixes
	Resolvers []netip.Addr   // virtual resolver addresses
	// Transports defaults to a single Direct transport using Host.Protect.
	Transports []Transport
	// Policy is the initial per-flow policy (JSON, see ParsePolicy). Empty
	// means DefaultPolicy. It is installed before the first packet is read.
	Policy []byte
	// DisableRACK turns off RACK loss detection in the stack facing apps,
	// leaving classic duplicate-ACK recovery and the retransmission timer.
	// The TUN between apps and the engine rarely loses packets, and RACK's
	// per-ACK bookkeeping costs about 5% of the engine's CPU in bulk
	// transfers.
	DisableRACK bool
	// DisablePacketForwarding keeps TCP flows routed to packet transports
	// (OpenVPN) on the netstack path instead of forwarding them at the IP
	// level (see PacketTransport).
	DisablePacketForwarding bool
	// Echo requests are relayed separately from netstack, never answered
	// until the selected transport has received a real remote ICMP reply.
	AllowICMP   bool
	AllowICMPv6 bool
}

const (
	nicID            = 1
	outboundQueueLen = 512
	maxTCPInFlight   = 512
	maxUDPFlows      = 1024
	udpIdleTimeout   = 60 * time.Second
	udpReceiveBuffer = 212992 // Linux net.core.rmem_default
	dnsIdleTimeout   = 10 * time.Second
	stopTimeout      = 3 * time.Second
)

type Engine struct {
	cfg    Config
	router *Router
	stack  *stack.Stack
	ep     *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc

	wg        sync.WaitGroup
	stopOnce  sync.Once
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	err       atomic.Value // string
	tunRC     syscall.RawConn
	fast      *fastPath // nil without packet transports
	pingSlots chan struct{}

	c counters
}

// Start brings up the stack and begins processing packets.
func Start(cfg Config) (_ *Engine, err error) {
	if cfg.TUN == nil || cfg.Host == nil {
		return nil, errors.New("engine: TUN and Host are required")
	}
	defer func() {
		if err != nil {
			cfg.TUN.Close()
		}
	}()
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.Transports == nil {
		cfg.Transports = []Transport{NewDirect(cfg.Host.Protect)}
	}
	router, err := NewRouter(cfg.Tunnel, cfg.Resolvers, cfg.Transports...)
	if err != nil {
		return nil, err
	}
	if len(cfg.Policy) > 0 {
		if err := router.SetPolicy(cfg.Policy); err != nil {
			return nil, err
		}
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := configureTCP(s, cfg.DisableRACK); err != nil {
		s.Destroy()
		return nil, err
	}
	ep := channel.New(outboundQueueLen, cfg.MTU, "")
	if terr := s.CreateNIC(nicID, ep); terr != nil {
		s.Destroy()
		return nil, fmt.Errorf("engine: create NIC: %v", terr)
	}
	// Accept packets for any destination and answer as that destination.
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	v4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	v6, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
	s.SetRouteTable([]tcpip.Route{{Destination: v4, NIC: nicID}, {Destination: v6, NIC: nicID}})

	rc, err := cfg.TUN.SyscallConn()
	if err != nil {
		s.Destroy()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{cfg: cfg, router: router, stack: s, ep: ep, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}, tunRC: rc}
	e.pingSlots = make(chan struct{}, 64)

	tcpFwd := tcp.NewForwarder(s, 0, maxTCPInFlight, e.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, e.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	if !cfg.DisablePacketForwarding {
		e.fast = newFastPath(e, cfg.Transports)
	}
	e.goSafe(e.readTUN)
	e.goSafe(e.writeTUN)
	return e, nil
}

func configureTCP(s *stack.Stack, disableRACK bool) error {
	sack := tcpip.TCPSACKEnabled(true)
	cubic := tcpip.CongestionControlOption("cubic")
	// Modest defaults with auto-tuning headroom: memory scales with active
	// connections on a phone, so don't start every socket at the maximum.
	rx := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	tx := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	opts := []tcpip.SettableTransportProtocolOption{&sack, &cubic, &rx, &tx}
	if disableRACK {
		recovery := tcpip.TCPRecovery(0)
		opts = append(opts, &recovery)
	}
	for _, opt := range opts {
		if terr := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); terr != nil {
			return fmt.Errorf("engine: tcp option %T: %v", opt, terr)
		}
	}
	return nil
}

// readTUN moves packets from the TUN device into netstack. The fd is
// non-blocking and registered with Go's netpoller, so an idle tunnel parks
// this goroutine without polling. Packets are read straight into a netstack
// view: no intermediate copy.
func (e *Engine) readTUN() {
	for {
		v := buffer.NewViewSize(int(e.cfg.MTU))
		n, err := e.cfg.TUN.Read(v.AsSlice())
		if err != nil {
			v.Release()
			e.abort(fmt.Errorf("tun read: %w", err))
			return
		}
		e.c.packetsIn.Add(1)
		proto, reason := classify(v.AsSlice()[:n])
		if reason == "icmp" && ((v.AsSlice()[0]>>4 == 4 && e.cfg.AllowICMP) || (v.AsSlice()[0]>>4 == 6 && e.cfg.AllowICMPv6)) {
			e.handleEcho(v.AsSlice()[:n])
			v.Release()
			continue
		}
		if reason != "" {
			v.Release()
			e.c.drop(reason)
			continue
		}
		if e.fast != nil && e.fast.outbound(v.AsSlice()[:n]) {
			v.Release()
			continue
		}
		v.CapLength(n)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(v)})
		e.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

// writeTUN moves packets from netstack to the TUN device with one writev per
// packet (no flattening copy). If the device is busy the goroutine waits in
// the netpoller; while it waits, netstack's queue fills and TCP backs off.
func (e *Engine) writeTUN() {
	rc, err := e.cfg.TUN.SyscallConn()
	if err != nil {
		e.abort(err)
		return
	}
	for {
		pkt := e.ep.ReadContext(e.ctx)
		if pkt == nil {
			return
		}
		slices := pkt.AsSlices()
		var werr error
		err := rc.Write(func(fd uintptr) bool {
			_, werr = unix.Writev(int(fd), slices)
			return werr != unix.EAGAIN
		})
		pkt.DecRef()
		if err != nil {
			e.abort(fmt.Errorf("tun write: %w", err))
			return
		}
		if werr != nil {
			e.c.drop("tun write error")
			continue
		}
		e.c.packetsOut.Add(1)
	}
}

// classify admits only TCP and UDP. Everything else (ICMP, ICMPv6, ESP, ...)
// is dropped and counted rather than handed to netstack, which would
// otherwise answer pings to arbitrary addresses on their behalf.
func classify(p []byte) (tcpip.NetworkProtocolNumber, string) {
	if len(p) < 1 {
		return 0, "malformed"
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return 0, "malformed"
		}
		switch p[9] {
		case 6, 17:
			return ipv4.ProtocolNumber, ""
		case 1:
			return 0, "icmp"
		}
		return 0, "unsupported protocol"
	case 6:
		if len(p) < 40 {
			return 0, "malformed"
		}
		next := p[6]
		if next == 44 && len(p) >= 48 { // fragment header: netstack reassembles
			next = p[40]
		}
		switch next {
		case 6, 17:
			return ipv6.ProtocolNumber, ""
		case 58:
			return 0, "icmp"
		}
		return 0, "unsupported protocol"
	}
	return 0, "malformed"
}

// Stop shuts the engine down and closes the TUN fd. It is idempotent and
// returns within stopTimeout even if host callbacks (DNS) are still running;
// those finish on their own and their answers are discarded.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		if e.fast != nil {
			e.fast.stop()
		}
		e.cancel()
		e.cfg.TUN.Close()
		e.mu.Lock()
		for c := range e.conns {
			c.Close()
		}
		e.mu.Unlock()
		e.ep.Close()
		e.stack.Close()
		done := make(chan struct{})
		go func() { e.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(stopTimeout):
			e.fail(errors.New("stop: timed out waiting for flows"))
		}
	})
}

// SetPolicy atomically replaces the per-flow policy. New flows use it;
// established flows keep their transport. On error the old policy stays.
func (e *Engine) SetPolicy(data []byte) error { return e.router.SetPolicy(data) }

func (e *Engine) ownerUID(f Flow) int {
	e.c.uidLookups.Add(1)
	return e.cfg.Host.OwnerUID(f)
}

// Done is closed when the engine has stopped (by Stop or a fatal error).
func (e *Engine) Done() <-chan struct{} { return e.ctx.Done() }

func (e *Engine) fail(err error) {
	e.err.CompareAndSwap(nil, err.Error())
}

// abort records an unexpected error and stops the engine asynchronously
// (Stop waits for tracked goroutines, including the caller). Errors caused by
// an orderly Stop are not recorded.
func (e *Engine) abort(err error) {
	if e.ctx.Err() != nil {
		return
	}
	e.fail(err)
	go e.Stop()
}

// goSafe runs fn tracked by the wait group. A panic stops the engine instead
// of crashing the process: the VPN keeps its TUN, so traffic is blackholed
// (fail closed) rather than leaking around a dead VPN.
func (e *Engine) goSafe(fn func()) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.guard(fn)
	}()
}

// goDetached is goSafe without Stop waiting for it. Used for DNS handlers,
// which block inside host callbacks we cannot cancel; Stop closes their
// connections, so they exit as soon as the callback returns.
func (e *Engine) goDetached(fn func()) {
	go e.guard(fn)
}

func (e *Engine) guard(fn func()) {
	func() {
		defer func() {
			if r := recover(); r != nil {
				e.abort(fmt.Errorf("panic: %v\n%s", r, debug.Stack()))
			}
		}()
		fn()
	}()
}

func (e *Engine) track(c net.Conn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx.Err() != nil {
		c.Close()
		return false
	}
	e.conns[c] = struct{}{}
	return true
}

func (e *Engine) untrack(c net.Conn) {
	c.Close()
	e.mu.Lock()
	delete(e.conns, c)
	e.mu.Unlock()
}
