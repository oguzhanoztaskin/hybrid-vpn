package openvpn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"hybridvpn/netcore/engine"
)

// TunConfig is what the server pushed for one tunnel session, as reported by
// the core's tun builder (client.cpp).
type TunConfig struct {
	Addresses      []PrefixJSON `json:"addresses"`
	Routes         []PrefixJSON `json:"routes"`
	ExcludedRoutes []PrefixJSON `json:"excluded_routes"`
	RerouteIPv4    bool         `json:"reroute_ipv4"`
	RerouteIPv6    bool         `json:"reroute_ipv6"`
	MTU            int          `json:"mtu"`
	Remote         string       `json:"remote"`
	Session        string       `json:"session"`
	DNSServers     []string     `json:"dns_servers"`
	DNSDomains     []string     `json:"dns_domains"`
	SearchDomains  []string     `json:"search_domains"`
	// AFPrefix: packets carry a 4-byte address-family header (macOS utun
	// framing, used by the core on the host build).
	AFPrefix bool `json:"af_prefix"`
}

type PrefixJSON struct {
	Address string `json:"address"`
	Prefix  int    `json:"prefix"`
	IPv6    bool   `json:"ipv6"`
}

func (p PrefixJSON) parse() (netip.Prefix, error) {
	a, err := netip.ParseAddr(p.Address)
	if err != nil {
		return netip.Prefix{}, err
	}
	pfx := netip.PrefixFrom(a.Unmap(), p.Prefix) // keeps the host bits
	if !pfx.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix length %d", p.Prefix)
	}
	return pfx, nil
}

// routeSet decides which destinations the server routes. OpenVPN considers
// the interface subnet, pushed routes, and (with redirect-gateway) everything
// of that family as routed, minus excluded routes.
type routeSet struct {
	include, exclude []netip.Prefix
	all4, all6       bool
}

func newRouteSet(c TunConfig) (routeSet, error) {
	var r routeSet
	for _, list := range [][]PrefixJSON{c.Addresses, c.Routes} {
		for _, p := range list {
			pfx, err := p.parse()
			if err != nil {
				return r, fmt.Errorf("route %s/%d: %w", p.Address, p.Prefix, err)
			}
			r.include = append(r.include, pfx.Masked())
		}
	}
	for _, p := range c.ExcludedRoutes {
		pfx, err := p.parse()
		if err != nil {
			return r, fmt.Errorf("excluded route %s/%d: %w", p.Address, p.Prefix, err)
		}
		r.exclude = append(r.exclude, pfx.Masked())
	}
	r.all4, r.all6 = c.RerouteIPv4, c.RerouteIPv6
	return r, nil
}

func (r routeSet) owns(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range r.exclude {
		if p.Contains(a) {
			return false
		}
	}
	if (a.Is4() && r.all4) || (a.Is6() && r.all6) {
		return true
	}
	for _, p := range r.include {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Prefixes lists the routed prefixes for display.
func (r routeSet) Prefixes() []string {
	var out []string
	if r.all4 {
		out = append(out, "0.0.0.0/0")
	}
	if r.all6 {
		out = append(out, "::/0")
	}
	for _, p := range r.include {
		out = append(out, p.String())
	}
	for _, p := range r.exclude {
		out = append(out, "!"+p.String())
	}
	return out
}

const (
	nicID            = 1
	outboundQueueLen = 512
	defaultMTU       = 1500
)

// tunnel is a userspace network stack on the packet socket the core reads
// and writes. Flows the router assigns to this transport are dialed from it,
// with the VPN addresses the server pushed as source.
type tunnel struct {
	cfg    TunConfig
	routes routeSet
	local4 tcpip.Address // zero if no IPv4 address was pushed
	local6 tcpip.Address
	mtu    int
	file   *os.File
	stack  *stack.Stack
	ep     *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	wg     sync.WaitGroup
	closed atomic.Bool
	// sink, when set, is offered every packet from the core first: the
	// engine's fast path takes those of flows it forwards at the IP level.
	sink *atomic.Pointer[engine.PacketSink]
	rc   syscall.RawConn

	packetsIn, packetsOut atomic.Int64 // from / to the core
}

// newTunnel takes ownership of fd in every case.
func newTunnel(fd int, cfg TunConfig, sink *atomic.Pointer[engine.PacketSink]) (_ *tunnel, err error) {
	// Non-blocking before NewFile, so the file uses Go's poller.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Room for bursts from the engine's fast path, which drops rather than
	// waits when the core falls behind.
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	file := os.NewFile(uintptr(fd), "openvpn-tun")
	defer func() {
		if err != nil {
			file.Close()
		}
	}()
	routes, err := newRouteSet(cfg)
	if err != nil {
		return nil, err
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	ep := channel.New(outboundQueueLen, uint32(mtu), "")
	if terr := s.CreateNIC(nicID, ep); terr != nil {
		s.Destroy()
		return nil, fmt.Errorf("create NIC: %v", terr)
	}
	// Ephemeral ports below the range apps use (Android: 32768-60999), so
	// flows this stack dials never collide with fast-path flows, which keep
	// the app's own port.
	if terr := s.SetPortRange(10000, 32767); terr != nil {
		s.Destroy()
		return nil, fmt.Errorf("port range: %v", terr)
	}
	rc, err := file.SyscallConn()
	if err != nil {
		s.Destroy()
		return nil, err
	}
	t := &tunnel{cfg: cfg, routes: routes, mtu: mtu, file: file, stack: s, ep: ep, sink: sink, rc: rc}
	var table []tcpip.Route
	for _, p := range cfg.Addresses {
		pfx, err := p.parse()
		if err != nil {
			s.Destroy()
			return nil, err
		}
		addr := tcpip.AddrFromSlice(pfx.Addr().AsSlice())
		proto := ipv4.ProtocolNumber
		if pfx.Addr().Is6() {
			proto = ipv6.ProtocolNumber
			if t.local6.Len() == 0 {
				t.local6 = addr
			}
		} else if t.local4.Len() == 0 {
			t.local4 = addr
		}
		pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: pfx.Bits()}}
		if terr := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); terr != nil {
			s.Destroy()
			return nil, fmt.Errorf("add address %s: %v", pfx, terr)
		}
	}
	// Every destination leaves through the tunnel; routeSet decides beforehand
	// which ones may be dialed at all.
	if t.local4.Len() > 0 {
		v4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
		table = append(table, tcpip.Route{Destination: v4, NIC: nicID})
	}
	if t.local6.Len() > 0 {
		v6, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
		table = append(table, tcpip.Route{Destination: v6, NIC: nicID})
	}
	s.SetRouteTable(table)
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.wg.Add(2)
	go t.read()
	go t.write()
	return t, nil
}

func (t *tunnel) close() {
	t.once.Do(func() {
		t.closed.Store(true)
		t.cancel()
		t.file.Close() // unblocks read
		t.wg.Wait()
		t.ep.Close()
		t.stack.Close()
		t.stack.Wait()
	})
}

// read takes packets from the core in batches. Each is offered to the
// engine's fast path first (which may hold it until the batch's Flush to
// coalesce it), otherwise handed to this session's netstack.
func (t *tunnel) read() {
	defer t.wg.Done()
	hdr := 0
	if t.cfg.AFPrefix {
		hdr = 4
	}
	b := newReadBatch(t.mtu + hdr)
	defer b.release()
	for {
		n, err := b.read(t.rc)
		if err != nil {
			return
		}
		sink := t.sink.Load()
		for i := 0; i < n; i++ {
			size := b.sizes[i]
			if size <= hdr {
				continue
			}
			t.packetsIn.Add(1)
			if sink != nil && (*sink).Packet(b.views[i].AsSlice()[hdr:size]) {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch b.views[i].AsSlice()[hdr] >> 4 {
			case header.IPv4Version:
				proto = ipv4.ProtocolNumber
			case header.IPv6Version:
				proto = ipv6.ProtocolNumber
			default:
				continue
			}
			v := b.take(i)
			v.CapLength(size)
			v.TrimFront(hdr)
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(v)})
			t.ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
		if sink != nil {
			(*sink).Flush()
		}
	}
}

func (t *tunnel) write() {
	defer t.wg.Done()
	rc, err := t.file.SyscallConn()
	if err != nil {
		return
	}
	for {
		pkt := t.ep.ReadContext(t.ctx)
		if pkt == nil {
			return
		}
		slices := pkt.AsSlices()
		if t.cfg.AFPrefix {
			af := uint32(unix.AF_INET)
			if pkt.NetworkProtocolNumber == ipv6.ProtocolNumber {
				af = unix.AF_INET6
			}
			var h [4]byte
			binary.BigEndian.PutUint32(h[:], af)
			slices = append([][]byte{h[:]}, slices...)
		}
		var werr error
		err := rc.Write(func(fd uintptr) bool {
			_, werr = unix.Writev(int(fd), slices)
			return werr != unix.EAGAIN
		})
		pkt.DecRef()
		if err != nil {
			return
		}
		if werr == nil {
			t.packetsOut.Add(1)
		}
		// Other write errors drop the packet, as a full TUN queue would.
	}
}

var errNotRouted = errors.New("destination is not routed by this OpenVPN server")

// packetPath is the engine's fast path into this tunnel (engine.PacketPath).
type packetPath struct {
	t     *tunnel
	local netip.Addr
}

func (t *tunnel) packetPath(dst netip.Addr) (engine.PacketPath, bool) {
	dst = dst.Unmap()
	if t.closed.Load() || !t.routes.owns(dst) {
		return nil, false
	}
	local := t.local4
	if dst.Is6() {
		local = t.local6
	}
	if local.Len() == 0 {
		return nil, false
	}
	a, _ := netip.AddrFromSlice(local.AsSlice())
	return packetPath{t, a}, true
}

func (p packetPath) Local() netip.Addr { return p.local }
func (p packetPath) MTU() int          { return p.t.mtu }
func (p packetPath) Valid() bool       { return !p.t.closed.Load() }

var errPathFull = errors.New("openvpn tunnel is full")

// Send writes one packet to the core, never waiting: a full socket drops it.
func (p packetPath) Send(b []byte) error {
	var werr error
	err := p.t.rc.Write(func(fd uintptr) bool {
		if p.t.cfg.AFPrefix {
			var h [4]byte
			af := uint32(unix.AF_INET)
			if b[0]>>4 == 6 {
				af = unix.AF_INET6
			}
			binary.BigEndian.PutUint32(h[:], af)
			_, werr = unix.Writev(int(fd), [][]byte{h[:], b})
		} else {
			_, werr = unix.Write(int(fd), b)
		}
		return true
	})
	if err != nil {
		return err
	}
	if werr == unix.EAGAIN {
		return errPathFull
	}
	if werr == nil {
		p.t.packetsOut.Add(1)
	}
	return werr
}

// dial opens a TCP or UDP flow to dst through the tunnel.
func (t *tunnel) dial(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
	addr := dst.Addr().Unmap()
	if !t.routes.owns(addr) {
		return nil, fmt.Errorf("%s: %w", addr, errNotRouted)
	}
	proto, local := ipv4.ProtocolNumber, t.local4
	if addr.Is6() {
		proto, local = ipv6.ProtocolNumber, t.local6
	}
	if local.Len() == 0 {
		return nil, fmt.Errorf("%s: the server pushed no address of this family", addr)
	}
	remote := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(addr.AsSlice()), Port: dst.Port()}
	switch network {
	case "tcp":
		return gonet.DialTCPWithBind(ctx, t.stack, tcpip.FullAddress{NIC: nicID, Addr: local}, remote, proto)
	case "udp":
		return gonet.DialUDP(t.stack, &tcpip.FullAddress{NIC: nicID, Addr: local}, &remote, proto)
	}
	return nil, fmt.Errorf("unsupported network %q", network)
}
