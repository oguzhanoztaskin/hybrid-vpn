package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	appV4     = netip.MustParseAddr("10.215.173.1")
	appV6     = netip.MustParseAddr("fdc1:7e57:dead::1")
	resolver4 = netip.MustParseAddr("10.215.173.2")
	resolver6 = netip.MustParseAddr("fdc1:7e57:dead::2")
	tunnel    = []netip.Prefix{netip.MustParsePrefix("10.215.173.0/30"), netip.MustParsePrefix("fdc1:7e57:dead::/126")}
)

// fakeDirect stands in for a transport (by default the physical network): it
// maps public test destinations onto loopback servers and refuses everything
// else. name/kind/caps/fail let tests register several transports.
type fakeDirect struct {
	mu     sync.Mutex
	routes map[string]string // "dst" or "proto/dst" -> loopback target
	dials  int
	name   string
	kind   string
	tcpOff bool // Capabilities: no TCP
	udpOff bool // Capabilities: no UDP
	fail   bool // every dial fails
}

func newFake(name, kind string) *fakeDirect {
	return &fakeDirect{routes: map[string]string{}, name: name, kind: kind}
}

func (d *fakeDirect) Name() string {
	if d.name == "" {
		return DirectName
	}
	return d.name
}

func (d *fakeDirect) Kind() string {
	if d.kind == "" {
		return "direct"
	}
	return d.kind
}

func (d *fakeDirect) Capabilities() Capabilities { return Capabilities{TCP: !d.tcpOff, UDP: !d.udpOff} }

func (d *fakeDirect) route(dst, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.routes[dst] = target
}

func (d *fakeDirect) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

func (d *fakeDirect) Dial(ctx context.Context, f Flow) (net.Conn, error) {
	d.mu.Lock()
	target, ok := d.routes[f.Protocol.String()+"/"+f.Dst.String()]
	if !ok {
		target, ok = d.routes[f.Dst.String()]
	}
	d.dials++
	fail := d.fail
	d.mu.Unlock()
	if fail {
		return nil, fmt.Errorf("%s: transport down", d.Name())
	}
	if !ok {
		return nil, fmt.Errorf("no route to %v", f.Dst)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, f.Protocol.String(), target)
}

type fakeHost struct {
	mu       sync.Mutex
	flows    []Flow
	dnsDelay time.Duration
	uids     map[uint16]int // app source port -> owning UID
	lookups  int
}

func (h *fakeHost) Protect(int) bool { return true }

func (h *fakeHost) OwnerUID(f Flow) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lookups++
	if uid, ok := h.uids[f.Src.Port()]; ok {
		return uid
	}
	return UnknownUID
}

// DNS answers by echoing the query with the QR bit set.
func (h *fakeHost) DNS(q []byte, f Flow) []byte {
	h.mu.Lock()
	h.flows = append(h.flows, f)
	delay := h.dnsDelay
	h.mu.Unlock()
	time.Sleep(delay)
	if len(q) < 12 {
		return nil
	}
	resp := append([]byte(nil), q...)
	resp[2] |= 0x80
	return resp
}

// testApp is the "phone": a second gVisor stack whose NIC is the other end
// of a datagram socketpair standing in for the TUN device.
type testApp struct {
	s    *stack.Stack
	ep   *channel.Endpoint
	sock *os.File
	ctx  context.Context
}

type harness struct {
	app    *testApp
	eng    *Engine
	direct *fakeDirect
	host   *fakeHost
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

// newHarnessWith starts an engine with an initial policy and extra transports.
func newHarnessWith(t *testing.T, policy []byte, extra ...Transport) *harness {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
	}
	direct := &fakeDirect{routes: map[string]string{}}
	host := &fakeHost{uids: map[uint16]int{}}
	transports := append([]Transport{direct}, extra...)
	eng, err := Start(Config{
		TUN:        os.NewFile(uintptr(fds[0]), "tun"),
		MTU:        1500,
		Host:       host,
		Tunnel:     tunnel,
		Resolvers:  []netip.Addr{resolver4, resolver6},
		Transports: transports,
		Policy:     policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Stop)
	return &harness{app: newTestApp(t, os.NewFile(uintptr(fds[1]), "app")), eng: eng, direct: direct, host: host}
}

func newTestApp(t *testing.T, sock *os.File) *testApp {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	ep := channel.New(512, 1500, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	for _, a := range []netip.Addr{appV4, appV6} {
		proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}, stack.AddressProperties{})
	}
	v4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	v6, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
	s.SetRouteTable([]tcpip.Route{{Destination: v4, NIC: 1}, {Destination: v6, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	app := &testApp{s: s, ep: ep, sock: sock, ctx: ctx}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := sock.Read(buf)
			if err != nil {
				return
			}
			proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
			if buf[0]>>4 == 6 {
				proto = ipv6.ProtocolNumber
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:n])})
			ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()
	go func() {
		rc, _ := sock.SyscallConn()
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			slices := pkt.AsSlices()
			rc.Write(func(fd uintptr) bool {
				_, err := unix.Writev(int(fd), slices)
				return err != unix.EAGAIN
			})
			pkt.DecRef()
		}
	}()
	t.Cleanup(func() {
		cancel()
		sock.Close()
		s.Close()
	})
	return app
}

func full(ap netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if ap.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}, proto
}

func (a *testApp) dialTCP(t *testing.T, dst string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr, proto := full(netip.MustParseAddrPort(dst))
	c, err := gonet.DialContextTCP(ctx, a.s, addr, proto)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (a *testApp) dialUDP(t *testing.T, dst string) net.Conn {
	t.Helper()
	addr, proto := full(netip.MustParseAddrPort(dst))
	c, err := gonet.DialUDP(a.s, nil, &addr, proto)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func listenTCP(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return ln.Addr().String()
}

func TestTCPForwardingIntegrity(t *testing.T) {
	h := newHarness(t)
	echo := listenTCP(t, func(c net.Conn) { io.Copy(c, c); c.Close() })
	h.direct.route("203.0.113.10:443", echo)

	c, err := h.app.dialTCP(t, "203.0.113.10:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := make([]byte, 8<<20)
	rand.Read(payload)
	go func() {
		c.Write(payload)
		c.(*gonet.TCPConn).CloseWrite()
	}()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("payload corrupted: got %d bytes, want %d", len(got), len(payload))
	}
	waitFor(t, func() bool { return h.eng.Stats().TCPActive == 0 })
	st := h.eng.Stats()
	if st.TCPTotal != 1 || st.BytesUp != int64(len(payload)) || st.BytesDown != int64(len(payload)) {
		t.Errorf("stats: %+v", st)
	}
}

func TestTCPHalfClose(t *testing.T) {
	h := newHarness(t)
	srv := listenTCP(t, func(c net.Conn) {
		req, _ := io.ReadAll(c) // until the app's FIN
		c.Write(append([]byte("got "), req...))
		c.Close()
	})
	h.direct.route("[2001:db8::7]:80", srv)
	c, err := h.app.dialTCP(t, "[2001:db8::7]:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("request"))
	c.(*gonet.TCPConn).CloseWrite()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	got, _ := io.ReadAll(c)
	if string(got) != "got request" {
		t.Fatalf("got %q", got)
	}
}

func TestTCPRefusedWhenUnreachable(t *testing.T) {
	h := newHarness(t)
	start := time.Now()
	if _, err := h.app.dialTCP(t, "203.0.113.99:80"); err == nil {
		t.Fatal("dial to unreachable destination succeeded")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("refusal took %v; expected an immediate RST", time.Since(start))
	}
	if h.eng.Stats().TCPFailed != 1 {
		t.Errorf("stats: %+v", h.eng.Stats())
	}
}

func TestLoopAndResolverPortsDropped(t *testing.T) {
	h := newHarness(t)
	for _, dst := range []string{"10.215.173.3:80", "10.215.173.2:853", "[fdc1:7e57:dead::2]:853"} {
		if _, err := h.app.dialTCP(t, dst); err == nil {
			t.Errorf("%s: connection accepted", dst)
		}
	}
	if h.direct.dialCount() != 0 {
		t.Errorf("transport was dialed %d times", h.direct.dialCount())
	}
	d := h.eng.Stats().Dropped
	if d["tunnel address"] != 1 || d["virtual resolver serves only port 53"] != 2 {
		t.Errorf("dropped: %v", d)
	}
}

func TestUDPForwarding(t *testing.T) {
	h := newHarness(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	h.direct.route("198.51.100.7:9000", pc.LocalAddr().String())
	c := h.app.dialUDP(t, "198.51.100.7:9000")
	defer c.Close()
	buf := make([]byte, 2048)
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("datagram %d", i)
		c.Write([]byte(msg))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "echo:"+msg {
			t.Fatalf("got %q", buf[:n])
		}
	}
	if st := h.eng.Stats(); st.UDPTotal != 1 || st.UDPActive != 1 {
		t.Errorf("expected one UDP association: %+v", st)
	}
}

func dnsQuery(id uint16) []byte {
	q := make([]byte, 12, 32)
	binary.BigEndian.PutUint16(q, id)
	q[5] = 1 // one question
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1)
	return q
}

func TestDNSInterceptedForAnyResolver(t *testing.T) {
	h := newHarness(t)
	for _, dst := range []string{"10.215.173.2:53", "8.8.8.8:53", "[2001:4860:4860::8888]:53"} {
		c := h.app.dialUDP(t, dst)
		c.Write(dnsQuery(0x1234))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			t.Fatalf("%s: %v", dst, err)
		}
		if n < 12 || buf[2]&0x80 == 0 || binary.BigEndian.Uint16(buf) != 0x1234 {
			t.Fatalf("%s: bad answer %x", dst, buf[:n])
		}
	}
	if h.direct.dialCount() != 0 {
		t.Error("DNS leaked to the direct transport")
	}
	h.host.mu.Lock()
	defer h.host.mu.Unlock()
	if len(h.host.flows) != 3 || h.host.flows[1].Dst != netip.MustParseAddrPort("8.8.8.8:53") || h.host.flows[0].Src.Addr() != appV4 {
		t.Errorf("host saw flows %v", h.host.flows)
	}
}

func TestDNSOverTCP(t *testing.T) {
	h := newHarness(t)
	c, err := h.app.dialTCP(t, "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for id := uint16(1); id <= 2; id++ {
		q := dnsQuery(id)
		c.Write(append([]byte{0, byte(len(q))}, q...))
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint16(resp) != id || resp[2]&0x80 == 0 {
			t.Fatalf("bad answer %x", resp)
		}
	}
	if h.direct.dialCount() != 0 {
		t.Error("DNS over TCP leaked to the direct transport")
	}
}

func TestICMPDroppedNotAnswered(t *testing.T) {
	h := newHarness(t)
	// Raw IPv4 ICMP echo request 10.215.173.1 -> 192.0.2.1, written straight into the "TUN".
	pkt := []byte{0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 215, 173, 1, 192, 0, 2, 1, 8, 0, 0xf7, 0xff, 0, 0, 0, 0}
	if _, err := h.app.sock.Write(pkt); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return h.eng.Stats().Dropped["icmp"] == 1 })
	time.Sleep(200 * time.Millisecond)
	if out := h.eng.Stats().PacketsOut; out != 0 {
		t.Fatalf("engine emitted %d packets in response to ICMP", out)
	}
}

func TestStopIsPromptAndReleasesResources(t *testing.T) {
	h := newHarness(t)
	h.host.dnsDelay = 20 * time.Second // a DNS upstream that hangs
	echo := listenTCP(t, func(c net.Conn) { io.Copy(c, c); c.Close() })
	h.direct.route("203.0.113.10:443", echo)
	c, err := h.app.dialTCP(t, "203.0.113.10:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u := h.app.dialUDP(t, "8.8.8.8:53")
	u.Write(dnsQuery(9))
	waitFor(t, func() bool { return h.eng.Stats().DNSQueries == 1 && h.eng.Stats().TCPActive == 1 })

	start := time.Now()
	h.eng.Stop()
	h.eng.Stop() // idempotent
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("Stop took %v despite a hung DNS callback", d)
	}
	t.Logf("Stop returned in %v", time.Since(start))
	if st := h.eng.Stats(); st.Running {
		t.Error("still running after Stop")
	}
	// The engine owned the TUN fd: its peer must now see the far end closed.
	if _, err := h.app.sock.Write([]byte{0x45}); err == nil {
		t.Error("TUN fd still open after Stop")
	}
	// The forwarded TCP connection was torn down.
	// No RST can reach the app once the engine has closed the TUN fd; the app
	// sees silence (fail closed). On Android the OS destroys sockets on the
	// VPN network when the interface goes away.
	c.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Errorf("app received data after Stop (n=%d, err=%v)", n, err)
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	base := runtime.NumGoroutine()
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			h := newHarness(t)
			echo := listenTCP(t, func(c net.Conn) { io.Copy(c, c); c.Close() })
			h.direct.route("203.0.113.10:443", echo)
			c, err := h.app.dialTCP(t, "203.0.113.10:443")
			if err != nil {
				t.Fatal(err)
			}
			c.Write([]byte("x"))
			io.ReadFull(c, make([]byte, 1))
			h.eng.Stop()
			c.Close()
		})
	}
	waitFor(t, func() bool { return runtime.NumGoroutine() <= base+40 })
	t.Logf("goroutines: base %d, after 3 engine lifecycles %d", base, runtime.NumGoroutine())
}

func TestClassify(t *testing.T) {
	v6 := func(next byte) []byte { p := make([]byte, 48); p[0] = 0x60; p[6] = next; return p }
	frag := v6(44)
	frag[40] = 17
	cases := []struct {
		pkt    []byte
		reason string
	}{
		{[]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}, ""},
		{[]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}, "icmp"},
		{[]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 50, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}, "unsupported protocol"},
		{v6(17), ""},
		{v6(58), "icmp"},
		{frag, ""},
		{v6(0), "unsupported protocol"},
		{[]byte{0x45}, "malformed"},
		{nil, "malformed"},
	}
	for i, c := range cases {
		if _, reason := classify(c.pkt); reason != c.reason {
			t.Errorf("case %d: reason %q, want %q", i, reason, c.reason)
		}
	}
}

func TestRouterDecisions(t *testing.T) {
	r, err := NewRouter(tunnel, []netip.Addr{resolver4, resolver6}, &fakeDirect{})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Action{
		"93.184.216.34:443":      ActionForward,
		"[2606:4700::1]:443":     ActionForward,
		"9.9.9.9:53":             ActionDNS,
		"10.215.173.2:53":        ActionDNS,
		"10.215.173.2:853":       ActionDrop,
		"10.215.173.3:80":        ActionDrop,
		"224.0.0.251:5353":       ActionDrop,
		"255.255.255.255:67":     ActionDrop,
		"127.0.0.1:80":           ActionDrop,
		"[::ffff:8.8.4.4]:443":   ActionForward,
		"[fdc1:7e57:dead::3]:80": ActionDrop,
	}
	for dst, want := range cases {
		if got := r.Decide(Flow{Protocol: TCP, Dst: netip.MustParseAddrPort(dst)}, nil); got.Action != want {
			t.Errorf("%s: %v, want %v", dst, got, want)
		}
	}
	if _, _, err := r.Dial(context.Background(), Flow{}, Decision{Action: ActionForward, Transport: "tailnet:work"}); err == nil {
		t.Error("unknown transport did not fail closed")
	}
	if _, err := NewRouter(nil, nil, &fakeDirect{}, &fakeDirect{}); err == nil {
		t.Error("duplicate transport accepted")
	}
	empty, _ := NewRouter(tunnel, nil)
	d := empty.Decide(Flow{Protocol: TCP, Dst: netip.MustParseAddrPort("1.2.3.4:80")}, nil)
	if _, _, err := empty.Dial(context.Background(), Flow{Protocol: TCP}, d); err == nil {
		t.Errorf("router without transports must fail closed, decision %v", d)
	}
}

func TestDirectProtectsEverySocket(t *testing.T) {
	addr := listenTCP(t, func(c net.Conn) { c.Close() })
	var protected []int
	ok := NewDirect(func(fd int) bool { protected = append(protected, fd); return true })
	c, err := ok.Dial(context.Background(), Flow{Protocol: TCP, Dst: netip.MustParseAddrPort(addr)})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(protected) != 1 || protected[0] <= 2 {
		t.Errorf("protect calls: %v", protected)
	}
	refused := NewDirect(func(int) bool { return false })
	if _, err := refused.Dial(context.Background(), Flow{Protocol: TCP, Dst: netip.MustParseAddrPort(addr)}); !errors.Is(err, ErrProtectFailed) {
		t.Errorf("unprotectable socket: got %v, want ErrProtectFailed", err)
	}
	if _, err := refused.Dial(context.Background(), Flow{Protocol: UDP, Dst: netip.MustParseAddrPort("127.0.0.1:9")}); !errors.Is(err, ErrProtectFailed) {
		t.Errorf("unprotectable UDP socket: got %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConfigureTCPRACK(t *testing.T) {
	for _, disable := range []bool{false, true} {
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		})
		if err := configureTCP(s, disable); err != nil {
			t.Fatal(err)
		}
		var got tcpip.TCPRecovery
		if terr := s.TransportProtocolOption(tcp.ProtocolNumber, &got); terr != nil {
			t.Fatal(terr)
		}
		if want := map[bool]tcpip.TCPRecovery{false: tcpip.TCPRACKLossDetection, true: 0}[disable]; got != want {
			t.Errorf("disable=%v: recovery = %v, want %v", disable, got, want)
		}
		s.Destroy()
	}
}
