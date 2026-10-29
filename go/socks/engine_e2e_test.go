//go:build darwin || linux

package socks

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"hybridvpn/netcore/engine"
)

type e2eHost struct{}

func (e2eHost) Protect(int) bool               { return true }
func (e2eHost) DNS([]byte, engine.Flow) []byte { return nil }
func (e2eHost) OwnerUID(engine.Flow) int       { return engine.UnknownUID }

// appStack is a minimal "phone": a gVisor stack whose NIC is one end of a
// datagram socketpair; the other end is the engine's TUN.
func appStack(t *testing.T) (*stack.Stack, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
		unix.SetNonblock(fd, true)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, 1500, "")
	s.CreateNIC(1, ep)
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 215, 173, 1}).WithPrefix()}, stack.AddressProperties{})
	any4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	s.SetRouteTable([]tcpip.Route{{Destination: any4, NIC: 1}})
	sock := os.NewFile(uintptr(fds[1]), "app")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := sock.Read(buf)
			if err != nil {
				return
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:n])})
			ep.InjectInbound(ipv4.ProtocolNumber, pkt)
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
			s := pkt.AsSlices()
			rc.Write(func(fd uintptr) bool { _, err := unix.Writev(int(fd), s); return err != unix.EAGAIN })
			pkt.DecRef()
		}
	}()
	t.Cleanup(func() { cancel(); sock.Close(); s.Close() })
	return s, os.NewFile(uintptr(fds[0]), "tun")
}

// TestEngineRoutesThroughSOCKS5 runs the real engine with a SOCKS5 transport:
// app TCP and UDP to TEST-NET reach the echo servers only via the proxy. Once
// the proxy is gone, flows fail instead of leaking to the direct transport.
func TestEngineRoutesThroughSOCKS5(t *testing.T) {
	l := startLab(t, "alice", "secret")
	var d net.Dialer
	proxy, err := New(Config{ID: "lab", Server: l.proxy, Username: "alice", Password: "secret", Dial: d.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	policy := []byte(`{"version":1,
		"transports":[{"id":"direct","type":"direct"},{"id":"socks5:lab","type":"socks5"}],
		"default":{"transport":"direct","on_failure":"block"},
		"rules":[{"id":"proxy","any_app":true,"cidrs":["192.0.2.0/24"],"action":"route","transport":"socks5:lab","on_failure":"block"}]}`)
	s, tun := appStack(t)
	eng, err := engine.Start(engine.Config{
		TUN: tun, MTU: 1500, Host: e2eHost{},
		Tunnel:     []netip.Prefix{netip.MustParsePrefix("10.215.173.0/30")},
		Transports: []engine.Transport{engine.NewDirect(func(int) bool { return true }), proxy.Transport()},
		Policy:     policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Stop)

	addr := func(ap netip.AddrPort) tcpip.FullAddress {
		return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
	}
	echoTCP := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := gonet.DialContextTCP(ctx, s, addr(tcpTarget), ipv4.ProtocolNumber)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		msg := make([]byte, 256<<10)
		for i := range msg {
			msg[i] = byte(i)
		}
		go c.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			return err
		}
		for i := range got {
			if got[i] != msg[i] {
				t.Fatalf("byte %d corrupted", i)
			}
		}
		return nil
	}
	echoUDP := func() (string, error) {
		c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{NIC: 1, Addr: addr(udpTarget).Addr, Port: udpTarget.Port()}, ipv4.ProtocolNumber)
		if err != nil {
			return "", err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return "", err
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		return string(buf[:n]), err
	}

	if err := echoTCP(); err != nil {
		t.Fatalf("TCP via socks5:lab: %v", err)
	}
	if got, err := echoUDP(); got != "echo:ping" {
		t.Fatalf("UDP via socks5:lab: %q %v", got, err)
	}

	// Take the proxy away: the same flows must now fail closed.
	l.stopProxy()
	if err := echoTCP(); err == nil {
		t.Error("TCP succeeded without the proxy")
	}
	if got, _ := echoUDP(); got != "" {
		t.Errorf("UDP answered without the proxy: %q", got)
	}
	st := eng.Stats()
	t.Logf("routed %v, dropped %v", st.Routed, st.Dropped)
	if st.Routed["direct"] != 0 {
		t.Errorf("flows leaked to direct: %v", st.Routed)
	}
	if st.Routed["socks5:lab"] != 2 {
		t.Errorf("unexpected routing: %v", st.Routed)
	}
}
