//go:build openvpn3 && darwin

package openvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
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
	"hybridvpn/netcore/ovpnlab"
)

type e2eHost struct{}

func (e2eHost) Protect(int) bool               { return true }
func (e2eHost) DNS([]byte, engine.Flow) []byte { return nil }
func (e2eHost) OwnerUID(engine.Flow) int       { return engine.UnknownUID }

// appStack is a minimal "phone": a gVisor stack whose NIC is one end of a
// datagram socketpair; the other end is the engine's TUN.
func appStack(t *testing.T) (*stack.Stack, *os.File) { return appStackMTU(t, 1500) }

func appStackMTU(t testing.TB, mtu uint32) (*stack.Stack, *os.File) {
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
	ep := channel.New(512, mtu, "")
	s.CreateNIC(1, ep)
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 215, 173, 1}).WithPrefix()}, stack.AddressProperties{})
	any4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	s.SetRouteTable([]tcpip.Route{{Destination: any4, NIC: 1}})
	sock := os.NewFile(uintptr(fds[1]), "app")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		buf := make([]byte, mtu+4)
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

// TestEngineRoutesThroughOpenVPN runs the real engine with an OpenVPN
// transport. The policy sends the server's networks to openvpn:lab, and also
// (wrongly) a network the server does not route: that flow must fail rather
// than leak to the direct transport.
func TestEngineRoutesThroughOpenVPN(t *testing.T) {
	lab := startLab(t, ovpnlab.Options{})
	c := connect(t, Config{Profile: lab.Profile})
	waitState(t, c, StateConnected, 20*time.Second)

	policy := []byte(`{"version":1,
		"transports":[{"id":"direct","type":"direct"},{"id":"openvpn:lab","type":"openvpn"}],
		"default":{"transport":"direct","on_failure":"block"},
		"rules":[
		  {"id":"corp","any_app":true,"cidrs":["10.8.0.0/24","10.9.0.0/24"],"action":"route","transport":"openvpn:lab","on_failure":"block"},
		  {"id":"not-pushed","any_app":true,"cidrs":["192.0.2.0/24"],"action":"route","transport":"openvpn:lab","on_failure":"block"}]}`)
	s, tun := appStack(t)
	eng, err := engine.Start(engine.Config{
		TUN: tun, MTU: 1500, Host: e2eHost{},
		Tunnel:     []netip.Prefix{netip.MustParsePrefix("10.215.173.0/30")},
		Transports: []engine.Transport{engine.NewDirect(func(int) bool { return true }), c.Transport()},
		Policy:     policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Stop)

	fetch := func(dst string) (string, error) {
		ap := netip.MustParseAddrPort(dst)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}, ipv4.ProtocolNumber)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		b, err := io.ReadAll(conn)
		return strings.TrimSpace(string(b)), err
	}
	for _, dst := range []string{"10.8.0.1:8080", "10.9.0.1:8080"} {
		if got, err := fetch(dst); !strings.HasPrefix(got, "ovpnlab") {
			t.Fatalf("%s via openvpn:lab: %q %v", dst, got, err)
		}
	}
	if got, err := fetch("192.0.2.1:80"); err == nil {
		t.Errorf("unrouted network reached %q", got)
	}
	c.Stop()
	if got, err := fetch("10.9.0.1:8080"); err == nil {
		t.Errorf("reached %q after the VPN stopped", got)
	}
	st := eng.Stats()
	t.Logf("routed %v, dropped %v, fast path out/in %d/%d", st.Routed, st.Dropped, st.FastPacketsOut, st.FastPacketsIn)
	if st.Routed["openvpn:lab"] != 2 || st.Routed["direct"] != 0 {
		t.Errorf("unexpected routing: %v", st.Routed)
	}
	if st.FastPacketsOut == 0 || st.FastPacketsIn == 0 {
		t.Errorf("flows did not take the fast path: out %d in %d", st.FastPacketsOut, st.FastPacketsIn)
	}
}

// TestEngineOpenVPNIntegrity echoes random data through the engine and the
// VPN, on the fast path and on the netstack path.
func TestEngineOpenVPNIntegrity(t *testing.T) {
	lab := startLab(t, ovpnlab.Options{})
	c := connect(t, Config{Profile: lab.Profile})
	waitState(t, c, StateConnected, 20*time.Second)
	for _, fast := range []bool{true, false} {
		t.Run(map[bool]string{true: "fast", false: "netstack"}[fast], func(t *testing.T) {
			s, eng := openvpnEngine(t, c, 16384, !fast)
			conn := dialApp(t, s, "10.9.0.1:8081")
			defer conn.Close()
			payload := make([]byte, 8<<20)
			rand.Read(payload)
			go conn.Write(payload)
			got := make([]byte, len(payload))
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("echo: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("echo corrupted")
			}
			if st := eng.Stats(); fast != (st.FastPacketsIn > 0) {
				t.Errorf("fast path packets in: %d", st.FastPacketsIn)
			}
		})
	}
}

// BenchmarkEngineOpenVPNDownload downloads through the engine and the VPN,
// with and without the fast path:
//
//	go test -tags openvpn3 -run x -bench EngineOpenVPN ./openvpn
func BenchmarkEngineOpenVPNDownload(b *testing.B) {
	lab := startLab(b, ovpnlab.Options{})
	c := connect(b, Config{Profile: lab.Profile})
	waitState(b, c, StateConnected, 20*time.Second)
	for _, fast := range []bool{true, false} {
		b.Run(map[bool]string{true: "fast", false: "netstack"}[fast], func(b *testing.B) {
			s, _ := openvpnEngine(b, c, 16384, !fast)
			const size = 64 << 20
			buf := make([]byte, 256<<10)
			b.SetBytes(size)
			var ru0, ru1 unix.Rusage
			unix.Getrusage(unix.RUSAGE_SELF, &ru0)
			b.ResetTimer()
			for range b.N {
				conn := dialApp(b, s, "10.9.0.1:5201")
				var req [9]byte
				req[0] = 'D'
				binary.BigEndian.PutUint64(req[1:], size)
				conn.Write(req[:])
				if n, err := io.CopyBuffer(io.Discard, io.LimitReader(conn, size), buf); n != size {
					b.Fatalf("got %d bytes: %v", n, err)
				}
				conn.Close()
			}
			b.StopTimer()
			unix.Getrusage(unix.RUSAGE_SELF, &ru1)
			cpu := time.Duration(ru1.Utime.Nano() + ru1.Stime.Nano() - ru0.Utime.Nano() - ru0.Stime.Nano())
			b.ReportMetric(float64(cpu.Milliseconds())/float64(b.N)/64, "cpu-ms/MiB")
		})
	}
}

// openvpnEngine starts an engine whose app side has the given MTU and whose
// policy sends the lab's networks to c.
func openvpnEngine(t testing.TB, c *Client, mtu uint32, disableFast bool) (*stack.Stack, *engine.Engine) {
	policy := []byte(`{"version":1,
		"transports":[{"id":"direct","type":"direct"},{"id":"openvpn:lab","type":"openvpn"}],
		"default":{"transport":"direct","on_failure":"block"},
		"rules":[{"id":"corp","any_app":true,"cidrs":["10.8.0.0/24","10.9.0.0/24"],"action":"route","transport":"openvpn:lab","on_failure":"block"}]}`)
	s, tun := appStackMTU(t, mtu)
	eng, err := engine.Start(engine.Config{
		TUN: tun, MTU: mtu, Host: e2eHost{},
		Tunnel:                  []netip.Prefix{netip.MustParsePrefix("10.215.173.0/30")},
		Transports:              []engine.Transport{engine.NewDirect(func(int) bool { return true }), c.Transport()},
		Policy:                  policy,
		DisablePacketForwarding: disableFast,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Stop)
	return s, eng
}

func dialApp(t testing.TB, s *stack.Stack, dst string) net.Conn {
	ap := netip.MustParseAddrPort(dst)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
