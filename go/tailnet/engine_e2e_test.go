package tailnet

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
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
	"tailscale.com/ipn/store/mem"
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

// TestEngineRoutesToTheNamedTailnet runs the real engine with two tailnets
// whose machines have the same address. The policy routes port 8080 to the
// personal tailnet and 8081 to the work tailnet; the address alone never
// selects a tailnet.
func TestEngineRoutesToTheNamedTailnet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	personalURL := startTailnet(t, "personal.ts.net")
	workURL := startTailnet(t, "work.ts.net")
	peer := startPeer(t, ctx, personalURL, "nas", "personal")
	if w := startPeer(t, ctx, workURL, "build", "work"); w != peer {
		t.Fatalf("expected overlapping addresses, got %v and %v", peer, w)
	}
	m := NewManager()
	t.Cleanup(func() { m.Close() })
	var transports []engine.Transport
	for _, tn := range []struct{ id, url string }{{"personal", personalURL}, {"work", workURL}} {
		inst, err := m.Add(Config{ID: tn.id, StateDir: filepath.Join(t.TempDir(), tn.id), ControlURL: tn.url,
			Hostname: "phone-" + tn.id, Store: new(mem.Store), Ephemeral: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inst.Up(ctx); err != nil {
			t.Fatal(err)
		}
		transports = append(transports, inst.Transport())
	}

	policy := []byte(`{"version":1,
		"transports":[{"id":"direct","type":"direct"},{"id":"tailnet:personal","type":"tailnet"},{"id":"tailnet:work","type":"tailnet"}],
		"default":{"transport":"direct","on_failure":"block"},
		"rules":[
		  {"id":"personal","any_app":true,"cidrs":["100.64.0.0/10"],"ports":[[8080,8080]],"action":"route","transport":"tailnet:personal"},
		  {"id":"work","any_app":true,"cidrs":["100.64.0.0/10"],"ports":[[8081,8081]],"action":"route","transport":"tailnet:work"},
		  {"id":"no-other-tailnet-traffic","any_app":true,"cidrs":["100.64.0.0/10"],"action":"block"}]}`)
	s, tun := appStack(t)
	eng, err := engine.Start(engine.Config{
		TUN: tun, MTU: 1500, Host: e2eHost{},
		Tunnel:     []netip.Prefix{netip.MustParsePrefix("10.215.173.0/30")},
		Transports: append([]engine.Transport{engine.NewDirect(func(int) bool { return true })}, transports...),
		Policy:     policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Stop)

	fetch := func(port uint16) (string, error) {
		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		defer dcancel()
		c, err := gonet.DialContextTCP(dctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(peer.AsSlice()), Port: port}, ipv4.ProtocolNumber)
		if err != nil {
			return "", err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		b, err := io.ReadAll(c)
		return string(b), err
	}
	// Same address, both peers serve their tailnet's name on 8080 and 8081:
	// which machine answers depends only on the transport the policy named.
	if got, err := fetch(8080); got != "personal" {
		t.Fatalf("%v:8080 via tailnet:personal: got %q (%v)", peer, got, err)
	}
	if got, err := fetch(8081); got != "work" {
		t.Fatalf("%v:8081 via tailnet:work: got %q (%v)", peer, got, err)
	}
	if got, err := fetch(9999); err == nil {
		t.Errorf("tailnet port without a route reached %q; the block rule should apply", got)
	}
	st := eng.Stats()
	t.Logf("routed %v, dropped %v", st.Routed, st.Dropped)
	if st.Routed["tailnet:personal"] != 1 || st.Routed["tailnet:work"] != 1 || st.Routed["direct"] != 0 {
		t.Errorf("unexpected routing: %v", st.Routed)
	}
	if st.Dropped["policy:no-other-tailnet-traffic"] != 1 {
		t.Errorf("dropped: %v", st.Dropped)
	}
}
