package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

type testPingTransport struct {
	*fakeDirect
	calls atomic.Int32
	probe func(context.Context, netip.Addr) error
}

func (t *testPingTransport) Ping(ctx context.Context, dst netip.Addr) error {
	t.calls.Add(1)
	return t.probe(ctx, dst)
}

func echoPacket(v6 bool) []byte {
	src, dst, proto := appV4, netip.MustParseAddr("192.0.2.1"), ICMP
	if v6 {
		src, dst, proto = appV6, netip.MustParseAddr("2001:db8::1"), ICMPv6
	}
	// reply() swaps the endpoints and builds valid IP and ICMP checksums.
	r := echoRequest{flow: Flow{Protocol: proto, Src: netip.AddrPortFrom(dst, 0), Dst: netip.AddrPortFrom(src, 0)}, data: []byte{0, 0, 0, 0, 0x12, 0x34, 0, 7, 'o', 'd', 'd'}}
	p := r.reply()
	off, typ := 20, byte(8)
	if v6 {
		off, typ = 40, 128
	}
	p[off], p[off+2], p[off+3] = typ, 0, 0
	binary.BigEndian.PutUint16(p[off+2:off+4], ^icmpSum(src, dst, p[off:]))
	return p
}

func echoHarness(t *testing.T, v4, v6 bool, policy []byte, transports ...Transport) (*Engine, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
	}
	e, err := Start(Config{TUN: os.NewFile(uintptr(fds[0]), "echo-tun"), Host: &fakeHost{}, Tunnel: tunnel,
		Resolvers: []netip.Addr{resolver4, resolver6}, Transports: transports, Policy: policy, AllowICMP: v4, AllowICMPv6: v6})
	if err != nil {
		unix.Close(fds[1])
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[1]), "echo-app")
	t.Cleanup(func() { e.Stop(); f.Close() })
	return e, f
}

func TestOptionalEchoNeedsRemoteReply(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "ipv6"}[v6], func(t *testing.T) {
			ready := make(chan struct{})
			tr := &testPingTransport{fakeDirect: newFake("direct", "direct"), probe: func(ctx context.Context, _ netip.Addr) error {
				select {
				case <-ready:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}}
			e, f := echoHarness(t, !v6, v6, nil, tr)
			p := echoPacket(v6)
			if _, err := f.Write(p); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { return tr.calls.Load() == 1 })
			f.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
			buf := make([]byte, 1500)
			if _, err := f.Read(buf); err == nil {
				t.Fatal("answered before remote replied")
			}
			close(ready)
			f.SetReadDeadline(time.Now().Add(time.Second))
			n, err := f.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			r, ok := parseEcho(p)
			if !ok || !bytes.Equal(buf[:n], r.reply()) {
				t.Fatalf("invalid reply: %x", buf[:n])
			}
			if e.Stats().Routed["direct"] != 1 {
				t.Fatal("ping route not counted")
			}
		})
	}
}

func TestEchoDisabledAndPolicyBlocks(t *testing.T) {
	for _, tc := range []struct {
		name          string
		v4, v6, send6 bool
		policy        []byte
		reason        string
	}{
		{"default-off", false, false, false, nil, "icmp"},
		{"v6-stays-off", true, false, true, nil, "icmp"},
		{"v4-stays-off", false, true, false, nil, "icmp"},
		{"protocol-block", true, true, false, testPolicy(directT, defDir, `{"id":"no-ping","any_app":true,"protocol":"icmp","action":"block"}`), "policy:no-ping"},
		{"unknown-owner", true, true, true, testPolicy(directT, defDir, `{"id":"unknown","unknown_app":true,"action":"block"}`), "policy:unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &testPingTransport{fakeDirect: newFake("direct", "direct"), probe: func(context.Context, netip.Addr) error { return nil }}
			e, f := echoHarness(t, tc.v4, tc.v6, tc.policy, tr)
			f.Write(echoPacket(tc.send6))
			waitFor(t, func() bool { return e.Stats().Dropped[tc.reason] == 1 })
			if tr.calls.Load() != 0 || e.Stats().PacketsOut != 0 || e.Stats().UIDLookups != 0 {
				t.Fatal("blocked ping reached transport or owner API")
			}
		})
	}
}

func TestPingRoutingFailsClosed(t *testing.T) {
	good := &testPingTransport{fakeDirect: newFake("direct", "direct"), probe: func(context.Context, netip.Addr) error { return nil }}
	bad := newFake("socks5:test", "socks5") // no PingTransport
	r, _ := NewRouter(tunnel, []netip.Addr{resolver4}, good, bad)
	f := Flow{Protocol: ICMP, Src: netip.AddrPortFrom(appV4, 0), Dst: netip.MustParseAddrPort("192.0.2.1:0")}
	d := Decision{Action: ActionForward, Transport: bad.Name(), OnFailure: Block}
	if _, err := r.Ping(context.Background(), f, d); !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("got %v", err)
	}
	if good.calls.Load() != 0 {
		t.Fatal("implicit direct fallback")
	}
	d.OnFailure = "direct"
	if used, err := r.Ping(context.Background(), f, d); err != nil || used != "direct" {
		t.Fatalf("explicit fallback: %s %v", used, err)
	}
	for _, dst := range []netip.Addr{resolver4, appV4, netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("127.0.0.1")} {
		f.Dst = netip.AddrPortFrom(dst, 0)
		if d := r.Decide(f, nil); d.Action != ActionDrop {
			t.Fatalf("guard missed %s", dst)
		}
	}
}

func TestParseEchoRejectsMalformed(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		p := echoPacket(v6)
		for n := 0; n < len(p); n++ {
			if _, ok := parseEcho(p[:n]); ok {
				t.Fatalf("accepted truncation %d", n)
			}
		}
		p[len(p)-1] ^= 1
		if _, ok := parseEcho(p); ok {
			t.Fatal("accepted bad checksum")
		}
	}
	p := echoPacket(false)
	p[6] |= 0x20 // first fragment
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], ^checksum.Checksum(p[:20], 0))
	if _, ok := parseEcho(p); ok {
		t.Fatal("accepted fragment")
	}
}

func TestDirectPingProtected(t *testing.T) {
	for _, dst := range []string{"127.0.0.1", "::1"} {
		t.Run(dst, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := NewDirect(func(int) bool { return false }).Ping(ctx, netip.MustParseAddr(dst)); !errors.Is(err, ErrProtectFailed) {
				t.Fatalf("protection: %v", err)
			}
			if err := NewDirect(func(int) bool { return true }).Ping(ctx, netip.MustParseAddr(dst)); err != nil {
				t.Fatalf("real loopback ping: %v", err)
			}
		})
	}
}

func TestEchoCapacityAndStop(t *testing.T) {
	tr := &testPingTransport{fakeDirect: newFake("direct", "direct"), probe: func(ctx context.Context, _ netip.Addr) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	e, f := echoHarness(t, true, false, nil, tr)
	for range 65 {
		if _, err := f.Write(echoPacket(false)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return e.Stats().Dropped["icmp capacity"] == 1 })
	if tr.calls.Load() != 64 {
		// Wait for the admitted goroutines, which may not all have run yet.
		waitFor(t, func() bool { return tr.calls.Load() == 64 })
	}
	start := time.Now()
	e.Stop()
	if time.Since(start) > time.Second || e.Stats().PacketsOut != 0 {
		t.Fatal("shutdown did not cancel outstanding probes promptly")
	}
}
