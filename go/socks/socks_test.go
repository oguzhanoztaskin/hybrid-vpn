package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"hybridvpn/netcore/engine"
	"tailscale.com/net/socks5"
)

// Destinations in TEST-NET-1. The proxy maps them to local echo servers, so a
// flow only succeeds if it really went through the proxy.
var (
	tcpTarget    = netip.MustParseAddrPort("192.0.2.10:7")
	udpTarget    = netip.MustParseAddrPort("192.0.2.10:7")
	closedTarget = netip.MustParseAddrPort("192.0.2.99:9")
)

type lab struct {
	proxy   string
	tcpEcho string
	udpEcho string
	// stopProxy closes the proxy's listener: new flows can't reach it.
	stopProxy func()
}

// startLab runs tailscale's SOCKS5 server (an independent implementation)
// plus TCP and UDP echo servers on loopback.
func startLab(t *testing.T, user, pass string) lab {
	t.Helper()
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			ul.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	l := lab{tcpEcho: tl.Addr().String(), udpEcho: ul.LocalAddr().String()}

	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pl.Close() })
	srv := &socks5.Server{
		Logf:     t.Logf,
		Username: user,
		Password: pass,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			switch {
			case network == "tcp" && addr == tcpTarget.String():
				return d.DialContext(ctx, network, l.tcpEcho)
			case network == "udp" && addr == udpTarget.String():
				return d.DialContext(ctx, network, l.udpEcho)
			}
			return nil, errors.New("lab: destination not reachable")
		},
	}
	go srv.Serve(pl)
	l.proxy = pl.Addr().String()
	l.stopProxy = func() { pl.Close() }
	return l
}

func newProxy(t *testing.T, server, user, pass string) *Proxy {
	t.Helper()
	var d net.Dialer
	p, err := New(Config{ID: "lab", Server: server, Username: user, Password: pass, Dial: d.DialContext})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func dial(t *testing.T, p *Proxy, proto engine.Protocol, dst netip.AddrPort) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.Transport().Dial(ctx, engine.Flow{Protocol: proto, Src: netip.MustParseAddrPort("10.215.173.1:40000"), Dst: dst})
}

func TestTCPConnect(t *testing.T) {
	l := startLab(t, "", "")
	p := newProxy(t, l.proxy, "", "")
	c, err := dial(t, p, engine.TCP, tcpTarget)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo %q %v", buf, err)
	}
	if s := p.Summary(); s.TCPActive != 1 || s.State != StateReady || s.Flows != 1 {
		t.Errorf("summary while open: %+v", s)
	}
	c.Close()
	c.Close()
	if s := p.Summary(); s.TCPActive != 0 {
		t.Errorf("active after close: %+v", s)
	}
}

func TestUDPAssociate(t *testing.T) {
	l := startLab(t, "", "")
	p := newProxy(t, l.proxy, "", "")
	c, err := dial(t, p, engine.UDP, udpTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for _, msg := range []string{"one", "two", strings.Repeat("x", 1200)} {
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "echo:"+msg {
			t.Fatalf("echo %q: got %q %v", msg[:3], buf[:min(n, 20)], err)
		}
	}
	if s := p.Summary(); s.UDPActive != 1 {
		t.Errorf("summary: %+v", s)
	}
}

func TestAuthentication(t *testing.T) {
	l := startLab(t, "alice", "secret")
	if _, err := dial(t, newProxy(t, l.proxy, "alice", "secret"), engine.TCP, tcpTarget); err != nil {
		t.Fatalf("right password: %v", err)
	}
	p := newProxy(t, l.proxy, "alice", "wrong")
	if _, err := dial(t, p, engine.TCP, tcpTarget); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("wrong password: %v", err)
	}
	if s := p.Summary(); s.State != StateError || s.Failures != 1 {
		t.Errorf("summary after bad password: %+v", s)
	}
	if err := newProxy(t, l.proxy, "", "").Check(context.Background()); err == nil || !strings.Contains(err.Error(), "requires authentication") {
		t.Errorf("no credentials: %v", err)
	}
}

// A destination the proxy can't reach is the proxy's answer, not a broken proxy.
func TestRefusedDestinationKeepsProxyReady(t *testing.T) {
	l := startLab(t, "", "")
	p := newProxy(t, l.proxy, "", "")
	_, err := dial(t, p, engine.TCP, closedTarget)
	var refused *refusedError
	if !errors.As(err, &refused) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if s := p.Summary(); s.State != StateReady || s.Failures != 1 {
		t.Errorf("summary: %+v", s)
	}
}

func TestUnreachableProxy(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens here any more
	p := newProxy(t, addr, "", "")
	if _, err := dial(t, p, engine.TCP, tcpTarget); err == nil {
		t.Fatal("dial through a dead proxy succeeded")
	}
	if s := p.Summary(); s.State != StateError || !strings.Contains(s.Error, "can't reach") {
		t.Errorf("summary: %+v", s)
	}
}

// Closing the control connection must end the UDP association.
func TestUDPAssociationEndsWithControlConnection(t *testing.T) {
	l := startLab(t, "", "")
	p := newProxy(t, l.proxy, "", "")
	c, err := dial(t, p, engine.UDP, udpTarget)
	if err != nil {
		t.Fatal(err)
	}
	uc := c.(*udpConn)
	uc.control.Close()
	deadline := time.Now().Add(2 * time.Second)
	for p.Summary().UDPActive != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if p.Summary().UDPActive != 0 {
		t.Fatal("association still active")
	}
	if _, err := c.Write([]byte("late")); err == nil {
		t.Error("write after the association ended succeeded")
	}
}

func TestConfigValidation(t *testing.T) {
	var d net.Dialer
	for _, c := range []Config{
		{ID: "", Server: "proxy:1080", Dial: d.DialContext},
		{ID: "a", Server: "proxy", Dial: d.DialContext},
		{ID: "a", Server: "proxy:0", Dial: d.DialContext},
		{ID: "a", Server: ":1080", Dial: d.DialContext},
		{ID: "a", Server: "proxy:1080", Password: "x", Dial: d.DialContext},
		{ID: "a", Server: "proxy:1080", Username: strings.Repeat("u", 256), Dial: d.DialContext},
		{ID: "a", Server: "proxy:1080"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	if _, err := New(Config{ID: "a", Server: "[2001:db8::1]:1080", Dial: d.DialContext}); err != nil {
		t.Error(err)
	}
	broken := NewFailed("bad", "proxy", errors.New("bad config"))
	if _, err := broken.Transport().Dial(context.Background(), engine.Flow{Protocol: engine.TCP, Dst: tcpTarget}); err == nil {
		t.Error("a failed proxy dialed")
	}
	if s := broken.Summary(); s.State != StateError || s.Error != "bad config" || s.Failures != 1 {
		t.Errorf("failed proxy summary: %+v", s)
	}
}

func TestRelayAddress(t *testing.T) {
	proxy := netip.MustParseAddr("203.0.113.5")
	for bound, want := range map[string]string{
		"0.0.0.0:4000":      "203.0.113.5:4000",
		"[::]:4000":         "203.0.113.5:4000",
		"127.0.0.1:4000":    "203.0.113.5:4000",
		"198.51.100.7:4000": "198.51.100.7:4000",
	} {
		if got := relayAddress(netip.MustParseAddrPort(bound), proxy); got.String() != want {
			t.Errorf("%s: got %s, want %s", bound, got, want)
		}
	}
}
