package tailnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"hybridvpn/netcore/engine"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// startTailnet runs an in-process control server with its own DERP/STUN
// relay: a completely separate, offline tailnet.
func startTailnet(t *testing.T, domain string) string {
	t.Helper()
	netns.SetEnabled(false) // host tests: no Android socket protection
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: domain,
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}

// startPeer runs a plain tsnet node standing in for a remote machine. It
// answers TCP :8080 and UDP :9090 with banner.
func startPeer(t *testing.T, ctx context.Context, controlURL, hostname, banner string) netip.Addr {
	t.Helper()
	s := &tsnet.Server{
		Dir:        filepath.Join(t.TempDir(), hostname),
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.Discard,
		UserLogf:   logger.Discard,
	}
	t.Cleanup(func() { s.Close() })
	st, err := s.Up(ctx)
	if err != nil {
		t.Fatalf("peer %s up: %v", hostname, err)
	}
	for _, port := range []string{":8080", ":8081"} {
		ln, err := s.Listen("tcp", port)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				io.WriteString(c, banner)
				c.Close()
			}
		}()
	}
	pc, err := s.ListenPacket("udp", netip.AddrPortFrom(st.TailscaleIPs[0], 9090).String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte(banner+":"), buf[:n]...), from)
		}
	}()
	return st.TailscaleIPs[0]
}

func readBanner(t *testing.T, c net.Conn) string {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTwoIsolatedTailnets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	personalURL := startTailnet(t, "personal.ts.net")
	workURL := startTailnet(t, "work.ts.net")

	// Remote machines register first in each tailnet, so both get node ID 1
	// and therefore the same address: overlapping tailnets by construction.
	personalPeer := startPeer(t, ctx, personalURL, "nas", "personal")
	workPeer := startPeer(t, ctx, workURL, "build-server", "work")
	t.Logf("personal peer %v, work peer %v", personalPeer, workPeer)
	if personalPeer != workPeer {
		t.Fatalf("expected overlapping peer addresses, got %v and %v", personalPeer, workPeer)
	}

	m := NewManager()
	t.Cleanup(func() { m.Close() })
	base := t.TempDir()
	add := func(id, url string) *Instance {
		inst, err := m.Add(Config{ID: id, StateDir: filepath.Join(base, id), ControlURL: url, Hostname: "phone-" + id, Store: new(mem.Store), Ephemeral: true})
		if err != nil {
			t.Fatal(err)
		}
		return inst
	}
	personal := add("personal", personalURL)
	work := add("work", workURL)

	if _, err := m.Add(Config{ID: "personal", StateDir: filepath.Join(base, "x")}); err == nil {
		t.Error("duplicate id accepted")
	}
	if _, err := m.Add(Config{ID: "other", StateDir: filepath.Join(base, "work") + "/"}); err == nil {
		t.Error("shared state directory accepted")
	}

	// Bring both up concurrently.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for n, inst := range []*Instance{personal, work} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[n] = inst.Up(ctx)
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	for _, inst := range []*Instance{personal, work} {
		st, err := inst.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: state=%s self=%v peers=%d", inst.ID(), st.BackendState, st.TailscaleIPs, len(st.Peer))
		if st.BackendState != "Running" || len(st.Peer) != 1 {
			t.Fatalf("%s: unexpected status %s with %d peers", inst.ID(), st.BackendState, len(st.Peer))
		}
	}

	// Real ICMP probes stay within the selected instance, including when
	// two tailnets have the same peer address. A non-member cannot leak direct.
	for _, inst := range []*Instance{personal, work} {
		ping := inst.Transport().(engine.PingTransport)
		if err := ping.Ping(ctx, personalPeer); err != nil {
			t.Fatalf("%s ping: %v", inst.ID(), err)
		}
		if err := ping.Ping(ctx, netip.MustParseAddr("192.0.2.99")); !errors.Is(err, ErrNotInTailnet) {
			t.Fatalf("non-member ping: %v", err)
		}
	}

	// Same destination address, different tailnet selected, different machine reached.
	dst := netip.AddrPortFrom(personalPeer, 8080).String()
	for _, tc := range []struct {
		inst *Instance
		want string
	}{{personal, "personal"}, {work, "work"}} {
		c, err := tc.inst.Dial(ctx, "tcp", dst)
		if err != nil {
			t.Fatalf("%s tcp dial: %v", tc.inst.ID(), err)
		}
		if got := readBanner(t, c); got != tc.want {
			t.Errorf("%s: tcp %s reached %q, want %q", tc.inst.ID(), dst, got, tc.want)
		}
	}

	// UDP takes the same explicit path.
	for _, tc := range []struct {
		inst *Instance
		want string
	}{{personal, "personal:ping"}, {work, "work:ping"}} {
		c, err := tc.inst.Dial(ctx, "udp", netip.AddrPortFrom(personalPeer, 9090).String())
		if err != nil {
			t.Fatalf("%s udp dial: %v", tc.inst.ID(), err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			t.Fatalf("%s udp read: %v", tc.inst.ID(), err)
		}
		if got := string(buf[:n]); got != tc.want {
			t.Errorf("%s: udp reply %q, want %q", tc.inst.ID(), got, tc.want)
		}
	}

	// Through the engine's routing boundary: the decision names the tailnet,
	// and only that instance can be reached.
	router, err := engine.NewRouter(nil, nil, personal.Transport(), work.Transport())
	if err != nil {
		t.Fatal(err)
	}
	flow := engine.Flow{Protocol: engine.TCP, Dst: netip.AddrPortFrom(personalPeer, 8080)}
	for id, want := range map[string]string{"personal": "personal", "work": "work"} {
		c, _, err := router.Dial(ctx, flow, engine.Decision{Action: engine.ActionForward, Transport: TransportPrefix + id})
		if err != nil {
			t.Fatalf("router dial via %s: %v", id, err)
		}
		if got := readBanner(t, c); got != want {
			t.Errorf("router via %s reached %q", id, got)
		}
	}
	if _, _, err := router.Dial(ctx, flow, engine.Decision{Action: engine.ActionForward, Transport: TransportPrefix + "family"}); err == nil {
		t.Error("unknown tailnet transport did not fail closed")
	}
	if _, _, err := router.Dial(ctx, engine.Flow{Protocol: engine.TCP, Dst: netip.MustParseAddrPort("100.64.0.77:80")},
		engine.Decision{Action: engine.ActionForward, Transport: TransportPrefix + "work"}); !errors.Is(err, ErrNotInTailnet) {
		t.Errorf("non-member via transport: got %v, want ErrNotInTailnet", err)
	}

	// A tailnet address that exists in neither tailnet is refused, not routed elsewhere.
	if _, err := work.Dial(ctx, "tcp", "100.64.0.77:8080"); !errors.Is(err, ErrNotInTailnet) {
		t.Errorf("unknown tailnet address: got %v, want ErrNotInTailnet", err)
	}

	// Closing one tailnet leaves the other working.
	if err := m.Remove("personal"); err != nil {
		t.Fatal(err)
	}
	c, err := work.Dial(ctx, "tcp", dst)
	if err != nil {
		t.Fatalf("work after personal removed: %v", err)
	}
	if got := readBanner(t, c); got != "work" {
		t.Errorf("work after removal reached %q", got)
	}
}

// TestRawTsnetDialFallsBackToHost documents the upstream behaviour that makes
// Instance.Dial's membership check necessary: tsnet.Server.Dial sends
// non-tailnet destinations over the host network.
func TestRawTsnetDialFallsBackToHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	url := startTailnet(t, "leak.ts.net")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.WriteString(c, "host network")
			c.Close()
		}
	}()

	m := NewManager()
	t.Cleanup(func() { m.Close() })
	inst, err := m.Add(Config{ID: "t", StateDir: filepath.Join(t.TempDir(), "t"), ControlURL: url, Hostname: "phone", Store: new(mem.Store), Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Up(ctx); err != nil {
		t.Fatal(err)
	}

	c, err := inst.srv.Dial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("raw tsnet dial: %v (upstream behaviour changed? update ADR 0006)", err)
	}
	if got := readBanner(t, c); got != "host network" {
		t.Fatalf("raw tsnet dial reached %q", got)
	}
	t.Log("confirmed: raw tsnet.Server.Dial reached a host-network listener")

	if _, err := inst.Dial(ctx, "tcp", ln.Addr().String()); !errors.Is(err, ErrNotInTailnet) {
		t.Fatalf("guarded dial: got %v, want ErrNotInTailnet", err)
	}
}

func TestMain(m *testing.M) {
	// Belt and braces: no test may upload logs even if the logic above changes.
	DisableRemoteLogging()
	os.Exit(m.Run())
}
