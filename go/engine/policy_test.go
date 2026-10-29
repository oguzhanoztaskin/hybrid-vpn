package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	uidBrowser                         = 10100
	uidMail                            = 10200
	portBrowser, portMail, portUnknown = 40100, 40200, 40300
)

func testPolicy(transports, def, rules string) []byte {
	return []byte(fmt.Sprintf(`{"version":1,"transports":[%s],"default":%s,"rules":[%s]}`, transports, def, rules))
}

const (
	directT = `{"id":"direct","type":"direct"}`
	altT    = `{"id":"alt","type":"socks5"}`
	deadT   = `{"id":"broken","type":"socks5"}`
	tcpT    = `{"id":"tcponly","type":"http"}`
	defDir  = `{"transport":"direct","on_failure":"block"}`
)

// bannerServer answers every TCP connection with name, and every UDP datagram
// with name + ":" + payload.
func bannerServer(t *testing.T, name string) (tcpAddr, udpAddr string) {
	t.Helper()
	tcpAddr = listenTCP(t, func(c net.Conn) { io.WriteString(c, name); c.Close() })
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte(name+":"), buf[:n]...), from)
		}
	}()
	return tcpAddr, pc.LocalAddr().String()
}

// routeAll maps the same public destinations on a transport to its own banner server.
func routeAll(t *testing.T, tr *fakeDirect, dsts ...string) {
	tcpAddr, udpAddr := bannerServer(t, tr.Name())
	for _, d := range dsts {
		tr.route("tcp/"+d, tcpAddr) // protocol-specific keys: TCP and UDP share destinations
		tr.route("udp/"+d, udpAddr)
	}
}

// tcpFrom dials dst from a fixed app source port (which the fake host maps to a UID).
func (a *testApp) tcpFrom(t *testing.T, srcPort uint16, dst string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raddr, proto := full(netip.MustParseAddrPort(dst))
	src := appV4
	if netip.MustParseAddrPort(dst).Addr().Is6() {
		src = appV6
	}
	laddr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(src.AsSlice()), Port: srcPort}
	c, err := gonet.DialTCPWithBind(ctx, a.s, laddr, raddr, proto)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	return string(b), err
}

// udpFrom sends one datagram from a fixed source port and returns the reply ("" on timeout).
func (a *testApp) udpFrom(t *testing.T, srcPort uint16, dst string) string {
	t.Helper()
	raddr, proto := full(netip.MustParseAddrPort(dst))
	src := appV4
	if netip.MustParseAddrPort(dst).Addr().Is6() {
		src = appV6
	}
	laddr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(src.AsSlice()), Port: srcPort}
	c, err := gonet.DialUDP(a.s, &laddr, &raddr, proto)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("ping"))
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func newRoutingHarness(t *testing.T, policy []byte) (*harness, *fakeDirect, *fakeDirect, *fakeDirect) {
	alt := newFake("alt", "socks5")
	broken := newFake("broken", "socks5")
	broken.fail = true
	tcpOnly := newFake("tcponly", "http")
	tcpOnly.udpOff = true
	h := newHarnessWith(t, policy, alt, broken, tcpOnly)
	h.host.uids[portBrowser] = uidBrowser
	h.host.uids[portMail] = uidMail
	for _, tr := range []*fakeDirect{h.direct, alt, tcpOnly} {
		routeAll(t, tr, "203.0.113.10:443", "203.0.113.10:25", "198.51.100.1:443", "[2001:db8::5]:80")
	}
	return h, alt, broken, tcpOnly
}

func TestPolicyPerAppRouting(t *testing.T) {
	policy := testPolicy(directT+","+altT, defDir, `
		{"id":"browser-alt","uids":[10100],"action":"route","transport":"alt","on_failure":"block"},
		{"id":"mail-blocked","uids":[10200],"action":"block"}`)
	h, _, _, _ := newRoutingHarness(t, policy)

	if got, err := h.app.tcpFrom(t, portBrowser, "203.0.113.10:443"); got != "alt" {
		t.Errorf("browser TCP: got %q, %v; want alt", got, err)
	}
	if got, err := h.app.tcpFrom(t, portMail, "203.0.113.10:443"); err == nil {
		t.Errorf("mail TCP should be refused, got %q", got)
	}
	if got, _ := h.app.tcpFrom(t, portUnknown, "203.0.113.10:443"); got != "direct" {
		t.Errorf("unattributed TCP should take the default route, got %q", got)
	}
	if got := h.app.udpFrom(t, portBrowser, "203.0.113.10:443"); got != "alt:ping" {
		t.Errorf("browser UDP: got %q; want alt:ping", got)
	}
	if got := h.app.udpFrom(t, portMail, "203.0.113.10:443"); got != "" {
		t.Errorf("mail UDP should be dropped, got %q", got)
	}
	if got := h.app.udpFrom(t, portUnknown, "203.0.113.10:443"); got != "direct:ping" {
		t.Errorf("unattributed UDP: got %q; want direct:ping", got)
	}
	st := h.eng.Stats()
	if st.Dropped["policy:mail-blocked"] != 2 || st.Routed["alt"] != 2 || st.UIDLookups != 6 {
		t.Errorf("stats: dropped %v routed %v lookups %d", st.Dropped, st.Routed, st.UIDLookups)
	}
}

func TestPolicyUnknownAppIsExplicit(t *testing.T) {
	policy := testPolicy(directT, defDir, `{"id":"unattributed","unknown_app":true,"action":"block"}`)
	h, _, _, _ := newRoutingHarness(t, policy)
	if got, err := h.app.tcpFrom(t, portUnknown, "198.51.100.1:443"); err == nil {
		t.Errorf("unknown owner should be blocked, got %q", got)
	}
	if got, _ := h.app.tcpFrom(t, portBrowser, "198.51.100.1:443"); got != "direct" {
		t.Errorf("known owner should pass, got %q", got)
	}
}

func TestPolicyCIDRPortProtocolAndPrecedence(t *testing.T) {
	first := testPolicy(directT+","+altT, defDir, `
		{"id":"no-smtp","any_app":true,"cidrs":["203.0.113.0/24"],"protocol":"tcp","ports":[[25,25]],"action":"block"},
		{"id":"doc-net","any_app":true,"cidrs":["203.0.113.0/24","2001:db8::/32"],"action":"route","transport":"alt"}`)
	h, _, _, _ := newRoutingHarness(t, first)
	cases := []struct {
		dst, proto, want string
	}{
		{"203.0.113.10:25", "tcp", ""},         // first rule wins
		{"203.0.113.10:443", "tcp", "alt"},     // second rule
		{"203.0.113.10:25", "udp", "alt:ping"}, // protocol excludes rule 1
		{"198.51.100.1:443", "tcp", "direct"},  // no rule: default
		{"[2001:db8::5]:80", "tcp", "alt"},     // IPv6 CIDR
	}
	// Each round uses fresh source ports: an app-side TIME_WAIT would refuse reuse.
	check := func(label string, base uint16) {
		for i, c := range cases {
			src := base + uint16(i)
			var got string
			if c.proto == "tcp" {
				got, _ = h.app.tcpFrom(t, src, c.dst)
			} else {
				got = h.app.udpFrom(t, src, c.dst)
			}
			if got != c.want {
				t.Errorf("%s: %s %s: got %q, want %q", label, c.proto, c.dst, got, c.want)
			}
		}
	}
	check("initial", 41000)
	if h.eng.Stats().UIDLookups != 0 {
		t.Error("owner looked up although no rule matches on apps")
	}

	// Swap rule order: precedence follows the list, and new flows see it at once.
	swapped := testPolicy(directT+","+altT, defDir, `
		{"id":"doc-net","any_app":true,"cidrs":["203.0.113.0/24","2001:db8::/32"],"action":"route","transport":"alt"},
		{"id":"no-smtp","any_app":true,"cidrs":["203.0.113.0/24"],"protocol":"tcp","ports":[[25,25]],"action":"block"}`)
	if err := h.eng.SetPolicy(swapped); err != nil {
		t.Fatal(err)
	}
	cases[0].want = "alt"
	check("swapped", 42000)
}

func TestPolicyTransportFailureNeverFallsBackSilently(t *testing.T) {
	blocking := testPolicy(directT+","+deadT, defDir, `{"id":"via-broken","any_app":true,"action":"route","transport":"broken","on_failure":"block"}`)
	h, _, _, _ := newRoutingHarness(t, blocking)
	if got, err := h.app.tcpFrom(t, portUnknown, "198.51.100.1:443"); err == nil {
		t.Errorf("failed transport must not deliver, got %q", got)
	}
	if got := h.app.udpFrom(t, portUnknown, "198.51.100.1:443"); got != "" {
		t.Errorf("failed transport must not deliver UDP, got %q", got)
	}
	if h.direct.dialCount() != 0 {
		t.Fatalf("direct was dialed %d times without an explicit fallback", h.direct.dialCount())
	}

	explicit := testPolicy(directT+","+deadT, defDir, `{"id":"via-broken","any_app":true,"action":"route","transport":"broken","on_failure":"direct"}`)
	if err := h.eng.SetPolicy(explicit); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.app.tcpFrom(t, portUnknown, "198.51.100.1:443"); got != "direct" {
		t.Errorf("explicit on_failure direct: got %q", got)
	}
	if st := h.eng.Stats(); st.Fallbacks != 1 {
		t.Errorf("fallbacks = %d, want 1", st.Fallbacks)
	}
}

func TestPolicyUnsupportedProtocolFailsClosed(t *testing.T) {
	policy := testPolicy(directT+","+tcpT, defDir, `{"id":"proxy","any_app":true,"action":"route","transport":"tcponly"}`)
	h, _, _, _ := newRoutingHarness(t, policy)
	if got, _ := h.app.tcpFrom(t, portUnknown, "198.51.100.1:443"); got != "tcponly" {
		t.Errorf("TCP via tcp-only transport: got %q", got)
	}
	if got := h.app.udpFrom(t, portUnknown, "198.51.100.1:443"); got != "" {
		t.Errorf("UDP via tcp-only transport must fail closed, got %q", got)
	}
	if h.eng.Stats().Dropped["transport failed: tcponly"] != 1 {
		t.Errorf("dropped: %v", h.eng.Stats().Dropped)
	}
	h.app.udpFrom(t, portUnknown, "198.51.100.1:443")
	f := h.eng.Stats().Failures
	if len(f) != 1 || f[0].Transport != "tcponly" || f[0].Protocol != "udp" || f[0].Count != 2 ||
		!strings.Contains(f[0].Error, "protocol") {
		t.Errorf("failures: %+v", f)
	}
}

func TestFailureLogIsBounded(t *testing.T) {
	var c counters
	for i := range maxFailures + 10 {
		c.failed("direct", TCP, fmt.Errorf("error %d", i))
	}
	c.failed("direct", TCP, fmt.Errorf("error %d", maxFailures+9))
	if len(c.failures) != maxFailures {
		t.Fatalf("kept %d kinds, want %d", len(c.failures), maxFailures)
	}
	if _, ok := c.failures["direct|tcp|error 0"]; ok {
		t.Error("the oldest kind should have been forgotten")
	}
	if f := c.failures[fmt.Sprintf("direct|tcp|error %d", maxFailures+9)]; f == nil || f.Count != 2 {
		t.Errorf("repeat not counted: %+v", f)
	}
}

func TestDNSStaysWithFirewallWhateverThePolicy(t *testing.T) {
	policy := testPolicy(directT+","+altT, defDir, `{"id":"everything","any_app":true,"action":"route","transport":"alt"}`)
	h, alt, _, _ := newRoutingHarness(t, policy)
	c := h.app.dialUDP(t, "8.8.8.8:53")
	defer c.Close()
	c.Write(dnsQuery(7))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 512)); err != nil {
		t.Fatalf("no DNS answer: %v", err)
	}
	if alt.dialCount() != 0 || h.direct.dialCount() != 0 {
		t.Error("DNS reached a transport")
	}
}

func TestParsePolicyRejectsWhatItCannotEnforce(t *testing.T) {
	ts := map[string]Transport{"direct": &fakeDirect{}, "alt": newFake("alt", "socks5")}
	bad := map[string][]byte{
		"unknown transport":   testPolicy(directT, `{"transport":"tailnet:work"}`, ``),
		"declared not built":  testPolicy(directT+`,{"id":"tailnet:work","type":"tailnet"}`, defDir, ``),
		"type mismatch":       testPolicy(directT+`,{"id":"alt","type":"openvpn"}`, defDir, ``),
		"bad cidr":            testPolicy(directT, defDir, `{"id":"r","any_app":true,"cidrs":["10.0.0.0/33"],"action":"block"}`),
		"bad protocol":        testPolicy(directT, defDir, `{"id":"r","any_app":true,"protocol":"esp","action":"block"}`),
		"any_app with uids":   testPolicy(directT, defDir, `{"id":"r","any_app":true,"uids":[1],"action":"block"}`),
		"duplicate id":        testPolicy(directT, defDir, `{"id":"r","any_app":true,"action":"block"},{"id":"r","any_app":true,"action":"block"}`),
		"unknown action":      testPolicy(directT, defDir, `{"id":"r","any_app":true,"action":"tunnel"}`),
		"bad port range":      testPolicy(directT, defDir, `{"id":"r","any_app":true,"ports":[[90,80]],"action":"block"}`),
		"unknown fallback":    testPolicy(directT, defDir, `{"id":"r","any_app":true,"action":"route","transport":"direct","on_failure":"openvpn:x"}`),
		"unsupported version": []byte(`{"version":2,"default":{"transport":"direct"}}`),
	}
	for name, p := range bad {
		if _, err := ParsePolicy(p, ts); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.HasPrefix(err.Error(), "policy:") {
			t.Errorf("%s: unclear error %v", name, err)
		}
	}
}
