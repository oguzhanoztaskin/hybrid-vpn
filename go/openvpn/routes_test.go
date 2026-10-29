package openvpn

import (
	"net/netip"
	"testing"
)

func TestRouteSet(t *testing.T) {
	cfg := TunConfig{
		Addresses:      []PrefixJSON{{Address: "10.8.0.6", Prefix: 24}, {Address: "fd00:8::1000", Prefix: 64, IPv6: true}},
		Routes:         []PrefixJSON{{Address: "10.9.0.0", Prefix: 16}},
		ExcludedRoutes: []PrefixJSON{{Address: "10.9.9.0", Prefix: 24}},
	}
	r, err := newRouteSet(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"10.8.0.1":         true,  // interface subnet
		"10.9.1.1":         true,  // pushed route
		"10.9.9.9":         false, // excluded
		"::ffff:10.9.1.1":  true,  // mapped form
		"fd00:8::1":        true,
		"8.8.8.8":          false,
		"2001:db8::1":      false,
		"10.10.0.1":        false,
		"::ffff:192.0.2.1": false,
	} {
		if got := r.owns(netip.MustParseAddr(addr)); got != want {
			t.Errorf("owns(%s) = %v, want %v", addr, got, want)
		}
	}

	cfg.RerouteIPv4 = true
	r, _ = newRouteSet(cfg)
	if !r.owns(netip.MustParseAddr("8.8.8.8")) || r.owns(netip.MustParseAddr("10.9.9.9")) || r.owns(netip.MustParseAddr("2001:db8::1")) {
		t.Error("redirect-gateway ipv4: wrong membership")
	}

	if _, err := newRouteSet(TunConfig{Routes: []PrefixJSON{{Address: "10.0.0.0", Prefix: 33}}}); err == nil {
		t.Error("invalid prefix accepted")
	}
}

func TestUnavailableOrDialFailsClosed(t *testing.T) {
	c := &Client{cfg: Config{ID: "x"}, state: StateIdle}
	if _, err := c.Dial(t.Context(), "tcp", netip.MustParseAddrPort("10.8.0.1:80")); err == nil {
		t.Error("dial succeeded without a session")
	}
}
