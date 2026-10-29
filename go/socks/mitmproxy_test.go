package socks

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"hybridvpn/netcore/engine"
)

// TestMitmproxyCompatibility runs against a real mitmproxy in SOCKS5 mode. It
// is skipped unless MITMPROXY_SOCKS is set (--ssl-insecure because the test
// servers have self-signed certificates):
//
//	mitmdump --mode socks5@127.0.0.1:1081 --proxyauth alice:secret --ssl-insecure
//	MITMPROXY_SOCKS=127.0.0.1:1081 MITMPROXY_AUTH=alice:secret go test -run Mitmproxy -v ./socks
func TestMitmproxyCompatibility(t *testing.T) {
	server := os.Getenv("MITMPROXY_SOCKS")
	if server == "" {
		t.Skip("set MITMPROXY_SOCKS to a mitmproxy --mode socks5 address")
	}
	user, pass, _ := strings.Cut(os.Getenv("MITMPROXY_AUTH"), ":")

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "plain ok") }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tls ok") }))
	defer secure.Close()

	p := newProxy(t, server, user, pass)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}

	t.Run("http", func(t *testing.T) {
		c, err := dial(t, p, engine.TCP, netip.MustParseAddrPort(plain.Listener.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		body := get(t, c, "plain.test")
		if body != "plain ok" {
			t.Errorf("body %q", body)
		}
	})

	t.Run("tls intercepted", func(t *testing.T) {
		c, err := dial(t, p, engine.TCP, netip.MustParseAddrPort(secure.Listener.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{ServerName: "secure.test", InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		issuer := tc.ConnectionState().PeerCertificates[0].Issuer.String()
		t.Logf("certificate issuer: %s", issuer)
		if !strings.Contains(issuer, "mitmproxy") {
			t.Errorf("TLS was not intercepted by mitmproxy (issuer %q)", issuer)
		}
		if body := get(t, tc, "secure.test"); body != "tls ok" {
			t.Errorf("body %q", body)
		}
	})

	if user != "" {
		t.Run("wrong password", func(t *testing.T) {
			bad := newProxy(t, server, user, pass+"x")
			if err := bad.Check(context.Background()); err == nil {
				t.Error("mitmproxy accepted a wrong password")
			} else {
				t.Logf("refused: %v", err)
			}
		})
	}

	t.Run("udp", func(t *testing.T) {
		before := p.Summary().Failures
		_, err := dial(t, p, engine.UDP, netip.MustParseAddrPort("192.0.2.1:443"))
		t.Logf("UDP ASSOCIATE: %v", err)
		if err == nil {
			t.Skip("this mitmproxy supports UDP ASSOCIATE")
		}
		if !errors.Is(err, ErrNoUDP) {
			t.Errorf("want ErrNoUDP, got %v", err)
		}
		// Later UDP flows are refused locally, without another round trip.
		start := time.Now()
		if _, err := dial(t, p, engine.UDP, netip.MustParseAddrPort("192.0.2.1:443")); !errors.Is(err, ErrNoUDP) {
			t.Errorf("second UDP flow: %v", err)
		}
		if d := time.Since(start); d > 50*time.Millisecond {
			t.Errorf("second UDP flow took %v; it should not contact the proxy", d)
		}
		if s := p.Summary(); s.State != StateReady || !s.NoUDP || s.Failures != before+2 {
			t.Errorf("summary: %+v", s)
		}
	})
}

func get(t *testing.T, c net.Conn, host string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
