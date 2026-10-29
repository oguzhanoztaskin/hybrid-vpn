package httpproxy

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
	"sync/atomic"
	"testing"
	"time"

	"hybridvpn/netcore/engine"
)

func newProxy(t *testing.T, server, user, pass string) *Proxy {
	t.Helper()
	d := engine.NewDirect(func(int) bool { return true })
	p, err := New(Config{ID: "lab", Server: server, Username: user, Password: pass, Dial: d.DialAddress})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func dial(t *testing.T, p *Proxy, dst string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return p.Transport().Dial(ctx, engine.Flow{Protocol: engine.TCP, Dst: netip.MustParseAddrPort(dst)})
}

func TestCONNECTBufferedDataAuthenticationAndHalfClose(t *testing.T) {
	seen := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		// Informational response, final response and immediate tunnel data.
		fmt.Fprint(rw, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\nbanner")
		rw.Flush()
		b, _ := io.ReadAll(rw)
		c.Write(b)
	}))
	defer srv.Close()
	p := newProxy(t, srv.Listener.Addr().String(), "alice", "secret")
	c, err := dial(t, p, "[2001:db8::42]:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	r := <-seen
	if r.Method != "CONNECT" || r.Host != "[2001:db8::42]:443" || r.Header.Get("Proxy-Authorization") != "Basic YWxpY2U6c2VjcmV0" {
		t.Fatalf("incorrect CONNECT request")
	}
	b := make([]byte, 6)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "banner" {
		t.Fatalf("lost buffered bytes: %q %v", b, err)
	}
	c.Write([]byte("duplex payload"))
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err = io.ReadAll(c)
	if err != nil || string(b) != "duplex payload" {
		t.Fatalf("half-close lost reply: %q %v", b, err)
	}
	c.Close()
	c.Close()
	if s := p.Summary(); s.TCPActive != 0 || s.Flows != 1 || s.State != "ready" || !s.NoUDP {
		t.Fatalf("summary: %+v", s)
	}
}

func TestRefusalsAndMalformedResponses(t *testing.T) {
	for _, tc := range []struct{ name, response, state string }{
		{"authentication", "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "error"},
		{"destination", "HTTP/1.1 403 Forbidden\r\n\r\n", "ready"},
		{"upstream", "HTTP/1.1 502 Bad Gateway\r\n\r\n", "ready"},
		{"redirect", "HTTP/1.1 302 Found\r\nLocation: http://other/\r\n\r\n", "ready"},
		{"malformed", "not an HTTP response\r\n\r\n", "error"},
		{"oversized", "HTTP/1.1 200 OK\r\nX-Fill: " + strings.Repeat("x", 20000) + "\r\n\r\n", "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, _, _ := w.(http.Hijacker).Hijack()
				defer c.Close()
				fmt.Fprint(c, tc.response)
			}))
			defer srv.Close()
			p := newProxy(t, srv.Listener.Addr().String(), "alice", "secret")
			if c, err := dial(t, p, "192.0.2.1:443"); err == nil {
				c.Close()
				t.Fatal("accepted refused or invalid response")
			} else if strings.Contains(err.Error(), "secret") {
				t.Fatal("password in error")
			}
			if s := p.Summary(); s.Failures != 1 || s.TCPActive != 0 || s.State != tc.state {
				t.Fatalf("summary: %+v", s)
			}
		})
	}
}

func TestCancelledHandshakeClosesSocket(t *testing.T) {
	started, done := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		defer c.Close()
		close(started)
		io.Copy(io.Discard, c)
		close(done)
	}))
	defer srv.Close()
	p := newProxy(t, srv.Listener.Addr().String(), "", "")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := p.Transport().Dial(ctx, engine.Flow{Protocol: engine.TCP, Dst: netip.MustParseAddrPort("192.0.2.1:80")})
		errCh <- err
	}()
	<-started
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cancelled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("socket leaked")
	}
}

func TestPolicyRoutingAndUnsupportedProtocolsFailClosed(t *testing.T) {
	var dials atomic.Int32
	p, _ := New(Config{ID: "lab", Server: "127.0.0.1:1", Dial: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("proxy down")
	}})
	r, err := engine.NewRouter(nil, nil, p.Transport())
	if err != nil {
		t.Fatal(err)
	}
	err = r.SetPolicy([]byte(`{"version":1,"transports":[{"id":"http:lab","type":"http"}],"default":{"transport":"http:lab","on_failure":"block"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, proto := range []engine.Protocol{engine.UDP, engine.ICMP, engine.ICMPv6} {
		f := engine.Flow{Protocol: proto, Dst: netip.MustParseAddrPort("192.0.2.1:443")}
		d := r.Decide(f, nil)
		var err error
		if proto == engine.UDP {
			_, _, err = r.Dial(context.Background(), f, d)
		} else {
			_, err = r.Ping(context.Background(), f, d)
		}
		if !errors.Is(err, engine.ErrUnsupportedProtocol) {
			t.Fatalf("%s: %v", proto, err)
		}
	}
	if dials.Load() != 0 {
		t.Fatal("unsupported protocol reached proxy")
	}
	f := engine.Flow{Protocol: engine.TCP, Dst: netip.MustParseAddrPort("192.0.2.1:443")}
	if _, _, err := r.Dial(context.Background(), f, r.Decide(f, nil)); err == nil {
		t.Fatal("down proxy succeeded")
	}
	if dials.Load() != 1 {
		t.Fatal("unexpected fallback")
	}
}

func TestProtectedSocketFailure(t *testing.T) {
	d := engine.NewDirect(func(int) bool { return false })
	p, _ := New(Config{ID: "lab", Server: "127.0.0.1:8080", Dial: d.DialAddress})
	if _, err := dial(t, p, "192.0.2.1:443"); !errors.Is(err, engine.ErrProtectFailed) {
		t.Fatalf("got %v", err)
	}
}

// Run with MITMPROXY_HTTP=127.0.0.1:8080, optionally MITMPROXY_AUTH=user:pass.
// mitmdump's regular mode requires no --mode flag; --ssl-insecure permits the
// local HTTPS test server. Certificate verification is disabled only in this lab.
func TestMitmproxyCompatibility(t *testing.T) {
	addr := os.Getenv("MITMPROXY_HTTP")
	if addr == "" {
		t.Skip("set MITMPROXY_HTTP for real regular-mode mitmproxy")
	}
	user, pass, _ := strings.Cut(os.Getenv("MITMPROXY_AUTH"), ":")
	p := newProxy(t, addr, user, pass)
	if err := p.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, secure := range []bool{false, true} {
		name := "HTTP"
		if secure {
			name = "HTTPS"
		}
		t.Run(name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "mitmproxy regular ok") })
			srv := httptest.NewUnstartedServer(h)
			if secure {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()
			c, err := dial(t, p, srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if secure {
				tc := tls.Client(c, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
				if err := tc.Handshake(); err != nil {
					t.Fatal(err)
				}
				issuer := tc.ConnectionState().PeerCertificates[0].Issuer.String()
				if !strings.Contains(issuer, "mitmproxy") {
					t.Fatalf("not intercepted: %s", issuer)
				}
				c = tc
			}
			fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", srv.Listener.Addr().String())
			res, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			b, err := io.ReadAll(res.Body)
			if err != nil || string(b) != "mitmproxy regular ok" {
				t.Fatalf("%q %v", b, err)
			}
		})
	}
	if user != "" {
		bad := newProxy(t, addr, user, pass+"wrong")
		if c, err := dial(t, bad, "192.0.2.1:443"); err == nil {
			c.Close()
			t.Fatal("wrong password accepted")
		}
	}
}
