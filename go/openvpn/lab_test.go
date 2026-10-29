//go:build openvpn3 && darwin

package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hybridvpn/netcore/engine"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hybridvpn/netcore/ovpnlab"
)

// startLab runs a local OpenVPN 2 server (ovpnlab), skipping when its
// binaries were not built.
func startLab(t testing.TB, o ovpnlab.Options) *ovpnlab.Lab {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../..")
	openvpn, shim, err := ovpnlab.Binaries(root)
	if err != nil {
		t.Skip(err)
	}
	o.Dir, o.OpenVPN, o.Shim = t.TempDir(), openvpn, shim
	o.Port = freePort(t, o.Proto)
	o.Listen = "127.0.0.1"
	if v := os.Getenv("OVPNLAB_VERB"); v != "" {
		o.Verb, _ = strconv.Atoi(v)
	}
	if testing.Verbose() {
		o.Log = testWriter{t, "server"}
	}
	lab, err := ovpnlab.Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	return lab
}

// freePort finds a port free for both TCP and UDP (a crashed earlier run may
// have left servers behind on fixed ports).
func freePort(t testing.TB, proto string) int {
	for i := 0; i < 20; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			u.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

type testWriter struct {
	t      testing.TB
	prefix string
}

func (w testWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.t.Logf("%s: %s", w.prefix, line)
	}
	return len(p), nil
}

func connect(t testing.TB, cfg Config) *Client {
	t.Helper()
	if cfg.ID == "" {
		cfg.ID = "lab"
	}
	if testing.Verbose() {
		cfg.Logf = t.Logf
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	c.Start()
	return c
}

func waitState(t testing.TB, c *Client, want string, d time.Duration) Summary {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		s := c.Summary()
		if s.State == want {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %q, want %q (event %s, error %q)", s.State, want, s.Event, s.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func dialLine(t *testing.T, c *Client, dst string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "tcp", netip.MustParseAddrPort(dst))
	if err != nil {
		if tun := c.tun; tun != nil {
			t.Logf("tunnel packets: in %d, out %d; core: %s", tun.packetsIn.Load(), tun.packetsOut.Load(), c.native.counters())
		}
		t.Fatalf("dial %s: %v", dst, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read %s: %v", dst, err)
	}
	return strings.TrimSpace(line)
}

func TestEvalProfile(t *testing.T) {
	lab := startLab(t, ovpnlab.Options{Username: "alice", Password: "s3cret"})
	p, err := Eval(lab.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if p.Error || p.Autologin || p.RemoteHost != "127.0.0.1" || p.RemoteProto != "udp" {
		t.Fatalf("eval: %+v", p)
	}
	if p, _ := Eval("this is not a profile"); !p.Error {
		t.Fatalf("garbage profile accepted: %+v", p)
	}
	// OpenVPN 3 has no script support: such directives are accepted and ignored
	// (the app tells the user on import).
	if p, _ := Eval(lab.Profile + "script-security 2\nup /bin/sh\n"); p.Error {
		t.Errorf("profile with script directives: %q", p.Message)
	}
}

// TestCertificateSession: connect with certificates only, check the pushed
// configuration, then carry TCP (IPv4, IPv6, bulk) and UDP through the VPN.
func TestCertificateSession(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			lab := startLab(t, ovpnlab.Options{Proto: proto})
			c := connect(t, Config{Profile: lab.Profile})
			s := waitState(t, c, StateConnected, 20*time.Second)
			t.Logf("summary: %+v", s)
			if !strings.HasPrefix(s.VPNv4, "10.8.0.") || !strings.HasPrefix(s.VPNv6, "fd00:8::") {
				t.Errorf("VPN addresses %q %q", s.VPNv4, s.VPNv6)
			}
			routes := strings.Join(s.Routes, " ")
			for _, r := range []string{"10.8.0.0/24", "10.9.0.0/24", "fd00:8::/64"} {
				if !strings.Contains(routes, r) {
					t.Errorf("routes %v lack %s", s.Routes, r)
				}
			}
			if len(s.DNSServers) != 1 || s.DNSServers[0] != "10.8.0.1" || !strings.Contains(strings.Join(s.DNSDomains, " "), "lab.test") {
				t.Errorf("DNS %v %v", s.DNSServers, s.DNSDomains)
			}

			if got := dialLine(t, c, "10.8.0.1:8080"); !strings.Contains(got, "10.8.0.1:8080") {
				t.Errorf("banner via subnet: %q", got)
			}
			if got := dialLine(t, c, "10.9.0.1:8080"); !strings.Contains(got, "10.9.0.1:8080") {
				t.Errorf("banner via pushed route: %q", got)
			}
			if got := dialLine(t, c, "[fd00:8::1]:8080"); !strings.Contains(got, "fd00:8::1") {
				t.Errorf("banner via IPv6: %q", got)
			}

			// Echo probes use the tunnel stack, for IPv4 and IPv6; unrouted
			// destinations must never escape onto the host network.
			for _, dst := range []string{"10.8.0.1", "10.9.0.1", "fd00:8::1"} {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				err := c.Transport().(engine.PingTransport).Ping(ctx, netip.MustParseAddr(dst))
				cancel()
				if err != nil {
					t.Fatalf("ping %s: %v", dst, err)
				}
			}
			if err := c.Transport().(engine.PingTransport).Ping(context.Background(), netip.MustParseAddr("192.0.2.99")); err == nil {
				t.Fatal("unrouted ping accepted")
			}

			// Bulk TCP echo, both directions at once.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := c.Dial(ctx, "tcp", netip.MustParseAddrPort("10.9.0.1:8081"))
			if err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 4<<20)
			rand.Read(payload)
			start := time.Now()
			go func() { conn.Write(payload) }()
			got := make([]byte, len(payload))
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("echo: %v", err)
			}
			conn.Close()
			if !bytes.Equal(got, payload) {
				t.Fatal("echo corrupted")
			}
			t.Logf("4 MiB echoed in %v", time.Since(start).Round(time.Millisecond))

			// UDP echo.
			u, err := c.Dial(ctx, "udp", netip.MustParseAddrPort("10.9.0.1:9090"))
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			for i := 0; i < 20; i++ {
				msg := []byte("ping " + strings.Repeat("x", i*50))
				u.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := u.Write(msg); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 2048)
				n, err := u.Read(buf)
				if err != nil || !bytes.Equal(buf[:n], msg) {
					t.Fatalf("udp echo %d: %q %v", i, buf[:n], err)
				}
			}

			// Not routed by this server: fails closed.
			if _, err := c.Dial(ctx, "tcp", netip.MustParseAddrPort("1.1.1.1:443")); !errors.Is(err, errNotRouted) {
				t.Errorf("unrouted destination: %v", err)
			}
			if s := c.Summary(); s.BytesIn == 0 || s.BytesOut == 0 {
				t.Errorf("no transport bytes counted: %+v", s)
			}

			c.Stop()
			if s := c.Summary(); s.State != StateStopped {
				t.Errorf("after stop: %+v", s)
			}
			if _, err := c.Dial(ctx, "tcp", netip.MustParseAddrPort("10.9.0.1:8080")); err == nil {
				t.Error("dial succeeded after stop")
			}
		})
	}
}

func TestPasswordSession(t *testing.T) {
	lab := startLab(t, ovpnlab.Options{Username: "alice", Password: "s3cret"})
	if _, err := New(Config{ID: "x", Profile: lab.Profile}); err == nil {
		t.Error("profile needing credentials accepted without them")
	}

	bad := connect(t, Config{ID: "bad", Profile: lab.Profile, Username: "alice", Password: "wrong"})
	s := waitState(t, bad, StateError, 30*time.Second)
	if !strings.Contains(s.Error, "AUTH_FAILED") {
		t.Errorf("wrong password: %+v", s)
	}
	if _, err := bad.Dial(context.Background(), "tcp", netip.MustParseAddrPort("10.8.0.1:8080")); err == nil {
		t.Error("dial succeeded after auth failure")
	}

	good := connect(t, Config{ID: "good", Profile: lab.Profile, Username: "alice", Password: "s3cret"})
	waitState(t, good, StateConnected, 20*time.Second)
	if got := dialLine(t, good, "10.8.0.1:8080"); !strings.HasPrefix(got, "ovpnlab") {
		t.Errorf("banner: %q", got)
	}
}

// TestEncryptedPrivateKey: a profile whose key is encrypted (PKCS#8, PBES2),
// like many providers' profiles.
func TestEncryptedPrivateKey(t *testing.T) {
	lab := startLab(t, ovpnlab.Options{KeyPassword: "k3y pass"})
	p, err := Eval(lab.Profile)
	if err != nil || p.Error || !p.PrivateKeyPassword || !p.Autologin {
		t.Fatalf("eval: %+v %v", p, err)
	}
	for pw, want := range map[string]bool{"k3y pass": true, "wrong": false, "": false} {
		if ok, err := CheckKeyPassword(lab.Profile, pw); ok != want || err != nil {
			t.Errorf("CheckKeyPassword(%q) = %v, %v; want %v", pw, ok, err, want)
		}
	}
	if _, err := CheckKeyPassword("client\n", "x"); err == nil {
		t.Error("profile without a key: no error")
	}
	if _, err := New(Config{ID: "x", Profile: lab.Profile}); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("encrypted key without password: %v", err)
	}

	bad := connect(t, Config{ID: "bad", Profile: lab.Profile, KeyPassword: "wrong"})
	if s := waitState(t, bad, StateError, 20*time.Second); s.Error == "" {
		t.Errorf("wrong key password: %+v", s)
	} else {
		t.Logf("wrong key password: %s", s.Error)
	}

	good := connect(t, Config{ID: "good", Profile: lab.Profile, KeyPassword: "k3y pass"})
	waitState(t, good, StateConnected, 20*time.Second)
	if got := dialLine(t, good, "10.9.0.1:8080"); !strings.HasPrefix(got, "ovpnlab") {
		t.Errorf("banner: %q", got)
	}
}

func TestProtectIsCalled(t *testing.T) {
	lab := startLab(t, ovpnlab.Options{})
	var calls atomic.Int32
	c := connect(t, Config{Profile: lab.Profile, Protect: func(int) bool { calls.Add(1); return true }})
	waitState(t, c, StateConnected, 20*time.Second)
	if calls.Load() == 0 {
		t.Error("transport socket was not protected")
	}
}

func TestProtectFailureFailsClosed(t *testing.T) {
	lab := startLab(t, ovpnlab.Options{})
	c := connect(t, Config{Profile: lab.Profile, Protect: func(int) bool { return false }})
	time.Sleep(3 * time.Second)
	if s := c.Summary(); s.State == StateConnected {
		t.Fatalf("connected over an unprotected socket: %+v", s)
	}
}

// BenchmarkLabDownload measures bulk download through a session on the host,
// as a baseline for device runs (the lab server's own limit):
//
//	go test -tags openvpn3 -run x -bench LabDownload ./openvpn
func BenchmarkLabDownload(b *testing.B) {
	lab := startLab(b, ovpnlab.Options{Proto: "udp"})
	c := connect(b, Config{Profile: lab.Profile})
	waitState(b, c, StateConnected, 20*time.Second)
	const size = 64 << 20
	buf := make([]byte, 256<<10)
	b.SetBytes(size)
	b.ResetTimer()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		conn, err := c.Dial(ctx, "tcp", netip.MustParseAddrPort("10.9.0.1:5201"))
		cancel()
		if err != nil {
			b.Fatal(err)
		}
		var req [9]byte
		req[0] = 'D'
		binary.BigEndian.PutUint64(req[1:], size)
		conn.Write(req[:])
		if n, err := io.CopyBuffer(io.Discard, io.LimitReader(conn, size), buf); n != size {
			b.Fatalf("got %d bytes: %v", n, err)
		}
		conn.Close()
	}
}
