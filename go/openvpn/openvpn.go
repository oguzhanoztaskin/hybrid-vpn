// Package openvpn runs OpenVPN client sessions (OpenVPN 3 Core, ADR 0008) as
// routing transports. Each session gets its own userspace network stack on a
// packet socket the core reads and writes; nothing is routed by the OS.
//
// A transport carries only destinations its server routes (the pushed
// addresses, routes and redirect-gateway), and only while connected. Any
// other flow fails closed: there is no fallback to the host network.
//
// The core is linked only with the build tag openvpn3 (third_party/ built by
// scripts/openvpn3-deps.sh). Without it, Available reports false and New fails.
package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hybridvpn/netcore/engine"
)

// TransportPrefix prefixes OpenVPN transport ids in routing decisions.
const TransportPrefix = "openvpn:"

// ErrUnavailable means this build does not include OpenVPN 3 Core.
var ErrUnavailable = errors.New("OpenVPN support is not included in this build")

// Config describes one profile.
type Config struct {
	ID       string
	Profile  string // inline .ovpn text; external file references are not supported
	Username string
	Password string
	// KeyPassword decrypts an encrypted private key in the profile.
	KeyPassword string
	// Protect excludes a transport socket from the VPN (VpnService.protect).
	Protect func(fd int) bool
	Logf    func(format string, args ...any)
}

// Profile is what a profile says about itself, before connecting.
type Profile struct {
	Error              bool   `json:"error"`
	Message            string `json:"message"`
	Autologin          bool   `json:"autologin"`     // false: needs username and password
	Username           string `json:"username"`      // locked username, if any
	FriendlyName       string `json:"friendly_name"` // set by the profile's FRIENDLY_NAME comment, if any
	ProfileName        string `json:"profile_name"`  // usually the server host
	RemoteHost         string `json:"remote_host"`
	RemotePort         string `json:"remote_port"`
	RemoteProto        string `json:"remote_proto"`
	StaticChallenge    string `json:"static_challenge"`
	PrivateKeyPassword bool   `json:"private_key_password"` // the private key is encrypted
	ExternalPKI        bool   `json:"external_pki"`
}

// State of a session.
const (
	StateIdle       = "idle"
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateError      = "error"
	StateStopped    = "stopped"
)

// Summary is a session's state for the UI.
type Summary struct {
	ID         string   `json:"id"`
	State      string   `json:"state"`
	Event      string   `json:"event,omitempty"` // last core event, e.g. RECONNECTING
	Error      string   `json:"error,omitempty"`
	Server     string   `json:"server,omitempty"` // host:port/proto
	ServerIP   string   `json:"server_ip,omitempty"`
	VPNv4      string   `json:"vpn_ipv4,omitempty"`
	VPNv6      string   `json:"vpn_ipv6,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	DNSServers []string `json:"dns_servers,omitempty"`
	DNSDomains []string `json:"dns_domains,omitempty"`
	BytesIn    int64    `json:"bytes_in"`
	BytesOut   int64    `json:"bytes_out"`
	Since      int64    `json:"connected_since,omitempty"` // unix ms
}

// native is the OpenVPN 3 Core session (native.go), replaceable in tests.
type native interface {
	connect() (status, error)
	stop()
	reconnect(seconds int)
	info() connectionInfo
	stats() (bytesIn, bytesOut int64)
	counters() string // diagnostics
	free()
}

type status struct {
	Error   bool   `json:"error"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type connectionInfo struct {
	Defined     bool   `json:"defined"`
	ServerHost  string `json:"server_host"`
	ServerPort  string `json:"server_port"`
	ServerProto string `json:"server_proto"`
	ServerIP    string `json:"server_ip"`
	VPNv4       string `json:"vpn_ip4"`
	VPNv6       string `json:"vpn_ip6"`
}

// Client is one OpenVPN session.
type Client struct {
	cfg    Config
	native native
	// nmu guards native against use after free: calls hold it for reading,
	// Stop frees under the write lock.
	nmu      sync.RWMutex
	freed    bool
	stopOnce sync.Once

	mu      sync.Mutex
	state   string
	event   string
	err     string
	tun     *tunnel
	since   time.Time
	started bool
	done    chan struct{}

	logMu sync.Mutex
	logs  []string

	// sink is the engine's fast-path receiver (engine.PacketTransport).
	sink atomic.Pointer[engine.PacketSink]
}

func (c *Client) ID() string { return c.cfg.ID }

func (c *Client) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	c.logMu.Lock()
	if len(c.logs) == maxLogLines {
		copy(c.logs, c.logs[1:])
		c.logs = c.logs[:maxLogLines-1]
	}
	c.logs = append(c.logs, time.Now().Format("15:04:05 ")+strings.TrimRight(line, "\n"))
	c.logMu.Unlock()
	if c.cfg.Logf != nil {
		c.cfg.Logf("openvpn %s: %s", c.cfg.ID, line)
	}
}

const maxLogLines = 300

// Logs returns the session's recent log lines (core log and events), oldest
// first, for diagnostics in the app. The core never logs credentials.
func (c *Client) Logs() []string {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	return append([]string(nil), c.logs...)
}

// NewFailed returns a session that could not be created (e.g. an invalid
// profile or missing credentials). Its transport refuses every flow, so
// routes that name it fail closed, and Summary reports err.
func NewFailed(id string, err error) *Client {
	c := &Client{cfg: Config{ID: id}, native: nopNative{}, state: StateError, err: err.Error(), done: make(chan struct{})}
	c.started = true // never connects
	close(c.done)
	c.logf("not started: %v", err)
	return c
}

type nopNative struct{}

func (nopNative) connect() (status, error) { return status{}, nil }
func (nopNative) stop()                    {}
func (nopNative) reconnect(int)            {}
func (nopNative) info() connectionInfo     { return connectionInfo{} }
func (nopNative) stats() (int64, int64)    { return 0, 0 }
func (nopNative) counters() string         { return "" }
func (nopNative) free()                    {}

// Start runs the session in the background. The core reconnects by itself
// after transient failures; the session ends only on Stop or a fatal error
// (e.g. authentication failed), which Summary reports.
func (c *Client) Start() {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	c.state = StateConnecting
	c.mu.Unlock()
	go func() {
		defer close(c.done)
		st, err := c.native.connect()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.tun != nil {
			c.tun.close()
			c.tun = nil
		}
		switch {
		case err != nil:
			c.state, c.err = StateError, err.Error()
		case st.Error:
			c.state = StateError
			if c.err == "" {
				c.err = strings.TrimPrefix(strings.TrimSpace(st.Status+": "+friendlyError(st.Message)), ": ")
			}
		case c.state != StateError:
			c.state = StateStopped
		}
		c.logf("session ended: %s %s", c.state, c.err)
	}()
}

// Stop ends the session, waits for it to finish and releases it. Calling
// Stop again does nothing.
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		c.mu.Lock()
		started := c.started
		c.mu.Unlock()
		if started {
			c.native.stop()
			<-c.done
		}
		c.nmu.Lock()
		defer c.nmu.Unlock()
		c.freed = true
		c.native.free()
	})
}

// Reconnect restarts the session's connection now (e.g. after the physical
// network changed), keeping the tunnel if nothing else changed.
func (c *Client) Reconnect() {
	c.mu.Lock()
	connected := c.state == StateConnected || c.state == StateConnecting
	c.mu.Unlock()
	if !connected {
		return
	}
	c.nmu.RLock()
	defer c.nmu.RUnlock()
	if !c.freed {
		c.native.reconnect(0)
	}
}

func (c *Client) Summary() Summary {
	c.mu.Lock()
	s := Summary{ID: c.cfg.ID, State: c.state, Event: c.event, Error: c.err}
	tun := c.tun
	since := c.since
	c.mu.Unlock()
	c.nmu.RLock()
	defer c.nmu.RUnlock()
	if c.freed {
		return s
	}
	if s.State == StateConnected {
		info := c.native.info()
		if info.ServerHost != "" {
			s.Server = net.JoinHostPort(info.ServerHost, info.ServerPort) + "/" + strings.ToLower(info.ServerProto)
		}
		s.ServerIP, s.VPNv4, s.VPNv6 = info.ServerIP, info.VPNv4, info.VPNv6
		s.Since = since.UnixMilli()
	}
	if tun != nil {
		s.Routes = tun.routes.Prefixes()
		s.DNSServers = tun.cfg.DNSServers
		s.DNSDomains = append(append([]string(nil), tun.cfg.DNSDomains...), tun.cfg.SearchDomains...)
	}
	if s.State != StateIdle {
		s.BytesIn, s.BytesOut = c.native.stats()
	}
	return s
}

// Dial opens a flow through the VPN, if it is connected and the server
// routes the destination.
func (c *Client) Dial(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
	c.mu.Lock()
	tun, state := c.tun, c.state
	c.mu.Unlock()
	if state != StateConnected || tun == nil {
		return nil, fmt.Errorf("%s%s is not connected (%s)", TransportPrefix, c.cfg.ID, state)
	}
	return tun.dial(ctx, network, dst)
}

// --- callbacks from the core ---

func (c *Client) onEstablish(fd int, cfg TunConfig) error {
	t, err := newTunnel(fd, cfg, &c.sink)
	if err != nil {
		c.logf("tunnel setup failed: %v", err)
		return err
	}
	c.mu.Lock()
	old := c.tun
	c.tun = t
	c.mu.Unlock()
	if old != nil {
		old.close()
	}
	c.logf("tunnel up: addresses %v, routes %v, dns %v", cfg.Addresses, t.routes.Prefixes(), cfg.DNSServers)
	return nil
}

func (c *Client) onTeardown(disconnect bool) {
	c.mu.Lock()
	t := c.tun
	c.tun = nil
	c.mu.Unlock()
	if t != nil {
		t.close()
	}
}

func (c *Client) onEvent(name, info string, isError, fatal bool) {
	info = friendlyError(info)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.event = name
	switch {
	case name == "CONNECTED":
		c.state, c.err, c.since = StateConnected, "", time.Now()
	case fatal:
		c.state = StateError
		c.err = strings.TrimSpace(name + ": " + info)
	case name == "DISCONNECTED":
		if c.state != StateError {
			c.state = StateStopped
		}
	case isError:
		// Non-fatal: the core retries. Keep the reason visible meanwhile.
		c.err = strings.TrimSpace(name + ": " + info)
		if c.state == StateConnected {
			c.state = StateConnecting
		}
	case name == "RECONNECTING" || name == "RESOLVE" || name == "WAIT" || name == "CONNECTING" ||
		name == "GET_CONFIG" || name == "ASSIGN_IP" || name == "ADD_ROUTES" || name == "PAUSE":
		if c.state != StateError {
			c.state = StateConnecting
		}
	}
	if name != "INFO" || isError {
		c.logf("event %s %s", name, info)
	}
}

func (c *Client) protect(fd int) bool {
	if c.cfg.Protect == nil {
		return true
	}
	return c.cfg.Protect(fd)
}

// friendlyError replaces the core's OpenSSL error chains where the cause is
// known. A wrong key password shows up as a PEM parse failure whose OpenSSL
// details vary with the garbage the wrong key decrypted to.
func friendlyError(s string) string {
	if strings.Contains(s, "PKey::parse_pem: error in private key") {
		return "the private key password is wrong"
	}
	return s
}

// --- engine transport ---

// Transport adapts a Client to the engine's routing boundary, as
// "openvpn:<id>".
func (c *Client) Transport() engine.Transport { return transport{c} }

type transport struct{ c *Client }

func (t transport) Name() string { return TransportPrefix + t.c.cfg.ID }
func (t transport) Kind() string { return "openvpn" }
func (t transport) Capabilities() engine.Capabilities {
	return engine.Capabilities{TCP: true, UDP: true}
}

func (t transport) Dial(ctx context.Context, f engine.Flow) (net.Conn, error) {
	return t.c.Dial(ctx, f.Protocol.String(), f.Dst)
}

func (t transport) Ping(ctx context.Context, dst netip.Addr) error {
	t.c.mu.Lock()
	tun, state := t.c.tun, t.c.state
	t.c.mu.Unlock()
	if state != StateConnected || tun == nil || tun.closed.Load() || !tun.routes.owns(dst) {
		return fmt.Errorf("openvpn: not connected or destination not routed: %s", dst)
	}
	local := tun.local4
	if dst.Is6() {
		local = tun.local6
	}
	if local.Len() == 0 {
		return fmt.Errorf("openvpn: no local address for %s", dst)
	}
	localAddr, _ := netip.AddrFromSlice(local.AsSlice())
	return engine.PingStack(ctx, tun.stack, localAddr, dst)
}

// PacketPath lets the engine forward TCP flows at the IP level, while
// connected and only to destinations the server routes.
func (t transport) PacketPath(dst netip.Addr) (engine.PacketPath, bool) {
	t.c.mu.Lock()
	tun, state := t.c.tun, t.c.state
	t.c.mu.Unlock()
	if state != StateConnected || tun == nil {
		return nil, false
	}
	return tun.packetPath(dst)
}

func (t transport) SetPacketSink(sink engine.PacketSink) {
	if sink == nil {
		t.c.sink.Store(nil)
		return
	}
	t.c.sink.Store(&sink)
}
