// Package httpproxy carries TCP through a regular HTTP proxy using CONNECT.
// HTTP and HTTPS payloads stay with the app/proxy; no TLS interception happens here.
package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hybridvpn/netcore/engine"
)

const TransportPrefix = "http:"
const handshakeTimeout = 10 * time.Second
const maxHeaders = 16 << 10

type Config struct {
	ID, Server, Username, Password string
	// Dial reaches only the proxy, through a protected physical-network socket.
	Dial func(context.Context, string, string) (net.Conn, error)
}

type Proxy struct {
	cfg                     Config
	broken                  error
	mu                      sync.Mutex
	state, lastErr          string
	lastSeen                time.Time
	active, flows, failures atomic.Int64
}

func New(cfg Config) (*Proxy, error) {
	host, port, err := net.SplitHostPort(cfg.Server)
	n, perr := strconv.Atoi(port)
	if cfg.ID == "" || err != nil || host == "" || strings.ContainsAny(host, "\r\n\t /") || perr != nil || n < 1 || n > 65535 {
		return nil, errors.New("http proxy: invalid id or host:port")
	}
	if len(cfg.Username) > 255 || len(cfg.Password) > 255 || strings.Contains(cfg.Username, ":") || (cfg.Username == "" && cfg.Password != "") {
		return nil, errors.New("http proxy: invalid Basic authentication credentials")
	}
	if cfg.Dial == nil {
		return nil, errors.New("http proxy: no protected dialer")
	}
	return &Proxy{cfg: cfg, state: "idle"}, nil
}

func NewFailed(id, server string, err error) *Proxy {
	return &Proxy{cfg: Config{ID: id, Server: server}, broken: err, state: "error", lastErr: err.Error()}
}

func (p *Proxy) Transport() engine.Transport { return transport{p} }

type transport struct{ p *Proxy }

func (t transport) Name() string                      { return TransportPrefix + t.p.cfg.ID }
func (t transport) Kind() string                      { return "http" }
func (t transport) Capabilities() engine.Capabilities { return engine.Capabilities{TCP: true} }
func (t transport) Dial(ctx context.Context, f engine.Flow) (net.Conn, error) {
	return t.p.dial(ctx, f)
}

type Summary struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Server    string `json:"server"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	LastSeen  int64  `json:"last_seen,omitempty"`
	NoUDP     bool   `json:"no_udp"`
	TCPActive int64  `json:"tcp_active"`
	UDPActive int64  `json:"udp_active"`
	Flows     int64  `json:"flows"`
	Failures  int64  `json:"failures"`
}

func (p *Proxy) Summary() Summary {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Summary{ID: p.cfg.ID, Type: "http", Server: p.cfg.Server, State: p.state, Error: p.lastErr, NoUDP: true,
		TCPActive: p.active.Load(), Flows: p.flows.Load(), Failures: p.failures.Load()}
	if !p.lastSeen.IsZero() {
		s.LastSeen = p.lastSeen.UnixMilli()
	}
	return s
}

func (p *Proxy) record(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		p.state, p.lastErr, p.lastSeen = "ready", "", time.Now()
	} else {
		p.state, p.lastErr = "error", err.Error()
	}
}

// Check checks TCP reachability only. HTTP has no destination-free auth
// handshake: credentials are validated when the first CONNECT is attempted.
func (p *Proxy) Check(ctx context.Context) error {
	if p.broken != nil {
		return p.broken
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	c, err := p.cfg.Dial(ctx, "tcp", p.cfg.Server)
	if err == nil {
		c.Close()
	}
	p.record(err)
	return err
}

type refused struct{ status int }

func (e *refused) Error() string {
	return fmt.Sprintf("http proxy: CONNECT refused (HTTP %d)", e.status)
}

func (p *Proxy) dial(ctx context.Context, f engine.Flow) (_ net.Conn, err error) {
	if f.Protocol != engine.TCP {
		return nil, engine.ErrUnsupportedProtocol
	}
	if p.broken != nil {
		p.failures.Add(1)
		return nil, p.broken
	}
	defer func() {
		if err != nil {
			p.failures.Add(1)
			var r *refused
			if errors.As(err, &r) && r.status != http.StatusProxyAuthRequired {
				p.record(nil)
			} else {
				p.record(err)
			}
		} else {
			p.flows.Add(1)
			p.record(nil)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	c, err := p.cfg.Dial(ctx, "tcp", p.cfg.Server)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	dl, _ := ctx.Deadline()
	if err := c.SetDeadline(dl); err != nil {
		return nil, err
	}
	dst := f.Dst.String()
	request := "CONNECT " + dst + " HTTP/1.1\r\nHost: " + dst + "\r\n"
	if p.cfg.Username != "" {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(p.cfg.Username+":"+p.cfg.Password)) + "\r\n"
	}
	if _, err := fmt.Fprint(c, request+"\r\n"); err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	// Bound all response headers, including any informational responses, and
	// retain buffered tunnel bytes received together with the final headers.
	budget := maxHeaders
	for {
		var h []byte
		for {
			if budget == 0 {
				return nil, errors.New("http proxy: response headers exceed 16 KiB")
			}
			b, err := r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("http proxy: response: %w", err)
			}
			budget--
			h = append(h, b)
			if bytes.HasSuffix(h, []byte("\r\n\r\n")) {
				break
			}
		}
		res, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(h)), &http.Request{Method: "CONNECT"})
		if err != nil {
			return nil, errors.New("http proxy: malformed CONNECT response")
		}
		if res.StatusCode >= 100 && res.StatusCode < 200 && res.StatusCode != 101 {
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, &refused{res.StatusCode}
		}
		break
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	p.active.Add(1)
	return &conn{Conn: c, r: r, active: &p.active}, nil
}

type conn struct {
	net.Conn
	r      *bufio.Reader
	active *atomic.Int64
	once   sync.Once
}

func (c *conn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *conn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.active.Add(-1) })
	return err
}
func (c *conn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
func (c *conn) CloseRead() error {
	if v, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return nil
}
