// Package tailnet runs several independent Tailscale nodes (one per tailnet or
// account) inside one process, and dials through exactly one of them.
//
// It is a feasibility spike for ADR 0006: each instance has its own state,
// credentials and status, and Dial refuses destinations the selected tailnet
// does not own instead of silently using the host network, which is what
// tsnet.Server.Dial does.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/logtail"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/netstack"
)

// ErrNotInTailnet is returned when the destination is not a peer address or an
// approved subnet route of the selected tailnet.
var ErrNotInTailnet = errors.New("destination is not part of the selected tailnet")

var disableUploads sync.Once

// DisableRemoteLogging turns off Tailscale's log upload for the whole process.
// It must run before the first instance starts; NewManager calls it.
func DisableRemoteLogging() {
	disableUploads.Do(func() {
		envknob.SetNoLogsNoSupport()
		logtail.Disable()
	})
}

// Config describes one tailnet identity. Nothing is shared between configs.
type Config struct {
	ID         string         // stable identifier used by policy routes, e.g. "work"
	StateDir   string         // must be unique per instance
	Store      ipn.StateStore // optional; defaults to a file store in StateDir
	ControlURL string         // empty means the Tailscale default
	AuthKey    string         // optional; without it the node needs interactive login
	Hostname   string
	Ephemeral  bool
	Logf       logger.Logf // optional verbose backend logs
}

// Instance is one running tailnet node.
type Instance struct {
	cfg Config
	srv *tsnet.Server

	snap      atomic.Pointer[snapshot]   // nil until the node has reported status
	peers     atomic.Pointer[[]PeerInfo] // last machine list read, for when a read fails
	watchOnce sync.Once
	stopWatch context.CancelFunc
	watchMu   sync.Mutex
}

// startWatch keeps the routing/naming snapshot current (once per instance).
func (i *Instance) startWatch() {
	i.watchOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		i.watchMu.Lock()
		i.stopWatch = cancel
		i.watchMu.Unlock()
		go i.watch(ctx)
	})
}

func (i *Instance) close() error {
	i.watchMu.Lock()
	if i.stopWatch != nil {
		i.stopWatch()
	}
	i.watchMu.Unlock()
	return i.srv.Close()
}

// Manager owns all instances in the process.
type Manager struct {
	mu        sync.Mutex
	instances map[string]*Instance
	dirs      map[string]string // cleaned state dir -> instance id
}

func NewManager() *Manager {
	DisableRemoteLogging()
	return &Manager{instances: map[string]*Instance{}, dirs: map[string]string{}}
}

// Add registers a tailnet. It does not connect; call Up.
func (m *Manager) Add(cfg Config) (*Instance, error) {
	if cfg.ID == "" || cfg.StateDir == "" {
		return nil, errors.New("tailnet: ID and StateDir are required")
	}
	dir := filepath.Clean(cfg.StateDir)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[cfg.ID]; ok {
		return nil, fmt.Errorf("tailnet: duplicate id %q", cfg.ID)
	}
	if other, ok := m.dirs[dir]; ok {
		return nil, fmt.Errorf("tailnet: %q would share state with %q", cfg.ID, other)
	}
	srv := &tsnet.Server{
		Dir:        dir,
		Store:      cfg.Store,
		ControlURL: cfg.ControlURL,
		AuthKey:    cfg.AuthKey,
		Hostname:   cfg.Hostname,
		Ephemeral:  cfg.Ephemeral,
		Logf:       cfg.Logf,
		UserLogf:   logger.Discard,
	}
	if srv.Logf == nil {
		srv.Logf = logger.Discard
	}
	inst := &Instance{cfg: cfg, srv: srv}
	m.instances[cfg.ID] = inst
	m.dirs[dir] = cfg.ID
	return inst, nil
}

func (m *Manager) Get(id string) *Instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.instances[id]
}

// Remove closes and forgets one instance; the others keep running.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	inst := m.instances[id]
	delete(m.instances, id)
	if inst != nil {
		delete(m.dirs, filepath.Clean(inst.cfg.StateDir))
	}
	m.mu.Unlock()
	if inst == nil {
		return nil
	}
	return inst.close()
}

func (m *Manager) Close() error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.instances))
	for id := range m.instances {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var errs []error
	for _, id := range ids {
		errs = append(errs, m.Remove(id))
	}
	return errors.Join(errs...)
}

func (i *Instance) ID() string { return i.cfg.ID }

// Start brings the node up without waiting: it may need interactive login
// (see Summary's AuthURL) before it can carry traffic.
func (i *Instance) Start() error {
	if err := i.srv.Start(); err != nil {
		return err
	}
	i.startWatch()
	return nil
}

// Summary is the per-tailnet status shown to the user.
type Summary struct {
	ID      string   `json:"id"`
	State   string   `json:"state"` // NoState, NeedsLogin, NeedsMachineAuth, Starting, Running, Stopped, or Error
	AuthURL string   `json:"auth_url,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Peers   int      `json:"peers"`
	Error   string   `json:"error,omitempty"`
}

// Summary reports this instance's state. It never fails: errors become State "Error".
func (i *Instance) Summary(ctx context.Context) Summary {
	s := Summary{ID: i.cfg.ID}
	st, err := i.Status(ctx)
	if err != nil {
		s.State, s.Error = "Error", err.Error()
		return s
	}
	s.State, s.AuthURL, s.Peers = st.BackendState, st.AuthURL, len(st.Peer)
	for _, ip := range st.TailscaleIPs {
		s.IPs = append(s.IPs, ip.String())
	}
	return s
}

// Rebind re-opens the node's sockets and re-discovers its endpoints, e.g.
// after a Wi-Fi/cellular switch. Errors are ignored: the node also recovers
// on its own, just later.
func (i *Instance) Rebind(ctx context.Context) {
	lc, err := i.srv.LocalClient()
	if err != nil {
		return
	}
	lc.DebugAction(ctx, "rebind")
	lc.DebugAction(ctx, "restun")
}

// All returns the instances in no particular order.
func (m *Manager) All() []*Instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Instance, 0, len(m.instances))
	for _, inst := range m.instances {
		out = append(out, inst)
	}
	return out
}

// Up connects and waits until the node is running (or ctx expires, e.g. while
// waiting for interactive login).
func (i *Instance) Up(ctx context.Context) (*ipnstate.Status, error) {
	st, err := i.srv.Up(ctx)
	if err == nil {
		i.snap.Store(newSnapshot(st))
		i.startWatch()
	}
	return st, err
}

// Status reports this instance's own view: backend state, addresses and peers.
func (i *Instance) Status(ctx context.Context) (*ipnstate.Status, error) {
	lc, err := i.srv.LocalClient()
	if err != nil {
		return nil, err
	}
	return lc.Status(ctx)
}

// Owns reports whether ip belongs to this tailnet: a peer's Tailscale address
// or a subnet route that control has made primary for a peer. It reads the
// snapshot kept current from the IPN bus, and asks LocalAPI only before the
// first snapshot exists.
func (i *Instance) Owns(ctx context.Context, ip netip.Addr) (bool, error) {
	if s := i.snap.Load(); s != nil {
		return s.owns(ip.Unmap()), nil
	}
	st, err := i.Status(ctx)
	if err != nil {
		return false, err
	}
	ip = ip.Unmap()
	for _, peer := range st.Peer {
		for _, a := range peer.TailscaleIPs {
			if a == ip {
				return true, nil
			}
		}
		if peer.PrimaryRoutes != nil {
			for _, p := range peer.PrimaryRoutes.All() {
				if p.Contains(ip) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Dial connects to addr ("ip:port") through this tailnet only. Hostnames are
// rejected: name resolution belongs to the DNS layer, which knows which
// tailnet's namespace a name came from.
//
// It deliberately bypasses tsnet.Server.Dial, which falls back to the host
// network for non-tailnet addresses, and dials the instance's own netstack,
// which can only reach the tailnet. The membership check gives a clear error
// up front; the netstack dial guarantees no fallback even if the netmap
// changes between the check and the dial.
func (i *Instance) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tailnet %s: want ip:port, got %q", i.cfg.ID, addr)
	}
	dst := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	owned, err := i.Owns(ctx, dst.Addr())
	if err != nil {
		return nil, err
	}
	if !owned {
		return nil, fmt.Errorf("tailnet %s: %v: %w", i.cfg.ID, dst.Addr(), ErrNotInTailnet)
	}
	ns, ok := i.srv.Sys().Netstack.Get().(*netstack.Impl)
	if !ok {
		return nil, fmt.Errorf("tailnet %s: netstack unavailable", i.cfg.ID)
	}
	v4, v6 := i.srv.TailscaleIPs()
	src := v4
	if dst.Addr().Is6() {
		src = v6
	}
	if !src.IsValid() {
		return nil, fmt.Errorf("tailnet %s: no local address for %v", i.cfg.ID, dst.Addr())
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		c, err := ns.DialContextTCPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return c, nil
	case "udp", "udp4", "udp6":
		c, err := ns.DialContextUDPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return c, nil
	default:
		return nil, fmt.Errorf("tailnet %s: unsupported network %q", i.cfg.ID, network)
	}
}

// Name resolution results (Manager.Resolve).
const (
	NameNotTailnet = "none"      // no tailnet claims the name's suffix
	NameFound      = "ok"        // resolved inside exactly one tailnet
	NameNXDomain   = "nxdomain"  // inside a tailnet's namespace, but no such node
	NameAmbiguous  = "ambiguous" // several tailnets claim the suffix: refuse to guess
)

// NameResult answers a MagicDNS lookup without leaving the tailnets.
type NameResult struct {
	Status    string       `json:"status"`
	Tailnet   string       `json:"tailnet,omitempty"`
	Addrs     []netip.Addr `json:"addrs,omitempty"`
	Claimants []string     `json:"claimants,omitempty"`
}

// Resolve answers name from the one tailnet whose MagicDNS suffix contains
// it. Names are namespaced per tailnet: a name is never looked up in, or
// answered from, a tailnet that does not own its suffix.
func (m *Manager) Resolve(name string) NameResult {
	name = normalizeName(name)
	var owner *Instance
	var claimants []string
	for _, inst := range m.All() {
		if s := inst.snap.Load(); s != nil && s.claims(name) {
			owner = inst
			claimants = append(claimants, inst.cfg.ID)
		}
	}
	switch len(claimants) {
	case 0:
		return NameResult{Status: NameNotTailnet}
	case 1:
		if addrs := owner.snap.Load().names[name]; len(addrs) > 0 {
			return NameResult{Status: NameFound, Tailnet: owner.cfg.ID, Addrs: addrs}
		}
		return NameResult{Status: NameNXDomain, Tailnet: owner.cfg.ID}
	default:
		return NameResult{Status: NameAmbiguous, Claimants: claimants}
	}
}
