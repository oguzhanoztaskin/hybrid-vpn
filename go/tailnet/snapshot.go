package tailnet

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

// snapshot is a tailnet's routing and naming view, rebuilt from Status when
// the IPN bus reports a relevant change. Flows and DNS lookups read it
// without a LocalAPI round trip.
type snapshot struct {
	suffix   string                  // MagicDNS suffix, lower case, no dots at the ends ("tail1234.ts.net")
	names    map[string][]netip.Addr // FQDN (lower case, no trailing dot) -> addresses
	addrs    map[netip.Addr]bool     // peer Tailscale addresses
	prefixes []netip.Prefix          // approved, primary subnet routes of peers
}

func newSnapshot(st *ipnstate.Status) *snapshot {
	s := &snapshot{names: map[string][]netip.Addr{}, addrs: map[netip.Addr]bool{}}
	if st.CurrentTailnet != nil {
		s.suffix = normalizeName(st.CurrentTailnet.MagicDNSSuffix)
	}
	if st.Self != nil && st.Self.DNSName != "" {
		s.names[normalizeName(st.Self.DNSName)] = st.Self.TailscaleIPs
	}
	for _, p := range st.Peer {
		for _, a := range p.TailscaleIPs {
			s.addrs[a] = true
		}
		if p.DNSName != "" {
			s.names[normalizeName(p.DNSName)] = p.TailscaleIPs
		}
		if p.PrimaryRoutes != nil {
			s.prefixes = append(s.prefixes, p.PrimaryRoutes.AsSlice()...)
		}
	}
	return s
}

func (s *snapshot) owns(ip netip.Addr) bool {
	if s.addrs[ip] {
		return true
	}
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// claims reports whether name is inside this tailnet's MagicDNS namespace.
func (s *snapshot) claims(name string) bool {
	return s.suffix != "" && (name == s.suffix || strings.HasSuffix(name, "."+s.suffix))
}

func normalizeName(n string) string { return strings.ToLower(strings.Trim(n, ".")) }

// refresh rebuilds the snapshot from the node's current status.
func (i *Instance) refresh(ctx context.Context) {
	if st, err := i.Status(ctx); err == nil {
		i.snap.Store(newSnapshot(st))
	}
}

// watch keeps the snapshot current until ctx ends. Endpoint-only peer
// patches are ignored: they change neither addresses nor names.
func (i *Instance) watch(ctx context.Context) {
	for ctx.Err() == nil {
		lc, err := i.srv.LocalClient()
		if err == nil {
			var w interface {
				Next() (ipn.Notify, error)
				Close() error
			}
			w, err = lc.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyInitialStatus|ipn.NotifyPeerChanges)
			if err == nil {
				for {
					n, err := w.Next()
					if err != nil {
						break
					}
					if n.State != nil || n.InitialStatus != nil || n.SelfChange != nil || n.LoginFinished != nil ||
						len(n.PeersChanged) > 0 || len(n.PeersRemoved) > 0 {
						i.refresh(ctx)
					}
				}
				w.Close()
			}
		}
		select { // the node is restarting or not up yet: retry calmly
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}
