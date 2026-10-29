package tailnet

import (
	"context"
	"sort"
	"time"

	"tailscale.com/ipn/ipnstate"
)

// PeerInfo is what the app shows about one machine in a tailnet. It comes
// from the node's own status; nothing is fetched from elsewhere.
type PeerInfo struct {
	Self           bool     `json:"self,omitempty"`
	ID             string   `json:"id"`
	HostName       string   `json:"hostname"`
	DNSName        string   `json:"dns_name,omitempty"`
	OS             string   `json:"os,omitempty"`
	User           string   `json:"user,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	IPs            []string `json:"ips,omitempty"`
	SubnetRoutes   []string `json:"subnet_routes,omitempty"`
	Online         bool     `json:"online"`
	LastSeen       int64    `json:"last_seen,omitempty"` // unix ms; reported only while offline
	Connection     string   `json:"connection,omitempty"`
	ExitNode       bool     `json:"exit_node,omitempty"`
	ExitNodeOption bool     `json:"exit_node_option,omitempty"`
	Shared         bool     `json:"shared,omitempty"` // shared in from another tailnet
	RxBytes        int64    `json:"rx_bytes,omitempty"`
	TxBytes        int64    `json:"tx_bytes,omitempty"`
	Created        int64    `json:"created,omitempty"`
	LastHandshake  int64    `json:"last_handshake,omitempty"`
	KeyExpiry      int64    `json:"key_expiry,omitempty"`
}

// Peers lists this tailnet's machines, this device first, then online
// machines, then by name. If the node can't be read in time (it is busy
// starting or reconnecting), the last list read is returned instead, so a
// slow moment doesn't make the tailnet look empty; err is set only when there
// is no earlier list.
func (i *Instance) Peers(ctx context.Context) ([]PeerInfo, error) {
	st, err := i.Status(ctx)
	if err != nil {
		if last := i.peers.Load(); last != nil {
			return *last, nil
		}
		return nil, err
	}
	var out []PeerInfo
	if st.Self != nil {
		p := peerInfo(st, st.Self)
		p.Self, p.Online, p.Connection = true, true, "this device"
		out = append(out, p)
	}
	for _, ps := range st.Peer {
		out = append(out, peerInfo(st, ps))
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Self != out[b].Self {
			return out[a].Self
		}
		if out[a].Online != out[b].Online {
			return out[a].Online
		}
		return out[a].HostName < out[b].HostName
	})
	i.peers.Store(&out)
	return out, nil
}

func peerInfo(st *ipnstate.Status, ps *ipnstate.PeerStatus) PeerInfo {
	p := PeerInfo{
		ID: string(ps.ID), HostName: ps.HostName, DNSName: normalizeName(ps.DNSName), OS: ps.OS,
		Online: ps.Online, ExitNode: ps.ExitNode, ExitNodeOption: ps.ExitNodeOption, Shared: ps.ShareeNode,
		RxBytes: ps.RxBytes, TxBytes: ps.TxBytes,
		Created: ms(ps.Created), LastSeen: ms(ps.LastSeen), LastHandshake: ms(ps.LastHandshake),
	}
	if ps.KeyExpiry != nil {
		p.KeyExpiry = ms(*ps.KeyExpiry)
	}
	if u, ok := st.User[ps.UserID]; ok {
		p.User = u.LoginName
		if p.User == "" {
			p.User = u.DisplayName
		}
	}
	if ps.Tags != nil {
		p.Tags = ps.Tags.AsSlice()
	}
	for _, a := range ps.TailscaleIPs {
		p.IPs = append(p.IPs, a.String())
	}
	if ps.PrimaryRoutes != nil {
		for _, r := range ps.PrimaryRoutes.All() {
			p.SubnetRoutes = append(p.SubnetRoutes, r.String())
		}
	}
	switch {
	case ps.CurAddr != "":
		p.Connection = "direct " + ps.CurAddr
	case ps.PeerRelay != "":
		p.Connection = "peer relay " + ps.PeerRelay
	case ps.Relay != "" && ps.Active:
		p.Connection = "relayed via DERP " + ps.Relay
	case ps.Relay != "":
		p.Connection = "idle (home DERP " + ps.Relay + ")"
	}
	return p
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}
