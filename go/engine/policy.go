package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

// UnknownUID is the owner of a flow whose app could not be attributed.
const UnknownUID = -1

// Block is the on_failure value meaning "drop the flow".
const Block = "block"

// RouteSpec names a transport and what to do if it cannot deliver.
type RouteSpec struct {
	Transport string
	// OnFailure is Block or another transport id. It is never implicit: a
	// failed transport falls back only where the policy says so.
	OnFailure string
}

// Rule is one compiled per-flow rule. Empty matchers are wildcards; non-empty
// matchers must all match (AND), any entry within one may match (OR).
type Rule struct {
	ID         string
	AnyApp     bool             // no app constraint
	UIDs       map[int]struct{} // owning app UIDs
	UnknownApp bool             // also match flows whose owner is unknown
	CIDRs      []netip.Prefix
	Protocol   Protocol // 0 = any
	Ports      [][2]uint16
	Block      bool
	Route      RouteSpec
}

// Policy is the ordered per-flow rule table. It is immutable once built and
// swapped atomically.
type Policy struct {
	Rules    []Rule
	Default  RouteSpec
	needsUID bool
}

// DefaultPolicy routes everything direct and blocks if direct fails.
func DefaultPolicy() *Policy {
	return &Policy{Default: RouteSpec{Transport: DirectName, OnFailure: Block}}
}

// NeedsUID reports whether any rule matches on the owning app, i.e. whether
// flows must be attributed (one host upcall per new flow).
func (p *Policy) NeedsUID() bool { return p.needsUID }

// Match returns the first matching rule, or nil for the default route.
func (p *Policy) Match(f Flow, uid int) *Rule {
	dst := f.Dst.Addr().Unmap()
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.AnyApp {
			if uid == UnknownUID {
				if !r.UnknownApp {
					continue
				}
			} else if _, ok := r.UIDs[uid]; !ok {
				continue
			}
		}
		if r.Protocol != 0 && r.Protocol != f.Protocol {
			continue
		}
		if len(r.Ports) > 0 && !portIn(f.Dst.Port(), r.Ports) {
			continue
		}
		if len(r.CIDRs) > 0 && !prefixIn(dst, r.CIDRs) {
			continue
		}
		return r
	}
	return nil
}

func portIn(p uint16, ranges [][2]uint16) bool {
	for _, r := range ranges {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}

func prefixIn(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Wire format produced by the Kotlin exporter (FlowPolicyExporter).
type policyJSON struct {
	Version    int `json:"version"`
	Transports []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"transports"`
	Default struct {
		Transport string `json:"transport"`
		OnFailure string `json:"on_failure"`
	} `json:"default"`
	Rules []struct {
		ID         string      `json:"id"`
		AnyApp     bool        `json:"any_app"`
		UIDs       []int       `json:"uids"`
		UnknownApp bool        `json:"unknown_app"`
		CIDRs      []string    `json:"cidrs"`
		Protocol   string      `json:"protocol"`
		Ports      [][2]uint16 `json:"ports"`
		Action     string      `json:"action"`
		Transport  string      `json:"transport"`
		OnFailure  string      `json:"on_failure"`
	} `json:"rules"`
}

// ParsePolicy validates a policy against the transports this engine has.
// Anything it cannot enforce exactly is rejected, never approximated.
func ParsePolicy(data []byte, transports map[string]Transport) (*Policy, error) {
	var pj policyJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if pj.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d", pj.Version)
	}
	for _, t := range pj.Transports {
		tr, ok := transports[t.ID]
		if !ok {
			return nil, fmt.Errorf("policy: transport %q (%s) is not available in this engine", t.ID, t.Type)
		}
		if tr.Kind() != t.Type {
			return nil, fmt.Errorf("policy: transport %q is %s here, policy says %s", t.ID, tr.Kind(), t.Type)
		}
	}
	route := func(where, transport, onFailure string) (RouteSpec, error) {
		if _, ok := transports[transport]; !ok {
			return RouteSpec{}, fmt.Errorf("policy: %s: unknown transport %q", where, transport)
		}
		if onFailure == "" {
			onFailure = Block
		}
		if onFailure != Block {
			if _, ok := transports[onFailure]; !ok {
				return RouteSpec{}, fmt.Errorf("policy: %s: unknown on_failure transport %q", where, onFailure)
			}
		}
		return RouteSpec{Transport: transport, OnFailure: onFailure}, nil
	}
	def, err := route("default", pj.Default.Transport, pj.Default.OnFailure)
	if err != nil {
		return nil, err
	}
	p := &Policy{Default: def}
	seen := map[string]bool{}
	for _, rj := range pj.Rules {
		where := fmt.Sprintf("rule %q", rj.ID)
		if rj.ID == "" || seen[rj.ID] {
			return nil, fmt.Errorf("policy: missing or duplicate rule id %q", rj.ID)
		}
		seen[rj.ID] = true
		r := Rule{ID: rj.ID, AnyApp: rj.AnyApp, UnknownApp: rj.UnknownApp, UIDs: map[int]struct{}{}}
		if r.AnyApp && (len(rj.UIDs) > 0 || rj.UnknownApp) {
			return nil, fmt.Errorf("policy: %s: any_app excludes uids/unknown_app", where)
		}
		for _, u := range rj.UIDs {
			if u < 0 {
				return nil, fmt.Errorf("policy: %s: invalid uid %d", where, u)
			}
			r.UIDs[u] = struct{}{}
		}
		if !r.AnyApp {
			p.needsUID = true
		}
		for _, c := range rj.CIDRs {
			pfx, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("policy: %s: %w", where, err)
			}
			r.CIDRs = append(r.CIDRs, pfx.Masked())
		}
		switch rj.Protocol {
		case "":
		case "tcp":
			r.Protocol = TCP
		case "udp":
			r.Protocol = UDP
		case "icmp":
			r.Protocol = ICMP
		case "icmpv6":
			r.Protocol = ICMPv6
		default:
			return nil, fmt.Errorf("policy: %s: unsupported protocol %q", where, rj.Protocol)
		}
		for _, pr := range rj.Ports {
			if pr[0] == 0 || pr[1] < pr[0] {
				return nil, fmt.Errorf("policy: %s: invalid port range %v", where, pr)
			}
		}
		r.Ports = rj.Ports
		switch rj.Action {
		case "block":
			r.Block = true
		case "route":
			if r.Route, err = route(where, rj.Transport, rj.OnFailure); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("policy: %s: unsupported action %q", where, rj.Action)
		}
		p.Rules = append(p.Rules, r)
	}
	return p, nil
}

// ErrUnsupportedProtocol is returned by a transport that cannot carry the
// flow's protocol (e.g. UDP over an HTTP CONNECT proxy).
var ErrUnsupportedProtocol = errors.New("transport does not support this protocol")
