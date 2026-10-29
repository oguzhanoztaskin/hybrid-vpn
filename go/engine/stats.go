package engine

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type counters struct {
	packetsIn, packetsOut   atomic.Int64
	bytesUp, bytesDown      atomic.Int64
	tcpActive, tcpTotal     atomic.Int64
	tcpFailed               atomic.Int64
	udpActive, udpTotal     atomic.Int64
	udpFailed               atomic.Int64
	dnsQueries, dnsFailures atomic.Int64
	udpDatagramsUp          atomic.Int64
	udpDatagramsDown        atomic.Int64
	uidLookups              atomic.Int64
	fallbacks               atomic.Int64

	mu       sync.Mutex
	dropped  map[string]int64
	byRoute  map[string]int64
	failures map[string]*Failure
	failSeq  uint64
}

// Failure is one kind of failed dial, for diagnostics: the same transport,
// protocol and error are counted, not repeated. Kept in memory only.
type Failure struct {
	Transport string `json:"transport"`
	Protocol  string `json:"protocol"`
	Error     string `json:"error"`
	Count     int64  `json:"count"`
	Last      int64  `json:"last"` // unix ms
	seq       uint64 // order of the last occurrence
}

const maxFailures = 50

// failed records a dial that failed on transport; the oldest kind is
// forgotten once maxFailures kinds are kept.
func (c *counters) failed(transport string, p Protocol, err error) {
	key := transport + "|" + p.String() + "|" + err.Error()
	now := time.Now().UnixMilli()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures == nil {
		c.failures = map[string]*Failure{}
	}
	c.failSeq++
	if f, ok := c.failures[key]; ok {
		f.Count++
		f.Last, f.seq = now, c.failSeq
		return
	}
	if len(c.failures) >= maxFailures {
		oldest := ""
		for k, f := range c.failures {
			if oldest == "" || f.seq < c.failures[oldest].seq {
				oldest = k
			}
		}
		delete(c.failures, oldest)
	}
	c.failures[key] = &Failure{Transport: transport, Protocol: p.String(), Error: err.Error(), Count: 1, Last: now, seq: c.failSeq}
}

// routed counts a flow carried by transport; fellBack marks an explicit
// on_failure fallback.
func (c *counters) routed(transport string, fellBack bool) {
	if fellBack {
		c.fallbacks.Add(1)
	}
	c.mu.Lock()
	if c.byRoute == nil {
		c.byRoute = map[string]int64{}
	}
	c.byRoute[transport]++
	c.mu.Unlock()
}

func (c *counters) drop(reason string) { c.dropN(reason, 1) }

func (c *counters) dropN(reason string, n int) {
	c.mu.Lock()
	if c.dropped == nil {
		c.dropped = map[string]int64{}
	}
	c.dropped[reason] += int64(n)
	c.mu.Unlock()
}

// Stats is a point-in-time snapshot, serialised to JSON for the UI.
type Stats struct {
	Running     bool   `json:"running"`
	Error       string `json:"error,omitempty"`
	PacketsIn   int64  `json:"packetsIn"`
	PacketsOut  int64  `json:"packetsOut"`
	BytesUp     int64  `json:"bytesUp"`
	BytesDown   int64  `json:"bytesDown"`
	TCPActive   int64  `json:"tcpActive"`
	TCPTotal    int64  `json:"tcpTotal"`
	TCPFailed   int64  `json:"tcpFailed"`
	UDPActive   int64  `json:"udpActive"`
	UDPTotal    int64  `json:"udpTotal"`
	UDPFailed   int64  `json:"udpFailed"`
	DNSQueries  int64  `json:"dnsQueries"`
	DNSFailures int64  `json:"dnsFailures"`
	// UDP datagrams relayed app→remote and remote→app.
	UDPDatagramsUp   int64 `json:"udpDatagramsUp"`
	UDPDatagramsDown int64 `json:"udpDatagramsDown"`
	// Datagrams netstack dropped because a flow's receive buffer was full.
	UDPReceiveBufferDrops uint64           `json:"udpReceiveBufferDrops"`
	Dropped               map[string]int64 `json:"dropped,omitempty"`
	// Flows per transport, explicit on_failure fallbacks, owner lookups.
	Routed     map[string]int64 `json:"routed,omitempty"`
	Fallbacks  int64            `json:"fallbacks"`
	UIDLookups int64            `json:"uidLookups"`
	// Recent kinds of failed dials, newest first.
	Failures []Failure `json:"failures,omitempty"`
	// TCP flows forwarded at the IP level through a packet transport
	// (included in TCPActive/TCPTotal), packets each way, and drops.
	FastActive     int64 `json:"fastActive"`
	FastPacketsOut int64 `json:"fastPacketsOut"`
	FastPacketsIn  int64 `json:"fastPacketsIn"`
	FastDropped    int64 `json:"fastDropped"`
	FastCoalesced  int64 `json:"fastCoalesced"` // segments merged before reaching apps
}

func (e *Engine) Stats() Stats {
	c := &e.c
	s := Stats{
		Running:     e.ctx.Err() == nil,
		PacketsIn:   c.packetsIn.Load(),
		PacketsOut:  c.packetsOut.Load(),
		BytesUp:     c.bytesUp.Load(),
		BytesDown:   c.bytesDown.Load(),
		TCPActive:   c.tcpActive.Load(),
		TCPTotal:    c.tcpTotal.Load(),
		TCPFailed:   c.tcpFailed.Load(),
		UDPActive:   c.udpActive.Load(),
		UDPTotal:    c.udpTotal.Load(),
		UDPFailed:   c.udpFailed.Load(),
		DNSQueries:  c.dnsQueries.Load(),
		DNSFailures: c.dnsFailures.Load(),

		UDPDatagramsUp:        c.udpDatagramsUp.Load(),
		UDPDatagramsDown:      c.udpDatagramsDown.Load(),
		UDPReceiveBufferDrops: e.stack.Stats().UDP.ReceiveBufferErrors.Value(),
		Fallbacks:             c.fallbacks.Load(),
		UIDLookups:            c.uidLookups.Load(),
	}
	if f := e.fast; f != nil {
		s.FastActive = f.active.Load()
		s.TCPActive += s.FastActive
		s.FastPacketsOut, s.FastPacketsIn, s.FastDropped = f.packetsOut.Load(), f.packets.Load(), f.dropped.Load()
		s.FastCoalesced = f.coalesced.Load()
	}
	if msg, ok := e.err.Load().(string); ok {
		s.Error = msg
	}
	c.mu.Lock()
	if len(c.byRoute) > 0 {
		s.Routed = make(map[string]int64, len(c.byRoute))
		for k, v := range c.byRoute {
			s.Routed[k] = v
		}
	}
	if len(c.dropped) > 0 {
		s.Dropped = make(map[string]int64, len(c.dropped))
		for k, v := range c.dropped {
			s.Dropped[k] = v
		}
	}
	for _, f := range c.failures {
		s.Failures = append(s.Failures, *f)
	}
	c.mu.Unlock()
	sort.Slice(s.Failures, func(a, b int) bool { return s.Failures[a].seq > s.Failures[b].seq })
	return s
}
