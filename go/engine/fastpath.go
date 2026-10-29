package engine

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// PacketTransport is a transport that can also carry a flow's raw IP packets
// (OpenVPN, whose server routes IP). For TCP flows routed to it, the engine
// then skips netstack: it rewrites the app's address to the transport's own
// and back, instead of terminating the connection and re-originating it from
// a second TCP stack. Transports must still refuse (by returning no path)
// whatever they cannot deliver; the flow then takes the normal path, where
// on_failure applies.
type PacketTransport interface {
	Transport
	// PacketPath returns a path for flows to dst if the transport can carry
	// them now (connected, and dst is routed by the server).
	PacketPath(dst netip.Addr) (PacketPath, bool)
	// SetPacketSink installs the engine's receiver for packets arriving from
	// the transport (nil removes it).
	SetPacketSink(sink PacketSink)
}

// PacketSink receives packets from a PacketTransport in batches.
type PacketSink interface {
	// Packet offers one packet and reports whether the sink took it;
	// packets it doesn't take go to the transport's own stack. The sink may
	// keep using p until Flush returns.
	Packet(p []byte) bool
	// Flush ends a batch: packets the sink held back (to coalesce them) are
	// written out.
	Flush()
}

// PacketPath is one way into a PacketTransport.
type PacketPath interface {
	// Local is the transport's address for the destination's family; it
	// becomes the flow's source address.
	Local() netip.Addr
	// MTU bounds packets on this path; TCP's MSS is clamped to fit.
	MTU() int
	// Send writes one IP packet without retaining p. It must not block: a
	// full path drops the packet (TCP retransmits).
	Send(p []byte) error
	// Valid reports whether the path still exists (e.g. the tunnel was not
	// torn down).
	Valid() bool
}

const (
	maxFastFlows     = 8192
	fastIdleTimeout  = 2 * time.Hour // like an established conntrack entry
	fastCloseLinger  = 10 * time.Second
	fastSweepEvery   = 10 * time.Second
	fastPendingLimit = 512
)

// fastKey identifies a TCP flow by its two endpoints, in one direction.
type fastKey struct{ a, b netip.AddrPort }

type fastFlow struct {
	app       netip.AddrPort // the app's side (TUN address and port)
	remote    netip.AddrPort
	local     netip.Addr // the transport's address replacing app's
	path      PacketPath
	transport string
	mss       uint16
	last      atomic.Int64 // unix nanoseconds of the last packet
	closeAt   atomic.Int64 // when to forget a closed flow, 0 while open
	finOut    atomic.Bool
	finIn     atomic.Bool
}

// fastPath forwards TCP flows routed to a PacketTransport at the IP level.
type fastPath struct {
	e     *Engine
	mu    sync.RWMutex
	out   map[fastKey]*fastFlow // (app, remote)
	in    map[fastKey]*fastFlow // (remote, local:appPort)
	pend  map[fastKey]struct{}  // SYNs waiting for a routing decision
	pre   atomic.Pointer[prefilter]
	sinks []PacketTransport

	active, total       atomic.Int64
	packetsOut, packets atomic.Int64
	dropped             atomic.Int64
	coalesced           atomic.Int64 // segments merged into a previous one
}

// prefilter answers cheaply, per policy, whether a destination can be routed
// to a packet transport at all, so other flows never touch the fast path.
type prefilter struct {
	policy   *Policy
	all      bool
	prefixes []netip.Prefix
}

func newFastPath(e *Engine, transports []Transport) *fastPath {
	f := &fastPath{e: e, out: map[fastKey]*fastFlow{}, in: map[fastKey]*fastFlow{}, pend: map[fastKey]struct{}{}}
	for _, t := range transports {
		if pt, ok := t.(PacketTransport); ok {
			f.sinks = append(f.sinks, pt)
		}
	}
	if len(f.sinks) == 0 {
		return nil
	}
	for _, pt := range f.sinks {
		pt.SetPacketSink(&inboundSink{f: f})
	}
	e.goSafe(f.sweep)
	return f
}

func (f *fastPath) stop() {
	for _, pt := range f.sinks {
		pt.SetPacketSink(nil)
	}
}

func (f *fastPath) isPacketTransport(id string) bool {
	for _, pt := range f.sinks {
		if pt.Name() == id {
			return true
		}
	}
	return false
}

func (f *fastPath) mayRoute(dst netip.Addr) bool {
	p := f.e.router.policy.Load()
	pf := f.pre.Load()
	if pf == nil || pf.policy != p {
		pf = &prefilter{policy: p}
		for _, r := range p.Rules {
			if r.Block || !f.isPacketTransport(r.Route.Transport) {
				continue
			}
			if len(r.CIDRs) == 0 {
				pf.all = true
				break
			}
			pf.prefixes = append(pf.prefixes, r.CIDRs...)
		}
		if f.isPacketTransport(p.Default.Transport) {
			pf.all = true
		}
		f.pre.Store(pf)
	}
	return pf.all || prefixIn(dst.Unmap(), pf.prefixes)
}

// tcpPacket is the parsed part of an IPv4/IPv6 TCP packet the fast path
// needs. Packets it can't handle (options in IPv6, fragments) aren't parsed.
type tcpPacket struct {
	v6       bool
	tcp      header.TCP
	src, dst netip.AddrPort
}

func parseTCP(p []byte) (tcpPacket, bool) {
	var t tcpPacket
	var hdr int
	switch p[0] >> 4 {
	case 4:
		ip := header.IPv4(p)
		if len(p) < header.IPv4MinimumSize || ip.Protocol() != 6 || ip.More() || ip.FragmentOffset() != 0 {
			return t, false
		}
		hdr = int(ip.HeaderLength())
		if hdr < header.IPv4MinimumSize || int(ip.TotalLength()) != len(p) {
			return t, false
		}
		t.src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[12:16])), 0)
		t.dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[16:20])), 0)
	case 6:
		if len(p) < header.IPv6MinimumSize || p[6] != 6 { // TCP directly, no extension headers
			return t, false
		}
		if int(binary.BigEndian.Uint16(p[4:6]))+header.IPv6MinimumSize != len(p) {
			return t, false
		}
		hdr = header.IPv6MinimumSize
		t.v6 = true
		t.src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(p[8:24])), 0)
		t.dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(p[24:40])), 0)
	default:
		return t, false
	}
	if len(p) < hdr+header.TCPMinimumSize {
		return t, false
	}
	t.tcp = header.TCP(p[hdr:])
	if off := int(t.tcp.DataOffset()); off < header.TCPMinimumSize || off > len(t.tcp) {
		return t, false
	}
	t.src = netip.AddrPortFrom(t.src.Addr(), t.tcp.SourcePort())
	t.dst = netip.AddrPortFrom(t.dst.Addr(), t.tcp.DestinationPort())
	return t, true
}

// outbound handles a packet from an app. It returns true if the fast path
// took it (sent it, or holds/drops it while its flow is being decided).
func (f *fastPath) outbound(p []byte) bool {
	if len(p) < 1 {
		return false
	}
	t, ok := parseTCP(p)
	if !ok {
		return false
	}
	key := fastKey{t.src, t.dst}
	f.mu.RLock()
	fl := f.out[key]
	_, pending := f.pend[key]
	f.mu.RUnlock()
	if fl != nil {
		f.send(fl, t, p)
		return true
	}
	flags := t.tcp.Flags()
	if !flags.Contains(header.TCPFlagSyn) || flags.Contains(header.TCPFlagAck) || !f.mayRoute(t.dst.Addr()) {
		return false
	}
	if pending {
		return true // a retransmitted SYN while the first one is being decided
	}
	f.mu.Lock()
	if len(f.pend) >= fastPendingLimit {
		f.mu.Unlock()
		return false
	}
	f.pend[key] = struct{}{}
	f.mu.Unlock()
	syn := append([]byte(nil), p...)
	// The decision may need the owning app (a host upcall), so it must not
	// block the TUN reader.
	go f.e.guard(func() { f.decide(key, syn) })
	return true
}

// decide routes a new TCP flow from its SYN: through the fast path if the
// policy sends it to a packet transport that can carry it now, otherwise into
// netstack, where the usual handling (including on_failure) applies.
func (f *fastPath) decide(key fastKey, syn []byte) {
	defer func() {
		f.mu.Lock()
		delete(f.pend, key)
		f.mu.Unlock()
	}()
	flow := Flow{Protocol: TCP, Src: key.a, Dst: key.b}
	d := f.e.router.Decide(flow, func() int { return f.e.ownerUID(flow) })
	if fl := f.install(key, d); fl != nil {
		t, _ := parseTCP(syn)
		f.send(fl, t, syn)
		return
	}
	f.e.inject(syn)
}

func (f *fastPath) install(key fastKey, d Decision) *fastFlow {
	if d.Action != ActionForward {
		return nil
	}
	var pt PacketTransport
	for _, s := range f.sinks {
		if s.Name() == d.Transport {
			pt = s
		}
	}
	if pt == nil {
		return nil
	}
	path, ok := pt.PacketPath(key.b.Addr())
	if !ok {
		return nil
	}
	local := path.Local()
	if !local.IsValid() || local.Is4() != key.a.Addr().Is4() {
		return nil
	}
	hdr := 40
	if local.Is6() {
		hdr = 60
	}
	fl := &fastFlow{app: key.a, remote: key.b, local: local, path: path, transport: d.Transport}
	if m := path.MTU() - hdr; m > 0 && m < 65536 {
		fl.mss = uint16(m)
	}
	fl.last.Store(time.Now().UnixNano())
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.out) >= maxFastFlows {
		return nil
	}
	inKey := fastKey{key.b, netip.AddrPortFrom(local, key.a.Port())}
	if _, taken := f.in[inKey]; taken {
		return nil // the same remote and port through this address: leave it to netstack
	}
	f.out[key] = fl
	f.in[inKey] = fl
	f.active.Add(1)
	f.total.Add(1)
	f.e.c.routed(d.Transport, false)
	f.e.c.tcpTotal.Add(1)
	return fl
}

// send rewrites an app's packet to the transport's address and sends it.
func (f *fastPath) send(fl *fastFlow, t tcpPacket, p []byte) {
	if !fl.path.Valid() {
		f.remove(fl)
		f.dropped.Add(1)
		return
	}
	rewrite(p, t, fl.local, true)
	flags := t.tcp.Flags()
	if flags.Contains(header.TCPFlagSyn) {
		clampMSS(t.tcp, fl.mss)
		if !flags.Contains(header.TCPFlagAck) { // the app reuses the addresses for a new connection
			fl.closeAt.Store(0)
			fl.finIn.Store(false)
			fl.finOut.Store(false)
		}
	}
	if err := fl.path.Send(p); err != nil {
		f.dropped.Add(1)
		return
	}
	fl.last.Store(time.Now().UnixNano())
	f.packetsOut.Add(1)
	f.e.c.bytesUp.Add(int64(len(t.tcp.Payload())))
	f.track(fl, flags, &fl.finOut)
}

// inboundSink takes packets of fast-path flows from one packet transport,
// rewrites them for the app, and coalesces consecutive data segments of a
// flow into one larger packet (up to the TUN's MTU) before writing them, as
// Linux GRO does: the TUN then sees a fraction of the packets the VPN
// delivers. One per transport; a transport's reader calls it from one
// goroutine (the mutex only covers a tunnel being replaced).
type inboundSink struct {
	f       *fastPath
	mu      sync.Mutex
	pending []groSegment
	// writeHook replaces the TUN write in tests.
	writeHook func([]byte)
}

// groSegment is a packet held back for coalescing. buf aliases the
// transport's buffer until a second segment is merged into it.
type groSegment struct {
	fl     *fastFlow
	buf    []byte
	tcpOff int // TCP header offset in buf
	v6     bool
	seq    uint32 // sequence number of the next byte expected
	merged bool
	n      int // segments in buf
}

const groMaxPending = 16

func (s *inboundSink) Packet(p []byte) bool {
	f := s.f
	if len(p) < 1 {
		return false
	}
	t, ok := parseTCP(p)
	if !ok {
		return false
	}
	f.mu.RLock()
	fl := f.in[fastKey{t.src, t.dst}]
	f.mu.RUnlock()
	if fl == nil {
		return false
	}
	rewrite(p, t, fl.app.Addr(), false)
	flags := t.tcp.Flags()
	if flags.Contains(header.TCPFlagSyn) {
		clampMSS(t.tcp, fl.mss)
	}
	fl.last.Store(time.Now().UnixNano())
	f.packets.Add(1)
	f.e.c.bytesDown.Add(int64(len(t.tcp.Payload())))
	f.track(fl, flags, &fl.finIn)

	s.mu.Lock()
	defer s.mu.Unlock()
	tcpOff := len(p) - len(t.tcp)
	for i := range s.pending {
		g := &s.pending[i]
		if g.fl != fl {
			continue
		}
		if s.merge(g, p, t, tcpOff) {
			return true
		}
		s.write(g) // can't extend it: keep order, then this packet starts anew
		s.pending = append(s.pending[:i], s.pending[i+1:]...)
		break
	}
	if !coalescable(t.tcp) {
		s.writeRaw(p)
		return true
	}
	if len(s.pending) >= groMaxPending {
		s.write(&s.pending[0])
		s.pending = s.pending[1:]
	}
	s.pending = append(s.pending, groSegment{fl: fl, buf: p, tcpOff: tcpOff, v6: t.v6,
		seq: t.tcp.SequenceNumber() + uint32(len(t.tcp.Payload())), n: 1})
	return true
}

func (s *inboundSink) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pending {
		s.write(&s.pending[i])
	}
	s.pending = s.pending[:0]
}

// coalescable: a data segment with only ACK (and PSH) set.
func coalescable(tcp header.TCP) bool {
	return len(tcp.Payload()) > 0 && tcp.Flags()&^header.TCPFlagPsh == header.TCPFlagAck
}

// merge appends p's payload to g if p continues g exactly: same flow, next
// sequence number, identical TCP header apart from sequence number, checksum
// and PSH, and g not ended by PSH. The result must fit the TUN.
func (s *inboundSink) merge(g *groSegment, p []byte, t tcpPacket, tcpOff int) bool {
	gt := header.TCP(g.buf[g.tcpOff:])
	payload := t.tcp.Payload()
	if !coalescable(t.tcp) || gt.Flags()&header.TCPFlagPsh != 0 || t.tcp.SequenceNumber() != g.seq ||
		len(g.buf)+len(payload) > int(s.f.e.cfg.MTU) || tcpOff != g.tcpOff || t.tcp.DataOffset() != gt.DataOffset() {
		return false
	}
	// ack, data offset/flags (bar PSH), window, urgent pointer and options.
	if string(gt[8:12]) != string(t.tcp[8:12]) || gt[12] != t.tcp[12] || gt[13]&^byte(header.TCPFlagPsh) != t.tcp[13]&^byte(header.TCPFlagPsh) ||
		string(gt[14:16]) != string(t.tcp[14:16]) || string(gt[18:t.tcp.DataOffset()]) != string(t.tcp[18:t.tcp.DataOffset()]) {
		return false
	}
	if !g.v6 && (g.buf[1] != p[1] || g.buf[8] != p[8]) { // TOS, TTL
		return false
	}
	if !g.merged {
		b := make([]byte, len(g.buf), s.f.e.cfg.MTU)
		copy(b, g.buf)
		g.buf, g.merged = b, true
	}
	g.buf = append(g.buf, payload...)
	g.buf[g.tcpOff+13] |= t.tcp[13] & byte(header.TCPFlagPsh)
	g.seq += uint32(len(payload))
	g.n++
	return true
}

// write sends a held segment, fixing lengths and checksums if it was merged.
func (s *inboundSink) write(g *groSegment) {
	if g.merged {
		p := g.buf
		tcp := header.TCP(p[g.tcpOff:])
		var src, dst tcpip.Address
		if g.v6 {
			ip := header.IPv6(p)
			ip.SetPayloadLength(uint16(len(tcp)))
			src, dst = ip.SourceAddress(), ip.DestinationAddress()
		} else {
			ip := header.IPv4(p)
			ip.SetTotalLength(uint16(len(p)))
			ip.SetChecksum(0)
			ip.SetChecksum(^ip.CalculateChecksum())
			src, dst = ip.SourceAddress(), ip.DestinationAddress()
		}
		tcp.SetChecksum(0)
		sum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(len(tcp)))
		tcp.SetChecksum(^checksum.Checksum(tcp, sum))
		s.f.coalesced.Add(int64(g.n - 1))
	}
	s.writeRaw(g.buf)
}

func (s *inboundSink) writeRaw(p []byte) {
	if s.writeHook != nil {
		s.writeHook(p)
		return
	}
	if !s.f.e.writeTUNPacket(p) {
		s.f.dropped.Add(1)
	}
}

// track ends a flow after a reset, or a while after both sides closed (late
// ACKs and retransmitted FINs still pass meanwhile).
func (f *fastPath) track(fl *fastFlow, flags header.TCPFlags, fin *atomic.Bool) {
	switch {
	case flags.Contains(header.TCPFlagRst):
		fl.closeAt.CompareAndSwap(0, time.Now().Add(time.Second).UnixNano())
	case flags.Contains(header.TCPFlagFin):
		fin.Store(true)
		if fl.finIn.Load() && fl.finOut.Load() {
			fl.closeAt.CompareAndSwap(0, time.Now().Add(fastCloseLinger).UnixNano())
		}
	}
}

func (f *fastPath) remove(fl *fastFlow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := fastKey{fl.app, fl.remote}
	if f.out[key] == fl {
		delete(f.out, key)
		delete(f.in, fastKey{fl.remote, netip.AddrPortFrom(fl.local, fl.app.Port())})
		f.active.Add(-1)
	}
}

func (f *fastPath) sweep() {
	tick := time.NewTicker(fastSweepEvery)
	defer tick.Stop()
	for {
		select {
		case <-f.e.ctx.Done():
			return
		case <-tick.C:
		}
		now := time.Now().UnixNano()
		var stale []*fastFlow
		f.mu.RLock()
		for _, fl := range f.out {
			if c := fl.closeAt.Load(); (c != 0 && now > c) || now-fl.last.Load() > int64(fastIdleTimeout) || !fl.path.Valid() {
				stale = append(stale, fl)
			}
		}
		f.mu.RUnlock()
		for _, fl := range stale {
			f.remove(fl)
		}
	}
}

// rewrite replaces the source (outbound) or destination (inbound) address,
// updating the IPv4 header checksum and TCP's pseudo-header checksum
// incrementally.
func rewrite(p []byte, t tcpPacket, addr netip.Addr, source bool) {
	na := tcpip.AddrFromSlice(addr.AsSlice())
	var old tcpip.Address
	if t.v6 {
		ip := header.IPv6(p)
		if source {
			old = ip.SourceAddress()
			ip.SetSourceAddress(na)
		} else {
			old = ip.DestinationAddress()
			ip.SetDestinationAddress(na)
		}
	} else {
		ip := header.IPv4(p)
		if source {
			old = ip.SourceAddress()
			ip.SetSourceAddressWithChecksumUpdate(na)
		} else {
			old = ip.DestinationAddress()
			ip.SetDestinationAddressWithChecksumUpdate(na)
		}
	}
	t.tcp.UpdateChecksumPseudoHeaderAddress(old, na, true)
}

// clampMSS lowers a SYN's MSS option to mss, so neither side sends segments
// larger than the transport carries (the TUN's MTU is much larger).
func clampMSS(tcp header.TCP, mss uint16) {
	if mss == 0 {
		return
	}
	opts := tcp[header.TCPMinimumSize:tcp.DataOffset()]
	for i := 0; i < len(opts); {
		switch opts[i] {
		case header.TCPOptionEOL:
			return
		case header.TCPOptionNOP:
			i++
			continue
		}
		if i+1 >= len(opts) || opts[i+1] < 2 || i+int(opts[i+1]) > len(opts) {
			return
		}
		if opts[i] == header.TCPOptionMSS && opts[i+1] == 4 {
			old := binary.BigEndian.Uint16(opts[i+2:])
			if old > mss {
				binary.BigEndian.PutUint16(opts[i+2:], mss)
				o, n := old, mss
				if (header.TCPMinimumSize+i+2)%2 == 1 {
					// The field straddles two checksum words: its bytes count swapped.
					o, n = bits.ReverseBytes16(o), bits.ReverseBytes16(n)
				}
				tcp.SetChecksum(^checksumReplace16(^tcp.Checksum(), o, n))
			}
			return
		}
		i += int(opts[i+1])
	}
}

// checksumReplace16 updates a one's complement sum (not inverted) for one
// 16-bit word changing from old to new (RFC 1624, eqn. 3).
func checksumReplace16(sum, old, new uint16) uint16 {
	s := uint32(sum) + uint32(^old) + uint32(new)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	return uint16(s)
}

// inject hands a packet to netstack, as readTUN does.
func (e *Engine) inject(p []byte) {
	proto := ipv4.ProtocolNumber
	if p[0]>>4 == 6 {
		proto = ipv6.ProtocolNumber
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	e.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

// writeTUNPacket writes one packet to the TUN from outside writeTUN (one
// write per packet, so concurrent writers don't interleave). A full device
// drops the packet instead of blocking the transport's reader.
func (e *Engine) writeTUNPacket(p []byte) bool {
	var werr error
	if err := e.tunRC.Write(func(fd uintptr) bool {
		_, werr = unix.Write(int(fd), p)
		return true
	}); err != nil || werr != nil {
		return false
	}
	e.c.packetsOut.Add(1)
	return true
}
