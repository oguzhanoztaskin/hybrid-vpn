package engine

import (
	"bytes"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// tcp4 builds a valid IPv4 TCP packet.
func tcp4(src, dst netip.AddrPort, seq uint32, flags header.TCPFlags, opts, payload []byte) []byte {
	tcpLen := header.TCPMinimumSize + len(opts)
	p := make([]byte, header.IPv4MinimumSize+tcpLen+len(payload))
	ip := header.IPv4(p)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(p)), TTL: 64, Protocol: 6,
		SrcAddr: tcpip.AddrFrom4(src.Addr().As4()), DstAddr: tcpip.AddrFrom4(dst.Addr().As4())})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(p[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{SrcPort: src.Port(), DstPort: dst.Port(), SeqNum: seq, AckNum: 7,
		DataOffset: uint8(tcpLen), Flags: flags, WindowSize: 1000})
	copy(tcp[header.TCPMinimumSize:], opts)
	copy(tcp[tcpLen:], payload)
	sum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
	tcp.SetChecksum(^checksum.Checksum(tcp, sum))
	return p
}

func valid4(t *testing.T, p []byte) {
	t.Helper()
	ip := header.IPv4(p)
	if !ip.IsChecksumValid() {
		t.Error("IPv4 checksum invalid")
	}
	tcp := header.TCP(p[ip.HeaderLength():])
	if !tcp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(), checksum.Checksum(tcp.Payload(), 0), uint16(len(tcp.Payload()))) {
		t.Error("TCP checksum invalid")
	}
}

var (
	app    = netip.MustParseAddrPort("10.215.173.1:40000")
	remote = netip.MustParseAddrPort("10.9.0.1:443")
	vpn    = netip.MustParseAddr("10.8.0.2")
)

func TestRewriteKeepsChecksumsValid(t *testing.T) {
	p := tcp4(app, remote, 1, header.TCPFlagAck, nil, []byte("hello"))
	pt, ok := parseTCP(p)
	if !ok {
		t.Fatal("parse")
	}
	rewrite(p, pt, vpn, true)
	if got := header.IPv4(p).SourceAddress(); got != tcpip.AddrFrom4(vpn.As4()) {
		t.Errorf("source %v", got)
	}
	valid4(t, p)
}

func TestClampMSS(t *testing.T) {
	mss := []byte{header.TCPOptionNOP, header.TCPOptionMSS, 4, 0x3f, 0xd8} // 16344, after a NOP
	opts := append(mss, header.TCPOptionNOP, header.TCPOptionNOP, header.TCPOptionNOP)
	p := tcp4(app, remote, 1, header.TCPFlagSyn, opts, nil)
	pt, _ := parseTCP(p)
	clampMSS(pt.tcp, 1460)
	if got := uint16(pt.tcp[23])<<8 | uint16(pt.tcp[24]); got != 1460 {
		t.Errorf("MSS %d, want 1460", got)
	}
	valid4(t, p)
	// MSS first (the usual layout, aligned) as well.
	q := tcp4(app, remote, 1, header.TCPFlagSyn, []byte{header.TCPOptionMSS, 4, 0x3f, 0xd8}, nil)
	qt, _ := parseTCP(q)
	clampMSS(qt.tcp, 1360)
	if got := uint16(qt.tcp[22])<<8 | uint16(qt.tcp[23]); got != 1360 {
		t.Errorf("aligned MSS %d, want 1360", got)
	}
	valid4(t, q)
	clampMSS(pt.tcp, 9000) // never raised
	if got := uint16(pt.tcp[23])<<8 | uint16(pt.tcp[24]); got != 1460 {
		t.Errorf("MSS raised to %d", got)
	}
}

// sinkUnderTest is an inboundSink whose TUN writes are captured.
func sinkUnderTest(t *testing.T) (*inboundSink, *fastFlow, *[][]byte) {
	var written [][]byte
	e := &Engine{cfg: Config{MTU: 16384}}
	f := &fastPath{e: e, out: map[fastKey]*fastFlow{}, in: map[fastKey]*fastFlow{}}
	fl := &fastFlow{app: app, remote: remote, local: vpn}
	f.out[fastKey{app, remote}] = fl
	f.in[fastKey{remote, netip.AddrPortFrom(vpn, app.Port())}] = fl
	s := &inboundSink{f: f}
	s.writeHook = func(p []byte) { written = append(written, append([]byte(nil), p...)) }
	return s, fl, &written
}

func TestCoalescesContiguousSegments(t *testing.T) {
	s, _, written := sinkUnderTest(t)
	to := netip.AddrPortFrom(vpn, app.Port())
	ts := []byte{header.TCPOptionNOP, header.TCPOptionNOP, header.TCPOptionTS, 10, 0, 0, 0, 1, 0, 0, 0, 2}
	var want []byte
	seq := uint32(1000)
	for i := 0; i < 5; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 1400)
		flags := header.TCPFlagAck
		if i == 4 {
			flags |= header.TCPFlagPsh
		}
		if !s.Packet(tcp4(remote, to, seq, flags, ts, payload)) {
			t.Fatal("packet of a fast flow not taken")
		}
		seq += uint32(len(payload))
		want = append(want, payload...)
	}
	s.Flush()
	if len(*written) != 1 {
		t.Fatalf("wrote %d packets, want 1", len(*written))
	}
	p := (*written)[0]
	valid4(t, p)
	ip := header.IPv4(p)
	tcp := header.TCP(p[ip.HeaderLength():])
	if ip.DestinationAddress() != tcpip.AddrFrom4(app.Addr().As4()) || tcp.SequenceNumber() != 1000 ||
		!bytes.Equal(tcp.Payload(), want) || !tcp.Flags().Contains(header.TCPFlagPsh) {
		t.Errorf("merged packet: dst %v seq %d len %d flags %v", ip.DestinationAddress(), tcp.SequenceNumber(), len(tcp.Payload()), tcp.Flags())
	}
	if s.f.coalesced.Load() != 4 {
		t.Errorf("coalesced %d, want 4", s.f.coalesced.Load())
	}
}

func TestDoesNotCoalesceAcrossGapsOrFlags(t *testing.T) {
	s, _, written := sinkUnderTest(t)
	to := netip.AddrPortFrom(vpn, app.Port())
	data := bytes.Repeat([]byte{1}, 100)
	s.Packet(tcp4(remote, to, 1000, header.TCPFlagAck, nil, data))
	s.Packet(tcp4(remote, to, 1200, header.TCPFlagAck, nil, data)) // gap
	s.Packet(tcp4(remote, to, 1300, header.TCPFlagAck|header.TCPFlagFin, nil, data))
	s.Packet(tcp4(remote, to, 1401, header.TCPFlagAck, nil, nil)) // pure ACK
	s.Flush()
	if len(*written) != 4 {
		t.Fatalf("wrote %d packets, want 4 (none merged)", len(*written))
	}
	for i, p := range *written {
		valid4(t, p)
		if seq := header.TCP(p[20:]).SequenceNumber(); seq != []uint32{1000, 1200, 1300, 1401}[i] {
			t.Errorf("packet %d out of order: seq %d", i, seq)
		}
	}
}

func TestUnknownFlowsAreLeftToTheTransport(t *testing.T) {
	s, _, written := sinkUnderTest(t)
	other := netip.MustParseAddrPort("10.9.0.1:80")
	if s.Packet(tcp4(other, netip.AddrPortFrom(vpn, 20000), 1, header.TCPFlagAck, nil, []byte("x"))) {
		t.Error("took a packet of a flow it doesn't own")
	}
	s.Flush()
	if len(*written) != 0 {
		t.Error("wrote a packet it doesn't own")
	}
}
