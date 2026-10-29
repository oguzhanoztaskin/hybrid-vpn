package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// PingTransport probes through exactly one transport. Success must mean an
// ICMP echo reply from dst, never a local reply or a Tailscale disco/TSMP pong.
// The engine proxies reachability, retaining the app's ID, sequence and data;
// it does not forward arbitrary ICMP messages or promise end-to-end payload/TTL.
type PingTransport interface {
	Transport
	Ping(ctx context.Context, dst netip.Addr) error
}

const pingTimeout = 3 * time.Second

func (r *Router) Ping(ctx context.Context, f Flow, d Decision) (string, error) {
	if d.Action != ActionForward {
		return "", errNotForwarded
	}
	one := func(id string) error {
		t, ok := r.transports[id].(PingTransport)
		if !ok {
			return fmt.Errorf("%s: %w", id, ErrUnsupportedProtocol)
		}
		return t.Ping(ctx, f.Dst.Addr())
	}
	err := one(d.Transport)
	if err == nil {
		return d.Transport, nil
	}
	if d.OnFailure == "" || d.OnFailure == Block || d.OnFailure == d.Transport {
		return "", err
	}
	if ferr := one(d.OnFailure); ferr != nil {
		return "", fmt.Errorf("%v; fallback %s: %w", err, d.OnFailure, ferr)
	}
	return d.OnFailure, nil
}

type echoRequest struct {
	flow Flow
	data []byte // ICMP header and payload
}

func icmpSum(src, dst netip.Addr, data []byte) uint16 {
	var sum uint16
	if src.Is6() {
		sum = header.PseudoHeaderChecksum(58, tcpip.AddrFromSlice(src.AsSlice()), tcpip.AddrFromSlice(dst.AsSlice()), uint16(len(data)))
	}
	return checksum.Checksum(data, sum)
}

// Only complete, checksummed echo requests are accepted. Fragmented IPv4,
// IPv6 extension headers and every other ICMP type remain unsupported.
func parseEcho(p []byte) (echoRequest, bool) {
	var r echoRequest
	var src, dst netip.Addr
	var off int
	var typ byte
	if len(p) < 1 {
		return r, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 || p[9] != 1 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return r, false
		}
		off = int(p[0]&15) * 4
		if off < 20 || off > len(p) || checksum.Checksum(p[:off], 0) != 0xffff {
			return r, false
		}
		src, dst = netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
		r.flow.Protocol, typ = ICMP, 8
	case 6:
		if len(p) < 40 || p[6] != 58 || int(binary.BigEndian.Uint16(p[4:6]))+40 != len(p) {
			return r, false
		}
		src, dst = netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40]))
		r.flow.Protocol, off, typ = ICMPv6, 40, 128
	default:
		return r, false
	}
	if len(p)-off < 8 || p[off] != typ || p[off+1] != 0 || src.IsUnspecified() || src.IsMulticast() || icmpSum(src, dst, p[off:]) != 0xffff {
		return r, false
	}
	r.flow.Src, r.flow.Dst = netip.AddrPortFrom(src, 0), netip.AddrPortFrom(dst, 0)
	r.data = p[off:]
	return r, true
}

func (r echoRequest) reply() []byte {
	src, dst := r.flow.Dst.Addr(), r.flow.Src.Addr()
	off := 20
	if src.Is6() {
		off = 40
	}
	p := make([]byte, off+len(r.data))
	copy(p[off:], r.data)
	p[off], p[off+2], p[off+3] = 0, 0, 0
	if src.Is6() {
		p[0], p[6], p[7], p[off] = 0x60, 58, 64, 129
		binary.BigEndian.PutUint16(p[4:6], uint16(len(r.data)))
		copy(p[8:24], src.AsSlice())
		copy(p[24:40], dst.AsSlice())
	} else {
		p[0], p[8], p[9] = 0x45, 64, 1
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		copy(p[12:16], src.AsSlice())
		copy(p[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(p[10:12], ^checksum.Checksum(p[:20], 0))
	}
	binary.BigEndian.PutUint16(p[off+2:off+4], ^icmpSum(src, dst, p[off:]))
	return p
}

func (e *Engine) handleEcho(p []byte) {
	r, ok := parseEcho(p)
	if !ok {
		e.c.drop("unsupported or malformed icmp")
		return
	}
	// Android's connection-owner API supports TCP/UDP only. ICMP has unknown
	// ownership, so app rules match only explicit @unknown, never another UID.
	d := e.router.Decide(r.flow, nil)
	if d.Action != ActionForward {
		e.c.drop(d.Reason)
		return
	}
	select {
	case e.pingSlots <- struct{}{}:
	default:
		e.c.drop("icmp capacity")
		return
	}
	r.data = append([]byte(nil), r.data...)
	e.goSafe(func() {
		defer func() { <-e.pingSlots }()
		ctx, cancel := context.WithTimeout(e.ctx, pingTimeout)
		defer cancel()
		used, err := e.router.Ping(ctx, r.flow, d)
		if err != nil {
			e.c.failed(d.Transport, r.flow.Protocol, err)
			e.c.drop("icmp probe failed")
			return
		}
		if e.ctx.Err() != nil {
			return
		}
		e.c.routed(used, used != d.Transport)
		e.writeTUNPacket(r.reply())
	})
}

// newPing makes a small unpredictable probe, independent of the app's data.
func newPing(v6 bool) ([]byte, error) {
	p := make([]byte, 24)
	if _, err := rand.Read(p[4:]); err != nil {
		return nil, err
	}
	p[0] = 8
	if v6 {
		p[0] = 128 // checksum supplied by the kernel/netstack
	} else {
		binary.BigEndian.PutUint16(p[2:4], ^checksum.Checksum(p, 0))
	}
	return p, nil
}
