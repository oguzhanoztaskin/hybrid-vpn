package engine

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func flowOf(p Protocol, id stack.TransportEndpointID) Flow {
	return Flow{
		Protocol: p,
		Src:      netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort),
		Dst:      netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort),
	}
}

func addrOf(a tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return ip
}

// handleTCP runs on its own goroutine per SYN (gVisor's forwarder spawns it).
// The outbound connection is dialed first, so the app only sees a completed
// handshake when the destination is actually reachable, and a RST otherwise.
func (e *Engine) handleTCP(r *tcp.ForwarderRequest) {
	f := flowOf(TCP, r.ID())
	d := e.router.Decide(f, func() int { return e.ownerUID(f) })
	switch d.Action {
	case ActionDrop:
		e.c.drop(d.Reason)
		r.Complete(true) // RST: the app fails fast
		return
	case ActionDNS:
		local, ok := e.accept(r)
		if ok {
			e.goDetached(func() { e.serveDNSOverTCP(local, f) })
		}
		return
	}

	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	remote, used, err := e.router.Dial(ctx, f, d)
	cancel()
	if err != nil {
		e.c.tcpFailed.Add(1)
		e.c.drop("transport failed: " + d.Transport)
		e.c.failed(d.Transport, f.Protocol, err)
		r.Complete(true)
		return
	}
	e.c.routed(used, used != d.Transport)
	local, ok := e.accept(r)
	if !ok {
		remote.Close()
		return
	}
	e.c.tcpTotal.Add(1)
	e.goSafe(func() { e.splice(local, remote) })
}

func (e *Engine) accept(r *tcp.ForwarderRequest) (net.Conn, bool) {
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return nil, false
	}
	r.Complete(false)
	return gonet.NewTCPConn(&wq, ep), true
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// splice copies both directions with pooled buffers, propagating half-close.
// Backpressure is end to end: a slow side stops reads on the other, which
// closes netstack's receive window towards the app (or the kernel's towards
// the server).
func (e *Engine) splice(local, remote net.Conn) {
	if !e.track(local) || !e.track(remote) {
		local.Close()
		remote.Close()
		return
	}
	e.c.tcpActive.Add(1)
	defer e.c.tcpActive.Add(-1)
	defer e.untrack(local)
	defer e.untrack(remote)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n := copyHalf(remote, local)
		e.c.bytesUp.Add(n)
	}()
	n := copyHalf(local, remote)
	e.c.bytesDown.Add(n)
	wg.Wait()
}

func copyHalf(dst, src net.Conn) int64 {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	// Hide ReadFrom/WriteTo so our pooled buffer is used instead of a fresh
	// allocation per connection.
	n, _ := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *bp)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
	return n
}

// handleUDP runs synchronously in the packet path, so it only creates the
// endpoint and hands the flow to a goroutine. Returning false makes netstack
// answer ICMP port unreachable: dropped flows fail fast instead of timing out.
func (e *Engine) handleUDP(r *udp.ForwarderRequest) bool {
	f := flowOf(UDP, r.ID())
	// This runs in the packet path, so the app lookup (a host upcall) must not
	// happen here: built-in guards decide now, the policy decides in the
	// flow's goroutine when it needs the owning app.
	d, decided := e.router.Builtin(f)
	if !decided && !e.router.NeedsUID() {
		d, decided = e.router.Policy(f, UnknownUID), true
	}
	if decided && d.Action == ActionDrop {
		e.c.drop(d.Reason)
		return false // ICMP port unreachable: the app fails fast
	}
	if d.Action != ActionDNS && e.c.udpActive.Load() >= maxUDPFlows {
		e.c.drop("udp flow limit")
		return false
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return false
	}
	// gVisor's default UDP receive buffer is 32 KiB (~26 full-size datagrams);
	// match the Linux default the app's own socket path would have.
	ep.SocketOptions().SetReceiveBufferSize(udpReceiveBuffer, true)
	local := gonet.NewUDPConn(&wq, ep)
	if d.Action == ActionDNS {
		e.goDetached(func() { e.serveDNSOverUDP(local, f) })
	} else {
		e.c.udpActive.Add(1)
		e.c.udpTotal.Add(1)
		e.goSafe(func() {
			defer e.c.udpActive.Add(-1)
			if !decided {
				if d = e.router.Policy(f, e.ownerUID(f)); d.Action == ActionDrop {
					e.c.drop(d.Reason) // decided after the endpoint exists: silent drop
					local.Close()
					return
				}
			}
			e.relayUDP(ep, &wq, local, f, d)
		})
	}
	return true
}

func (e *Engine) serveDNSOverUDP(local net.Conn, f Flow) {
	if !e.track(local) {
		return
	}
	defer e.untrack(local)
	buf := make([]byte, 65535)
	for {
		local.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		n, err := local.Read(buf)
		if err != nil {
			return
		}
		if resp := e.dns(buf[:n], f); resp != nil {
			local.Write(resp)
		}
	}
}

// serveDNSOverTCP handles RFC 1035 §4.2.2 length-prefixed messages, so
// DNS-over-TCP fallbacks are filtered too.
func (e *Engine) serveDNSOverTCP(local net.Conn, f Flow) {
	if !e.track(local) {
		return
	}
	defer e.untrack(local)
	var hdr [2]byte
	for {
		local.SetDeadline(time.Now().Add(dnsIdleTimeout))
		if _, err := io.ReadFull(local, hdr[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(local, msg); err != nil {
			return
		}
		resp := e.dns(msg, f)
		if resp == nil || len(resp) > 65535 {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := local.Write(out); err != nil {
			return
		}
	}
}

func (e *Engine) dns(q []byte, f Flow) []byte {
	e.c.dnsQueries.Add(1)
	resp := e.cfg.Host.DNS(q, f)
	if resp == nil {
		e.c.dnsFailures.Add(1)
	}
	return resp
}
