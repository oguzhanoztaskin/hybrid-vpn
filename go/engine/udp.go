package engine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// udpBatch bounds how many datagrams one wake-up drains and sends.
const udpBatch = 64

// relayUDP forwards one UDP association until it has been idle for
// udpIdleTimeout. The first datagram is already queued on ep.
//
// App → remote is the direction apps burst into (TUN gives them no
// back-pressure), so it is built to drain faster than netstack fills it: on
// each wake-up it empties the endpoint without per-datagram goroutine
// hand-offs and sends the whole batch with one sendmmsg. A slow remote socket
// blocks only this flow. Remote → app is paced by the network and stays a
// simple read/write loop.
func (e *Engine) relayUDP(ep tcpip.Endpoint, wq *waiter.Queue, local net.Conn, f Flow, d Decision) {
	if !e.track(local) {
		return
	}
	defer e.untrack(local)
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	remote, used, err := e.router.Dial(ctx, f, d)
	cancel()
	if err != nil {
		e.c.udpFailed.Add(1)
		e.c.drop("transport failed: " + d.Transport)
		e.c.failed(d.Transport, f.Protocol, err)
		return
	}
	e.c.routed(used, used != d.Transport)
	if !e.track(remote) {
		return
	}
	defer e.untrack(remote)

	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var once sync.Once
	stop := func() { once.Do(func() { local.Close(); remote.Close() }) }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.udpUp(ep, wq, remote, &last, stop)
	}()
	e.udpDown(local, remote, &last, stop)
	wg.Wait()
}

func (e *Engine) udpUp(ep tcpip.Endpoint, wq *waiter.Queue, remote net.Conn, last *atomic.Int64, stop func()) {
	defer stop()
	entry, notify := waiter.NewChannelEntry(waiter.EventIn | waiter.EventHUp | waiter.EventErr)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)

	out := newBatchSender(remote)
	bufs := make([]bytes.Buffer, udpBatch)
	idle := time.NewTimer(udpIdleTimeout)
	defer idle.Stop()
	for {
		n := 0
		for n < udpBatch {
			bufs[n].Reset()
			if _, terr := ep.Read(&bufs[n], tcpip.ReadOptions{}); terr != nil {
				if _, empty := terr.(*tcpip.ErrWouldBlock); empty {
					break
				}
				return // endpoint closed
			}
			n++
		}
		if n > 0 {
			last.Store(time.Now().UnixNano())
			sent, bytesSent, failed := out.send(bufs[:n])
			e.c.udpDatagramsUp.Add(int64(sent))
			e.c.bytesUp.Add(bytesSent)
			if failed > 0 {
				e.c.dropN("udp send error", failed)
			}
			continue // drain again before sleeping
		}
		select {
		case <-notify:
		case <-idle.C:
			if rest := udpIdleTimeout - time.Since(time.Unix(0, last.Load())); rest > 0 {
				idle.Reset(rest) // the other direction was active
				continue
			}
			return
		}
	}
}

func (e *Engine) udpDown(local, remote net.Conn, last *atomic.Int64, stop func()) {
	defer stop()
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		remote.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := remote.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) && time.Since(time.Unix(0, last.Load())) < udpIdleTimeout {
				continue // the other direction was active
			}
			return
		}
		last.Store(time.Now().UnixNano())
		if _, err := local.Write(buf[:n]); err != nil {
			e.c.drop("udp write error")
			continue
		}
		e.c.bytesDown.Add(int64(n))
		e.c.udpDatagramsDown.Add(1)
	}
}

// batchSender sends datagrams with sendmmsg on kernel UDP sockets (one
// syscall per batch on Linux/Android) and falls back to one Write per
// datagram for other transports' connections.
type batchSender struct {
	conn  net.Conn
	batch interface {
		WriteBatch([]ipv4.Message, int) (int, error)
	}
	msgs []ipv4.Message
}

func newBatchSender(c net.Conn) *batchSender {
	b := &batchSender{conn: c, msgs: make([]ipv4.Message, udpBatch)}
	if uc, ok := c.(*net.UDPConn); ok {
		if ra, ok := uc.RemoteAddr().(*net.UDPAddr); ok && ra.IP.To4() == nil {
			b.batch = ipv6.NewPacketConn(uc)
		} else {
			b.batch = ipv4.NewPacketConn(uc)
		}
	}
	for i := range b.msgs {
		b.msgs[i].Buffers = make([][]byte, 1)
	}
	return b
}

// send transmits every datagram, blocking (this flow only) while the socket
// buffer is full. A datagram the kernel rejects (e.g. ECONNREFUSED after an
// ICMP unreachable) is counted as failed and skipped.
func (b *batchSender) send(bufs []bytes.Buffer) (sent int, n int64, failed int) {
	if b.batch == nil {
		for i := range bufs {
			if _, err := b.conn.Write(bufs[i].Bytes()); err != nil {
				failed++
				continue
			}
			sent++
			n += int64(bufs[i].Len())
		}
		return
	}
	for i := range bufs {
		b.msgs[i].Buffers[0] = bufs[i].Bytes()
	}
	for i := 0; i < len(bufs); {
		k, err := b.batch.WriteBatch(b.msgs[i:len(bufs)], 0)
		for j := i; j < i+k; j++ {
			n += int64(bufs[j].Len())
		}
		sent += k
		i += k
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				failed += len(bufs) - i
				return
			}
			failed++ // skip the datagram the kernel rejected
			i++
		}
	}
	return
}
