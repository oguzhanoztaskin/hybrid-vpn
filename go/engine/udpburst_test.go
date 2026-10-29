package engine

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// udpSink counts datagrams received on a loopback socket.
func udpSink(t *testing.T) (addr string, count *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc.(*net.UDPConn).SetReadBuffer(8 << 20)
	t.Cleanup(func() { pc.Close() })
	count = new(atomic.Int64)
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			count.Add(1)
		}
	}()
	return pc.LocalAddr().String(), count
}

// TestUDPMicroBurstsNoLoss: bursts of 64 back-to-back datagrams (more than
// netstack's default 32 KiB buffer holds) separated by short gaps, i.e. a
// burst pattern the path can carry on average. Nothing may be lost.
func TestUDPMicroBurstsNoLoss(t *testing.T) {
	const bursts, per, size = 60, 64, 1200
	h := newHarness(t)
	sink, got := udpSink(t)
	h.direct.route("198.51.100.9:9999", sink)
	c := h.app.dialUDP(t, "198.51.100.9:9999")
	defer c.Close()
	payload := make([]byte, size)
	for b := 0; b < bursts; b++ {
		for i := 0; i < per; i++ {
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	const n = bursts * per
	waitForOrTimeout(func() bool { return got.Load() == n }, 10*time.Second)
	st := h.eng.Stats()
	t.Logf("sent %d; relayed %d; netstack buffer drops %d; sink %d", n, st.UDPDatagramsUp, st.UDPReceiveBufferDrops, got.Load())
	if got.Load() != n || st.UDPReceiveBufferDrops != 0 {
		t.Errorf("lost %d of %d datagrams (%d at the netstack buffer)", n-int(got.Load()), n, st.UDPReceiveBufferDrops)
	}
}

// TestUDPOverloadIsAccounted: an unpaced burst faster than the relay can
// send. Loss is expected above capacity (a TUN gives the sender no
// back-pressure), but every datagram the engine read must be either relayed
// or counted as dropped: no silent loss.
func TestUDPOverloadIsAccounted(t *testing.T) {
	const n, size = 5000, 1200
	h := newHarness(t)
	sink, got := udpSink(t)
	h.direct.route("198.51.100.9:9999", sink)
	c := h.app.dialUDP(t, "198.51.100.9:9999")
	defer c.Close()
	payload := make([]byte, size)
	for i := 0; i < n; i++ {
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	var st Stats
	waitForOrTimeout(func() bool {
		st = h.eng.Stats()
		return st.UDPDatagramsUp+int64(st.UDPReceiveBufferDrops)+st.Dropped["udp send error"] == st.PacketsIn
	}, 10*time.Second)
	t.Logf("app sent %d; engine read %d; relayed %d; buffer drops %d; send errors %d; sink %d",
		n, st.PacketsIn, st.UDPDatagramsUp, st.UDPReceiveBufferDrops, st.Dropped["udp send error"], got.Load())
	if acc := st.UDPDatagramsUp + int64(st.UDPReceiveBufferDrops) + st.Dropped["udp send error"]; acc != st.PacketsIn {
		t.Errorf("unaccounted datagrams: read %d, relayed+dropped %d", st.PacketsIn, acc)
	}
	waitForOrTimeout(func() bool { return got.Load() == st.UDPDatagramsUp }, 5*time.Second)
	if got.Load() != st.UDPDatagramsUp {
		t.Errorf("relayed %d but sink received %d", st.UDPDatagramsUp, got.Load())
	}
}

func waitForOrTimeout(cond func() bool, d time.Duration) {
	deadline := time.Now().Add(d)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}
