package engine

import (
	"io"
	"net"
	"testing"
	"time"
)

// A one-byte request/response must not be delayed by a timer (Nagle,
// delayed ACK, or anything in the splice path).
func TestSmallExchangeLatency(t *testing.T) {
	h := newHarness(t)
	srv := listenTCP(t, func(c net.Conn) {
		b := make([]byte, 1)
		for {
			if _, err := io.ReadFull(c, b); err != nil {
				c.Close()
				return
			}
			c.Write(b)
		}
	})
	h.direct.route("203.0.113.10:7", srv)
	for i := 0; i < 5; i++ {
		c, err := h.app.dialTCP(t, "203.0.113.10:7")
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		c.Write([]byte{'P'})
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		rtt := time.Since(start)
		c.Close()
		t.Logf("round trip %d: %v", i, rtt)
		if rtt > 50*time.Millisecond {
			t.Errorf("round trip %d took %v", i, rtt)
		}
	}
}
