// Command hvbench measures what traffic experiences through the VPN.
//
//	hvbench server [-listen :5201]                 # on the host
//	hvbench <mode> -server HOST:5201 [flags]       # on the device (adb shell), as a static linux binary
//
// Modes: tcp-down, tcp-up, connect, udp, dns. Each run prints one JSON line
// with raw results so runs can be compared and archived (docs/benchmarks).
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hvbench server|tcp-down|tcp-up|connect|udp|dns [flags]")
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	listen := fs.String("listen", ":5201", "server: listen address (TCP and UDP)")
	server := fs.String("server", "10.0.2.2:5201", "client: server address")
	bytesN := fs.Int64("bytes", 64<<20, "tcp-down/tcp-up: bytes to transfer")
	count := fs.Int("n", 200, "connect/dns: iterations; udp: datagrams")
	size := fs.Int("size", 1200, "udp: datagram size")
	rate := fs.Float64("rate", 0, "udp: pace to this many Mbit/s (0 = unpaced burst)")
	dnsName := fs.String("name", "example.com", "dns: name to query")
	uncached := fs.Bool("uncached", false, "dns: random subdomain per query (forces an upstream lookup)")
	label := fs.String("label", "", "free-form label copied into the result")
	fs.Parse(os.Args[2:])

	var res map[string]any
	switch mode {
	case "server":
		serve(*listen)
		return
	case "tcp-down":
		res = tcpTransfer(*server, 'D', *bytesN)
	case "tcp-up":
		res = tcpTransfer(*server, 'U', *bytesN)
	case "connect":
		res = connectLatency(*server, *count)
	case "rtt":
		res = rttOnOneConn(*server, *count)
	case "fetch":
		res = fetch(*server)
	case "udpping":
		res = udpPing(*server)
	case "udp":
		res = udpBlast(*server, *count, *size, *rate)
	case "dns":
		res = dnsLatency(*server, *dnsName, *count, *uncached)
	default:
		log.Fatalf("unknown mode %q", mode)
	}
	res["mode"] = mode
	res["label"] = *label
	res["time"] = time.Now().UTC().Format(time.RFC3339)
	json.NewEncoder(os.Stdout).Encode(res)
}

// --- server -----------------------------------------------------------------

func serve(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	go serveUDP(pc)
	log.Printf("hvbench server on %s (tcp+udp)", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serveTCP(c)
	}
}

// TCP protocol: 1 command byte, then 'D'/'U' carry an 8-byte length.
// 'D': server sends N bytes. 'U': server reads N bytes, replies 8-byte count.
// 'P': ping, server echoes one byte (used by connect).
func serveTCP(c net.Conn) {
	defer c.Close()
	var cmd [1]byte
	if _, err := io.ReadFull(c, cmd[:]); err != nil {
		return
	}
	switch cmd[0] {
	case 'P':
		c.Write(cmd[:])
	case 'E':
		io.Copy(c, c)
	case 'D', 'U':
		var n [8]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		total := int64(binary.BigEndian.Uint64(n[:]))
		if cmd[0] == 'D' {
			io.CopyN(c, zeros{}, total)
			return
		}
		got, _ := io.CopyN(io.Discard, c, total)
		binary.BigEndian.PutUint64(n[:], uint64(got))
		c.Write(n[:])
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// UDP protocol: data datagrams start with 'd' + 8-byte run id; the server
// counts them per run. 'q' + run id asks for the count. Anything else is echoed.
func serveUDP(pc net.PacketConn) {
	var mu sync.Mutex
	counts := map[uint64]int64{}
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n >= 9 && (buf[0] == 'd' || buf[0] == 'q') {
			id := binary.BigEndian.Uint64(buf[1:9])
			mu.Lock()
			if buf[0] == 'd' {
				counts[id]++
				mu.Unlock()
				continue
			}
			var out [8]byte
			binary.BigEndian.PutUint64(out[:], uint64(counts[id]))
			mu.Unlock()
			pc.WriteTo(out[:], from)
			continue
		}
		pc.WriteTo(buf[:n], from)
	}
}

// --- clients ----------------------------------------------------------------

func tcpTransfer(server string, cmd byte, total int64) map[string]any {
	start := time.Now()
	c, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return failed(err)
	}
	defer c.Close()
	var hdr [9]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint64(hdr[1:], uint64(total))
	if _, err := c.Write(hdr[:]); err != nil {
		return failed(err)
	}
	var moved int64
	if cmd == 'D' {
		moved, err = io.CopyN(io.Discard, c, total)
	} else {
		moved, err = io.CopyN(c, zeros{}, total)
		if err == nil {
			var ack [8]byte
			_, err = io.ReadFull(c, ack[:])
			moved = int64(binary.BigEndian.Uint64(ack[:]))
		}
	}
	secs := time.Since(start).Seconds()
	res := map[string]any{"bytes": moved, "seconds": secs, "mbit_per_s": float64(moved) * 8 / secs / 1e6}
	if err != nil {
		res["error"] = err.Error()
	}
	return res
}

func connectLatency(server string, n int) map[string]any {
	var lat, handshake []float64
	fails := 0
	for i := 0; i < n; i++ {
		start := time.Now()
		c, err := net.DialTimeout("tcp", server, 5*time.Second)
		if err != nil {
			fails++
			continue
		}
		handshake = append(handshake, ms(time.Since(start)))
		// Handshake plus one round trip to the server, so a proxy that accepts
		// locally before reaching the server can't look artificially fast.
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Write([]byte{'P'})
		if err == nil {
			_, err = io.ReadFull(c, make([]byte, 1))
		}
		c.Close()
		if err != nil {
			fails++
			continue
		}
		lat = append(lat, ms(time.Since(start)))
	}
	hs := summary(handshake, map[string]any{})
	return summary(lat, map[string]any{"attempts": n, "failures": fails, "handshake_p50_ms": hs["p50_ms"], "handshake_p99_ms": hs["p99_ms"]})
}

// fetch connects and returns whatever the server sends before closing.
func fetch(server string) map[string]any {
	start := time.Now()
	c, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return failed(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(c)
	res := map[string]any{"body": string(b), "ms": ms(time.Since(start))}
	if err != nil {
		res["error"] = err.Error()
	}
	return res
}

// udpPing sends one datagram and returns the reply.
func udpPing(server string) map[string]any {
	start := time.Now()
	c, err := net.Dial("udp", server)
	if err != nil {
		return failed(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return failed(err)
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		return failed(err)
	}
	return map[string]any{"body": string(buf[:n]), "ms": ms(time.Since(start))}
}

// rttOnOneConn measures 1-byte round trips on one established connection.
func rttOnOneConn(server string, n int) map[string]any {
	c, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return failed(err)
	}
	defer c.Close()
	c.Write([]byte{'E'})
	var lat []float64
	b := []byte{'x'}
	for i := 0; i < n; i++ {
		start := time.Now()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(b); err != nil {
			return failed(err)
		}
		if _, err := io.ReadFull(c, b); err != nil {
			return failed(err)
		}
		lat = append(lat, ms(time.Since(start)))
	}
	first := lat[0]
	res := summary(lat, map[string]any{"attempts": n})
	res["first_ms"] = first
	return res
}

func udpBlast(server string, n, size int, rateMbit float64) map[string]any {
	c, err := net.Dial("udp", server)
	if err != nil {
		return failed(err)
	}
	defer c.Close()
	id := rand.Uint64()
	pkt := make([]byte, size)
	pkt[0] = 'd'
	binary.BigEndian.PutUint64(pkt[1:9], id)
	start := time.Now()
	sendErrs := 0
	for i := 0; i < n; i++ {
		if _, err := c.Write(pkt); err != nil {
			sendErrs++
		}
		if rateMbit > 0 {
			// Pace in 16-datagram micro-bursts against a running schedule.
			if i%16 == 15 {
				due := start.Add(time.Duration(float64(i+1) * float64(size) * 8 / (rateMbit * 1e6) * float64(time.Second)))
				if d := time.Until(due); d > 0 {
					time.Sleep(d)
				}
			}
		} else if i%64 == 63 {
			time.Sleep(time.Millisecond) // unpaced burst: just yield occasionally
		}
	}
	sendSecs := time.Since(start).Seconds()
	time.Sleep(time.Second) // let stragglers arrive
	q := make([]byte, 9)
	q[0] = 'q'
	binary.BigEndian.PutUint64(q[1:], id)
	var received int64 = -1
	for try := 0; try < 3 && received < 0; try++ {
		c.Write(q)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var out [8]byte
		if _, err := c.Read(out[:]); err == nil {
			received = int64(binary.BigEndian.Uint64(out[:]))
		}
	}
	return map[string]any{
		"sent": n, "send_errors": sendErrs, "rate_mbit": rateMbit, "received": received, "size": size, "send_seconds": sendSecs,
		"loss_pct":           100 * (1 - float64(received)/float64(n)),
		"offered_mbit_per_s": float64(n*size) * 8 / sendSecs / 1e6,
		"goodput_mbit_per_s": float64(received*int64(size)) * 8 / sendSecs / 1e6,
	}
}

func dnsLatency(server, name string, n int, uncached bool) map[string]any {
	var lat []float64
	fails := 0
	var seq atomic.Uint32
	for i := 0; i < n; i++ {
		qname := name
		if uncached {
			qname = fmt.Sprintf("hvb%d-%d.%s", time.Now().UnixNano(), seq.Add(1), name)
		}
		start := time.Now()
		ok := dnsOnce(server, qname)
		if !ok {
			fails++
			continue
		}
		lat = append(lat, ms(time.Since(start)))
	}
	return summary(lat, map[string]any{"attempts": n, "failures": fails, "uncached": uncached, "name": name})
}

func dnsOnce(server, name string) bool {
	c, err := net.Dial("udp", server)
	if err != nil {
		return false
	}
	defer c.Close()
	id := uint16(rand.Uint32())
	q := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range splitLabels(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	return err == nil && n >= 12 && binary.BigEndian.Uint16(buf) == id
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func summary(lat []float64, extra map[string]any) map[string]any {
	sort.Float64s(lat)
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(p*float64(len(lat)-1))]
	}
	var sum float64
	for _, v := range lat {
		sum += v
	}
	extra["ok"] = len(lat)
	if len(lat) > 0 {
		extra["mean_ms"] = sum / float64(len(lat))
		extra["p50_ms"] = pct(0.50)
		extra["p90_ms"] = pct(0.90)
		extra["p99_ms"] = pct(0.99)
		extra["max_ms"] = lat[len(lat)-1]
	}
	return extra
}

func failed(err error) map[string]any { return map[string]any{"error": err.Error()} }
