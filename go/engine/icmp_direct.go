package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Ping uses an unprivileged datagram ICMP socket, protected before connect.
// The kernel may rewrite the echo ID; sequence and random data must match.
func (d *Direct) Ping(ctx context.Context, dst netip.Addr) error {
	family, proto := unix.AF_INET, unix.IPPROTO_ICMP
	var addr unix.Sockaddr
	if dst.Is6() {
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
		addr = &unix.SockaddrInet6{Addr: dst.As16()}
	} else {
		addr = &unix.SockaddrInet4{Addr: dst.As4()}
	}
	return d.pingSocket(ctx, dst, family, proto, addr)
}

func (d *Direct) pingSocket(ctx context.Context, dst netip.Addr, family, proto int, addr unix.Sockaddr) error {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, proto)
	if err != nil {
		return err
	}
	unix.CloseOnExec(fd)
	if !d.protect(fd) {
		unix.Close(fd)
		return ErrProtectFailed
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return err
	}
	f := os.NewFile(uintptr(fd), "icmp-ping")
	defer f.Close()
	deadline := time.Now().Add(pingTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := f.SetDeadline(deadline); err != nil {
		return err
	}
	if err := unix.Connect(fd, addr); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	p, err := newPing(dst.Is6())
	if err != nil {
		return err
	}
	if _, err := f.Write(p); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	wantType := byte(0)
	if dst.Is6() {
		wantType = 129
	}
	for {
		n, err := f.Read(buf)
		if err != nil {
			return fmt.Errorf("icmp %s: %w", dst, err)
		}
		reply := buf[:n]
		// Darwin includes the IPv4 header on datagram ICMP sockets.
		if !dst.Is6() && len(reply) >= 20 && reply[0]>>4 == 4 {
			off := int(reply[0]&15) * 4
			if off < 20 || off > len(reply) || netip.AddrFrom4([4]byte(reply[12:16])) != dst {
				continue
			}
			reply = reply[off:]
		}
		if len(reply) == len(p) && reply[0] == wantType && reply[1] == 0 && bytes.Equal(reply[6:], p[6:]) {
			return nil
		}
	}
}
