package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// PingStack sends a real echo through a transport's own netstack. The caller
// checks route membership and supplies that transport's local source address.
func PingStack(ctx context.Context, s *stack.Stack, local, dst netip.Addr) error {
	np, tp := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber), tcpip.TransportProtocolNumber(icmp.ProtocolNumber4)
	if dst.Is6() {
		np, tp = ipv6.ProtocolNumber, icmp.ProtocolNumber6
	}
	var wq waiter.Queue
	ep, terr := s.NewEndpoint(tp, np, &wq)
	if terr != nil {
		return fmt.Errorf("icmp endpoint: %s", terr)
	}
	defer ep.Close()
	if terr := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(local.AsSlice())}); terr != nil {
		return fmt.Errorf("icmp bind: %s", terr)
	}
	if terr := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.AsSlice())}); terr != nil {
		return fmt.Errorf("icmp connect: %s", terr)
	}
	// gonet's datagram adapter supports ICMP endpoints as well as UDP.
	c := gonet.NewUDPConn(&wq, ep)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	dl := time.Now().Add(pingTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(dl) {
		dl = deadline
	}
	c.SetDeadline(dl)
	p, err := newPing(dst.Is6())
	if err != nil {
		return err
	}
	if _, err := c.Write(p); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	want := byte(0)
	if dst.Is6() {
		want = 129
	}
	for {
		n, err := c.Read(buf)
		if err != nil {
			return err
		}
		if n == len(p) && buf[0] == want && buf[1] == 0 && bytes.Equal(buf[6:n], p[6:]) {
			return nil
		}
	}
}
