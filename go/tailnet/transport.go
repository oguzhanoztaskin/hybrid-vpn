package tailnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"hybridvpn/netcore/engine"
	"tailscale.com/tailcfg"
)

// TransportPrefix prefixes tailnet transport ids in routing decisions.
const TransportPrefix = "tailnet:"

// Transport adapts an Instance to the engine's routing boundary. Its name
// carries the tailnet identity ("tailnet:work"), so a routing decision can only
// ever reach the instance it names, and Dial keeps the membership check: a
// destination outside this tailnet fails closed.
func (i *Instance) Transport() engine.Transport { return transport{i} }

type transport struct{ inst *Instance }

func (t transport) Name() string { return TransportPrefix + t.inst.cfg.ID }
func (t transport) Kind() string { return "tailnet" }
func (t transport) Capabilities() engine.Capabilities {
	return engine.Capabilities{TCP: true, UDP: true}
}

func (t transport) Dial(ctx context.Context, f engine.Flow) (net.Conn, error) {
	return t.inst.Dial(ctx, f.Protocol.String(), f.Dst.String())
}

func (t transport) Ping(ctx context.Context, dst netip.Addr) error {
	owned, err := t.inst.Owns(ctx, dst)
	if err != nil {
		return err
	}
	if !owned {
		return ErrNotInTailnet
	}
	lc, err := t.inst.srv.LocalClient()
	if err != nil {
		return err
	}
	// Explicitly ICMP, not disco/TSMP: only a remote echo reply succeeds.
	res, err := lc.Ping(ctx, dst, tailcfg.PingICMP)
	if err != nil {
		return err
	}
	if res.Err != "" {
		return fmt.Errorf("tailnet icmp: %s", res.Err)
	}
	return nil
}
