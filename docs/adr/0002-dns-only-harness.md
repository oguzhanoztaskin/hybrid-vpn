# ADR 0002: M0 harness captures DNS only

Status: accepted

## Context

Forwarding arbitrary TCP from a TUN requires a userspace TCP/IP stack. Choosing that stack is tied
to the data-plane language decision (ADR 0003), which needs benchmarks first. Meanwhile we want to
validate the Android-side unknowns and ship something useful.

## Decision

The TUN routes only two virtual resolver addresses and is set as the system DNS. DNS is parsed,
filtered and answered in the app. All other traffic never touches the tunnel.

## Consequences

- No TCP stack is needed. Throughput, battery and latency are unaffected for non-DNS traffic.
- This validates lifecycle, revoke, always-on, `protect()`, network binding, owner-UID attribution,
  network switching and DNS interception (spec §14).
- DNS-over-TCP is refused with a RST. Answers larger than the MTU are truncated, and clients that
  then retry over TCP fail. In practice resolvers cap UDP answers near 1,232 bytes, below our limit.
- Apps using their own DoH/DoT bypass filtering (a spec §5 limitation, unchanged).
- `DnsProxy` is reused by the M2 full-tunnel data plane without changes.
