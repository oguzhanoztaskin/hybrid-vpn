# ADR 0003: Kotlin + Go architecture for the data plane

Status: **accepted** (2026-10-24). Supersedes the "open" version of this ADR.

## Decision

| Layer | Language | Responsibilities |
| --- | --- | --- |
| Android shell | Kotlin | UI, lifecycle, `VpnService` ownership, permissions, persistent configuration, LAN discovery and inventory, the existing DNS firewall |
| Network engine | Go | Userspace packet forwarding, TCP/UDP termination with an established stack, routing and transport policy enforcement, SOCKS5 / HTTP CONNECT, Tailscale via upstream Go packages (several independent instances, ADR 0006) |
| OpenVPN | Mature existing implementation behind a dedicated adapter | Protocol and cryptography. We never implement OpenVPN cryptography ourselves |

The Kotlin DNS firewall (`engine/`, `HybridVpnService`) stays as it is. It will **not** be migrated to
Go for consistency. Once the Go engine owns full-tunnel forwarding, DNS packets will be handed to the
existing Kotlin `DnsProxy` (or the proxy will be called through a narrow interface). That is decided
when the integration is built, not now.

## Rationale

- **Tailscale is Go.** Embedding `tailscale.com` packages (tsnet, wgengine, magicsock, netstack) keeps
  us on the maintained upstream implementation: control protocol, NAT traversal, DERP, MagicDNS and
  ACL behaviour. A Rust data plane would need either a Go↔Rust bridge on the hot path or an
  unofficial reimplementation, which we refuse to maintain.
- **One userspace stack.** Tailscale already ships gVisor netstack. Using the same stack for our own
  forwarding avoids carrying two TCP/IP implementations in one APK.
- **Go-to-Android embedding is well trodden.** Tailscale's Android app ships Go this way, built with the NDK.

We do **not** claim Go is faster than Rust. Go adds GC pauses, a larger binary and a runtime that
must be kept from waking the device needlessly. Those are measured, not assumed.

## Acceptance criteria (measured before M2 ships)

Each number is measured on a mid-range device and compared with the DNS-only build:

- Throughput and p50/p99 latency for TCP bulk, many short TCP flows, and UDP/QUIC.
- Memory: RSS at idle with 0, 1 and 2 tailnets; peak during bulk transfer.
- Idle CPU and **wake-ups per minute** with the screen off, plus battery drain over a fixed interval.
- APK size added per ABI.

A regression beyond agreed thresholds blocks the milestone. It does not trigger a rewrite in
another language without new evidence.

## Integration shape

- One `.so` per ABI built from a Go module with `-buildmode=c-shared` and the NDK toolchain, plus
  a thin JNI layer. Kotlin passes the TUN file descriptor once. **Packets never cross JNI**: Go
  reads and writes the fd directly.
- Control calls (start, stop, configure, status) cross JNI as small messages (JSON or protobuf)
  at human-scale rates.
- Go sockets to the physical network are protected through a callback into `VpnService.protect()`.
  Tailscale's own sockets use `netns.SetAndroidProtectFunc`.
- No telemetry: `logtail.Disable()` and `envknob.SetNoLogsNoSupport()` are called before any
  Tailscale component starts (see ADR 0006).

`docs/spikes/go-network-engine.md` (branch `experiment/go-network-engine`) records the feasibility
results that this decision depends on.
