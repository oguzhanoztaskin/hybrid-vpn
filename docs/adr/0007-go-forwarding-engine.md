# ADR 0007: Go full-tunnel forwarding engine (M2a)

Status: accepted; **the default engine since 0.3** (see the amendment at the end). DNS-only (ADR 0002) is the fallback.

## Context

ADR 0003 assigns packet forwarding to Go. M2a validates the core path, direct TCP and UDP, before
proxies, Tailscale or OpenVPN are added.

## Decisions

**Ownership of the TUN.** Kotlin keeps the `VpnService` and the original `ParcelFileDescriptor` for
the VPN's lifetime. Go receives `pfd.dup().detachFd()`, and ownership of that duplicate passes to Go
on every path, including start failures. If Go stops or dies, Kotlin's descriptor keeps the
interface up, so traffic is blackholed instead of leaking (fail closed). Stopping protection closes
both descriptors. `GoBridge.stop()` runs off the main thread, and a new start waits for a pending stop.

**No busy polling, few copies.** The fd is non-blocking and registered with Go's netpoller: an idle
tunnel parks one goroutine in epoll. Inbound packets are read directly into gVisor buffer views
(no intermediate copy). Outbound packets are written with one `writev` per packet. TCP payloads are
copied once more per direction by the splice, using pooled 32 KiB buffers.

**gVisor netstack** at the revision `tailscale.com` pins, behind a `channel` link endpoint with
promiscuous mode and spoofing, as Tailscale's own netstack does. CUBIC, SACK, and TCP buffers of
256 KiB default / 4 MiB max with auto-tuning.

**One routing boundary.** `engine.Router.Decide` classifies every flow, and `Router.Dial` is the only
path from routing to a `Transport`. M2a rules, in order:

1. Non-unicast destinations (unspecified, loopback, multicast, broadcast) → drop.
2. **Port 53 to any address** → the Kotlin DNS firewall (UDP and RFC 1035 TCP framing), so apps
   with hard-coded resolvers are filtered too.
3. Other ports on the virtual resolver (e.g. 853, the Private DNS probe) → drop.
4. Tunnel addresses → drop (loop guard).
5. Everything else → `direct`. Unknown transport names fail closed.

Future transports (`socks5:<id>`, `tailnet:<id>`, `openvpn:<id>`) plug in here. The tailnet adapter
already exists and keeps its membership check (ADR 0006).

**Protected sockets.** `Direct` passes every socket to `VpnService.protect()` (a JNI upcall, once per
socket) before connecting. If protection fails, the dial fails rather than looping through the tunnel.

**Honest TCP.** The outbound connection is dialed before the app's handshake completes, so the app
sees a SYN-ACK only when the destination answered, and a RST otherwise. Half-close is propagated.

**UDP** is an association per (source, destination), with a 60 s idle timeout and 1,024 concurrent
flows. Beyond the cap, and for dropped flows, netstack answers ICMP port unreachable so apps fail fast.

**Unsupported protocols are not silently bypassed.** Only TCP and UDP enter netstack. ICMP, ICMPv6
and other IP protocols are dropped at ingress and counted per reason (visible on the Status screen),
so netstack never fakes a ping reply for an arbitrary address. Ping therefore fails in this mode.

**Failure handling.** A panic in any engine goroutine stops the engine instead of crashing the
process, and reports through an upcall. The Status screen shows the error while the TUN stays up
(fail closed). `Stop` returns promptly: it doesn't wait for DNS callbacks it can't cancel. It closes
their connections and lets them finish.

**JNI.** Method IDs and the class are cached once from a Java thread. Go threads attach as daemons.
Every upcall runs inside a local reference frame, and R8 keeps `GoBridge`.

**Gate.** `EngineMode.GO_FORWARDING` is selectable only when `BuildConfig.DEBUG`. Release builds
always run DNS-only.

## Consequences and limitations

- ICMP (ping, traceroute) does not work in Go mode.
- In-flight TCP flows break on a Wi-Fi ↔ cellular switch, because the outbound socket is tied to the
  old network. New flows work immediately. This matches non-VPN behaviour for most apps.
- Apps' own TCP keepalives are answered by netstack. Our outbound keepalive starts only after 5 idle
  minutes (to limit wake-ups), so an idle NAT mapping can expire earlier than the app expects.
- DNS-over-HTTPS and DoT to third-party resolvers on port 443/853 still bypass DNS filtering
  (unchanged from ADR 0002). They are forwarded, not blocked.
- Every DNS query crosses JNI twice (into Kotlin and back). This is measured in `docs/benchmarks/`.

## Amendment (M2b): policy routing and UDP reliability

**Routing policy.** The router evaluates the user's policy after its built-in guards. Rules match on
the owning app's UID (or explicitly an unknown owner), destination CIDRs, protocol and port ranges.
Actions are `block` or `route` to a named transport. Kotlin remains the source of truth: it compiles
and validates the policy, then exports the per-flow subset for the current profile and network. Go
re-validates it against the transports it actually has and rejects anything it cannot enforce
exactly. A failed transport falls back only to an explicitly named `on_failure` transport. See
`docs/ROUTING.md`.

**Transport interface.** `Name`, `Kind`, `Capabilities` (TCP/UDP) and `Dial`. A transport refuses
what it cannot deliver and never chooses another path itself. Only `direct` is registered; the
tailnet adapter implements the interface but is not enabled.

**App attribution.** One upcall per new flow (`getConnectionOwnerUid`), made only when the policy
matches on apps, and for UDP kept off the packet path. Per-UID semantics (shared UIDs) are
surfaced as warnings.

**UDP under overload.** A TUN gives the sending app no back-pressure, so an unpaced burst above path
capacity must lose the excess somewhere. The original relay made the engine itself the bottleneck,
with one goroutine hand-off and one `sendto` per datagram behind gVisor's 32 KiB buffer. Under
overload it delivered well below capacity (emulator: 131 vs ≈220 Mbit/s). The app→remote direction
now drains the endpoint per wake-up and sends with `sendmmsg`, and the per-flow buffer matches the
Linux default. Overload now delivers path capacity, paced traffic up to 150 Mbit/s is loss-free (as
before), and every drop is counted (`udpReceiveBufferDrops`, per-reason drops). The remaining loss
above capacity is inherent to TUN.

**Invalid policy.** In the Go engine an invalid saved policy blocks all non-DNS flows, never routes
them direct.

## Amendment (0.3): default engine, modules switchable

The full tunnel is the default in every build that bundles the Go library, release builds
included; the debug-only gate is gone. DNS-only stays as the fallback: the user can choose it, and
it runs automatically, with a warning, when the library is missing. It enforces only the DNS
firewall, so Tailscale, OpenVPN and per-flow rules show as needing the full tunnel.

Tailnets and OpenVPN profiles can be switched off. The engine is started only with the enabled
ones, and the running policy leaves out every transport the engine doesn't have (switched off, or
switched on after start), because the engine rejects a policy naming an unknown transport. Rules
routing to such a transport are skipped rather than blocked: switching a connection off is a user
choice, not a failure. Fallbacks naming it still block, so it is never silently replaced by
`direct` where the policy said "else block".

## Amendment (0.3.2): full-tunnel MTU 16384

The TUN's MTU was 1500, so a bulk TCP transfer crossed the TUN as one packet per ≈1.4 kB, and each
packet cost a `read` or `writev`, a goroutine hand-off and a netstack pass. Profiling on a phone
(simpleperf, Xiaomi POCO F5 over Wi-Fi) put 44% of the engine's CPU at syscall boundaries and 11% in
futex wake-ups; gVisor's protocol work itself was small.

The full tunnel now uses MTU 16384 (`TunConfig.FULL_TUNNEL_MTU`; DNS-only keeps 1500). This is safe
because the MTU never reaches the network: the engine terminates every TCP flow and re-sends it
over ordinary sockets with the kernel's own segmentation, and UDP datagrams larger than the path MTU
are fragmented by the kernel as for any app (sockets default to `IP_PMTUDISC_WANT`). Tailnets and
OpenVPN keep their own stacks and MTUs. Per 128 MiB on the phone: app CPU 3.7–5.7 s → 1.2 s
downloading and 1.5 s → 0.4 s uploading, TUN syscalls ≈98,000 → ≈12,600, and downloads went from
216–347 Mbit/s to Wi-Fi line rate (≈580) under the same conditions. 9000 (common in other Android
VPNs) gave most of that (1.5 s / 0.5 s); 16384 costs no more memory, because netstack's buffer
chunks round both up to 16 KiB. Numbers: `docs/benchmarks/results.md`.

Both this and RACK loss detection are user settings (Settings → Performance), read at engine
start: "Large tunnel packets" (on by default; off restores 1500) and "TCP loss detection (RACK)"
(on by default). With RACK off, netstack's stack facing apps (`engine.Config.DisableRACK`,
`TCPRecovery(0)`) recovers with duplicate ACKs and the retransmission timer. Losses on that link
only happen when the TUN queue overflows, so RACK's per-ACK bookkeeping (6% of the engine's CPU in
the profile) buys little there; measured on the phone it saved 6% of app CPU on downloads (1.41 →
1.33 s per 128 MiB) at unchanged throughput. It stays on by default as the conservative choice.


## Amendment (0.4.0): optional ICMP echo reachability

Settings → Network compatibility has independent IPv4 and IPv6 ping switches, both off by default.
They are captured at engine start; Status offers a restart when either changes. Disabled families
keep the existing ingress drop. Enabled families accept only complete, checksummed echo requests;
IPv4 fragments, IPv6 extension headers and non-echo ICMP remain blocked.

Echo requests bypass the promiscuous netstack and go through the router's guards and policy,
with `icmp` / `icmpv6` protocols, no ports, and unknown app identity (Android's owner API only
supports TCP/UDP). CIDR, protocol and explicit `@unknown` rules apply. App-specific rules cannot
attribute ping to a package. A transport must implement `PingTransport`; SOCKS5 cannot. Only an
explicit `on_failure` transport is tried on failure, and no response is returned on failure.

This is a **reachability proxy**, not raw IP forwarding: a small independent probe must receive a
real ICMP echo reply before the app's ID, sequence and data are echoed back. Payload integrity and
TTL are not end-to-end; traceroute and ICMP errors/PMTU are not supported by this path. Direct uses
protected unprivileged datagram ICMP sockets; OpenVPN uses an ICMP endpoint in its own userspace
stack; Tailscale uses its instance's LocalAPI `PingICMP`, after the same membership check as Dial.
No disco or TSMP success is treated as an ICMP reply. Nothing enters the host network as fallback
without an explicit policy decision. There are at most 64 concurrent probes, a three-second
request deadline and cancellation at engine shutdown. Drops and transport failures use existing
Status/Logs counters.

Enabling gVisor's automatic echo responder on the promiscuous ingress stack is deliberately avoided:
it would report arbitrary unreachable destinations as alive. Echo support does not add incoming
TCP/UDP forwarding or multicast/broadcast discovery for KDE Connect.


## Amendment (0.6.0): deleted transport references

Deleting a configured connection retires its policy references: remove its declaration, convert
routes naming it to blocks and replace fallbacks with block. Preserve each rule's match, order and
enabled state. A deleted default is represented by a last IP-only catch-all block after every
explicit rule (including rules already at maximum priority). DNS keeps its existing behavior.
Previously deleted, now-unconfigured transports are repaired the same way during loadForRun and
persisted. This prevents one stale profile reference from invalidating and blackholing unrelated
traffic, without introducing an implicit direct fallback. Temporary switch-off semantics are
unchanged. Established flows still require a restart to disconnect, as with other policy updates.
