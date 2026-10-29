# Architecture

This document maps the specification (v0.1) to the code, and records what each milestone delivers.

## Milestone status

| Milestone | Scope | State |
| --- | --- | --- |
| M0 | Feasibility harness and architecture records | **Done.** DNS-only tunnel; data plane decided as Kotlin + Go ([ADR 0003](adr/0003-data-plane-language.md)); Go embedding and multi-tailnet spike merged |
| M1 | LAN inventory | **Implemented** |
| M2 | Full-tunnel forwarding and policy routing (Go engine) | **M2a+M2b, the default engine since 0.3**: direct TCP/UDP, per-flow policy (apps, CIDRs, protocol, ports, transports, block), fail-closed transport failures, UDP overload fix ([ADR 0007](adr/0007-go-forwarding-engine.md), [ROUTING](ROUTING.md)). DNS-only is the fallback |
| M3 | SOCKS5 / HTTP CONNECT | **SOCKS5 done**: proxies as `socks5:<id>` transports in the Go engine, TCP (CONNECT) and UDP (UDP ASSOCIATE), username/password encrypted at rest, per-app or all-traffic routes, fail closed ([ADR 0009](adr/0009-socks5-proxies.md)). HTTP CONNECT implemented (0.6.0; ADR 0011) |
| M4 | Tailscale: several isolated tailnets ([ADR 0006](adr/0006-multiple-tailnets.md)) | **M4a**: tailnets as transports in the Go engine, interactive login, policy routing, per-tailnet MagicDNS; verified offline. Open: real tailnets, key encryption at rest, short names/split DNS |
| M5 | OpenVPN | **M5a**: OpenVPN 3 Core (MPL-2.0) profiles as `openvpn:<id>` transports in the Go engine, each with its own userspace stack; import of inline `.ovpn`, username/password, encrypted at rest; verified against a local OpenVPN 2.7 server on host and emulator ([ADR 0008](adr/0008-openvpn3-core.md)). Open: pushed DNS, challenge/response, KeyChain certificates |
| M6 | Hardening, encrypted backup, reproducible builds | Not started |

## Modules

```
┌──────────────────────────── app (Android) ────────────────────────────┐
│  Compose UI ── AppContainer ── Room (networks, devices, identifiers,  │
│      │                         observations, filter_lists, dns_events)│
│      │                                                                │
│  HybridVpnService ──────────────┐        ScanController ───────────┐  │
│   TUN read loop (poll)          │         AndroidLan (Wi-Fi bind)  │  │
│   AppAttribution (owner UID)    │         MulticastLock            │  │
│   UnderlyingNetworkTracker      │         DeviceRepository         │  │
│   AndroidUpstreamSockets        │                                  │  │
│   (protect + bindSocket)        │                                  │  │
└─────────────────────────────────┼──────────────────────────────────┼──┘
                                  ▼                                  ▼
┌──────────── engine (JVM) ───────────────────┐  ┌──────── discovery (JVM) ─────────┐
│ packet: IpPacket, UdpDatagram, builders,    │  │ MdnsBrowser, SsdpDiscoverer,     │
│         TcpResetBuilder                     │  │ SubnetSweeper, ArpTable,         │
│ dns:    DnsMessage, FilterListParser,       │◀─│ NetworkScanner (aggregation),    │
│         DomainListIndex, DnsCache,          │  │ DeviceClassifier,                │
│         Udp/Dot/DohUpstream, DnsProxy,      │  │ IdentityResolver                 │
│         LocalZones                          │  └──────────────────────────────────┘
│ policy: PolicyConfig, PolicyCompiler,       │
│         PolicyEngine                        │
│ net:    IpLiteral, Cidr                     │
└─────────────────────────────────────────────┘
```

The spec's separation holds: **the policy engine decides, transports deliver.** `DnsProxy` takes a
`PolicyEngine` and `DnsUpstream`s and knows nothing about TUN. A future full-tunnel data plane reuses
it unchanged.

## M0: DNS-only harness

See [ADR 0002](adr/0002-dns-only-harness.md). The TUN interface gets a private /30 and /126, and only
the virtual resolver addresses (`10.215.173.2`, `fdc1:7e57:dead::2`) are routed into it. Android
sends every system-resolver query there, while all other traffic stays on the physical network.

Packet path:

1. The `tun-reader` thread polls the TUN fd (500 ms timeout, so shutdown never blocks) and parses IPv4/IPv6.
2. UDP/53 to the virtual resolver goes to a worker pool. TCP to it (DNS-over-TCP fallback, or the
   Private DNS port-853 probe) gets an immediate RST. Everything else is dropped.
3. A worker asks `ConnectivityManager.getConnectionOwnerUid` for the owner (Android 10+) and
   maps it to package names. An unknown owner stays unknown.
4. `DnsProxy` evaluates the policy. A block is answered locally (null IP, NXDOMAIN or REFUSED).
   Local zones go to the physical network's resolver. Everything else is answered from the cache or
   upstream. Upstream failure returns **SERVFAIL** (fail closed).
5. Responses larger than the MTU are truncated with TC set.

What the harness validates from the spec's M0 list:

| Spec item | Where |
| --- | --- |
| TUN establishment, lifecycle, revoke, always-on | `HybridVpnService` (`SUPPORTS_ALWAYS_ON`, `onRevoke`, sticky restart) |
| Protected underlying sockets | `AndroidUpstreamSockets`: `protect()` + `Network.bindSocket()`, DoT/DoH hostnames resolved on the physical network |
| DNS interception | `TunConfig`, `DnsProxy` |
| Controlled network switching | `UnderlyingNetworkTracker` picks the best non-VPN network; config and cache are rebuilt atomically on change |
| Direct TCP/UDP forwarding | **Not done**: needs a userspace TCP/IP stack (ADR 0003) |

## M2a: Go full-tunnel engine (the default)

The default under Settings → Engine whenever the build bundles the Go library; otherwise, or when
"DNS only" is chosen, the M0 DNS-only tunnel below runs instead. The TUN routes `0.0.0.0/0` and `::/0` by default (optional LAN exclusions: [ADR 0010](adr/0010-optional-lan-bypass.md)), with MTU 16384 to keep the packet count per transfer low (Settings → Performance can turn it off; [ADR 0007](adr/0007-go-forwarding-engine.md), 0.3.2 amendment). Kotlin still owns the `VpnService`, and Go owns a duplicate of the TUN fd.

```
apps ─► TUN ─(dup fd, netpoller)─► go/engine: classify (TCP/UDP; optional ICMP echo proxy; other protocols dropped+counted)
                                      │ gVisor netstack (channel endpoint, promiscuous, spoofing)
                                      ▼ TCP/UDP forwarders
                                   Router.Decide ──► drop (reason counted)
                                      │          ──► DNS (any :53, UDP or TCP) ─JNI─► Kotlin DnsProxy
                                      ▼
                                   Router.Dial ─► Direct (socket → JNI protect() → connect)
```

| Concern | Where |
| --- | --- |
| fd ownership and shutdown | `HybridVpnService` (dup + detach; Kotlin keeps the original), `go/jni` `startEngine`/`stopEngine`, `engine.Stop` |
| Routing boundary | `go/engine/router.go`; transports must refuse what they can't deliver |
| JNI upcalls | `go/jni/main.go` (`protect`, `dnsQuery`, `onEngineStopped`), `GoBridge.kt` |
| OpenVPN fast path | `engine/fastpath.go` (`PacketTransport`, flow table, coalescing), `openvpn/tunnel.go` (`packetPath`, batched reads); ADR 0008, 0.3.3 amendment |
| Stats and failure display | `engine.Stats` → `GoBridge.stats()` → Status screen (polled only while visible) |
| Modules on/off | `TailnetConfig.enabled`, `OpenVpnProfile.enabled`, `ProxyConfig.enabled`, `Settings.dnsFiltering`. Only enabled tailnets and profiles are handed to the engine at start; `PolicyRepository.loadForRun` drops switched-off (or not started) transports from the running policy via `PolicyConfig.withoutTransports`, so their rules are skipped and fallbacks naming them block. Starting or stopping a connection needs a restart (`VpnController.restart`); the Status screen offers it |

Details and limitations are in [ADR 0007](adr/0007-go-forwarding-engine.md).

## M1: LAN inventory

`NetworkScanner` runs mDNS (legacy-unicast one-shot queries), SSDP (M-SEARCH plus a bounded fetch of
the description document) and a subnet sweep (ICMP plus 14 TCP ports, 64-way parallel) concurrently.
Then it reads ARP (where readable) and reverse DNS, and merges the evidence per IP into
`HostObservation`s. On Android every socket is bound to the Wi-Fi `Network`, so scanning works with
the VPN up and never enters the tunnel.

Identity follows spec §9.2 ([ADR 0005](adr/0005-device-identity.md)). Persistence:

- `devices`: the device, not tied to a network
- `device_identifiers`: evidence; `scope` is `""` for globally unique kinds, otherwise the network id
- `device_observations`: one row per device per scan (history, online state); pruned after 180 days
- `networks`: keyed by SSID when known, otherwise by subnet and gateway; upgraded in place once the SSID becomes visible

## Threading

- Go engine (debug Go mode): one goroutine each for TUN read and write, one per TCP flow
  (plus one per direction for splicing), one per UDP association and DNS flow. Upcalls run on Go
  threads attached to the JVM as daemons.

- UI and repositories use coroutines. `AppContainer.scope` holds app-lifetime work such as scans and log batching.
- The VPN has one reader thread, 8 worker threads (upstream I/O is blocking), and a coroutine scope for start and reconfiguration.
- `DnsProxy.config` is a single volatile reference, so policy, profile, list and resolver changes swap atomically.

## Deliberate deviations from the spec

- **Kotlin, not Rust, for the M0/M1 core.** See [ADR 0004](adr/0004-jvm-core-for-m0-m1.md). The policy
  and DNS semantics are pinned by host tests, so porting the logic later is mechanical.
- **Policy documents are JSON, not YAML.** The spec allows "Proto or versioned JSON". The schema is in
  `schemas/policy.v1.schema.json`.
- **Gradle modules instead of the `android/ engine/ adapters/` tree.** `adapters/` will appear with the first transport (M3).


## Optional echo checks (0.4.0)

The full tunnel can separately enable IPv4/IPv6 ICMP echo reachability (both off by default).
Requests go through policy outside the promiscuous ingress netstack and are answered only after
the chosen transport receives a real remote echo reply. See ADR 0007's 0.4.0 amendment for the
reachability-proxy semantics and limits; arbitrary ICMP and incoming forwarding are not enabled.


## Optional LAN discovery and connections (0.5.0)

The Android VPN can leave connected Wi-Fi/Ethernet prefixes, limited broadcast, multicast and
link-local destinations outside its routes. This is an off-by-default bypass for all protocols,
allowing discovery and bidirectional LAN connections through the physical network. The complement
of the excluded CIDRs is installed on API 24+; explicit virtual DNS host routes retain system DNS
filtering. UnderlyingNetworkTracker publishes physical LAN prefix changes, which trigger a VPN
restart to rebuild immutable routes. Go's non-unicast guard remains unchanged for captured traffic.
See ADR 0010 for policy/filtering exceptions and limits.


## HTTP proxy transport (0.6.0)

`go/httpproxy` implements bounded HTTP CONNECT handshakes over protected sockets, with optional
Basic authentication, buffered tunnel data and half-close. `http:<id>` carries TCP only. Kotlin's
shared proxy repository stores the type (older entries remain SOCKS5), encrypts passwords and
exports HTTP/SOCKS5 configurations separately. JNI reports both proxy types in one status list.
UI order is HTTP then SOCKS5; existing policy order is unchanged. See ADR 0011.
