# Changelog

Versions follow [Semantic Versioning](https://semver.org): minor for new capabilities, patch for
fixes. Android `versionCode` increases with every release.

## [Unreleased]

## [0.6.0]

### Added
- **HTTP proxies**, compatible with mitmproxy's default regular mode on port 8080. TCP uses
  CONNECT, with optional Basic authentication and encrypted password storage. UDP/ICMP and failed
  connections block unless the policy explicitly names a fallback. HTTP appears before SOCKS5 in
  the UI; routing priorities and first-match semantics are unchanged.
- Custom circuit-lock shield launcher icon, including adaptive, round and monochrome variants.
- Public-release APK packaging for ARM64, x86_64 and universal downloads. Development builds
  continue to produce their ordinary APK; publishing remains an explicit release action.

### Fixed
- Deleting an OpenVPN profile, tailnet or proxy no longer leaves the entire saved policy invalid.
  Routes using the deleted connection become explicit blocks, removed fallbacks block, and stale
  references left by older versions are repaired on startup. Other routes remain usable.

### Compatibility
- Existing SOCKS5 entries, credentials and routes retain their identities. Proxy type defaults to
  SOCKS5 when loading older saved metadata. HTTPS inspection requires the app to trust the proxy CA.

## [0.5.0]

### Added
- Optional **LAN discovery & connections** under Settings → Network compatibility (off by default).
  Connected Wi-Fi/Ethernet subnets, multicast, broadcast and link-local destinations use the
  physical network outside the VPN, supporting UDP discovery and incoming LAN connections.
  These destinations bypass VPN routing and filtering rules; normal system DNS remains filtered.
- Active LAN exclusions in Status/routing, restart prompt for the switch, and automatic route
  rebuilding when connected LAN prefixes change. Works on Android 7+ without new dependencies.

## [0.4.0]

### Added
- Optional **IPv4 ping (ICMP)** and **IPv6 ping (ICMPv6)** switches under Settings → Network
  compatibility, both off by default and applied after a VPN restart. Echo requests follow the
  routing policy through direct, Tailscale or OpenVPN transports. Replies require a real remote
  ICMP response; SOCKS5 fails closed unless an explicit fallback is configured.
- Policy protocol matchers `icmp` and `icmpv6`. Android cannot attribute these packets to an app,
  so their owner is unknown. Other ICMP messages, traceroute and multicast discovery remain unsupported.

## [0.3.3]

### Changed
- **OpenVPN downloads are about 2× faster (up to 3×).** OpenVPN 3 Core left its transport socket at Android's
  default 224 KiB buffer, and bursts overflowed it (tens of thousands of drops per run, each a loss
  for TCP inside the tunnel). The socket now gets 4 MiB / 2 MiB. On a phone against a local server,
  downloads went from ≈110 Mbit/s to 165–370 Mbit/s.
- The OpenVPN session reads from the core in batches (`recvmmsg`), with far fewer syscalls.

### Added
- **OpenVPN packet forwarding** (Settings → Performance, on by default): TCP flows routed to OpenVPN
  are forwarded as packets (addresses rewritten, MSS clamped, returning segments coalesced) instead
  of through a second TCP stack. Upload CPU about halves, download CPU drops about 20%. Routing,
  fallbacks and what the server sees are unchanged; UDP keeps the old path.
- Status → Traffic shows packet-forwarded flows, packets, merges and drops.
- OpenVPN lab: `-reuse` keeps the keys of an earlier run, so a profile imported on a device keeps
  working; host benchmarks for the engine with and without forwarding.

## [0.3.2]

### Changed
- **Faster and cheaper full tunnel**: the tunnel interface's MTU is 16384 instead of 1500 (the
  full-tunnel engine terminates TCP and re-sends over ordinary sockets, so the real network is
  unaffected). On a phone over Wi-Fi this cut the engine's CPU per transferred byte about 3–4×
  (128 MiB: 1.2 s instead of 3.7–5.7 s downloading, 0.4 s instead of 1.5 s uploading) and downloads
  reached Wi-Fi line rate where they had been CPU-bound. DNS-only mode keeps 1500.

### Added
- **Settings → Performance**: "Large tunnel packets" (the MTU above; on by default, off means 1500)
  and "TCP loss detection (RACK)" (on by default; off saves about 6% of the engine's CPU on
  downloads, since the link between apps and the engine rarely loses packets). Both apply at the
  next start; Status offers the restart.
- OpenVPN lab: a throughput endpoint (TCP 5201, `hvbench` protocol) behind the test server, and a
  host benchmark (`go test -tags openvpn3 -run x -bench LabDownload ./openvpn`).
- Benchmark harness: works on phones (engine setting key fixed, optional idle and Wi-Fi phases, CPU
  cost per transfer recorded); first phone results in `docs/benchmarks/results.md`.

## [0.3.1]

### Added
- **Routing view** (Status → Routing → Routing paths): the rules the running engine applies, in
  evaluation order, each with what it matches, where matching traffic goes, its fallback, and
  whether that connection is up right now (with flow counts). Rules for another profile or network,
  or whose connection is switched off, are listed as not applied, with the reason. OpenVPN rules
  name destinations the server doesn't route (those are blocked). Built-in guards (DNS
  interception, loop guard, …) and DNS-only rules (filter lists) are hidden unless switched on.
  The Status card lists the active rules and the default.
- **Devices shortcut for Tailscale**: "Devices" on the Status card and "Show devices" on the
  Tailnets screen open Devices → Tailnets.
- **Failed connections in Logs → Engine**: dials a transport could not complete (e.g. "openvpn:x is
  not connected", a destination outside the tailnet), with time and count; memory only, cleared
  when protection stops.

### Fixed
- The tailnet machine list could disappear ("No tailnet is running") when one read of the node was
  slow, and one slow tailnet could time out the others. Each tailnet now gets its own deadline, the
  last list is kept when a read fails, and a tailnet whose list hasn't arrived says so.
- Status said "0 peers" right after connecting, before the machine list had arrived; it now says
  "no other machines yet".

## [0.3.0]

### Changed
- **The Go full-tunnel engine is the default** in every build that bundles it, and no longer
  "experimental" or debug-only. DNS-only is the fallback: chosen under Settings → Engine, or used
  automatically (with a warning on Status) when the build has no Go engine. The saved engine choice
  was reset once so that existing installs move to the full tunnel.
- **Status is a module overview**: protection on/off, then cards for DNS, Tailscale, OpenVPN and
  SOCKS5 proxies, each with live state and its own switches.
  Changes the engine reads only at start show a "Restart now" button.
- The DNS tab became **Logs**: DNS queries, OpenVPN session logs, and Go engine errors. DNS lists,
  my rules, the resolver and the blocked answer moved to one DNS screen (Status → DNS → Lists &
  resolver, or Settings → Modules). Tailnets and OpenVPN are reached from Status and Settings →
  Modules.

### Added
- **SOCKS5 proxies (M3).** Add proxies (host or IP, port, optional username and password, stored
  encrypted) under Status → SOCKS5 proxies; each becomes transport `socks5:<id>` in the Go engine.
  TCP goes through CONNECT, UDP through UDP ASSOCIATE. "Route apps" picks apps to send through a
  proxy, "Route all traffic" sends everything; DNS stays with the DNS firewall. An unreachable proxy
  or a refused destination fails closed, never direct. Status shows whether each proxy is reachable
  and its open flows. `cmd/socks5lab` is a local proxy for emulator tests.
- **Works with mitmproxy** (`--mode socks5`, optionally `--proxyauth`), verified with 12.2: TCP and
  HTTPS interception go through it. It has no UDP; after its first refusal the proxy is marked "TCP
  only" and UDP sent there is blocked locally, so apps fall back from QUIC to TCP.
- **Switch modules on and off**: the DNS module (filter lists and my rules; off, names are still
  resolved and logged, nothing is blocked), and each tailnet, OpenVPN profile and SOCKS5 proxy. A switched-off
  connection doesn't start, and rules routing to it are skipped; a fallback naming it blocks
  (`PolicyConfig.withoutTransports`). The saved policy is unchanged.
- **Licensed as GPL-3.0-or-later** (`LICENSE`). `THIRD_PARTY_NOTICES.md` lists every bundled
  component with its licence; the full texts ship in the app under Settings → About → Open-source
  licences, with the GPL notice, version and trademark disclaimer. `scripts/gen-notices.py`
  regenerates both from what the release build links.
- README: current status, experimental features, build notes for OpenVPN, licence and disclaimer.
- **OpenVPN (M5a), debug builds with the Go engine.** Import self-contained `.ovpn` profiles
  (Settings → OpenVPN); each becomes transport `openvpn:<id>` running OpenVPN 3 Core (MPL-2.0) on
  its own userspace stack. UDP and TCP servers, IPv4 and IPv6, username/password, reconnect on
  network change. Traffic goes there only through a policy rule, and only to networks the server
  routes ("Route its networks" / "Route all traffic"); everything else fails closed. Profiles and
  passwords are encrypted with an Android Keystore key. Status, pushed routes and DNS, traffic and
  a session log per profile. A profile that can't start blocks its own routes without stopping the
  VPN (ADR 0008). Profiles with an encrypted private key ask for its password at import and check
  it immediately; import errors appear in a dialog.
- `scripts/openvpn3-deps.sh`: pinned, checksum-verified native dependencies (OpenSSL 3.5.9 LTS,
  OpenVPN 3 Core 3.11.8, asio 1.24 with OpenVPN's patches, LZ4 1.10).
- `ovpnlab`: a local OpenVPN 2.7 server for tests that needs neither root nor containers.
- Devices → **Tailnets**: every machine in each running tailnet, with a detail view showing MagicDNS
  name, all addresses and subnet routes, online/last seen, connection path (direct, peer relay or
  DERP region), OS, owner, tags, exit-node status, key expiry and traffic. Tap to copy names and
  addresses.
- Tailnets screen explains why a tailnet isn't running and when no policy rule routes to it yet.
- Lab peer UDP echo and `hvbench udpping`; UDP into a tailnet verified through the full engine.

## [0.2.0] — 2026-10-24 (versionCode 2)

Kotlin + Go architecture, experimental full-tunnel engine with policy routing, and concurrent isolated
tailnets. Everything new is **debug-only**; release builds still run the DNS-only engine by default.

### Added
- **Experimental Go full-tunnel engine (M2a), debug builds only.** gVisor netstack with direct TCP
  and UDP forwarding over protected sockets; DNS on port 53 to any resolver goes through the existing
  DNS firewall; ICMP and other protocols are dropped and counted; fail-closed on engine failure.
  Selected under Settings → Experimental engine. DNS-only remains the default and the only mode in
  release builds (ADR 0007).
- Go ↔ Kotlin bridge (`libhybridvpn_go.so`, built by `:app:buildGoJni` when an NDK is installed).
- `tailnet` package: several isolated `tsnet` instances with membership-checked dials, plus a
  router adapter (`tailnet:<id>`). Not yet routed to.
- `hvbench` benchmark tool and reproducible emulator benchmark (`docs/benchmarks/`).
- ADR 0006 (concurrent isolated tailnets) and ADR 0007 (Go forwarding engine).

### Changed
- ADR 0003: data-plane architecture decided as Kotlin + Go. OpenVPN goes through a dedicated adapter
  around an existing implementation.
- Go dependencies track the current upstream: `tailscale.com` v1.104.2 with Go 1.27.3, provided via
  `go.mod` and `GOTOOLCHAIN=auto` (no system-wide install).

### Added (M4a, debug builds only)
- **Tailnets as transports.** Configure several tailnets (Settings → Tailnets) and route to them by
  policy (`tailnet:<id>`). Each has its own state, login and status. Tailscale's sockets are
  protected from the VPN, remote logging stays off, and no credentials are stored (login is
  interactive). Verified on the emulator against two offline lab tailnets with overlapping
  addresses.
- **Per-tailnet MagicDNS.** Names under a tailnet's suffix are answered by that tailnet only, never
  sent to a public resolver. Unknown nodes get NXDOMAIN; a suffix claimed by several tailnets is refused.
- Tailnet membership and names come from snapshots kept current by Tailscale's event bus, so there
  is no status query per connection.
- `tailnetlab` tool for offline tailnet testing; Go crash output is written to the app's files for
  diagnosis.

### Added (M2b, debug builds only)
- **Policy-based routing in the Go engine.** Ordered rules match the owning app (Android UID, or
  explicitly an unknown owner), destination CIDRs (IPv4/IPv6), protocol and ports; actions are block or
  route to a named transport with an explicit `on_failure`. A failed transport never falls back to
  direct unless the policy says so.
- Policy `transports` section (direct, tailnet, socks5, http, openvpn). Only `direct` runs in this
  build; other types are rejected with a clear error. Transport ids carry identity, so two tailnets
  are two transports.
- Transport interface with capabilities, shared by the direct transport and the existing tailnet adapter.
- Status screen: routing rule count, flows per transport, UDP datagram and buffer-drop counters.

### Fixed
- UDP throughput collapse under overload in the Go engine. The relay now drains per wake-up and sends
  with `sendmmsg`, delivering path capacity instead of ≈60% of it. Every drop is counted.
- Go engine: an invalid saved policy now blocks all non-DNS flows instead of routing them direct.
- Idle wake-ups: the DNS log now publishes only after activity, and the DNS-only TUN loop blocks
  indefinitely (a self-pipe wakes it on shutdown) instead of polling every 500 ms. Emulator:
  499 → 5 wake-ups/min.

### Security
- Tailnet dials go through the instance's own netstack. `tsnet.Server.Dial`, which falls back to the
  host network for non-tailnet addresses, is never reachable from routing code.

## [0.1.0] — 2026-10-24 (versionCode 1)

First baseline: milestones M0 (DNS-only feasibility harness) and M1 (LAN inventory).

### Added
- DNS firewall `VpnService` that routes only a virtual resolver into the tunnel. It filters with
  AdGuard-style, hosts and plain-domain lists plus JSON policy rules (per-app, per-profile);
  resolves via network DNS, plain UDP, DoT or DoH; fails closed (SERVFAIL); attributes queries to apps.
- Split DNS for local zones (`.local`, `home.arpa`, private reverse zones).
- Status screen showing transport, resolver, rule count, failure policy, physical network and warnings.
- LAN scanner: mDNS, SSDP/UPnP, ICMP/TCP probing, reverse DNS and ARP, with conservative
  evidence-based device identity, user labels, history, JSON/CSV export and new-device notifications.
- Pure-JVM `engine` and `discovery` modules with 67 host unit tests.
- Architecture docs, threat model, test plan, ADRs 0001–0005 and the policy JSON schema.
