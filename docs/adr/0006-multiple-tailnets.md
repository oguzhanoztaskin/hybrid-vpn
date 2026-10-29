# ADR 0006: Several concurrent, isolated tailnets

Status: accepted. **Implemented for debug builds (M4)** with the flow-level approach (A) below:
transports, policy routing and per-tailnet MagicDNS. Verified offline on the emulator. See
"Implementation (M4a)" at the end.

## Requirements

HybridVPN must run several Tailscale identities at once (for example a personal account and a work
account, with more later), alongside OpenVPN, proxies, DNS filtering, LAN discovery and direct traffic.

Each tailnet has:

- its own authentication, node key and state directory (never shared, never inferred from another);
- its own configuration and credentials, encrypted at rest (Keystore, M3+);
- its own connection status (needs login, starting, running, expired, error);
- an explicit route namespace and DNS namespace;
- isolation from every other tailnet by default.

Rules that follow:

1. **Addresses are not globally unique.** Every tailnet allocates from 100.64.0.0/10 and
   fd7a:115c:a1e0::/48, and subnet routers may advertise overlapping RFC 1918 ranges. A destination
   IP alone never selects a tailnet.
2. **Selection is explicit.** Policy routes name a tailnet transport (`tailnet:<id>`). Rules may
   match on app, domain, CIDR and so on, but the action always names exactly one tailnet. When two
   tailnets advertise the same prefix, the policy compiler warns (CIDR conflict detection already
   exists) and priority decides.
3. **No transit between tailnets.** Traffic arriving from tailnet A is never forwarded into tailnet B.
   The engine's default is deny. There is no subnet routing, exit-node service or loopback hairpin
   across instances.
4. **Membership is checked before dialing.** `tsnet.Server.Dial` silently falls back to the host
   network for addresses that no peer owns (`tsdial.Dialer.UserDial` → `SystemDial`). The engine
   must therefore check the tailnet's netmap (peer addresses, approved subnet routes, the selected
   exit node) before handing a flow to an instance. Otherwise it applies the rule's `on_failure`.
   It then dials through the instance's own netstack (`Sys().Netstack` → `DialContext{TCP,UDP}WithBind`),
   which cannot reach the host network, so a netmap change between check and dial can't leak either.
   The raw `*tsnet.Server` is never exposed to routing code.
5. **DNS namespaces.** `*.<tailnet>.ts.net` and each tailnet's split-DNS domains resolve only via
   that tailnet's resolver. When two tailnets claim the same domain, the policy must pick one
   explicitly.
6. **No remote logging.** tsnet uploads logs to `log.tailscale.com` unless disabled. The engine calls
   `logtail.Disable()` and `envknob.SetNoLogsNoSupport()` at process start, before the first instance.

## What upstream `tsnet` provides (v1.94.2 source reading)

| Need | tsnet | Notes |
| --- | --- | --- |
| Several instances per process | Yes. Documented: give each a unique `Dir` | Each has its own `tsd.System`, wgengine, magicsock, gVisor netstack and LocalBackend |
| Separate state and credentials | `Dir`, `Store` (custom `ipn.StateStore`), `AuthKey`, `ControlURL` per instance | `Store` lets us keep state in our own encrypted storage |
| Interactive login | AuthURL reported through `UserLogf` and the LocalAPI | Must be surfaced in our UI per tailnet |
| Outbound TCP/UDP to tailnet | `Dial(ctx, "tcp"|"udp", addr)` | **Connection-oriented**: no ICMP, no raw IP |
| Inbound from tailnet | `Listen`, `ListenPacket`, `RegisterFallbackTCPHandler` | Not needed for M4 |
| Status, peers, routes | `LocalClient()` → `Status`, `WatchIPNBus` | Used for the membership check (rule 4) |
| Exit node | Prefs via `LocalClient().EditPrefs` | Unverified for tsnet `Dial` to internet IPs |
| Socket protection on Android | `netns.SetAndroidProtectFunc` | **Process-wide**; fine, since every instance must be protected |
| Disable log upload | `logtail.Disable()` | Process-wide |
| Android interface monitoring | `netmon` reads `/proc/net/route`; netlink may be restricted for apps | Tailscale's Android app supplies interfaces through `netmon.RegisterInterfaceGetter` (process-wide). Needs testing on a device |

### tsnet is not a TUN router

tsnet terminates connections inside its own netstack. It does not accept arbitrary IP packets from
our TUN. Two integration options exist:

- **A. Flow-level (public API).** Our Go engine terminates TUN flows in its own gVisor netstack,
  decides a route per flow, and for `tailnet:<id>` calls that instance's `Dial` and splices the
  streams. It is simple and stable, and supports TCP and UDP. The cost is two userspace TCP stacks
  per flow (ours plus tsnet's), an extra copy per direction, and no ICMP or raw IP to tailnet peers.
- **B. Packet-level (internal API).** For each tailnet, build `wgengine.NewUserspaceEngine` with our
  own `tun.Device` that receives only packets routed to that tailnet, as Tailscale's Android app does
  with one real TUN. That gives one TCP stack and full IP semantics, but depends on unstable internal
  packages (`ipn/ipnlocal`, `wgengine`, `tsd`) that change between releases.

Start with **A** for M4 and keep the engine's transport interface packet-capable, so **B** can
replace it if the A benchmarks fail the ADR 0003 criteria.

## Unresolved questions

- Does `netmon` work on Android 14–17 for an app without Tailscale's Java interface getter?
- What is the idle wake-up cost of N instances? Each runs its own magicsock, DERP connection and
  control long-poll, so idle traffic scales with N.
- Does tsnet `Dial` reach the internet through an exit node, and how does that interact with rule 4?
- What does MagicDNS resolution look like per instance? Dial `100.100.100.100:53` (UDP) through that
  instance, or use `LocalClient().QueryDNS`?
- Key expiry and re-authentication UX across several accounts.
- Taildrop, Funnel and Serve stay out of scope.

## Implementation (M4a)

- **Where tailnets run.** They run inside the Go engine process, started and stopped with it (Go
  full-tunnel mode, debug builds). Each configured tailnet is one `tsnet` instance with its own
  state directory (`files/tailnets/<id>`), registered with the router as transport `tailnet:<id>`.
  Adding or removing a tailnet takes effect at the next start.
- **Reaching a tailnet.** Only through a policy rule naming the transport. The policy compiler
  rejects tailnet transports that are not configured. Until an instance is Running, its transport
  refuses flows, and the rule's `on_failure` (default `block`) applies.
- **Login is interactive.** The app shows the login URL. No auth keys or other credentials are
  stored by the app.
- **Android specifics**, handled as Tailscale's own app does:
  - `netns.SetAndroidProtectFunc` sends every Tailscale socket through `VpnService.protect()`.
  - `netmon.RegisterInterfaceGetter` is fed from Kotlin with the physical networks' interfaces.
    `net.Interfaces` is denied to apps, and the routing-based fallback would report our tunnel.
  - `TS_LOGS_DIR`/`TMPDIR` point to app-private directories. Without them `tsnet` panics in an app
    process. Uploads stay disabled.
  - On network changes the app triggers LocalAPI `rebind`/`restun`, because `netmon` on Android
    polls only every 10 minutes.
- **Verified** (emulator, offline lab `go/cmd/tailnetlab`):
  - Two tailnets run concurrently in the app with identical addresses.
  - The same peer address reaches the personal or the work machine depending only on the route.
  - Unrouted tailnet traffic is blocked.
  - It survives Wi-Fi off/on and restarts with the same identities.

- **Snapshots.** Each instance keeps its peers' addresses, approved subnet routes and MagicDNS names,
  refreshed from the IPN bus (state, self and peer add/remove/replace events; endpoint-only patches
  are ignored). Membership checks and name lookups read the snapshot, so no LocalAPI call is made per flow.
- **MagicDNS names (rule 5).** The Kotlin DNS firewall asks the tailnets after its block decision and
  before any upstream:
  - a name under exactly one tailnet's suffix is answered from that tailnet (30 s TTL);
  - an unknown node under that suffix gets NXDOMAIN, without asking anywhere else;
  - a suffix claimed by several tailnets gets SERVFAIL;
  - tailnet names never reach a public resolver.

  Verified on the emulator, including a peer joining while running (resolvable within 1 s).

### Still open

- **Short names and split DNS:** names must be fully qualified. Search domains and tailnet split-DNS
  routes to other resolvers are not applied.
- **Name versus route:** a name resolved via tailnet A yields an address. If that address also exists
  in tailnet B, the policy decides which tailnet the connection uses; the DNS origin does not carry
  over to the flow. Route rules must be written accordingly.
- **Real tailnets:** not tested against Tailscale's coordination server. That needs your accounts, or
  ephemeral auth keys entered at test time.
- **Node keys at rest:** stored in app-private storage without additional encryption (Keystore
  wrapping is planned, see THREAT_MODEL).
- **Interface list freshness:** it is pulled when Tailscale polls, so LAN-direct paths may use stale
  addresses for up to 10 minutes after a change. DERP and STUN recover immediately.
- **Size:** the Go library grows from 1.6 MB to ~22 MB per ABI. It is also linked into release
  builds, where tailnets are disabled; a build tag could drop it there.


### Amendment (0.4.0): optional ICMP reachability

The connection-oriented tsnet adapter still does not forward raw IP. When an echo family is enabled,
the engine can ask the selected instance to perform a LocalAPI `PingICMP`, after checking membership.
Only an actual ICMP response permits an app-facing echo reply. No host fallback, cross-tailnet
selection or new incoming listeners are added. See ADR 0007's 0.4.0 amendment for proxy semantics.
