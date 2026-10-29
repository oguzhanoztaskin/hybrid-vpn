# Routing and policy

## Policy document (v1)

Stored as `policy.json` in app storage and edited under Settings → Edit policy. The schema is
`schemas/policy.v1.schema.json`.

```json
{
  "version": 1,
  "transports": [],
  "default": { "route": "direct", "on_failure": "block" },
  "rules": [
    { "id": "no-smtp", "priority": 10,
      "match": { "destination_cidrs": ["0.0.0.0/0", "::/0"], "protocol": "tcp", "ports": ["25"] },
      "action": { "type": "block" } },
    { "id": "kids-tablet-social", "priority": 50,
      "match": { "apps": ["com.example.social"], "profiles": ["home"] },
      "action": { "type": "block" } },
    { "id": "lan-direct", "priority": 60,
      "match": { "destination_cidrs": ["192.168.0.0/16"] },
      "action": { "type": "route", "route": "direct", "on_failure": "block" } },
    { "id": "filter-lists", "priority": 1000,
      "match": { "domain_lists": ["@all"] },
      "action": { "type": "block" } }
  ]
}
```

### Transports

`transports` declares the named ways out of the device that routes may use. `direct` is implicit,
and `block` is an action, not a transport.

| Type | Status |
| --- | --- |
| `direct` | Implemented |
| `tailnet` | **Implemented with the Go engine.** Must name a configured tailnet (`tailnet:<id>`); membership-checked, no host-network fallback |
| `socks5` | **Implemented with the Go engine** (ADR 0009). Must name a configured proxy (`socks5:<id>`); TCP via CONNECT, UDP via UDP ASSOCIATE; destinations are IP addresses (flows carry no name); an unreachable proxy or a refused destination fails closed |
| `http` | **Implemented**: `http:<id>`, TCP via HTTP CONNECT; optional Basic authentication; UDP/ICMP fail closed |
| `openvpn` | **Implemented when the Go engine links OpenVPN 3 Core** (ADR 0008). Must name an imported profile (`openvpn:<id>`); carries only destinations its server routes (subnet, pushed routes, `redirect-gateway`), only while connected; otherwise fails closed |

A tailnet or OpenVPN profile the user switched off (Status page) is left out of the running policy:
rules routing to it are skipped, so traffic falls through to later rules; an `on_failure` naming it
blocks; a default route naming it becomes `direct`. The saved document is not changed.

A transport id carries identity. Two tailnets are two transports (`tailnet:work`, `tailnet:home`),
and a route reaches exactly the transport it names. Addresses never select a transport, because
tailnets overlap (ADR 0006).

Declaring a type this build cannot run is a **compile error**, not a silent no-op. Ids must be
lower-case letters, digits, `.`, `_`, `:` or `-`; `direct` and `block` are reserved.

### Semantics

- Rules are evaluated in ascending `priority`, with ties broken by `id`. The **first match decides**.
  If nothing matches, `default` applies.
- Within `match`, every non-empty field must match (AND). Within a list, any entry may match (OR).
- A flow attribute that is unknown (null) **never** matches a field that constrains it:
  - `apps`: package names. Flows whose owner could not be attributed match only the token `@unknown`.
  - `domains`: a domain matches itself and all its subdomains.
  - `domain_lists`: list ids (DNS → Lists), or `@all` for every enabled list. `@@` exceptions in any list win.
  - `destination_cidrs`, `protocol` (`tcp`/`udp`/`icmp`/`icmpv6`), `ports` (`"443"`, `"8000-8100"`).
  - `networks` (`wifi`, `cellular`, `ethernet`, `other`), `network_ids` (reserved: not populated yet),
    and `profiles` (Settings → Profile).
- `action` is either `{"type":"block"}` or `{"type":"route","route":"<id>","on_failure":"block"|"<route>"}`.
  When the route's transport is down, `on_failure` (or `default.on_failure`) decides. A fallback
  to another unhealthy transport blocks.

### Validation

A policy compiles completely or not at all: unknown routes, unknown lists, invalid CIDRs, ports or
domains, duplicate ids and malformed actions are all errors. The app refuses to save a failing
policy, and the running VPN keeps its previous one.

Warnings, which don't block saving:

- Overlapping CIDR rules that send traffic to different routes (e.g. a tailnet route shadowing an
  OpenVPN subnet). The warning names the winner.
- Ports without a protocol.

### When changes take effect

Policy, list and resolver changes swap into the running VPN atomically, with no reconnect. Android's
own resolver still caches answers per network for their TTL, though. A name resolved just before you
blocked it keeps resolving until that cached entry expires, and an unblocked name returns after at
most 60 seconds (the TTL on blocked answers). Restarting the VPN flushes the system cache.

### What applies where

| Rule kind | DNS stage (both engines) | IP flows (Go engine) |
| --- | --- | --- |
| `block` on domains / domain lists | Enforced: the query is answered as blocked | — (the name is never resolved) |
| `block` / `route` on apps, CIDRs, protocol, ports | App-only blocks apply to that app's DNS | **Enforced per flow** |
| `route` on domains | **Rejected** by the compiler: IP flows carry no domain | — |
| `profiles`, `networks` | Evaluated per query | Evaluated when the policy is exported; re-exported on profile or network change |

In DNS-only mode per-flow rules cannot be enforced, because no IP traffic passes through the app.
The Status screen says so and shows how many such rules exist.

## Packet routing in the Go engine (M2a/M2b)

The Go engine (ADR 0007) adds a per-flow routing boundary, `engine.Router`, which every flow
passes through:

| Order | Flow | Decision |
| --- | --- | --- |
| 1 | Unspecified, loopback, multicast or broadcast destination | Drop (counted) |
| 2 | Destination port 53, any address, UDP or TCP | DNS firewall (Kotlin `DnsProxy`), never forwarded |
| 3 | Virtual resolver, any other port (e.g. 853) | Drop: TCP reset / ICMP unreachable |
| 4 | Tunnel's own prefixes | Drop (loop guard) |
| 5 | Anything else | `direct` transport (protected socket) |
| — | ICMP / ICMPv6 echo requests | Optional per family (Settings → Network compatibility; off by default); guards and policy apply, then a transport probes reachability |
| — | Non-echo ICMP and other IP protocols | Dropped at ingress before routing (counted) |

After the built-in guards, the policy decides (M2b):

1. Kotlin compiles the policy, then **exports** the rules that act on IP flows for the current
   profile and network (`FlowPolicyExporter`). Package names become Android UIDs.
2. Go evaluates the rules in order. The first match decides; no match takes `default`.
3. A `route` dials only the named transport. If it fails, or can't carry the protocol (e.g. UDP over
   an HTTP CONNECT proxy), **only** an explicitly named `on_failure` transport is tried, and the
   default is `block`. There is no implicit direct fallback.
4. A policy change is installed atomically and applies to new flows; established flows keep their
   transport.
5. A TCP flow whose decision names an OpenVPN transport that can carry it right now is forwarded
   at the IP level instead of through a second TCP stack (ADR 0008, 0.3.3 amendment; Settings →
   Performance can turn this off). The decision, the fail-closed behaviour and what reaches the
   server are the same; only the engine's internal path differs.

**App identity.** Android attributes traffic per UID (`ConnectivityManager.getConnectionOwnerUid`,
Android 10+). The engine asks once per new flow, and only when some rule matches on apps.

- An unattributable flow has an unknown owner. It matches only rules listing `@unknown`, never an
  app rule by accident.
- Apps sharing a UID can't be told apart. A rule naming one applies to all of them, and the policy
  shows a warning saying so.
- A rule naming only uninstalled apps matches nothing, with a warning.

**Routing view.** Status → Routing → Routing paths shows the table as the running engine applies
it (`RoutingTable` in `engine/policy`, published with the VPN state): the built-in guards above,
the policy's rules in evaluation order, then the default. Each row shows its conditions, its target
with live state (connected, not running, …) and flow count, and its fallback. Rules for another
profile or network, and rules whose connection is switched off, are listed as not applied with the
reason. For an OpenVPN target, rule prefixes the server doesn't route are flagged, since flows to
them fail closed. Built-in guards and DNS-stage rules are hidden unless "Show DNS and built-in
rules" is on. Dials that fail are listed in Logs → Engine (transport, protocol, error, count), in
memory only.

**Invalid saved policy.** If the saved policy no longer compiles (for example after a build that
supports fewer transport types), DNS filtering uses the default policy and the Go engine **blocks
every non-DNS flow** until it is fixed, since the routing intent is unknown.

## Split DNS

`LocalZones` keeps local names away from public resolvers (RFC 6761/6762/6303/8375):

| Name | Resolved by |
| --- | --- |
| `*.local` | Nobody: NXDOMAIN, since it is mDNS-only |
| `home.arpa`, `lan`, `internal`, `localdomain`, `intranet`, `corp`, `home`, single-label names | The physical network's resolver |
| Reverse zones of RFC 1918, link-local and ULA space | The physical network's resolver |
| Everything else | The configured resolver (network, custom UDP, DoT, DoH) |

| `*.<suffix>` of a running tailnet (Go engine) | That tailnet only, from its node list (30 s TTL); NXDOMAIN for unknown nodes; SERVFAIL if several tailnets claim the suffix |

OpenVPN-pushed DNS servers and domains are shown per profile but not yet used as zones: queries for
them still go to the configured resolver (ADR 0008).

## Routing-loop protection

- The TUN routes only the two virtual resolver addresses, so upstream traffic cannot re-enter the tunnel.
- Every upstream socket is passed to `VpnService.protect()` **and** bound to the tracked physical
  `Network`. The second step is what will keep this correct once M2 routes everything.
- DoT and DoH hostnames are resolved with `Network.getAllByName()` and `Network.openConnection()` on
  the physical network. The system resolver would ask us, and we would deadlock on ourselves.
- LAN discovery sockets are bound to the Wi-Fi `Network` directly.
- Go engine: every outbound socket is protected through a JNI upcall before `connect`. If protection
  fails, the dial fails. Flows to the tunnel's own prefixes are dropped by the router.

## Domain ↔ IP association (future)

Spec §4.2 warns that IP traffic does not identify a unique domain. When M2 adds IP flows, domain
rules will match via DNS-observed associations carrying TTLs and an "ambiguous" flag. Rules will
never assume a single domain per IP.


## Optional ping

IPv4 and IPv6 echo checks are separately enabled under Settings → Network compatibility and require
restarting the VPN. Direct, Tailscale and OpenVPN can probe; SOCKS5 cannot, so it blocks unless a
fallback is explicitly configured. The reply is proxied only after a real remote ICMP response:
original ID, sequence and data are retained locally, while the probe has independent data and TTL.
This supports reachability checks, not traceroute, raw ICMP, end-to-end echo payload tests or PMTU.

Use `protocol: "icmp"` / `"icmpv6"` and/or CIDRs for echo policy. Ports do not apply. Android only
attributes TCP/UDP, so echo ownership is always unknown; app matchers only match `@unknown`.
Non-unicast, virtual-resolver and loop guards still apply. This does not add multicast discovery
or incoming connections for KDE Connect.


## Optional LAN discovery & connections

Settings → Network compatibility → LAN discovery & connections (off by default) adds a
**destination-based bypass before the Go engine**. It applies to all IP protocols, not only UDP:

- Connected Wi-Fi/Ethernet subnets, from physical LinkProperties addresses (IPv4 and IPv6).
- `255.255.255.255/32`, IPv4 multicast `224.0.0.0/4`, IPv6 multicast `ff00::/8`.
- IPv4 link-local `169.254.0.0/16` and IPv6 link-local `fe80::/10`.

Local UDP discovery, its unicast replies and incoming local TCP sessions use the real network.
Those destinations bypass every VPN policy rule and the DNS firewall, including hard-coded DNS
sent to LAN hosts. System DNS still goes to the VPN's virtual resolver, with explicit host routes
that override exclusions. Unrelated private networks, tailnet addresses and internet destinations
remain inside the VPN unless actually part of a connected LAN prefix. Go still drops any
non-unicast packets that do reach its TUN. This does not forward incoming Tailscale connections
or relay multicast across transports.

A toggle change requires a restart. Physical LAN prefix changes automatically restart the VPN
and replace the exclusions; Status and the routing view show the active prefixes. Android's
Block connections without VPN may prevent bypassed traffic. See ADR 0010.


## HTTP proxies

Add an HTTP proxy under Settings → HTTP / SOCKS5 proxies. The default port is 8080, matching
mitmproxy regular mode. Use Route apps or Route all traffic, or a policy route naming `http:<id>`.
HTTP appears before SOCKS5 in the UI; existing priorities, first-match ordering and explicit
fallback behavior are unchanged. HTTP supports TCP only. UDP (including QUIC) and ICMP sent to it
block unless on_failure explicitly selects another transport. DNS and optional LAN bypass keep
their existing behavior. HTTP health checks show TCP reachability; credentials are checked on the
first CONNECT request. Existing SOCKS5 entries keep their addresses, passwords and transport IDs.


## Deleting a connection (0.6.0)

Deleting a profile/tailnet/proxy removes its transport declaration and replaces rules routing to it
with explicit blocks, preserving their matches, priority and enabled state. Fallbacks naming it
become block. If it was the default route, a final IP-only catch-all block preserves unmatched
traffic blocking while earlier explicit rules and DNS retain their behavior. The app repairs stale
references left by older deletions when loading the running policy and persists that repair.

This differs from temporarily switching a connection off, whose rules are still skipped. The
removal message explains the blocking behavior; edit the policy to select another path. Existing
connections retain their transport until a restart, as with other policy changes.
