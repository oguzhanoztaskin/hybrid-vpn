# Threat model (M0/M1)

## Assets

- **DNS history:** which apps looked up which domains, and when. Highly sensitive.
- **LAN inventory:** devices, names, notes and history for each network the user has scanned.
- **Configuration:** filter lists, policy, resolver choice, VPN and proxy credentials.
- **Integrity of filtering:** the user relies on blocks actually happening.

## Trust boundaries

| Boundary | Crossing data | Controls |
| --- | --- | --- |
| Android OS → VPN service | Packets from the TUN, owner UIDs, VPN lifecycle | Only virtual-resolver routes; strict IPv4/IPv6/UDP parsing with bounds checks; unknown owner = no app match |
| Policy engine → upstreams | DNS queries | Protected sockets bound to the physical network; DoT certificate and hostname verified; DoH over HTTPS |
| Upstreams → app | DNS responses | Response id and question must match the query (UDP); size-bounded parsing; compression-loop limits |
| LAN devices → scanner | mDNS, SSDP, HTTP description XML | Untrusted input: bounded reads (64 KB description, 9 KB packets); description fetched only from the advertising IP over plain HTTP; tag scan instead of an XML parser (no DTD or entity expansion); CSV export escapes formula prefixes |
| Internet → filter lists | List text | HTTPS only (including after redirects); 25 MB cap; unsupported syntax counted, never approximated |
| App → storage | Database, prefs, files | App-private storage; Android backup and device transfer disabled entirely |

## Threats and mitigations

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Routing loop / self-recursion | See ROUTING.md § routing-loop protection | None known in DNS-only mode |
| Spoofed UDP DNS answer | Fresh random source port per query; id and question validation | Off-path attacks still possible with plain UDP; DoT/DoH remove them |
| Upstream outage leaks DNS elsewhere | SERVFAIL on failure; Android only uses the VPN's resolvers while it runs | — |
| Filtering bypass via the app's own DoH/DoT or hard-coded IPs | None in M0 | Documented limitation (spec §5). M2 can block known resolver endpoints |
| Bypass via Private DNS in strict mode | Detected and shown as a warning | User must change the setting |
| Traffic while the VPN is stopped or revoked | Status screen explains Always-on plus Block connections without VPN | The app cannot enforce a kill switch itself |
| Malicious LAN device crafting mDNS/SSDP to crash or exhaust the app | Bounds checks, size limits, timeouts, per-scan caps (1,024 hosts) | Misleading names or types are possible (they are heuristics, labelled with confidence) |
| Wrong identity merge corrupting history | Conservative resolver ([ADR 0005](adr/0005-device-identity.md)); conflicts reported, not merged | Duplicates are possible by design |
| Sensitive logs at rest | Off, memory-only or persistent modes; retention pruning; one-tap delete | Memory mode keeps 1,000 recent queries in RAM while the app process lives |
| Over-broad package visibility | `QUERY_ALL_PACKAGES` is used only to label DNS queries and resolve policy packages | Needs justification if published on Play |
| Telemetry | No analytics or crash SDKs; network use is limited to the user's resolver, user-enabled list URLs and the LAN | — |

### Go full-tunnel engine (M2a, the default)

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Engine traffic loops into the tunnel | Every outbound socket protected via `VpnService.protect()`; failed protection fails the dial; tunnel prefixes dropped | — |
| DNS leak via hard-coded resolvers (e.g. `8.8.8.8:53`) | All port-53 UDP/TCP goes to the DNS firewall regardless of destination | DoH/DoT to third parties is still forwarded (as in DNS-only mode) |
| Fail-open when the engine dies | Panics stop the engine (no process crash); Kotlin keeps the TUN, so traffic is blackholed; Status shows the error | Process death (e.g. OOM kill) tears down the VPN; Android's "Block connections without VPN" is the only guard |
| Netstack forging replies (e.g. ping to any address "succeeds") | Only TCP/UDP enter the promiscuous ingress netstack; optional echo probes require a real remote ICMP reply, and other protocols are dropped and counted | Echo is a reachability proxy with independent payload/TTL; traceroute remains unsupported |
| Resource exhaustion by an app opening many flows | 512 in-flight TCP handshakes, 1,024 UDP associations, bounded buffers | Many established TCP flows still consume memory (≈ buffer size each) |
| Malformed packets from the TUN | gVisor parses and validates; our classifier only reads fixed header offsets after length checks | — |
| Cross-tailnet leakage | The router reaches a tailnet only via `tailnet:<id>`; the adapter checks membership and dials the instance netstack (no host fallback); routes name exactly one transport, addresses never select one; separate state per tailnet | Verified offline only (no real tailnet yet) |
| Tailnet names leaking to public resolvers, or answered by the wrong tailnet | MagicDNS names are answered locally, only by the tailnet owning the suffix; unknown nodes get NXDOMAIN; shared suffixes are refused | Names resolve, but routing still follows policy (an address present in two tailnets goes where the rules say) |
| Tailscale sockets looping into our tunnel | `netns.SetAndroidProtectFunc` protects every control, DERP and WireGuard socket | — |
| Tailnet node keys at rest | App-private storage (`files/tailnets/<id>`), excluded from backup; deleted when the tailnet is removed | Not additionally encrypted yet (Keystore wrapping open) |
| Tailscale telemetry | `logtail.Disable()` and `SetNoLogsNoSupport` before any instance; local log state only, in an app-private directory | — |
| Traffic for a failed or unavailable transport leaking out directly | `on_failure` defaults to `block`; only an explicitly named fallback is tried; a transport that can't carry the protocol fails | — |
| Invalid or stale saved policy silently changing routing | Compiler rejects unsupported transports and domain-matching routes; the Go engine blocks all non-DNS flows while the saved policy is invalid; the UI never saves an invalid policy | DNS-only mode uses the default DNS policy (no flow routing exists there) |
| App rule matching the wrong app | Matching is per Android UID, the platform's unit of attribution; shared UIDs and uninstalled apps produce warnings; unattributed flows match only explicit `@unknown` rules | Shared-UID apps cannot be separated |
| OpenVPN profile running programs | OpenVPN 3 Core has no script support; script directives are ignored and the user is told at import | — |
| OpenVPN server pulling in traffic the user didn't route there | Pushed routes and redirect-gateway never change routing: only a policy rule naming `openvpn:<id>` sends traffic, and only to destinations the server routes; everything else in that rule fails closed | A server pushing `0.0.0.0/0` receives everything a "Route all traffic" rule sends |
| OpenVPN private keys and passwords at rest | AES-GCM with a non-exportable Android Keystore key (`SecretStore`); decrypted only to start the engine; app data excluded from backups | Readable by the app process while running |
| SOCKS5 proxy passwords at rest | Same `SecretStore`; decrypted only to start the engine | Readable by the app process while running |
| SOCKS5 on the wire | Shown in the app: SOCKS5 is unencrypted, so the proxy and networks on the way see destinations, the password and non-TLS payload | Inherent to SOCKS5; use it over a trusted network or for TLS traffic only |
| Proxy down or refusing | A flow routed to the proxy fails (TCP reset, UDP dropped); only an explicit `on_failure` transport is tried, never `direct` implicitly | — |
| Proxy relay spoofing UDP | Datagrams from the relay are accepted only with the flow's own destination as source, unfragmented | A malicious proxy can still forge or read anything it relays |
| OpenVPN traffic looping into our own TUN | The core's transport socket is protected (`VpnService.protect`) before connecting; failure prevents connecting | — |
| IP-level forwarding to OpenVPN sending traffic where the policy didn't | A flow is forwarded only after the router's decision for its SYN names that OpenVPN transport and the session confirms it routes the destination; packets go only into that session's socket; unmatched packets fall back to netstack, never to `direct`; the rewrite touches only addresses, checksums and the SYN's MSS | A server-side view is unchanged: the server sees the VPN address and the app's source port |
| Compression oracle (VORACLE) | The client never compresses (`compressionMode asym`) | — |
| UDP flood from an app | Drops are counted per layer; the relay can't be starved by other flows (per-flow back-pressure) | Excess above path capacity is dropped (inherent to TUN) |

## Explicitly out of scope (spec §2)

TLS interception, certificate installation, payload recording, stealth networking, and custom
cryptography.

## Open items for later milestones

- Pushed DNS from OpenVPN servers: today queries for pushed domains go to the configured resolver,
  which may leak internal names (M5).
- Encrypted, password-protected export and import (M6).
- SBOM, dependency pinning and reproducible builds (M6).


### Optional echo reachability (0.4.0)

IPv4 and IPv6 echo are individually off by default. Enabled requests are checksummed and bounded
(64 concurrent probes, three-second deadline, cancellation on shutdown), pass routing guards and
policy, and cannot create arbitrary raw IP sockets. Direct datagram ICMP sockets must be protected
before connect; Tailscale probes check membership and use only the named instance; OpenVPN checks
connection and server routes. Unsupported/down transports never imply direct fallback. Only a real
ICMP echo reply permits a response to the app. Android cannot attribute ICMP to UIDs, so app-specific
rules cannot govern echo by package; explicit unknown-owner, CIDR and protocol rules apply instead.


### Optional LAN bypass (0.5.0)

Off by default. When explicitly enabled, connected Wi-Fi/Ethernet prefixes, limited broadcast,
multicast and link-local destinations leave the VPN's routing boundary. All IP protocols to those
destinations bypass app/CIDR rules, transport selection and filtering (including direct-to-LAN DNS),
regardless of engine health or policy validity. The UI describes this exception; system DNS still
uses the captured virtual resolver. Only actual connected LAN prefixes are taken from physical
interfaces; no blanket private/tailnet exemptions are added. Prefix changes rebuild the VPN routes
so removed LANs do not remain excluded. Android lockdown is respected and can prohibit this bypass.
LAN applications retain responsibility for local-network permissions and multicast membership.


### HTTP proxy transport (0.6.0)

Each socket to an HTTP proxy is protected before connect. Basic credentials are encrypted at rest
using the existing SecretStore but sent over an unencrypted proxy connection, so that network and
the proxy must be trusted. The adapter does not install a CA or intercept TLS. CONNECT destinations
are literal flow IPs/ports; credentials never go into the tunneled application's request. Handshake
headers are bounded to 16 KiB and ten seconds; cancellation closes the socket. Redirects are not
followed, non-2xx responses fail, and unsupported protocols never imply direct fallback.


### Deleted connections (0.6.0)

Removing a transport never silently redirects its intended traffic: matching route rules become
blocks and removed fallback targets become block. A deleted default blocks unmatched IP traffic;
other explicit routes and system DNS remain usable. Missing connection declarations left by older
versions are retired this way on policy load. Other policy compilation errors still fail closed.
