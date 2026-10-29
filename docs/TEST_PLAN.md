# Test plan

## 0.6.0 HTTP proxy and icon (2026-10-29)

| Check | Result |
| --- | --- |
| Go vet and full Go suite; HTTP/SOCKS5 race tests | Pass |
| HTTP adapter: IPv6 CONNECT authority, Basic authentication, buffered payload, half-close, refusals/redirects, malformed/oversized headers, cancellation/socket cleanup, protection failure, unsupported protocols and fail-closed routing | Pass |
| Real mitmproxy 12.2.2 regular mode, with and without authentication: HTTP and intercepted HTTPS against local test servers; wrong password refused | Pass |
| Phone (Xiaomi 23049PCD8G, Android 15): add HTTP proxy through UI (8080 default); saved login and HTTP-first UI order | Pass |
| Phone TCP through HTTP proxy: HTTP 200 and HTTPS 200, certificate issuer mitmproxy | Pass, temporary CIDR/port test route |
| Deleted transport policy | Host tests cover matching rules, disabled rules, fallbacks, maximum-priority ordering and deleted default; device repair checked before release |
| Original chosen launcher artwork | Copied byte-for-byte; adaptive/legacy/round assets built and APK installed |
| Gradle app/core unit tests, discovery tests, assembly and lint | Pass |
| x86_64 runtime, IPv6 proxy server, HTTP proxy through cellular | Not device-tested |

The phone's temporary test proxy/route is removed after verification. Existing app settings and
policy are preserved. Lab-only TLS probes disable certificate verification to inspect mitmproxy's
issuer; HybridVPN does not install a CA or weaken application TLS verification.

## 0.5.0 optional LAN discovery (2026-10-29)

Phone: Xiaomi 23049PCD8G, Android 15, Wi-Fi, debug build installed over 0.4.0.

| Check | Result |
| --- | --- |
| New LAN discovery & connections switch defaults off; enabling it shows Restart now | Pass |
| After restart, Status says Outside VPN and lists the actual Wi-Fi IPv4/IPv6 prefixes plus discovery ranges | Pass |
| KDE Connect to the laptop at `192.168.1.106` with HybridVPN active and LAN bypass enabled | User confirmed working; logs show an incoming TCP identity and successful TLS handshake with `oo-personal` |
| Virtual DNS resolver keeps an explicit `10.215.173.2` route through `tun0`; DNS filtering remains active | Pass (routes and live DNS counters checked) |
| Unit tests: default full routes, exact IPv4/IPv6 subnet exclusion, overlapping/host prefixes, multicast/broadcast/link-local, unrelated private/tailnet/internet routes, removing old LANs | 4 tests pass |
| Gradle engine/discovery tests, debug APK assembly and debug lint | Pass |
| Android Block connections without VPN | Off on this device; never changed |
| Physical Ethernet, Android 7–12, IPv6 multicast service discovery, changing Wi-Fi subnets or Wi-Fi/cellular handover, turning bypass off after this connection | Not tested on a device; route complement/rebuild semantics covered by host tests |

This mode bypasses policy and filtering for the displayed local destinations, for all protocols.
It is not incoming Tailscale forwarding or multicast routing across tunnels. Left enabled on the
user's phone after testing; defaults remain off. See ADR 0010.

## 0.4.0 optional ICMP (2026-10-29)

Phone: Xiaomi 23049PCD8G, Android 15, Wi-Fi, debug build. Installed over the existing app.

| Check | Result |
| --- | --- |
| Settings → Network compatibility: independent IPv4/IPv6 ping switches, off by default; changes offer Restart now; preferences persist | Pass |
| IPv4 enabled, IPv6 disabled: laptop WLAN `192.168.1.106` and `1.1.1.1` answer through the running full tunnel; IPv6 ping gets no reply | Pass |
| Both enabled: IPv6 `2606:4700:4700::1111` answers through the running full tunnel | Pass |
| Both disabled + restart: IPv4 laptop and IPv6 internet probes receive no reply | Pass |
| Unreachable `192.0.2.1` while enabled | No fabricated reply |
| KDE Connect 1.37.0 Custom device list: laptop WLAN address | “Pinged in 11 milliseconds”; device connection still unavailable |
| Host Go tests and vet; race checks for engine, tailnet and OpenVPN | Pass |
| Offline overlapping tailnets: real ICMP via each named instance; non-member refusal | Pass |
| Host OpenVPN 2.7 lab over UDP and TCP: IPv4/IPv6 ICMP through OpenVPN 3; unrouted destination refused; existing TCP/UDP checks | Pass |
| Gradle engine/discovery tests, debug APK assembly, debug lint | Pass |
| Phone Tailscale/OpenVPN echo paths, cellular/network switching | Not tested; existing disabled transports left unchanged |

The feature proxies echo reachability, with independent probe data/TTL; it does not provide arbitrary
ICMP, traceroute, multicast discovery or incoming connections. KDE Connect connectivity remains open.
Host tests also cover reply gating, family switches, policy/unknown-owner blocks, explicit-only
fallback, routing guards, checksums/truncation/fragments, the 64-probe limit and shutdown cancellation.

## Automated (host, `./gradlew :engine:test :discovery:test`)

| Area | Tests | Covers |
| --- | --- | --- |
| IP and CIDR | `NetTest` | IPv4/IPv6 literal parsing without DNS, RFC 5952 formatting, masking, containment, overlap |
| Packets | `PacketTest` | IPv4/IPv6 UDP round trips and checksums, IPv6 extension headers, fragments, truncation, TCP RST (sequence wrap, IPv6) |
| DNS codec | `DnsMessageTest` | Queries, synthesised answers, compression pointers, pointer loops, error responses from unparseable input, truncation |
| Filter lists | `FilterRulesTest` | Adblock/hosts/plain syntax, modifiers, IDN, unsupported vs invalid counts, cross-list exceptions |
| Cache | `DnsCacheTest` | TTL ageing, id rewrite, expiry, negative caching, no SERVFAIL caching |
| Policy | `PolicyTest` | The spec §4.2 example end to end, unknown owners, failure fallbacks, ordering, ports/domains/profiles, whole-policy rejection, CIDR conflict warnings, JSON round trip, switched-off transports skipped (fallbacks block, default goes direct) |
| DNS proxy | `DnsProxyTest` | Block modes, exceptions, cache, split horizon, `.local`, fail-closed SERVFAIL, per-app rules, garbage input |
| UDP upstream | `UdpUpstreamTest` | Real sockets: forged-id answers ignored, client id restored, timeout |
| mDNS | `MdnsCollectorTest` | Type → instance → SRV/TXT → A walk, source-address fallback, no repeated questions |
| SSDP | `SsdpTest` | Header parsing, UUIDs, description parsing with hostile DOCTYPE, plain and chunked bodies, size cap |
| Subnet | `SubnetTest` | Host enumeration, /31, large-subnet narrowing, ARP parsing |
| Identity | `IdentityTest` | Strong, medium and weak matching, MAC conflicts, IP reuse by another device, stale IPs, conflict reporting, classification, aggregation |

## Automated (Go, `cd go && go test -race ./...`)

| Area | Tests | Covers |
| --- | --- | --- |
| Engine | `go/engine` (25) | A socketpair "TUN" with a second gVisor stack as the apps. TCP integrity (8 MiB, SHA-256), half-close, RST when unreachable, loop and resolver-port drops, UDP association, DNS intercepted for any resolver (UDP v4/v6 and TCP framing, never reaching the transport), ICMP dropped and never answered, prompt idempotent `Stop` with a hung DNS callback, no goroutine leak, small-exchange latency, classifier, router decisions, socket protection (fail closed when `protect` fails) |
| UDP bursts | `go/engine` (2) | 64-datagram micro-bursts with zero loss; unpaced overload where every datagram read is relayed or counted as dropped |
| Policy routing | `go/engine` (7) | Per-app TCP/UDP routing via UIDs, explicit unknown owner, CIDR (v4/v6), port and protocol matching, rule precedence and live policy swap, transport failure with and without explicit fallback (no implicit direct), unsupported protocol fails closed, DNS never reaches a transport, validation rejects what can't be enforced |
| DNS proxy | `DnsProxyTest` (9) | Adds tailnet names answered locally (A/AAAA/other types, NXDOMAIN, ambiguous → SERVFAIL), never upstream |
| Policy export | `FlowPolicyTest` (5) | Transport validation (unsupported types, reserved/duplicate ids), domain-matching routes rejected, UID export incl. unknown, shared UIDs and uninstalled apps, profile/network evaluation, default route |
| Tailnets | `go/tailnet` (5) | Includes the real engine routing to two overlapping offline tailnets by policy (port → named tailnet); per-tailnet MagicDNS (case/dot normalisation, NXDOMAIN inside a namespace, late joiners via the IPN bus, ambiguous shared suffix); snapshot built via `Start` |
| SOCKS5 | `go/socks` (9) | Against tailscale.com/net/socks5 (an independent server): TCP CONNECT echo, UDP ASSOCIATE echo, username/password (right, wrong, missing), refused destination keeps the proxy "ready", unreachable proxy, association ends with its control connection, relay address substitution (unspecified/loopback), config validation, failed-config proxy; opt-in `TestMitmproxyCompatibility` against a real mitmproxy (`MITMPROXY_SOCKS`): HTTP, HTTPS intercepted (mitmproxy issuer), wrong password, UDP refused once then locally; the real engine routing app TCP (256 KiB, byte-checked) and UDP to `socks5:lab`, then failing closed (never direct) once the proxy is gone |
| OpenVPN routes | `go/openvpn` (2) | Route membership (subnet, pushed routes, exclusions, mapped addresses, redirect-gateway per family); dial without a session fails |
| OpenVPN sessions | `go/openvpn`, tag `openvpn3`, macOS (7) | Against a local OpenVPN 2.7 server (`ovpnlab`): profile parsing; encrypted private key (PKCS#8/PBES2): password check, missing or wrong password refused with a clear error, right password connects; UDP and TCP servers; pushed addresses, routes, DNS; TCP over IPv4/IPv6 via subnet and pushed route; 4 MiB echo; UDP echo; unrouted destination and stopped session fail closed; username/password incl. `AUTH_FAILED`; socket protection called, and failure prevents connecting; the real engine routing by policy to `openvpn:lab`, with a misrouted network and a stopped VPN failing closed (never direct) |
| OpenVPN import | `OpenVpnScriptsTest` (2) | Script directives in profiles are detected and reported as ignored |
| Tailnets (spike) | `go/tailnet` | Two offline tailnets with overlapping addresses; explicit selection via `Instance.Dial` and the router adapter (`tailnet:<id>`); non-member refusal; independent removal; upstream fallback behaviour |

## 0.3.3 on a phone (2026-10-25, same Xiaomi, debug build, lab server from `cmd/ovpnlab -reuse`)

| Check | Result |
| --- | --- |
| OpenVPN with packet forwarding: lab bulk transfers, the user's real OpenVPN route (HTTP 200), web direct | Pass |
| Transport socket buffers: kernel drop counter on the core's UDP socket stays 0 under bulk download (was 25,881) | Pass |
| Packet forwarding off (preference + restart): same transfers work through the netstack path | Pass |
| Host: fast path carries flows (packet counters), 8 MiB echo intact on both paths, unrouted network still fails closed, nothing after the VPN stops; coalescing and MSS clamp unit tests (incl. an odd-offset MSS); race detector | Pass |
| Not tested: UDP through OpenVPN (unchanged path), IPv6 through OpenVPN, a TCP transport (`proto tcp`) server, two OpenVPN sessions carrying forwarded flows at once, long-idle forwarded flows (2 h timeout) | — |

## 0.3.2 on a phone (2026-10-25, same Xiaomi, debug build)

| Check | Result |
| --- | --- |
| Full tunnel comes up with MTU 16384; web, the user's OpenVPN route, DNS, UDP 1200 B and 8000 B datagrams work | Pass |
| Settings → Performance: switching RACK makes Status offer "Restart now"; after the restart the engine runs with the new setting (preference and switch state checked) | Pass |
| RACK off: transfers work, app CPU per 128 MiB down −6% | Pass |
| OpenVPN through the local lab server (`cmd/ovpnlab -remote <mac-lan-ip>`): import, connect next to the real profile, route 10.9.0.0/24, bulk transfers | Pass (79–141 / 232–281 Mbit/s) |
| Reinstalling to apply settings: once out of six, always-on VPN did not restart after `adb install -r`; a second install brought it back | Observed |
| Not tested: "Large tunnel packets" off through the UI (1500 was measured before the switch existed), tailnet data path, IPv6 | — |

## 0.3.1 on a phone (2026-10-25, Xiaomi 23049PCD8G, Android 15, Wi-Fi + IPv6-only LTE, debug build)

Real OpenVPN server (UDP, tls-crypt, 11 pushed /32 routes) and a real tailnet with 6 machines.

| Check | Result |
| --- | --- |
| Rule routing the server's networks to `openvpn:<id>`: `curl http://35.76.37.226/…` from the shell and in Brave answered (200, 0.7 s) through the VPN | Pass |
| Same client certificate connected from a second device: the server alternates the session, the phone logs `KEEPALIVE_TIMEOUT` and reconnects; flows time out meanwhile (server-side behaviour, not an app bug) | Observed |
| Routing view: OpenVPN rule, tailnet rule and default listed in order with live state and flow count; built-in rows only with the switch on | Pass |
| Status → Tailscale → Devices opens Devices → Tailnets with the machine list | Pass |
| Logs → Engine lists failed dials (OpenVPN timeout, tailnet destinations refused before the machine list arrived) | Pass |
| Not tested: a tailnet that is slow to answer (the cached list path), "no other machines yet" on a fresh tailnet, the "not routed by this server" warning, rules for another network | — |

## SOCKS5 on the API 37 emulator (2026-10-24, 0.3.0 debug build)

Host: `go run ./cmd/socks5lab -listen 127.0.0.1:1080 -user alice -pass secret`; app proxy `10.0.2.2:1080`.

| Check | Result |
| --- | --- |
| Add proxy with username/password; Status shows it "Reachable" after start | Pass |
| "Route all traffic": shell `nc` TCP to 1.1.1.1:80 and neverssl.com:80 answered; the proxy logged both CONNECTs (names resolved by the DNS firewall, proxy sees IPs) | Pass |
| UDP: NTP request to time.google.com:123 answered (48 bytes); proxy logged the UDP ASSOCIATE target | Pass (after fixing a loopback relay address, see ADR 0009) |
| Proxy stopped: TCP gets a reset, UDP gets no answer, nothing goes direct; Status shows "Not working" with the error | Pass |
| Proxy switched off while running: its rule is skipped after the reload, traffic goes direct | Pass |
| mitmproxy 12.2 (`--mode socks5@127.0.0.1:1081 --proxyauth alice:secret`) as the proxy: HTTP from the device answered and shown in mitmproxy; Google's push connection (IPv4 and IPv6) reached mitmproxy, which presented its own certificate (the emulator doesn't trust it, as expected) | Pass |
| mitmproxy and UDP: one UDP ASSOCIATE refused (07), later UDP flows refused locally without contacting mitmproxy; Status shows "Reachable, TCP only" | Pass |
| Not tested: "Route apps" with a real app, a proxy on the internet, IPv6 to the proxy, an app that trusts the mitmproxy CA | — |

## Status modules on the API 37 emulator (2026-10-24, 0.3.0 debug build)

| Check | Result |
| --- | --- |
| Fresh settings key: an install that had DNS-only saved starts in the full tunnel | Pass |
| Status shows DNS, Tailscale, OpenVPN and SOCKS5 cards with live state | Pass |
| Tailnet switched off while running: policy reload accepted (no "Settings not applied"), restart prompt shown; after Restart now the session runs without it | Pass |
| Tailnet switched back on while running: reload accepted, row says "connects at restart" | Pass |
| DNS module off: a listed domain is forwarded upstream instead of blocked; on again: blocked | Pass |
| Logs tab: DNS query log, OpenVPN session log per profile (newest first), engine error log | Pass |
| DNS-only fallback chosen: starts, still filters, Tailscale/OpenVPN rows say they need the full tunnel | Pass |
| Not tested: a real tailnet or a connected OpenVPN server (the lab server was not running), release build, automatic fallback when the Go library is missing | — |

## Go engine on the API 37 emulator (2026-10-24, debug build)

| Check | Result |
| --- | --- |
| Go mode selectable only in the debug build; setting persists; DNS-only stays the default | Pass |
| Full routes (`0.0.0.0/0`, `::/0`) on `tun0`; Status shows the Go transport | Pass |
| Blocking, `@@` exceptions and list blocks through Go → Kotlin DNS firewall | Pass |
| Query to hard-coded `8.8.8.8:53` answered by our firewall (not forwarded) | Pass |
| TCP and UDP to the host through the engine | Pass |
| Ping fails (ICMP dropped by design) | Pass |
| Wi-Fi off/on: tunnel stays up, new connections and DNS recover in <1 s | Pass (see benchmarks) |

## M2b on the API 37 emulator (Go mode, debug build)

| Check | Result |
| --- | --- |
| Per-app block (`com.android.shell` TCP to `10.0.2.2:5201`) → refused; per-rule drop counted | Pass |
| CIDR + port + protocol block for all apps (UDP 5200–5202) | Pass |
| A rule for another app leaves shell traffic untouched; explicit `direct` route carries UDP | Pass |
| Policy declaring an unsupported transport (`tailnet`) → clear error, Go engine blocks non-DNS flows, DNS works | Pass |
| DNS blocking; switching network ↔ DoT resolver while running | Pass |
| Wi-Fi → cellular → Wi-Fi with policy active: tunnel up, TCP and DNS work | Pass |
| Stop/start ×3 with traffic: `tun0` removed each time, file descriptors and threads stable (161 / 41) | Pass |
| UDP paced at 50/100/150 Mbit/s: 0% loss; unpaced overload delivers path capacity | Pass |
| DNS-only idle after M2b: ≈7 thread wake-ups/min | Pass |

## Tailnets on the API 37 emulator (offline lab, debug build)

Procedure (no Tailscale account needed):

```sh
cd go
go build -o /tmp/tailnetlab ./cmd/tailnetlab
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/tailnetlab-arm64 ./cmd/tailnetlab
/tmp/tailnetlab control -tailnets personal,work     # prints one control_url per tailnet (http://10.0.2.2:PORT)
adb push /tmp/tailnetlab-arm64 /data/local/tmp/tailnetlab
```

1. In the app (Go engine selected): Settings → Tailnets → add `personal` and `work` with those control URLs.
2. Policy: declare `tailnet:personal` and `tailnet:work`; route `100.64.0.0/10` TCP 8080 to
   personal, 8081 to work, and block other tailnet traffic.
3. Start protection. Both tailnets show Running with the same address.
4. `adb shell /data/local/tmp/tailnetlab peer -control <url> -name personal` (and `work`), in the background.
5. `adb shell /data/local/tmp/hvbench fetch -server 100.64.0.2:8080` → `personal`; `:8081` → `work`.

| Check | Result |
| --- | --- |
| Two tailnets Running in the app concurrently, both `100.64.0.1` (overlapping) | Pass |
| Same peer address `100.64.0.2`: port 8080 → personal machine, 8081 → work machine | Pass |
| Tailnet port without a route → refused by policy | Pass |
| Wi-Fi off and back on: both tailnets keep working | Pass |
| Stop removes `tun0`; restart restores the same tailnet identities | Pass |
| DNS-only mode: rules reported as not enforced, no tailnet started, no leak | Pass |
| Crash before the fix (`no safe place found to store log state`) captured via the Go crash log, then fixed | Pass |
| MagicDNS: `lab-work.work.lab.ts.net` → work address; the same host under `personal.lab.ts.net` → NXDOMAIN; unknown node → NXDOMAIN; all answered locally (DNS log "Local · tailnet:…"), never upstream | Pass |
| A peer joining while running becomes resolvable within ~1 s (IPN bus refresh) | Pass |

## OpenVPN on the API 37 emulator (local server, debug build)

No root, containers or accounts. The server is OpenVPN 2.7 with a userspace utun (ADR 0008):

```sh
scripts/openvpn3-deps.sh && scripts/ovpnlab/build-server.sh
cd go && go run ./cmd/ovpnlab -dir /tmp/ovpnlab -remote 10.0.2.2     # add -proto tcp, -user/-pass to vary
adb push /tmp/ovpnlab/client.ovpn /sdcard/Download/lab.ovpn
```

1. Go engine selected; Settings → OpenVPN → Import → pick `lab.ovpn`.
2. Start protection: the profile shows connected, VPN addresses, server routes and pushed DNS.
3. "Route its networks", restart protection, then
   `adb shell /data/local/tmp/hvbench fetch -server 10.9.0.1:8080` (and `udpping -server 10.9.0.1:9090`).

| Check (2026-10-24) | Result |
| --- | --- |
| Import through the system file picker; profile parsed by the core and stored encrypted | Pass |
| Connects over UDP: TLS 1.3, X25519MLKEM768, AES-256-GCM, epoch data keys; status shows 10.8.0.2 / fd00:8::1000, routes, DNS `10.8.0.1 for lab.test`, traffic | Pass |
| TCP to 10.8.0.1 (subnet), 10.9.0.1 (pushed route) and fd00:8::1; UDP echo over IPv4 and IPv6; 1–3 ms | Pass |
| Other internet traffic stays direct with "Route its networks" | Pass |
| "Route all traffic" against a server without redirect-gateway: VPN networks work, internet fails closed | Pass |
| Session log in the app; Stop sends the exit notification (server logs `CC-EEN`) | Pass |
| Username/password and private-key-password import dialogs on the emulator | Not run (emulator unstable under host memory pressure); covered by host tests |
| Real-world servers, Wi-Fi ↔ cellular reconnect, real device | Not yet |

## Verified on the API 37 emulator (2026-10-24)

| Check | Result |
| --- | --- |
| Start/stop, foreground notification, consent pre-granted via `appops` | Pass |
| `||example.com^` blocks the name and its subdomains; `@@||www.example.com^` exception; exact hosts rule | Pass |
| Per-app attribution in the DNS log (`com.google.android.gms`, `com.android.shell`, …) | Pass |
| Resolver: network default, DoT (Quad9), DoH (Cloudflare); switched live without reconnecting | Pass |
| AdGuard DNS filter: 190,834 rules (493 unsupported) downloaded, compiled and applied live; ~55 MB Java heap | Pass |
| Wi-Fi → cellular → Wi-Fi with the VPN up: resolution continues, status shows the active network | Pass |
| `.local` names answered NXDOMAIN locally; private PTR queries go to the network resolver | Pass |
| LAN scan with the VPN up: router, DNS host, emulator (named via its own mDNS) found; rescan finds 0 new | Pass |
| User-assigned name survives a rescan | Pass |
| Bugs found and fixed during this run | `protect()` before `bindSocket()` on TCP sockets (DoT), Quad9 DoH needs HTTP/2 (505), TLS close on the main thread crashed Stop |

## Manual device checklist (M0 harness)

Run on a physical device and on the API 37 emulator.

1. Start: consent dialog, then a foreground notification. The status screen shows the resolver, network and rule count.
2. Enable a list with `||example.com^` in My rules. `adb shell nslookup example.com` (or a browser) gets `0.0.0.0`, and the log shows *Blocked* with the app name.
3. Add `@@||example.com^`: it resolves again with no restart.
4. Switch the resolver to DoT, then DoH. Queries still resolve; the status screen shows the new resolver.
5. Toggle Wi-Fi ↔ mobile data while a page loads. Queries keep resolving and the status updates the physical network.
6. Turn on airplane mode. Queries return SERVFAIL quickly and nothing leaks (verify with `tcpdump` on the router).
7. Set Private DNS to a hostname: the warning appears.
8. Revoke by starting another VPN app. The state becomes *Stopped* with the revoke reason.
9. Always-on: enable it in system settings and reboot. The VPN starts without opening the app.

## Manual checklist (M1 scanner)

1. Scan the home network. The router, this phone, and mDNS/UPnP devices appear with sensible types.
2. Rescan after a device's DHCP lease changes: the same device, a new IP in its history.
3. Rename a device and rescan: the name is kept.
4. A device that leaves shows *last seen*; one that returns is not duplicated.
5. Two Raspberry Pis named `raspberrypi.local` stay separate when MACs are visible.
6. Scan with the VPN running. The results are identical.
7. Export JSON and CSV, then open the CSV in a spreadsheet: no formula execution.

## Network lab (M2+)

The spec §11 lab (Linux namespaces: DNS, proxy, OpenVPN server, subnets, traffic generators, pcap
leak assertions) becomes necessary once traffic other than DNS enters the tunnel. It is not built yet.
