# ADR 0008: OpenVPN through OpenVPN 3 Core (M5)

Status: accepted for **experimental, debug-only** use, like the Go engine it runs in (ADR 0007).

## Context

ADR 0003 sends OpenVPN through a dedicated adapter around an existing implementation instead of a
reimplementation of the protocol. The candidates:

| Implementation | Licence | Notes |
| --- | --- | --- |
| OpenVPN 2.x (Tunnelblick, ics-openvpn) | GPL-2.0 | A process with its own TUN and scripts; ics-openvpn drives it through the management interface. Would make the whole app GPL. |
| minivpn (Go) | GPL-3.0 | Small, but research-grade and not actively maintained. |
| **OpenVPN 3 Core** (C++, OpenVPN Connect's core) | AGPL-3.0-only **or** MPL-2.0, OpenSSL exception | Library with a client API and a `TunBuilder` abstraction made for Android/iOS; maintained by OpenVPN Inc. |

OpenVPN 3 Core is used under **MPL-2.0**, which applies per file and leaves the app's own licence
free. Known gaps relative to 2.x: no TAP (layer 2), no `fragment`, and no scripts.

## Decisions

**Linked into the Go library.** `go/openvpn/client.cpp` subclasses `ClientAPI::OpenVPNClient` and
is compiled by cgo into `libhybridvpn_go.so` with OpenSSL 3.5 LTS (static), OpenVPN's patched asio
and LZ4. Dependencies are fetched and verified by SHA-256 in `scripts/openvpn3-deps.sh` into
`third_party/` (git-ignored); the Gradle task adds `-tags openvpn3` only when they exist for every ABI.
Without them the app builds as before and `GoBridge.openvpnAvailable` is false. Static libraries are
kept out of the export table (`-Wl,--exclude-libs,ALL`, hidden visibility). Cost: about 7.5 MB per ABI.

**No real TUN.** `tun_builder_establish` returns one end of a packet socket pair (SOCK_SEQPACKET on
Android, because datagram socket pairs on Linux queue only `max_dgram_qlen` packets) and hands the
other end, with the pushed configuration, to Go. Go runs a gVisor netstack per session with the
pushed addresses. The app keeps its single `VpnService` TUN (ADR 0001); the OS never routes to the
VPN.

**A transport like any other.** Each profile is `openvpn:<id>`. The router reaches it only through
a policy rule naming it. The transport dials from its netstack only when the session is connected
and the destination is routed by the server: interface subnet, pushed routes, or the family's
default with `redirect-gateway`, minus excluded routes. Anything else fails closed. There is never
a fallback to the host network, and an address alone never selects a VPN.

**Protected transport sockets.** `socket_protect` calls `VpnService.protect()` (the same upcall as
`direct`). If protection fails the core can't connect, so no tunnel traffic loops into our own TUN.

**Sessions.** The core reconnects by itself after transient failures, with `tunPersist` keeping the
netstack across reconnects. Fatal errors (e.g. `AUTH_FAILED`) end the session, and the UI shows
them. On a physical network change the app asks the core to reconnect now instead of waiting for the
keepalive timeout. `compressionMode = asym`: decompress if a server insists, never compress (VORACLE).

**Profiles.** Only self-contained `.ovpn` files (inline certificates and keys) are accepted. The core
parses them at import. An encrypted private key (common in providers' profiles) needs its password
at import, which is checked right away by decrypting the key with OpenSSL. External PKI and static
challenges are rejected, and every rejection is shown in a dialog. Script directives are accepted by the core and ignored; the app says so at import. Profile
text, passwords and key passwords are encrypted at rest with an AES-GCM key in the Android Keystore (`SecretStore`),
and decrypted only to start the engine. App data is excluded from backups.

**A failed profile doesn't stop the VPN.** If a session can't be created (e.g. credentials missing),
its transport still exists but refuses every flow. Routes naming it fail closed while everything
else keeps working.

## Not yet

- Pushed DNS (servers, split domains) is shown but not used: queries for pushed domains still go to
  the configured resolver. Next step: answer pushed domains through the VPN's DNS server, as for
  MagicDNS.
- Proxy settings, challenge/response, and external certificates (Android KeyChain).
- Data-channel offload; the userspace path is the only one.

## Testing without root or containers

`go/ovpnlab` runs a real OpenVPN 2.7 server on macOS without root. `scripts/ovpnlab/utunshim.c` is
injected with `DYLD_INSERT_LIBRARIES` and answers the server's utun calls with a Unix socket. Behind
that socket, a userspace stack serves TCP and UDP test endpoints on the VPN subnet and on a network
reachable only via a pushed route. A fresh PKI and `tls-crypt` key are generated per run. Host tests
(`go test -tags openvpn3 ./openvpn`) cover UDP and TCP transports, IPv4/IPv6, bulk TCP, UDP,
username/password including `AUTH_FAILED`, protection, and fail-closed routing through the engine.
`cmd/ovpnlab` serves the same server to the emulator via 10.0.2.2, or to a phone with `-remote
<lan-ip>`; TCP 5201 behind it speaks `hvbench`'s protocol for throughput runs, and
`BenchmarkLabDownload` measures the host-only baseline. None of this ships in the app.

## Amendment (0.3.3): throughput

Measured on a phone against the local lab server (`docs/benchmarks/results.md`), downloads through
OpenVPN ran at ≈110 Mbit/s with no thread saturated. Three changes:

**Transport socket buffers.** The core never sizes its UDP/TCP transport socket, so it stays at the
system default (224 KiB on Android). Bursts arriving while the core's single thread is busy overflow
it: the kernel counted 25,881 drops on the lab connection during one run, each a loss for TCP inside
the tunnel. `socket_protect` (called for that socket before it connects) now sets 4 MiB receive and
2 MiB send buffers (capped by `net.core.rmem_max`/`wmem_max`). Drops went to zero and downloads to
165–370 Mbit/s. This is the largest effect, and it applies whatever path carries the flows.

**Batched reads from the core.** The session reads the core's packet socket in batches of up to 32
(`recvmmsg` on Android; read-until-empty elsewhere) into netstack views, so packets handed to the
session's netstack are not copied. Read syscalls per 64 MiB downloaded: ≈112,000 → ≈15,000.

**IP-level forwarding of TCP flows ("OpenVPN packet forwarding", Settings → Performance, on by
default).** The session transport implements `engine.PacketTransport`. When the router sends a new
TCP flow (decided on its SYN, off the TUN reader) to an OpenVPN transport that is connected and
whose server routes the destination, the engine forwards the flow's packets itself: the app's
address is replaced by the VPN address (and back), checksums are updated incrementally, the MSS in
both SYNs is clamped to the VPN's MTU, and packets go straight into the core's packet socket. The
second TCP stack and the splice drop out. Returning segments of a flow are coalesced within a batch
(contiguous, identical headers apart from sequence number and PSH, as Linux GRO) into packets of up
to the TUN's MTU before they are written. Anything that doesn't qualify (no path, another
transport, UDP) takes the netstack path as before, where `on_failure` applies; a flow, once
forwarded, stays on the path it started on. The session's own netstack uses ephemeral ports
10000–32767, below Android's range, so forwarded flows (which keep the app's port) can't collide
with it. Effect with the buffer fix in place: upload CPU 3.0–3.8 s → 1.8–2.0 s per 64 MiB,
download CPU ≈20% lower, throughput similar. Without coalescing the forwarded path was *worse*
for downloads: segments crossed the TUN at the VPN's MTU, one syscall each.

Not covered: UDP (still through the session's netstack), and segmentation of large app segments
for uploads (the app's MSS is clamped instead, so uploads cross the TUN at the VPN's MTU).
