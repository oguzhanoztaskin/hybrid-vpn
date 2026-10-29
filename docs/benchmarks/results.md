# Results

## Phone, 2026-10-25 (`raw/2026-10-25-poco-f5`)

Xiaomi POCO F5 (Snapdragon 7+ Gen 2, Android 15), debug build 0.3.1, Wi-Fi to an `hvbench server`
on a Mac on the same LAN (also on Wi-Fi). Tailnet and one OpenVPN profile running. The Mac was under
other load for part of the session, which makes downloads noisy; compare rows measured back to back.

**Main run** (harness, 3 runs each; screen on):

| Metric | VPN off | Go full tunnel, MTU 1500 |
| --- | --- | --- |
| TCP download, Mbit/s | 570–574 (one 218) | 577–586 |
| TCP upload, Mbit/s | 577–588 | 560–578 |
| UDP 1200 B burst loss % | 0–5.9 | 1.3–36.7 |
| TCP handshake p50 / p99, ms | 5.6 / 10.8 | 7.2 / 10.0 |
| TCP round trip on open conn p50 / p99, ms | 4.9 / 10.7 | 5.5 / 8.4 |
| DNS cached p50 / p99, ms | 3.5 / 7.7 (router) | 1.1 / 2.5 |
| DNS uncached p50 / p99, ms | 10.7 / 17.7 | 13.7 / 20.9 |
| App CPU per 128 MiB down / up, s | — | 2.2–2.9 / 1.7–1.8 |
| System busy per 128 MiB down / up, s (all CPUs) | 2.0–5.6 / 1.5–3.0 | 5.0–5.7 / 3.4–3.6 |

**Idle, screen off** (per-thread sampling, 5 min, no screen wake during the sample): **16 wake-ups
and 12 ms CPU per minute** for the whole app with the tailnet and OpenVPN up. The harness's own idle
figure for this run (310 ms/min) is invalid: the phone was unlocked during it.

**TUN MTU** (128 MiB per transfer, 3 runs, screen on, back to back; `mtu.jsonl`):

| | MTU 1500 | 9000 | 16384 (chosen) |
| --- | --- | --- | --- |
| Download, Mbit/s | 216–347 | 548–602 | 564–596 |
| Upload, Mbit/s | 578–597 | 565–591 | 559–602 |
| App CPU, down / up, s | 3.7–5.7 / 1.5–1.6 | 1.5–1.6 / 0.5 | 1.1–1.3 / 0.4 |
| TUN writes (down) / reads (up) | ≈98,500 / ≈93,300 | ≈17,000 / ≈15,200 | ≈12,600 / ≈8,500 |

Memory at 16384 after the runs: ≈21 MB "private other" (Go heap), in line with earlier
measurements at 1500; packet buffers come from 16 KiB chunks either way.

**RACK loss detection** (MTU 16384, alternating sets, 6 transfers each; `rack.jsonl`): app CPU per
128 MiB down 1.41 s with RACK, 1.33 s without (−6%); up 0.47 / 0.45 s (noise). Throughput unchanged.

**OpenVPN** (lab server from `go/ovpnlab` on the Mac, UDP; phone → Wi-Fi → Mac; 64 MiB per
transfer; `openvpn.jsonl`):

| | Down | Up |
| --- | --- | --- |
| Throughput, Mbit/s | 79–141 | 232–281 |
| App CPU per 64 MiB, s | 2.5–3.6 | 2.4–3.2 |
| App syscalls per 64 MiB | ≈70,000 | ≈85,000 |

The same lab server delivers ≈980 Mbit/s to OpenVPN 3 Core on the Mac itself
(`BenchmarkLabDownload`), so the phone-side path is the limit. No single thread was saturated
(busiest ≈20% of a core); the app made ≈13,000 context switches per second: every 1.4 kB packet
crosses the OpenVPN core's thread, a packet socket pair, the session's netstack, the splice and the
engine's netstack.

Follow-up (0.3.3, `openvpn-fastpath.jsonl`; same lab, per 64 MiB, 3 runs each):

| Build | Down Mbit/s | Down app CPU, s | Up Mbit/s | Up app CPU, s | Read / write syscalls (down) |
| --- | --- | --- | --- | --- | --- |
| 0.3.2 (netstack) | 79–141 | 2.5–3.6 | 232–281 | 2.4–3.2 | ≈70,000 / ≈65,000 |
| IP-level forwarding only | 69–101 | 2.4–4.0 | 222–256 | 1.6–2.0 | ≈110,000 / ≈127,000 |
| + batched reads, coalescing | 87–106 | 2.4–2.6 | 109–238 | 1.8–2.2 | ≈20,000 / ≈69,000 |
| + 4 MiB transport socket buffers (0.3.3 default) | 123–216 | 1.6–2.0 | 219–232 | 1.8–2.0 | ≈15,000 / ≈66,000 |
| 0.3.3 with forwarding off (netstack + buffers + batching) | 165–370 | 1.7–2.7 | 182–248 | 3.0–3.8 | ≈15,000 / ≈64,000 |

256 MiB downloads with 0.3.3: 306, 277, 267 Mbit/s forwarded; 238, 338 Mbit/s with forwarding off.
The kernel counted 25,881 receive-buffer drops on the core's socket in the 0.3.2 runs and none
after the buffer change: those drops, not CPU, held downloads at ≈110 Mbit/s. With them gone no
phone thread is saturated (busiest ≈13% of a core); the Mac (running the emulator at the time) and
Wi-Fi now dominate the variation.

Profile of an OpenVPN download on the phone (simpleperf, 8 s, ≈112 Mbit/s; Go frames can't be
unwound on arm64, so the Go side is split by leaf function only):

| Where the app's CPU goes | Share |
| --- | --- |
| OpenVPN 3 Core, total | ≈27% |
| · its UDP socket I/O (one syscall per packet) | 11% |
| · its packet-socket I/O to/from Go | 7% |
| · C++ logic and event loop | 5% |
| · crypto (AES-256-GCM, OpenSSL) | 3% |
| Our Go side, total | ≈65% |
| · syscalls (packet socket, TUN, sockets) | 20% |
| · gVisor (engine's and session's netstacks) | 18% |
| · goroutine hand-offs and scheduling | 14% |
| · copies, pools, allocation | 7% |

So the limit is mostly our plumbing, not OpenVPN's code: each packet is terminated by the engine's
TCP stack, spliced, and re-sent by a second TCP stack inside the session at the VPN's MTU (1500),
then crosses a packet socket into the core. Options, largest first: forward OpenVPN-routed flows at
the IP level (no second TCP stack or splice; needs NAT and MSS clamping), or batch the packet-socket
I/O and enable GRO in the session's stack.

Profile at MTU 1500 (simpleperf, frame pointers, during a download): 44% of the app's CPU at syscall
boundaries, 11% futex (goroutine hand-offs), 6% gVisor RACK loss detection, the rest spread thin.
Checked at 16384: web, OpenVPN route, DNS, UDP 1200 B at 100 Mbit/s (0.6% loss) and 8000 B
datagrams (fragmented, 0.4% loss). Not checked: the tailnet data path (no peer was online), IPv6.

# Emulator, 2026-10-24 — preliminary

Emulator only (API 37 arm64 AVD); not representative of battery or real-device performance.
Methodology and caveats are in [README.md](README.md). **Full benchmarking is deferred** until the
engine is feature-complete; these two runs are kept as a reference point.

## Run 2: after the idle wake-up fix (`raw/2026-10-24-emulator-api37-idlefix`)

| Metric | VPN off | DNS-only (default) | Go full tunnel (M2a) |
| --- | --- | --- | --- |
| TCP download, Mbit/s (median, min–max) | — | 260 (259–260) | 235 (231–236) |
| TCP upload, Mbit/s | — | 154 (144–155) | 156 (146–156) |
| UDP 1200 B burst: offered Mbit/s | — | 201 (199–205) | 438 (434–440) |
| UDP burst: delivered Mbit/s | — | 201 (199–205) | 197 (165–205) |
| UDP burst: loss % | — | 0.0 (0.0–0.0) | 55.2 (52.7–62.4) |
| TCP handshake p50 / p99, ms | —/— | 2.5/6.3 | 2.6/7.8 |
| TCP round trip on open conn p50 / p99, ms | —/— | 0.27/1.66 | 0.25/0.56 |
| DNS cached p50 / p99, ms | —/— | 0.69/24.19 | 1.84/35.31 |
| DNS uncached p50 / p99, ms | —/— | 21.4/46.1 | 19.1/45.2 |
| Idle CPU, ms per minute (screen off) | — | 10.0 | 20.0 |
| Idle voluntary context switches / min | — | 5 | 47 |
| Idle involuntary context switches / min | — | 1 | 34 |
| Threads (idle) | — | 44 | 35 |
| Memory start: PSS / native heap / private other, MB | — | 108 / 11 / 6 | 111 / 11 / 7 |
| Memory load: PSS / native heap / private other, MB | — | 96 / 11 / 6 | 115 / 11 / 23 |
| Memory idle: PSS / native heap / private other, MB | — | 93 / 11 / 6 | 112 / 11 / 23 |
| Wi-Fi off → new connection works, ms | — | 231 | 568 |
| Wi-Fi off → DNS works, ms | — | 460 | 959 |
| Bulk transfer across Wi-Fi off | — | completed | broke (EOF) after 124 MB |
| Tunnel up on cellular / after Wi-Fi back | — | true / true | true / true |

## Run 1: before the fix, with VPN off as a reference (`raw/2026-10-24-emulator-api37`)

| Metric | VPN off | DNS-only (default) | Go full tunnel (M2a) |
| --- | --- | --- | --- |
| TCP download, Mbit/s (median, min–max) | 255 (234–255) | 227 (224–255) | 251 (247–262) |
| TCP upload, Mbit/s | 168 (162–171) | 156 (155–156) | 141 (136–143) |
| UDP 1200 B burst: offered Mbit/s | 215 (203–215) | 219 (198–224) | 450 (445–452) |
| UDP burst: delivered Mbit/s | 215 (203–215) | 219 (198–224) | 184 (177–198) |
| UDP burst: loss % | 0.0 (0.0–0.0) | 0.0 (0.0–0.0) | 59.2 (56.1–60.2) |
| TCP handshake p50 / p99, ms | 3.3/6.1 | 1.4/3.5 | 4.2/9.6 |
| TCP round trip on open conn p50 / p99, ms | 0.30/2.09 | 0.23/0.40 | 0.30/1.97 |
| DNS cached p50 / p99, ms | 3.64/6.07 | 2.98/44.41 | 1.90/49.40 |
| DNS uncached p50 / p99, ms | 12.7/20.1 | 17.5/30.1 | 17.2/42.2 |
| Idle CPU, ms per minute (screen off) | 12.0 | 139.7 | 131.9 |
| Idle voluntary context switches / min | 20 | 497 | 416 |
| Idle involuntary context switches / min | 7 | 152 | 164 |
| Threads (idle) | 32 | 43 | 36 |
| Memory start: PSS / native heap / private other, MB | 79 / 10 / 6 | 109 / 11 / 6 | 120 / 11 / 7 |
| Memory load: PSS / native heap / private other, MB | 77 / 10 / 6 | 97 / 11 / 6 | 118 / 11 / 26 |
| Memory idle: PSS / native heap / private other, MB | 65 / 0 / 1 | 94 / 11 / 6 | 115 / 11 / 26 |
| Wi-Fi off → new connection works, ms | 866 | 837 | 556 |
| Wi-Fi off → DNS works, ms | 1077 | 1509 | 817 |
| Bulk transfer across Wi-Fi off | completed | completed | broke (EOF) after 134 MB |
| Tunnel up on cellular / after Wi-Fi back | false / n/a | true / true | true / true |

## Takeaways

- Idle cost was dominated by two of our own 500 ms timers (the DNS-log publisher, and the DNS-only
  TUN loop's poll timeout). Both are now event-driven: DNS-only idle wake-ups fell from 499/min to
  5/min. The Go runtime itself adds ≈0–3 thread wake-ups per minute.
- Go mode: TCP is roughly on par. An unpaced UDP burst loses ≈55%, because writes into the TUN never
  block the sender; delivered throughput is similar. It also uses ≈20 MB more memory (Go heap,
  "private other").
- In-flight TCP flows break on a Wi-Fi → cellular switch in Go mode; new flows recover in under 1 s.
- **Go forwarding is not ready to become the default.** UDP burst behaviour, memory and real-device
  measurements are open.

## M2b follow-up: UDP (short check, not a benchmark run)

Go mode on the emulator, 20,000 × 1200-byte datagrams:

| Load | Previous relay | M2b relay |
| --- | --- | --- |
| Paced 50 / 100 / 150 Mbit/s | 0% loss | 0% loss |
| Unpaced burst (≈440 Mbit/s offered) | 131 Mbit/s delivered | 220 Mbit/s delivered (path capacity) |

The cause and fix are described in ADR 0007's amendment.

## Scheduled for later

Real-device runs (battery, Doze, real Wi-Fi ↔ cellular), UDP burst handling, Go memory tuning.
