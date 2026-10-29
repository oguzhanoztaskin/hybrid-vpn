# Benchmarks

Compares the default **DNS-only** engine with the experimental **Go full-tunnel** engine (M2a,
ADR 0007), plus **VPN off** as a reference. Results: [results.md](results.md). Raw data:
[`raw/`](raw/), one directory per run, containing JSON lines from `hvbench` and `dumpsys meminfo`
snapshots.

> The first runs came from the Android emulator; they show relative behaviour and catch regressions
> but say nothing about battery. A first phone run (2026-10-25) is in results.md; battery
> measurements over a long unplugged idle are still to do (procedure below).

## Setup

| Item | Value |
| --- | --- |
| Host | Apple-silicon Mac, macOS, Android Emulator with the `Medium_Phone_API_37.0` AVD (arm64-v8a, Android 17) |
| App | Debug build of this branch, all filter lists as configured (≈190k rules), resolver = network DNS (`10.0.2.3`) in all modes |
| Traffic peer | `hvbench server` on the host at `127.0.0.1:5201`, reached from the emulator as `10.0.2.2` through the emulator's built-in user-space NAT |
| Client | `hvbench` (static linux/arm64) run with `adb shell`; shell traffic is subject to the VPN |

## Running

```sh
# once
cd go && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/hvbench-arm64 ./cmd/hvbench && go build -o /tmp/hvbench ./cmd/hvbench && cd ..
adb push /tmp/hvbench-arm64 /data/local/tmp/hvbench && adb shell chmod 755 /data/local/tmp/hvbench
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell appops set com.oguzhanstech.hybridvpn ACTIVATE_VPN allow
/tmp/hvbench server -listen 127.0.0.1:5201 &

# each run (~10 min per mode)
RUNS=3 IDLE_SECONDS=300 docs/benchmarks/run-emulator.sh docs/benchmarks/raw/<date>-<device> off dns go
python3 docs/benchmarks/summarize.py docs/benchmarks/raw/<date>-<device>
```

On a phone: `SERIAL=<serial> SERVER=<lan-ip>:5201 NETWORK_RESOLVER=<router>:53 SKIP_TRANSITION=1`
(the transition test turns Wi-Fi off), and `SKIP_IDLE=1` for every mode but the last, since the idle
phase locks the screen and the next mode needs the UI. Throughput runs also record the CPU they cost
(`"mode":"cpu"` lines: the app's CPU time and system-wide busy time).

`run-emulator.sh` selects the engine by writing the app's preferences (key `engine`) while the app is stopped,
starts protection through the UI, and per mode runs:

| Phase | Command | Notes |
| --- | --- | --- |
| DNS, cached | `hvbench dns -server <resolver> -name example.org -n 200` after a 5-query warm-up | Resolver is the VPN's virtual resolver (`10.215.173.2`), or the network's (`10.0.2.3`) with the VPN off |
| DNS, uncached | `… -name example.net -n 50 -uncached` | Random subdomain per query: always an upstream lookup |
| TCP setup | `hvbench connect -n 40` | Reports handshake time separately (see caveat 1) |
| TCP round trip | `hvbench rtt -n 200` | 1-byte ping-pong on one open connection |
| Throughput ×3 | `tcp-down`/`tcp-up` 128 MiB, `udp -n 20000 -size 1200` | UDP is an unpaced burst (≈64 datagrams per ms) |
| Memory | `dumpsys meminfo` at start, after load, and after idle | PSS, native heap, "private other" (Go's heap lives there) |
| Idle | Screen off, 60 s settle, then 300 s | CPU ticks from `/proc/<pid>/stat`; voluntary/involuntary context switches summed over all threads |
| Transition | 1 GiB download in flight; `svc wifi disable`; probe; `svc wifi enable` | Time until new TCP connections and DNS succeed; whether the bulk flow completed; whether `tun0` stayed up |

Per-thread wake-up attribution (used to find the idle hot spots) samples
`/proc/<pid>/task/*/status` over 60 s with the screen off. The script used is quoted in results.md.

## Caveats

1. **Emulator NAT artefact.** The first data exchange on every new TCP connection to `10.0.2.2` takes
   ≈500 ms, **with the VPN off as well**: a packet capture showed the delay outside our engine, and
   the same delay appears without any VPN. `connect` totals include it, so compare the handshake
   columns and the open-connection round trips instead.
2. **The throughput ceiling is the emulator.** About 250 Mbit/s down with the VPN off, so the engines
   are not being pushed to their own limits.
3. **The "bulk transfer survives Wi-Fi off" result is not meaningful on the emulator.** With the VPN
   off or DNS-only, the app's own socket kept working after `wlan0` went down because the emulator's
   NAT ignores the source address. On a phone the source address changes and plain TCP flows break
   in every mode. In Go mode the outbound socket belongs to the app process on the lost network, so
   Android destroys it.
4. **VPN off isn't an idle baseline for app timers.** Without a foreground service, Android's
   cached-app freezer suspends the process, so its idle cost is near zero for that reason.
5. **No battery numbers.** Context switches per minute are a proxy for wake-ups while the CPU is
   awake. They are not suspend wake-ups and not energy.

## Real-device procedure (battery part not yet run)

On a phone, with the user's consent:

1. Same build, consent and `hvbench` setup. Run the server on a LAN machine
   (`hvbench server -listen <lan-ip>:5201`) and pass `SERVER=<lan-ip>:5201` to the script.
2. Battery: unplug and run `adb shell dumpsys batterystats --reset` before each idle phase (over Wi-Fi
   adb, or with USB charging disabled). Afterwards collect `dumpsys batterystats --charged <pkg>`
   (CPU time, wake-locks, mobile radio active time) and `dumpsys batterystats | grep -i "wake reason"`.
3. Idle for at least 30 minutes with the screen off, so the device can enter Doze.
4. Transition: real Wi-Fi ↔ cellular, not `svc wifi`.
