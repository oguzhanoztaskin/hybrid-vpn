# Spike: Go network engine and multiple tailnets

Branch `experiment/go-network-engine`, 2026-10-24. Goal: validate the Go integration (ADR 0003) and
concurrent tailnets (ADR 0006) before building the engine. The existing Kotlin DNS path was not modified.

## Environment

| Item | Found | Notes |
| --- | --- | --- |
| Go | 1.25.5 (Homebrew) | Built with `GOTOOLCHAIN=local`; no toolchain downloads |
| `tailscale.com` | v1.94.2 | Newest release compatible with Go 1.25.5. Latest is v1.104.2, which needs Go 1.27.3 |
| Android SDK | platform 37, build-tools 36, emulator, API 37 arm64 image | — |
| Android NDK | none initially → **r30 (30.0.16248370)** installed with your approval | SHA-1 checked against Google's repository manifest |
| gomobile | not installed, not needed | See "Integration approach" |

## Integration approach

`go build -buildmode=c-shared` with the NDK's clang, plus hand-written JNI exports in a cgo file
(`go/jni`). Gradle's `:app:buildGoJni` task builds `arm64-v8a` and `x86_64` and adds the result as
generated `jniLibs`, **only if an NDK is installed**.

The alternative, `gomobile bind` (used by Tailscale's Android app), generates Java bindings and an
AAR. It needs the `golang.org/x/mobile` tool and is designed for exposing Go APIs as objects. We need
only a handful of control calls plus handing over the TUN fd, so c-shared avoids the extra tool and
keeps the JNI surface explicit. Revisit if the control API grows large.

## Results

### Kotlin ↔ Go call

| Test | Result |
| --- | --- |
| JNI glue on the host: Java → `libhybridvpn_go.dylib` (`version`, `echo` with non-ASCII text) | **Pass** |
| App builds unchanged without an NDK (`GoBridge.available == false`) | **Pass** |
| Android `.so` built with NDK r30 by `:app:buildGoJni` (arm64-v8a, x86_64) | **Pass** |
| ELF LOAD segments 16 KB aligned; APK passes `zipalign -c -P 16` | **Pass** |
| On the API 37 emulator (arm64), the Status screen shows `netcore android/arm64 go1.25.5 · echo ok`: library loaded, both JNI calls returned the expected values | **Pass** |
| DNS firewall regression with the Go library loaded: blocking, `@@` exceptions and AdGuard-list blocks unchanged; no crashes | **Pass** |
| `tsnet` cross-compiles for `android/arm64` | **Pass** (build only; not run on the device) |

### Concurrent tailnets (host, `go/tailnet`, fully offline)

`TestTwoIsolatedTailnets` runs two independent in-process control servers (upstream `testcontrol`),
each with its own DERP/STUN relay. Each tailnet has one remote peer, and our `Manager` runs one
node in each. Everything runs in one process.

| Check | Result |
| --- | --- |
| Two `tsnet` instances run concurrently with separate state, credentials and status | **Pass** |
| Duplicate id or a shared state directory is rejected | **Pass** |
| **Overlapping addresses**: both remote peers are `100.64.0.1` and both of our nodes are `100.64.0.2` | Reproduced by construction |
| Same destination `100.64.0.1:8080` reaches the personal machine via `personal` and the work machine via `work` (TCP) | **Pass** |
| Same for UDP (`:9090` echo) | **Pass** |
| Address owned by neither tailnet → `ErrNotInTailnet`, nothing dialed | **Pass** |
| Removing one tailnet leaves the other working | **Pass** |
| Race detector, 3 runs | **Pass** |

`TestRawTsnetDialFallsBackToHost` confirms the upstream behaviour behind ADR 0006 rule 4: **raw
`tsnet.Server.Dial` connected to a listener on the host network** (`127.0.0.1`) instead of failing.
Our guarded `Instance.Dial` refuses the same destination.

The pre-merge review hardened this further. `Instance.Dial` no longer calls `tsnet.Server.Dial` at
all. It dials the instance's own netstack (`DialContextTCPWithBind`/`DialContextUDPWithBind`),
which has no host-network fallback, so there is no window between the membership check and the
dial. The public accessor to the raw `*tsnet.Server` was removed.

**Not tested: real tailnets.** No credentials were available. Procedure:

1. Create two auth keys in two different tailnets (admin console → Settings → Keys). Use
   ephemeral, pre-approved keys for testing.
2. Add a small Go program (or test, gated on the env vars) that creates a `tailnet.Manager`, adds
   `Config{ID: "personal", StateDir: …, AuthKey: os.Getenv("TS_KEY_PERSONAL")}` and the same for
   `work`, calls `Up` on both concurrently, prints `Status` for each, and dials a known peer in each.
3. Check in both admin consoles that each tailnet saw exactly one new node, and that each node's
   peers contain only its own tailnet.
4. With an address that exists in only one tailnet, confirm the other instance returns `ErrNotInTailnet`.

Keys go in environment variables only, never in files under the repository (`.gitignore` also
excludes `*.authkey` and `tsnet-state*/`).

## Userspace TCP/IP stack options (Go)

| Option | Licence | Status | Integration complexity | Verdict |
| --- | --- | --- | --- | --- |
| **gVisor netstack** (`gvisor.dev/gvisor/pkg/tcpip`) | Apache-2.0 | Maintained; no tagged releases | Medium: we write the TUN link endpoint and TCP/UDP forwarders (~1–2k lines, following known patterns) | **Use.** It's already in the binary through `tailscale.com`, so it adds almost nothing. Must use the gVisor revision `tailscale.com` pins (`v0.0.0-20250205023644-9414b50a5633`) |
| xjasonlyu/tun2socks v2.6.0 | MIT | Maintained (May 2025) | Low as an application, awkward as a library (global engine) | **Reference only.** It pins a different gVisor (`…20250523…`); as a dependency, version selection would move Tailscale onto an untested gVisor |
| sagernet/sing-tun v0.9.6 | **GPL-3.0-or-later** | Maintained | Low–medium; has gVisor and "system" stacks | **Avoid** unless the project licence becomes GPL |
| eycorsican/go-tun2socks (lwIP via cgo) | MIT | **Unmaintained** (last release 2020) | Medium, plus cgo per packet | Reject |
| Tailscale `wgengine/netstack` | BSD-3 | Maintained, internal API | High coupling | Read for patterns (it forwards netstack flows to host sockets in userspace subnet-router mode) |

No new TCP/IP stack will be written.

## Expected packet path (M2+)

```
apps ─► TUN fd ──(Go owns fd; no JNI per packet)──► link endpoint ─► gVisor netstack
                                                                       │ TCP/UDP forwarders
                                                         policy lookup per flow (compiled table)
             ┌──────────────┬───────────────┬──────────────────┬──────┴─────────┬──────────────┐
           direct       socks5/http     tailnet:<id>          openvpn          dns (udp/53 to
     protected socket  via protected   Instance.Dial        adapter           virtual resolver)
     (protect() JNI    socket          (membership-checked, (packet-level)    → Kotlin DnsProxy
      upcall once per                   tsnet netstack +                       via JNI, once per
      socket)                           WireGuard)                             query)
```

Crossings and copies:

- **JNI**: once at start (TUN fd, config), once per new physical socket (`VpnService.protect`, or
  `netns.SetAndroidProtectFunc` for Tailscale's sockets), once per DNS query (bytes in, bytes out),
  plus control and status at human rates. **Never per packet.**
- **Copies per direction**: TUN read into a pooled buffer → netstack (zero-copy views where
  possible) → one splice copy between the netstack connection and the transport connection.
  `tailnet` flows add tsnet's own netstack and WireGuard encryption: two userspace stacks (option A
  in ADR 0006). This is the first thing to benchmark.
- **Backpressure**: TCP through netstack receive windows and bounded splice buffers. UDP through
  bounded per-flow queues that drop when full, with drops counted and shown.
- **Idle**: no polling loops. The TUN reader blocks in `read`. Each tailnet adds its own control
  long-poll, DERP keepalive and magicsock timers, so measure wake-ups with 0, 1 and 2 instances.

## Measurements (indicative, not benchmarks)

| Item | Value |
| --- | --- |
| Bridge-only `libhybridvpn_go.so` (arm64, `-s -w`) | 1.6 MB |
| With `tsnet`/`tailnet` linked (arm64, `-s -w`) | **18.8 MB** (6.6 MB gzipped). Libraries are stored uncompressed in the APK, so expect about +19 MB per ABI; Play split APKs ship one ABI |
| Threads added by loading the Go runtime | ~4 |
| App PSS on the emulator with the bridge loaded, VPN off | ~74 MB (not compared against a baseline yet) |

Follow-up: load the library lazily, only when a Go-backed transport is configured, so DNS-only users
don't pay for the Go runtime at all.

## Open questions carried forward

See ADR 0006. In addition:

- Whether `netmon` works on Android without Tailscale's Java interface getter. Requires running a
  tsnet instance on the device, which needs either a real tailnet or a control server reachable
  from the emulator.
