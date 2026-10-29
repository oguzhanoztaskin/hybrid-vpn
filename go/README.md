# Go network engine (spike)

Go side of the Kotlin + Go architecture (ADR 0003). Experimental: see
`docs/spikes/go-network-engine.md` for what has and hasn't been verified.

| Package | What |
| --- | --- |
| `engine/` | M2a full-tunnel data plane: TUN ↔ gVisor netstack, `Router` (the single routing boundary), `Direct` transport, DNS interception (ADR 0007) |
| `jni/` | `libhybridvpn_go.so` (`-buildmode=c-shared`): JNI exports for `com.oguzhanstech.hybridvpn.gobridge.GoBridge` and upcalls into it |
| `tailnet/` | Several independent `tsnet` instances in one process, with membership-checked dials; `Instance.Transport()` plugs a tailnet into the router as `tailnet:<id>` (ADR 0006) |
| `cmd/hvbench/` | Benchmark client (runs on the device) and server (runs on the host); see `docs/benchmarks/` |
| `openvpn/` | OpenVPN 3 Core sessions (C++ via cgo, build tag `openvpn3`) as `openvpn:<id>` transports, one userspace stack each (ADR 0008) |
| `httpproxy/` | Regular HTTP proxy transport: TCP CONNECT, Basic authentication, fail-closed routing (ADR 0011) |
| `socks/` | SOCKS5 client (CONNECT, UDP ASSOCIATE, username/password) as `socks5:<id>` transports (ADR 0009) |
| `cmd/socks5lab/` | Local SOCKS5 proxy that logs every request (tailscale.com/net/socks5), for the emulator |
| `ovpnlab/`, `cmd/ovpnlab/` | Local OpenVPN 2.7 test server without root (macOS): tests and the emulator |
| `cmd/tailnetlab/` | Offline test tailnets for the emulator (control, DERP, STUN on host loopback) and a peer mode; see `docs/TEST_PLAN.md` |

## Toolchain

`go.mod` tracks the current upstream: `tailscale.com` v1.104.2, which requires **Go 1.27.3**
(the `go` line in `go.mod`). With an older installed Go and the default `GOTOOLCHAIN=auto`, Go fetches
exactly go1.27.3 once into the module cache, verified against sum.golang.org. Nothing is installed
system-wide, and the Gradle task does the same. To use a system toolchain instead, install Go ≥ 1.27.3
(e.g. `brew upgrade go`).

```sh
cd go
go test ./...                    # host tests: engine (socketpair TUN), two offline tailnets
go test -race ./...

# Optional host check of the JNI glue (needs a JDK with C headers):
CGO_CFLAGS="-I$JDK/include -I$JDK/include/darwin" \
  go build -tags jnihost -buildmode=c-shared -o /tmp/libhybridvpn_go.dylib ./jni
```

OpenVPN needs native dependencies (OpenSSL 3.5, OpenVPN 3 Core, asio, LZ4), fetched by checksum
and built into the git-ignored `third_party/`:

```sh
scripts/openvpn3-deps.sh                 # android_arm64 android_amd64 host (a few minutes)
scripts/ovpnlab/build-server.sh          # macOS: OpenVPN 2.7 test server + utun shim
cd go && go test -tags openvpn3 ./openvpn   # sessions against the local server
```

The Android library is built by the `:app:buildGoJni` Gradle task when an NDK is installed
(`sdk.dir/ndk/<version>`, `ndk.dir` or `ANDROID_NDK_HOME`). Go is located through `go.executable` in
`local.properties`, then `GOROOT`, then the usual install paths, then `PATH`. Without an NDK the app builds without
the library, and `GoBridge.available` is false.

## Rules

- No log upload: `tailnet.DisableRemoteLogging()` runs before any Tailscale code.
- Routing code reaches transports only through `engine.Router.Dial`. Transports refuse what they
  cannot deliver; they never fall back to another path.
- The raw `tsnet.Server` is not exposed. Its `Dial` falls back to the host network for non-tailnet
  addresses; `tailnet.Instance.Dial` dials the instance's netstack after a membership check.
- Packets don't cross JNI. Only control messages do.
- OpenVPN transports dial only from their own netstack, only to destinations the server routes.
  OpenVPN 3 Core runs no scripts.
