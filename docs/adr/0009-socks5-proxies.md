# ADR 0009: SOCKS5 proxies as transports (M3)

Status: accepted. HTTP CONNECT proxies (the rest of M3) are not covered.

## Context

The policy has declared a `socks5` transport type since M0, rejected by the compiler as "not
runnable yet". Users want to send all traffic, or chosen apps, through a SOCKS5 proxy (an SSH `-D`
tunnel, a provider's proxy, Tor on the device), switchable like the other modules.

## Decisions

**Implemented in Go (`go/socks`), not with a library.** `golang.org/x/net/proxy` speaks only
CONNECT; UDP ASSOCIATE is needed for UDP flows. The client is about 500 lines: method negotiation,
username/password (RFC 1929), CONNECT, UDP ASSOCIATE. Tests run against Tailscale's server
(`tailscale.com/net/socks5`, already a dependency), so client and server are independent
implementations.

**A proxy is a transport `socks5:<id>`.** It carries TCP and UDP; each UDP flow gets its own
association (control connection plus a UDP socket to the relay) that ends when either closes, as RFC
1928 requires. Destinations are always IP addresses: flows carry no names, and DNS stays with the DNS
firewall (port 53 never reaches a transport). So the proxy sees IPs, and names resolve the way the
DNS module says, not at the proxy.

**Reached over the physical network.** Proxy sockets are protected (`engine.Direct.DialAddress`).
A host name is resolved by the system resolver; for our own process that query enters the tunnel and
is answered by the DNS firewall, so it works under any routing rule without a loop.

**Fail closed.** An unreachable proxy, a rejected login or a refused destination fails the dial; the
router then tries only an explicit `on_failure` transport. "Route apps" and "Route all traffic" write
rules with `on_failure: block`. A refused destination is reported as the proxy working (it answered);
the other failures mark it "not working" on Status. A configuration Go rejects becomes a proxy that
refuses every flow, so its routes fail closed without stopping the engine.

**Relay address.** A proxy that answers UDP ASSOCIATE with an unspecified (0.0.0.0, ::) or loopback
address means "my own address": it listens on loopback behind a port forward or NAT (found with the
emulator, where 10.0.2.2 forwards to the host's 127.0.0.1). We send to the address we connected to
instead; for a proxy on the device the two are the same. A relay given by host name is refused.

**Credentials.** The password is stored with `SecretStore` (Keystore AES-GCM) like OpenVPN secrets.
The app states that SOCKS5 itself is unencrypted.

**Status.** `Proxy.Check` authenticates without opening a flow at engine start and after every
network change, so Status shows "Reachable" or the error before anything uses the proxy, plus open
TCP/UDP flows and failures.

**mitmproxy is the target proxy.** Verified against mitmproxy 12.2 (`--mode socks5`, with and
without `--proxyauth`): CONNECT, username/password, and HTTPS interception (mitmproxy's certificate
is presented) work. mitmproxy answers UDP ASSOCIATE with "command not supported" (07). The first
such answer marks the proxy TCP-only: later UDP flows to it are refused locally until the next
check (engine start or network change), instead of a control connection and an error line in
mitmproxy for every QUIC attempt. UDP routed there is therefore blocked, which for interception is
what one wants: apps fall back from QUIC to TCP/TLS, which mitmproxy sees. Status shows "TCP only".
The reachability check appears in mitmproxy only as a client connect/disconnect.

The engine forwards a client's half-close (FIN) to the proxy. mitmproxy aborts an HTTP request whose
client half-closes before the response (seen with `nc`); browsers and normal apps don't do that.

## Consequences

- Apps that do their own DNS over UDP/53 or TCP/53 still get the DNS firewall, not the proxy; DoH to
  a third party goes through the proxy like any HTTPS.
- The proxy can see and alter everything it relays; only end-to-end TLS protects content.
- No HTTP CONNECT yet; no SOCKS4; no domain-name CONNECT (would need flows to carry names).
