# ADR 0011: HTTP CONNECT proxy transport

Status: accepted (0.6.0).

Regular HTTP proxies, including mitmproxy's default mode on port 8080, are exposed as `http:<id>`
transports. Each TCP flow opens a protected connection to the proxy and requests CONNECT to its
original IP and port. This works for HTTP, HTTPS and TCP protocols the selected server accepts;
no TLS interception or certificate installation is performed by HybridVPN. HTTPS interception at
mitmproxy still requires the originating app to trust its CA.

The transport supports optional HTTP Basic proxy authentication. Response headers are limited to
16 KiB, connect/handshake time to ten seconds, and cancellation closes the handshake socket.
Read-ahead bytes are preserved and TCP half-close is propagated. Only 2xx CONNECT responses
succeed; redirects/refusals fail closed. A 407 marks authentication failure; destination-specific
refusals do not imply the proxy itself is unreachable. Health checks test TCP reachability only,
because HTTP has no destination-free authentication handshake.

UDP and ICMP are unsupported, with no implicit fallback. DNS stays with the existing firewall,
and LAN bypass retains its existing precedence outside the TUN. The existing first-match policy
semantics, priorities and explicit on_failure behavior are unchanged. HTTP precedes SOCKS5 only
in the UI; neither transport chains to the other automatically.

Proxy metadata now includes a type, defaulting to SOCKS5 for older entries. Existing socks.json
and encrypted password storage are retained, avoiding migration of working credentials. An
existing entry cannot change type/transport identity in place. New HTTP entries default to 8080;
new SOCKS5 entries keep 1080. HTTP and SOCKS5 share management, status and routing controls.
