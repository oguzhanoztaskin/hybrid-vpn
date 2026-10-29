# ADR 0001: One VpnService, many internal transports

Status: accepted (spec §1)

Android allows one active VPN per user. The app therefore owns exactly one `VpnService`. Proxy,
Tailscale and OpenVPN become internal transports selected by the policy engine.
`addAllowedApplication`/`addDisallowedApplication` only decide which apps enter the tunnel; per-app
transport choice happens inside the engine.

Consequence: Tailscale and OpenVPN must be embedded as libraries that accept packets from our TUN
ownership model. Their stock Android apps cannot be reused. This is the project's main risk (ADR 0003).
