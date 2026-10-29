# ADR 0010: Optional LAN discovery and connections outside the VPN

Status: accepted (0.5.0).

## Context

The full tunnel forwards outbound TCP/UDP flows and blocks multicast and limited broadcast at
its router. A discovery announcement can require a new incoming connection (KDE Connect), not
just a reply to the originating UDP association. Re-sending the announcement from a protected
socket does not give Android apps ordinary bidirectional LAN connectivity or multicast membership.

## Decision

Add an off-by-default **LAN discovery & connections** switch under Settings → Network compatibility.
When enabled in full-tunnel mode, let Android route connected Wi-Fi/Ethernet subnets, IPv4 limited
broadcast, IPv4/IPv6 multicast and IPv4/IPv6 link-local destinations outside the VPN. This is an
explicit destination-based bypass for **all IP protocols**, not a UDP relay or a change to Go's
guards. The app shows that these destinations bypass policy and filtering, including hard-coded
DNS sent directly to LAN devices. System DNS still targets the virtual resolver, whose explicit
host routes remain in the VPN even if a physical prefix overlaps it.

Connected prefixes come from physical Wi-Fi/Ethernet LinkProperties addresses, including IPv6;
cellular and VPN interfaces, default prefixes and blanket RFC1918 exclusions are not used.
On Android API 24+, the VPN installs the complement of the excluded CIDRs through addRoute, so
it has the same behavior without requiring API 33's excludeRoute. Address-based routing cannot
exempt only UDP; it must also allow local unicast traffic to preserve discovery follow-up and
incoming connections. No application is globally excluded and no internet default is bypassed.

A setting change requires Restart now. On-link prefix additions/removals automatically restart
the tunnel so old LAN exclusions do not persist after moving networks. Existing connections may
be interrupted by that restart. The active prefixes appear in Status and the routing view.

## Consequences

- LAN discovery and incoming LAN sessions can use Android's real network sockets and addresses.
- These destinations bypass per-app blocks, transport rules and DNS filtering, even if the Go
  engine fails or the saved policy is invalid. This is the explicit scope of enabling the option.
- Android's Block connections without VPN may prohibit the bypass. This setting is never changed
  by the app. Each application's LAN permissions, multicast handling and device firewall still apply.
- Other destinations keep the normal firewall and routing behavior. The switch stays off by default.
- This does not relay multicast across Tailscale/OpenVPN, forward incoming tailnet connections,
  or join multicast groups on behalf of other applications.

## Verification

Host tests cover default full routes, exact IPv4/IPv6 CIDR subtraction, multicast/broadcast and
link-local ranges, unrelated private/tailnet/internet destinations, overlapping exclusions and
removing a previous LAN prefix. Device results are recorded in docs/TEST_PLAN.md.
