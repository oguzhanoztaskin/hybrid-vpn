# ADR 0005: Conservative, evidence-based device identity

Status: accepted (spec §9.2)

Each device has a UUID and a set of identifiers. Each identifier carries a kind, a value, a scope and first/last-seen times.

| Kind | Strength | Scope |
| --- | --- | --- |
| MAC, SSDP UUID | strong | global (unique by construction) |
| mDNS hostname | strong | per network (`raspberrypi.local` is not unique) |
| ROUTER_ID | strong | per network; reserved for router integrations |
| Reverse-DNS hostname | medium | per network |
| IP address | weak | per network |

Matching rules:

1. A shared strong identifier links the observation, unless the match is network-scoped and the MAC
   addresses contradict it. When several devices match, the best is chosen and the others are
   reported as possible duplicates, never merged.
2. A reverse-DNS hostname links when no MAC contradicts it.
3. An IP address alone links only when neither side has strong evidence, the IP was seen on this
   network within 7 days, no differing hostname exists, and the open-port and service fingerprint
   is identical.
4. Otherwise a new device is created.

Being the gateway is a role, not an identity: a replaced router does not inherit the old one's history.
User-assigned names always win over discovered names.

Rationale: a duplicate is visible and easy to fix by hand, whereas a wrong merge silently corrupts history.
