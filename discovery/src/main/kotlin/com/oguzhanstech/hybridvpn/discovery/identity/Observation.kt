package com.oguzhanstech.hybridvpn.discovery.identity

import com.oguzhanstech.hybridvpn.discovery.mdns.MdnsService
import com.oguzhanstech.hybridvpn.discovery.ssdp.SsdpDevice

enum class IdentifierKind(
    /** Globally unique kinds may link a device across networks; the rest are scoped to one network. */
    val global: Boolean,
    val strength: Strength,
) {
    MAC(true, Strength.STRONG),
    SSDP(true, Strength.STRONG),
    /** Reserved for router integrations (DHCP lease ids); not produced by active scanning. */
    ROUTER_ID(false, Strength.STRONG),
    MDNS(false, Strength.STRONG),
    HOSTNAME(false, Strength.MEDIUM),
    IP(false, Strength.WEAK);

    enum class Strength { STRONG, MEDIUM, WEAK }
}

data class Identifier(val kind: IdentifierKind, val value: String)

enum class DeviceType { ROUTER, COMPUTER, PHONE, TV, SPEAKER, PRINTER, NAS, CAMERA, SMART_HOME, GAME_CONSOLE, UNKNOWN }

/** Everything learned about one IP address during one scan. */
data class HostObservation(
    val ip: String,
    val mac: String?,
    val mdnsHostname: String?,
    val reverseDnsName: String?,
    val mdnsServices: List<MdnsService>,
    val ssdp: SsdpDevice?,
    val openPorts: Set<Int>,
    val reachable: Boolean,
    val isGateway: Boolean,
    val isSelf: Boolean,
) {
    val identifiers: List<Identifier>
        get() = buildList {
            add(Identifier(IdentifierKind.IP, ip))
            mac?.let { add(Identifier(IdentifierKind.MAC, it.lowercase())) }
            ssdp?.uuid?.let { add(Identifier(IdentifierKind.SSDP, it)) }
            mdnsHostname?.let { add(Identifier(IdentifierKind.MDNS, it.lowercase())) }
            reverseDnsName?.let { add(Identifier(IdentifierKind.HOSTNAME, it.lowercase())) }
            // Being the gateway is a role, not an identity: a replaced router must not inherit the old one's history.
        }

    /** Coarse behavioural fingerprint used only to support weak (IP-only) matches. */
    val fingerprint: String
        get() = (openPorts.sorted().map { "p$it" } + mdnsServices.map { it.type }.distinct().sorted()).joinToString(",")

    val serviceLabels: List<String>
        get() = (mdnsServices.map { "${it.type}:${it.port}" } + openPorts.sorted().map { "tcp:$it" }).distinct()
}
