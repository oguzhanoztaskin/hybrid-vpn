package com.oguzhanstech.hybridvpn.vpn

import com.oguzhanstech.hybridvpn.engine.net.IpLiteral

/**
 * Addressing for the DNS-only harness (ADR 0002). Only the virtual resolver addresses are
 * routed into the tunnel, so every other packet keeps using the physical network untouched.
 * The ranges are private and deliberately unusual to avoid colliding with real LANs.
 */
object TunConfig {
    const val MTU = 1500
    /**
     * The full tunnel's MTU with large packets on (Settings → Performance, the default). The Go
     * engine terminates every TCP and UDP flow and re-sends it over ordinary sockets, so this MTU
     * never reaches the real network; it only sets how many packets (each a syscall and a netstack
     * pass) a transfer costs between apps and the engine.
     */
    const val FULL_TUNNEL_MTU = 16384
    const val ADDRESS_V4 = "10.215.173.1"
    const val PREFIX_V4 = 30
    const val DNS_V4 = "10.215.173.2"
    const val ADDRESS_V6 = "fdc1:7e57:dead::1"
    const val PREFIX_V6 = 126
    const val DNS_V6 = "fdc1:7e57:dead::2"

    val dnsV4: ByteArray = IpLiteral.parse(DNS_V4)!!
    val dnsV6: ByteArray = IpLiteral.parse(DNS_V6)!!

    fun isVirtualDns(address: ByteArray) = address.contentEquals(dnsV4) || address.contentEquals(dnsV6)

    /**
     * Addressing handed to the Go engine (this file stays the single source of truth), plus the
     * initial per-flow policy, which is installed before the engine reads its first packet.
     */
    fun engineConfigJson(
        policyJson: String,
        mtu: Int = FULL_TUNNEL_MTU,
        disableRack: Boolean = false,
        disablePacketForwarding: Boolean = false,
        allowIcmp: Boolean = false,
        allowIcmpv6: Boolean = false,
        tailnets: org.json.JSONArray = org.json.JSONArray(),
        openvpn: org.json.JSONArray = org.json.JSONArray(),
        http: org.json.JSONArray = org.json.JSONArray(),
        socks5: org.json.JSONArray = org.json.JSONArray(),
        crashLog: String? = null,
        logsDir: String? = null,
        tempDir: String? = null,
    ): String = org.json.JSONObject()
        .put("mtu", mtu)
        .put("disable_rack", disableRack)
        .put("disable_packet_forwarding", disablePacketForwarding)
        .put("allow_icmp", allowIcmp)
        .put("allow_icmpv6", allowIcmpv6)
        .put("tunnel", org.json.JSONArray(listOf("$ADDRESS_V4/$PREFIX_V4", "$ADDRESS_V6/$PREFIX_V6")))
        .put("resolvers", org.json.JSONArray(listOf(DNS_V4, DNS_V6)))
        .put("policy", org.json.JSONObject(policyJson))
        .put("tailnets", tailnets)
        .put("openvpn", openvpn)
        .put("http", http)
        .put("socks5", socks5)
        .put("crash_log", crashLog ?: "")
        .put("logs_dir", logsDir ?: "")
        .put("temp_dir", tempDir ?: "")
        .toString()

    /** Largest DNS payload that fits one TUN packet without fragmentation. */
    fun maxDnsPayload(ipVersion: Int) = MTU - (if (ipVersion == 4) 20 else 40) - 8
}
