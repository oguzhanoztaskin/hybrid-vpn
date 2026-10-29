package com.oguzhanstech.hybridvpn.data

import android.content.Context
import com.oguzhanstech.hybridvpn.engine.dns.BlockResponse
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class UpstreamMode { NETWORK, UDP, DOT, DOH }

enum class LogMode { OFF, MEMORY, PERSISTENT }

/**
 * Packet engine. FULL_TUNNEL (the Go engine) is the default and runs every module; DNS_ONLY is the
 * fallback, used when chosen or when the build has no Go engine, and runs only the DNS firewall.
 */
enum class EngineMode { FULL_TUNNEL, DNS_ONLY }

data class Settings(
    /** NETWORK uses the resolver the current Wi-Fi/cellular network provides; no third party is chosen for the user. */
    val upstreamMode: UpstreamMode = UpstreamMode.NETWORK,
    val udpServers: String = "9.9.9.9, 149.112.112.112",
    val dotHost: String = "dns.quad9.net",
    /** Must accept HTTP/1.1 (Quad9's DoH endpoint does not; its DoT endpoint is fine). */
    val dohUrl: String = "https://cloudflare-dns.com/dns-query",
    val blockResponse: BlockResponse = BlockResponse.NULL_IP,
    val logMode: LogMode = LogMode.MEMORY,
    val retentionDays: Int = 7,
    val profile: String = "default",
    val notifyNewDevices: Boolean = true,
    val engineMode: EngineMode = EngineMode.FULL_TUNNEL,
    /** The DNS module: filter lists and my rules. Off, DNS is still resolved (and logged), never blocked by lists. */
    val dnsFiltering: Boolean = true,
    /** Performance: the full tunnel's large MTU ([com.oguzhanstech.hybridvpn.vpn.TunConfig.FULL_TUNNEL_MTU]); off, 1500. */
    val largeTunnelPackets: Boolean = true,
    /** Performance: RACK loss detection in the engine's stack facing apps; off saves CPU in bulk transfers. */
    val tcpLossDetection: Boolean = true,
    /** Performance: TCP flows routed to OpenVPN are forwarded as packets, without a second TCP stack. */
    val openvpnPacketForwarding: Boolean = true,
    /** Optional echo proxies; unsupported ICMP types stay blocked. */
    val allowIcmp: Boolean = false,
    val allowIcmpv6: Boolean = false,
    /** Let discovery and local connections use Wi-Fi/Ethernet outside the VPN. */
    val lanBypass: Boolean = false,
)

/** Small, synchronous preferences; secrets never go here (there are none yet in M0/M1). */
class AppSettings(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val state = MutableStateFlow(load())
    val settings: StateFlow<Settings> = state.asStateFlow()

    fun update(transform: (Settings) -> Settings) {
        val next = transform(state.value)
        prefs.edit()
            .putString("upstreamMode", next.upstreamMode.name)
            .putString("udpServers", next.udpServers)
            .putString("dotHost", next.dotHost)
            .putString("dohUrl", next.dohUrl)
            .putString("blockResponse", next.blockResponse.name)
            .putString("logMode", next.logMode.name)
            .putInt("retentionDays", next.retentionDays)
            .putString("profile", next.profile)
            .putBoolean("notifyNewDevices", next.notifyNewDevices)
            .putString("engine", next.engineMode.name)
            .putBoolean("dnsFiltering", next.dnsFiltering)
            .putBoolean("largeTunnelPackets", next.largeTunnelPackets)
            .putBoolean("tcpLossDetection", next.tcpLossDetection)
            .putBoolean("openvpnPacketForwarding", next.openvpnPacketForwarding)
            .putBoolean("allowIcmp", next.allowIcmp)
            .putBoolean("allowIcmpv6", next.allowIcmpv6)
            .putBoolean("lanBypass", next.lanBypass)
            .apply()
        state.value = next
    }

    private fun load(): Settings {
        val d = Settings()
        return Settings(
            upstreamMode = enumOr(prefs.getString("upstreamMode", null), d.upstreamMode),
            udpServers = prefs.getString("udpServers", null) ?: d.udpServers,
            dotHost = prefs.getString("dotHost", null) ?: d.dotHost,
            dohUrl = prefs.getString("dohUrl", null) ?: d.dohUrl,
            blockResponse = enumOr(prefs.getString("blockResponse", null), d.blockResponse),
            logMode = enumOr(prefs.getString("logMode", null), d.logMode),
            retentionDays = prefs.getInt("retentionDays", d.retentionDays),
            profile = prefs.getString("profile", null) ?: d.profile,
            notifyNewDevices = prefs.getBoolean("notifyNewDevices", d.notifyNewDevices),
            // "engine" replaced "engineMode" when the full tunnel became the default; the old key is ignored.
            engineMode = enumOr(prefs.getString("engine", null), d.engineMode),
            dnsFiltering = prefs.getBoolean("dnsFiltering", d.dnsFiltering),
            largeTunnelPackets = prefs.getBoolean("largeTunnelPackets", d.largeTunnelPackets),
            tcpLossDetection = prefs.getBoolean("tcpLossDetection", d.tcpLossDetection),
            openvpnPacketForwarding = prefs.getBoolean("openvpnPacketForwarding", d.openvpnPacketForwarding),
            allowIcmp = prefs.getBoolean("allowIcmp", d.allowIcmp),
            allowIcmpv6 = prefs.getBoolean("allowIcmpv6", d.allowIcmpv6),
            lanBypass = prefs.getBoolean("lanBypass", d.lanBypass),
        )
    }

    private inline fun <reified E : Enum<E>> enumOr(name: String?, default: E): E =
        name?.let { n -> enumValues<E>().firstOrNull { it.name == n } } ?: default
}
