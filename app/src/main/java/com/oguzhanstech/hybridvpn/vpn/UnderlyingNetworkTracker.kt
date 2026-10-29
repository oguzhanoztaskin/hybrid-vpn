package com.oguzhanstech.hybridvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import com.oguzhanstech.hybridvpn.engine.policy.NetworkKind
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import java.net.InetAddress

data class Underlying(
    val network: Network,
    val kind: NetworkKind,
    val validated: Boolean,
    val dnsServers: List<InetAddress>,
    val interfaceName: String?,
    /** Non-null when the user set Private DNS to a specific hostname; that bypasses our resolver. */
    val strictPrivateDns: String?,
)

/**
 * Tracks the physical (non-VPN) network our upstream sockets must use. The VPN itself becomes
 * the system default network once established, so the default-network callback is useless here.
 */
class UnderlyingNetworkTracker(context: Context, private val onChange: (Underlying?) -> Unit) {

    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val known = LinkedHashMap<Network, Pair<NetworkCapabilities?, LinkProperties?>>()

    @Volatile var current: Underlying? = null
        private set
    /** On-link prefixes of connected Wi-Fi/Ethernet networks, never cellular or VPN routes. */
    @Volatile var lanPrefixes: List<Cidr> = emptyList()
        private set

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = update(network) { it.copy(first = caps) }
        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = update(network) { it.copy(second = lp) }
        override fun onLost(network: Network) {
            synchronized(known) { known.remove(network) }
            recompute()
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(request, callback)
    }

    fun stop() {
        runCatching { cm.unregisterNetworkCallback(callback) }
    }

    private fun update(network: Network, change: (Pair<NetworkCapabilities?, LinkProperties?>) -> Pair<NetworkCapabilities?, LinkProperties?>) {
        synchronized(known) { known[network] = change(known[network] ?: (null to null)) }
        recompute()
    }

    private fun recompute() {
        val lan = synchronized(known) {
            known.values.flatMap { (caps, lp) ->
                if (caps == null || lp == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))) emptyList()
                else lp.linkAddresses.filter { !it.address.isLoopbackAddress && !it.address.isAnyLocalAddress }
                    .map { Cidr.of(it.address.address, it.prefixLength) }
            }.distinct().sortedBy { it.toString() }
        }
        val best = synchronized(known) {
            known.mapNotNull { (network, pair) ->
                val (caps, lp) = pair
                if (caps == null || lp == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
                val kind = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkKind.ETHERNET
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkKind.WIFI
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkKind.CELLULAR
                    else -> NetworkKind.OTHER
                }
                val strict = if (Build.VERSION.SDK_INT >= 28) lp.privateDnsServerName else null
                Underlying(network, kind, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED), lp.dnsServers, lp.interfaceName, strict)
            }.maxWithOrNull(compareBy<Underlying> { it.validated }.thenBy { PREFERENCE.indexOf(it.kind) })
        }
        if (best != current || lan != lanPrefixes) {
            current = best
            lanPrefixes = lan
            onChange(best)
        }
    }

    private companion object {
        val PREFERENCE = listOf(NetworkKind.OTHER, NetworkKind.CELLULAR, NetworkKind.WIFI, NetworkKind.ETHERNET)
    }
}
