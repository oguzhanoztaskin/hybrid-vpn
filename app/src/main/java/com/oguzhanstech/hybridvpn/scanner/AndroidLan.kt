package com.oguzhanstech.hybridvpn.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import com.oguzhanstech.hybridvpn.discovery.NetworkBinding
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.Socket

data class LanInfo(
    val network: Network,
    val interfaceName: String?,
    val address: String,
    val subnet: Cidr,
    val gateway: String?,
    val ssid: String?,
    val isWifi: Boolean,
) {
    /** Wi-Fi networks are identified by SSID when Android reveals it (needs location access). */
    val key: String get() = ssid?.let { "wifi:$it" } ?: fallbackKey
    val fallbackKey: String get() = "lan:$subnet|${gateway ?: "?"}"
    val displayName: String get() = ssid ?: "LAN $subnet"
}

object AndroidLan {
    /** What WifiManager reports when the SSID is redacted (WifiManager.UNKNOWN_SSID is API 30+). */
    private const val UNKNOWN_SSID = "<unknown ssid>"

    /** The physical LAN (Wi-Fi or Ethernet) with an IPv4 address, ignoring VPNs including our own. */
    @Suppress("DEPRECATION") // allNetworks/connectionInfo remain the simplest synchronous APIs for this.
    fun current(context: Context): LanInfo? {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
            if (!wifi && !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) continue
            val lp = cm.getLinkProperties(network) ?: continue
            val link = lp.linkAddresses.firstOrNull { it.address is Inet4Address && !it.address.isLoopbackAddress } ?: continue
            val address = link.address.hostAddress ?: continue
            val gateway = lp.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress
            val ssid = if (wifi) {
                context.applicationContext.getSystemService(WifiManager::class.java)?.connectionInfo?.ssid
                    ?.removeSurrounding("\"")?.takeIf { it.isNotBlank() && it != UNKNOWN_SSID }
            } else null
            val subnet = Cidr.of(link.address.address, link.prefixLength)
            return LanInfo(network, lp.interfaceName, address, subnet, gateway, ssid, wifi)
        }
        return null
    }

    fun binding(lan: LanInfo): NetworkBinding = object : NetworkBinding {
        override val networkInterface: NetworkInterface? =
            lan.interfaceName?.let { runCatching { NetworkInterface.getByName(it) }.getOrNull() }

        override fun bind(socket: DatagramSocket) = lan.network.bindSocket(socket)
        override fun bind(socket: Socket) = lan.network.bindSocket(socket)
    }
}
