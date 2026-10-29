package com.oguzhanstech.hybridvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.net.NetworkInterface

/**
 * The physical (non-VPN) networks' interfaces, for Tailscale's interface monitor. Android denies
 * apps the netlink calls behind net.Interfaces, so Tailscale's own Android app supplies this list
 * from Java too. Our own tunnel is excluded: its address is not a way to reach peers.
 */
fun physicalInterfacesJson(context: Context): String {
    val cm = context.getSystemService(ConnectivityManager::class.java)
    val out = JSONArray()
    @Suppress("DEPRECATION")
    for (network in cm.allNetworks) {
        val caps = cm.getNetworkCapabilities(network) ?: continue
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
        val lp = cm.getLinkProperties(network) ?: continue
        val name = lp.interfaceName ?: continue
        val index = runCatching { NetworkInterface.getByName(name)?.index }.getOrNull() ?: 0
        out.put(
            JSONObject()
                .put("name", name)
                .put("index", index)
                .put("mtu", if (Build.VERSION.SDK_INT >= 29 && lp.mtu > 0) lp.mtu else 1500)
                .put("addrs", JSONArray(lp.linkAddresses.map { "${it.address.hostAddress?.substringBefore('%')}/${it.prefixLength}" }))
        )
    }
    return out.toString()
}
