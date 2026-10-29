package com.oguzhanstech.hybridvpn.discovery

import java.net.DatagramSocket
import java.net.NetworkInterface
import java.net.Socket

/**
 * Pins discovery traffic to the physical LAN rather than whatever the default route is.
 * On Android this binds sockets to the Wi-Fi `Network`, so scanning keeps working (and never
 * enters our own tunnel) while the VPN is up.
 */
interface NetworkBinding {
    /** Interface used for outgoing multicast; null lets the OS choose. */
    val networkInterface: NetworkInterface?

    fun bind(socket: DatagramSocket)
    fun bind(socket: Socket)

    object Unbound : NetworkBinding {
        override val networkInterface: NetworkInterface? = null
        override fun bind(socket: DatagramSocket) = Unit
        override fun bind(socket: Socket) = Unit
    }
}
