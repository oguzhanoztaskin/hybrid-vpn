package com.oguzhanstech.hybridvpn.vpn

import android.net.VpnService
import com.oguzhanstech.hybridvpn.engine.dns.DnsUpstream
import com.oguzhanstech.hybridvpn.engine.dns.UdpUpstream
import com.oguzhanstech.hybridvpn.engine.dns.UpstreamException
import com.oguzhanstech.hybridvpn.engine.dns.UpstreamSockets
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/**
 * Upstream sockets that can never enter our own tunnel: each is protected and bound to the
 * current physical network, and hostnames (DoT/DoH servers) are resolved on that network rather
 * than through the system resolver, which would be ourselves.
 */
class AndroidUpstreamSockets(private val service: VpnService, private val tracker: UnderlyingNetworkTracker) : UpstreamSockets {

    private fun network() = tracker.current?.network ?: throw UpstreamException("no underlying network")

    override fun datagramSocket(): DatagramSocket = DatagramSocket().also { socket ->
        if (!service.protect(socket)) { socket.close(); throw UpstreamException("could not protect socket") }
        network().bindSocket(socket)
    }

    override fun socket(): Socket = Socket().also { socket ->
        // An unconnected java.net.Socket has no file descriptor until something forces one;
        // bindSocket() does, so it must run before protect().
        network().bindSocket(socket)
        if (!service.protect(socket)) { socket.close(); throw UpstreamException("could not protect socket") }
    }

    override fun openHttps(url: URL): HttpURLConnection = network().openConnection(url) as HttpURLConnection

    override fun resolve(host: String): List<InetAddress> = network().getAllByName(host).toList()
}

/** Plain DNS to whatever resolvers the current physical network advertises. */
class NetworkDnsUpstream(private val tracker: UnderlyingNetworkTracker, private val sockets: UpstreamSockets) : DnsUpstream {
    override val description: String
        get() = tracker.current?.let { u -> "network (${u.dnsServers.joinToString { it.hostAddress ?: "?" }})" } ?: "network (none)"

    override fun exchange(query: ByteArray, timeoutMs: Int): ByteArray {
        val servers = tracker.current?.dnsServers.orEmpty()
        if (servers.isEmpty()) throw UpstreamException("the current network advertises no DNS servers")
        return UdpUpstream(servers.map { InetSocketAddress(it, 53) }, sockets).exchange(query, timeoutMs)
    }
}
