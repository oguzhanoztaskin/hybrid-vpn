package com.oguzhanstech.hybridvpn.engine.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Creates sockets for upstream traffic. On Android every socket must be passed through
 * `VpnService.protect()` and bound to the underlying network, and hostnames must be resolved on
 * that network; otherwise upstream DNS traffic would loop back into our own tunnel.
 */
interface UpstreamSockets {
    fun datagramSocket(): DatagramSocket
    fun socket(): Socket
    fun openHttps(url: URL): HttpURLConnection
    fun resolve(host: String): List<InetAddress>

    /** Plain JVM sockets; for tests and host-side tools. */
    object Default : UpstreamSockets {
        override fun datagramSocket() = DatagramSocket()
        override fun socket() = Socket()
        override fun openHttps(url: URL) = url.openConnection() as HttpURLConnection
        override fun resolve(host: String): List<InetAddress> = InetAddress.getAllByName(host).toList()
    }
}

interface DnsUpstream {
    val description: String

    /** Sends [query] and returns the raw response. Blocking; throws [IOException] on failure. */
    fun exchange(query: ByteArray, timeoutMs: Int): ByteArray

    /** Releases pooled connections. May perform network I/O; never call on Android's main thread. */
    fun close() {}
}

class UpstreamException(message: String, cause: Throwable? = null) : IOException(message, cause)

/**
 * Plain DNS over UDP. Each exchange uses a fresh socket (and therefore a fresh random source
 * port) and verifies that the response echoes our id and question, as RFC 5452 recommends.
 */
class UdpUpstream(private val servers: List<InetSocketAddress>, private val sockets: UpstreamSockets) : DnsUpstream {

    override val description = "udp://" + servers.joinToString(",") { "${it.address.hostAddress}:${it.port}" }

    override fun exchange(query: ByteArray, timeoutMs: Int): ByteArray {
        if (servers.isEmpty()) throw UpstreamException("no DNS servers available")
        val question = DnsMessage.parseQuestion(query)
        val perServer = maxOf(500, timeoutMs / servers.size)
        var last: Exception? = null
        for (server in servers) {
            try {
                sockets.datagramSocket().use { socket ->
                    socket.soTimeout = perServer
                    val id = random.nextInt(0x10000)
                    socket.send(DatagramPacket(DnsMessageWriter.withId(query, id), query.size, server))
                    val buf = ByteArray(MAX_UDP_RESPONSE)
                    val deadline = System.currentTimeMillis() + perServer
                    while (true) {
                        val packet = DatagramPacket(buf, buf.size)
                        socket.receive(packet)
                        val n = packet.length
                        if (packet.address == server.address && n >= 12 &&
                            ((buf[0].toInt() and 0xFF) shl 8 or (buf[1].toInt() and 0xFF)) == id &&
                            DnsMessage.parseQuestion(buf, n) == question
                        ) {
                            return DnsMessageWriter.withId(buf.copyOf(n), queryId(query))
                        }
                        val remaining = deadline - System.currentTimeMillis()
                        if (remaining <= 0) throw SocketTimeoutException()
                        socket.soTimeout = remaining.toInt()
                    }
                }
            } catch (e: IOException) {
                last = e
            }
        }
        throw UpstreamException("all UDP upstreams failed", last)
    }

    private companion object {
        const val MAX_UDP_RESPONSE = 4096
        val random = SecureRandom()
    }
}

/** DNS over TLS (RFC 7858) with a small pool of persistent connections. */
class DotUpstream(
    private val host: String,
    private val port: Int = 853,
    private val sockets: UpstreamSockets,
    private val poolSize: Int = 4,
) : DnsUpstream {

    override val description = "tls://$host:$port"

    private val idle = ArrayBlockingQueue<SSLSocket>(poolSize)

    override fun exchange(query: ByteArray, timeoutMs: Int): ByteArray {
        // A pooled connection may have been closed by the server; retry once on a fresh one.
        idle.poll()?.let { pooled ->
            try { return roundTrip(pooled, query, timeoutMs) } catch (_: IOException) { pooled.closeQuietly() }
        }
        val fresh = connect(timeoutMs)
        try {
            return roundTrip(fresh, query, timeoutMs)
        } catch (e: IOException) {
            fresh.closeQuietly()
            throw UpstreamException("DoT exchange with $host failed", e)
        }
    }

    private fun roundTrip(socket: SSLSocket, query: ByteArray, timeoutMs: Int): ByteArray {
        socket.soTimeout = timeoutMs
        val out = DataOutputStream(socket.outputStream)
        out.writeShort(query.size)
        out.write(query)
        out.flush()
        val input = DataInputStream(socket.inputStream)
        val length = input.readUnsignedShort()
        val response = ByteArray(length)
        input.readFully(response)
        if (!idle.offer(socket)) socket.closeQuietly()
        return response
    }

    private fun connect(timeoutMs: Int): SSLSocket {
        val addresses = sockets.resolve(host)
        var last: Exception? = null
        for (address in addresses) {
            val plain = sockets.socket()
            try {
                plain.connect(InetSocketAddress(address, port), timeoutMs)
                val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(plain, host, port, true) as SSLSocket
                tls.soTimeout = timeoutMs
                tls.startHandshake()
                if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, tls.session)) {
                    tls.closeQuietly()
                    throw UpstreamException("certificate for $address does not match $host")
                }
                return tls
            } catch (e: IOException) {
                plain.closeQuietly()
                last = e
            }
        }
        throw UpstreamException("could not connect to $host:$port", last)
    }

    override fun close() {
        while (true) (idle.poll() ?: break).closeQuietly()
    }
}

/**
 * DNS over HTTPS (RFC 8484, POST) over HTTP/1.1. Connection reuse is left to HttpURLConnection
 * keep-alive. HTTP/2-only servers are reported clearly rather than failing obscurely.
 */
class DohUpstream(private val url: URL, private val sockets: UpstreamSockets) : DnsUpstream {

    init {
        require(url.protocol == "https") { "DoH requires an https:// URL" }
    }

    override val description = url.toString()

    override fun exchange(query: ByteArray, timeoutMs: Int): ByteArray {
        val connection = sockets.openHttps(url)
        try {
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.useCaches = false
            connection.setRequestProperty("Content-Type", MEDIA_TYPE)
            connection.setRequestProperty("Accept", MEDIA_TYPE)
            // RFC 8484 §4.1: id 0 maximises HTTP cache friendliness; restore the client's id after.
            val body = DnsMessageWriter.withId(query, 0)
            connection.setFixedLengthStreamingMode(body.size)
            connection.outputStream.use { it.write(body) }
            val code = connection.responseCode
            // Some servers (e.g. Quad9) only serve DoH over HTTP/2, which HttpURLConnection lacks.
            if (code == 505) throw UpstreamException("$url requires HTTP/2, which is not supported yet; use another DoH server or DoT")
            if (code != 200) throw UpstreamException("DoH HTTP $code from $url")
            val response = connection.inputStream.use { it.readBytes() }
            if (response.size < 12) throw UpstreamException("DoH response too short")
            return DnsMessageWriter.withId(response, queryId(query))
        } catch (e: IOException) {
            connection.disconnect()
            throw if (e is UpstreamException) e else UpstreamException("DoH exchange with $url failed", e)
        }
    }

    private companion object {
        const val MEDIA_TYPE = "application/dns-message"
    }
}

internal fun queryId(query: ByteArray) = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)

/** Closing must never throw: TLS close-notify can fail in many ways (and Android forbids it on the main thread). */
private fun java.io.Closeable.closeQuietly() = try { close() } catch (_: Exception) { }
