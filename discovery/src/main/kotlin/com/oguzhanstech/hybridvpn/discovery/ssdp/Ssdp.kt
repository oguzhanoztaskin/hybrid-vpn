package com.oguzhanstech.hybridvpn.discovery.ssdp

import com.oguzhanstech.hybridvpn.discovery.NetworkBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.net.URISyntaxException
import kotlin.coroutines.coroutineContext

data class SsdpDescription(
    val friendlyName: String?,
    val manufacturer: String?,
    val modelName: String?,
    val modelNumber: String?,
    val deviceType: String?,
    val udn: String?,
)

data class SsdpDevice(
    val address: String,
    val uuid: String?,
    val server: String?,
    val location: String?,
    val searchTargets: Set<String>,
    val description: SsdpDescription?,
)

object SsdpParser {

    /** Parses an M-SEARCH response or NOTIFY into lower-cased header names; null if not SSDP. */
    fun parseHeaders(text: String): Map<String, String>? {
        val lines = text.split("\r\n", "\n")
        val status = lines.firstOrNull() ?: return null
        if (!status.startsWith("HTTP/1.1 200") && !status.startsWith("NOTIFY")) return null
        return lines.drop(1).mapNotNull { line ->
            val colon = line.indexOf(':')
            if (colon <= 0) null else line.substring(0, colon).trim().lowercase() to line.substring(colon + 1).trim()
        }.toMap()
    }

    fun uuidOf(usnOrUdn: String?): String? {
        val s = usnOrUdn ?: return null
        val start = s.indexOf("uuid:", ignoreCase = true)
        if (start < 0) return null
        return s.substring(start + 5).substringBefore("::").trim().lowercase().takeIf { it.isNotEmpty() }
    }

    /**
     * Pulls the root device's fields out of a UPnP description. Deliberately not a full XML
     * parser: the documents are simple, untrusted and fetched from arbitrary LAN devices, so a
     * tag scan avoids entity expansion and DTD processing altogether.
     */
    fun parseDescription(xml: String): SsdpDescription {
        val device = xml.substringAfter("<device>", xml)
        fun tag(name: String): String? {
            val m = Regex("<(?:\\w+:)?$name>([^<]*)</(?:\\w+:)?$name>").find(device) ?: return null
            return unescape(m.groupValues[1]).trim().takeIf { it.isNotEmpty() }
        }
        return SsdpDescription(tag("friendlyName"), tag("manufacturer"), tag("modelName"), tag("modelNumber"), tag("deviceType"), tag("UDN"))
    }

    private fun unescape(s: String) = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
        .replace("&apos;", "'").replace("&#39;", "'").replace("&amp;", "&")
}

/** SSDP M-SEARCH discovery plus a bounded fetch of each device's description document. */
class SsdpDiscoverer(private val binding: NetworkBinding) {

    suspend fun discover(durationMs: Long = 3500, fetchDescriptions: Boolean = true): List<SsdpDevice> = withContext(Dispatchers.IO) {
        val responses = LinkedHashMap<String, MutableList<Map<String, String>>>()
        DatagramSocket(0).use { socket ->
            binding.bind(socket)
            val request = M_SEARCH.toByteArray(Charsets.US_ASCII)
            val target = InetSocketAddress(InetAddress.getByName(SSDP_GROUP), SSDP_PORT)
            socket.send(DatagramPacket(request, request.size, target))
            val start = System.currentTimeMillis()
            var resent = false
            val buf = ByteArray(4096)
            while (true) {
                coroutineContext.ensureActive()
                val elapsed = System.currentTimeMillis() - start
                if (elapsed >= durationMs) break
                if (!resent && elapsed > 1000) {
                    resent = true
                    socket.send(DatagramPacket(request, request.size, target))
                }
                socket.soTimeout = minOf(250L, durationMs - elapsed).toInt().coerceAtLeast(1)
                val packet = DatagramPacket(buf, buf.size)
                try { socket.receive(packet) } catch (_: SocketTimeoutException) { continue }
                val headers = SsdpParser.parseHeaders(String(buf, 0, packet.length, Charsets.UTF_8)) ?: continue
                responses.getOrPut(packet.address.hostAddress) { ArrayList() } += headers
            }
        }
        responses.map { (address, list) ->
            val location = list.firstNotNullOfOrNull { it["location"] }
            val description = if (fetchDescriptions && location != null) fetchDescription(address, location) else null
            SsdpDevice(
                address = address,
                uuid = list.firstNotNullOfOrNull { SsdpParser.uuidOf(it["usn"]) } ?: SsdpParser.uuidOf(description?.udn),
                server = list.firstNotNullOfOrNull { it["server"] },
                location = location,
                searchTargets = list.mapNotNull { it["st"] ?: it["nt"] }.toSet(),
                description = description,
            )
        }
    }

    /**
     * Fetches the description only from the device that advertised it, over plain HTTP, with
     * hard size and time limits. A raw socket keeps the request on the bound LAN network and
     * avoids needing an app-wide cleartext-traffic exemption.
     */
    private fun fetchDescription(responder: String, location: String): SsdpDescription? = try {
        val url = URI(location)
        if (url.scheme != "http" || url.host != responder) null
        else {
            val port = if (url.port == -1) 80 else url.port
            Socket().use { socket ->
                binding.bind(socket)
                socket.connect(InetSocketAddress(InetAddress.getByName(responder), port), 1500)
                socket.soTimeout = 2000
                val path = (url.rawPath.orEmpty() + (url.rawQuery?.let { "?$it" } ?: "")).ifEmpty { "/" }
                socket.getOutputStream().write(
                    "GET $path HTTP/1.0\r\nHost: $responder:$port\r\nUser-Agent: $USER_AGENT\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
                )
                val body = readHttpBody(socket.getInputStream(), MAX_DESCRIPTION_BYTES)
                body?.let { SsdpParser.parseDescription(it) }
            }
        }
    } catch (_: IOException) {
        null
    } catch (_: URISyntaxException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    companion object {
        const val SSDP_GROUP = "239.255.255.250"
        const val SSDP_PORT = 1900
        private const val USER_AGENT = "Android UPnP/1.1 HybridVPN/0.1"
        private const val MAX_DESCRIPTION_BYTES = 64 * 1024

        private val M_SEARCH = "M-SEARCH * HTTP/1.1\r\n" +
            "HOST: $SSDP_GROUP:$SSDP_PORT\r\n" +
            "MAN: \"ssdp:discover\"\r\n" +
            "MX: 2\r\n" +
            "ST: ssdp:all\r\n" +
            "USER-AGENT: $USER_AGENT\r\n\r\n"

        internal fun readHttpBody(input: java.io.InputStream, maxBytes: Int): String? {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (out.size() <= maxBytes) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
            }
            if (out.size() > maxBytes) return null
            val bytes = out.toByteArray()
            val split = indexOf(bytes, CRLF_CRLF, 0)
            if (split < 0) return null
            val head = String(bytes, 0, split, Charsets.ISO_8859_1)
            if (!head.startsWith("HTTP/1.") || head.substringBefore("\r\n").split(' ').getOrNull(1) != "200") return null
            val body = bytes.copyOfRange(split + 4, bytes.size)
            val decoded = if (head.lowercase().contains("transfer-encoding: chunked")) dechunk(body) else body
            return String(decoded, Charsets.UTF_8)
        }

        /** Chunk sizes count bytes, so this must run before character decoding. */
        internal fun dechunk(body: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            var pos = 0
            while (pos < body.size) {
                val lineEnd = indexOf(body, CRLF, pos)
                if (lineEnd < 0) break
                val size = String(body, pos, lineEnd - pos, Charsets.ISO_8859_1).substringBefore(';').trim().toIntOrNull(16) ?: break
                if (size == 0) break
                val start = lineEnd + 2
                out.write(body, start, minOf(size, body.size - start))
                pos = start + size + 2
            }
            return out.toByteArray()
        }

        private val CRLF = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())
        private val CRLF_CRLF = CRLF + CRLF

        private fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int): Int {
            outer@ for (i in from..haystack.size - needle.size) {
                for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
                return i
            }
            return -1
        }
    }
}
