package com.oguzhanstech.hybridvpn.discovery.subnet

import com.oguzhanstech.hybridvpn.discovery.NetworkBinding
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

data class ProbeResult(val address: String, val openPorts: Set<Int>, val respondedToPing: Boolean)

/**
 * Finds live hosts with ICMP echo plus TCP connects. A refused connection is as good as an open
 * one for liveness: something answered with a RST. Only open ports are reported as services.
 */
class SubnetSweeper(
    private val binding: NetworkBinding,
    private val ports: List<Int> = DEFAULT_PORTS,
    private val connectTimeoutMs: Int = 350,
    private val pingTimeoutMs: Int = 300,
    private val parallelism: Int = 64,
) {

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun sweep(targets: List<String>, onProgress: (done: Int, total: Int) -> Unit = { _, _ -> }): List<ProbeResult> = coroutineScope {
        val dispatcher = Dispatchers.IO.limitedParallelism(parallelism)
        val done = AtomicInteger()
        targets.map { target ->
            async(dispatcher) {
                probe(target).also { onProgress(done.incrementAndGet(), targets.size) }
            }
        }.awaitAll().filterNotNull()
    }

    private fun probe(target: String): ProbeResult? {
        val address = InetAddress.getByAddress(IpLiteral.parse(target) ?: return null)
        val pinged = try { address.isReachable(pingTimeoutMs) } catch (_: IOException) { false }
        var answered = pinged
        val open = LinkedHashSet<Int>()
        for (port in ports) {
            when (connect(address, port)) {
                PortState.OPEN -> { open += port; answered = true }
                PortState.CLOSED -> answered = true
                PortState.SILENT -> Unit
            }
        }
        return if (answered) ProbeResult(target, open, pinged) else null
    }

    private enum class PortState { OPEN, CLOSED, SILENT }

    private fun connect(address: InetAddress, port: Int): PortState = try {
        Socket().use { socket ->
            binding.bind(socket)
            socket.connect(InetSocketAddress(address, port), connectTimeoutMs)
            PortState.OPEN
        }
    } catch (e: ConnectException) {
        if (e.message?.contains("refused", ignoreCase = true) == true) PortState.CLOSED else PortState.SILENT
    } catch (_: IOException) {
        PortState.SILENT
    }

    companion object {
        /** Small, service-revealing set: SSH, DNS, HTTP(S), SMB, AFP, RTSP, IPP, Cast, JetDirect, iOS lockdown. */
        val DEFAULT_PORTS = listOf(22, 53, 80, 443, 445, 548, 554, 631, 5000, 8008, 8009, 8080, 9100, 62078)
    }
}

object ScanPlanner {
    const val MAX_HOSTS = 1024

    /**
     * Usable IPv4 host addresses of [subnet]. Subnets larger than [maxHosts] are narrowed to the
     * /24 around [around] so an accidental /16 cannot turn into a 65k-host sweep.
     */
    fun hosts(subnet: Cidr, around: String?, maxHosts: Int = MAX_HOSTS): List<String> {
        require(subnet.isIpv4) { "Only IPv4 subnets can be swept" }
        var effective = subnet
        if (isNarrowed(subnet, maxHosts)) {
            val anchor = around?.let { IpLiteral.parseV4(it) } ?: return emptyList()
            effective = Cidr.of(anchor, 24)
        }
        val base = toInt(effective.address)
        val size = 1L shl (32 - effective.prefixLength)
        val range = when {
            effective.prefixLength >= 31 -> 0 until size
            else -> 1 until size - 1
        }
        return range.map { IpLiteral.format(fromInt(base + it.toInt())) }
    }

    fun isNarrowed(subnet: Cidr, maxHosts: Int = MAX_HOSTS) = (1L shl (32 - subnet.prefixLength)) - 2 > maxHosts

    private fun toInt(b: ByteArray) = ((b[0].toInt() and 0xFF) shl 24) or ((b[1].toInt() and 0xFF) shl 16) or
        ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)

    private fun fromInt(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}

/** `/proc/net/arp` parsing. Readable on older Android releases only; absence is normal. */
object ArpTable {
    private const val FLAG_COMPLETE = 0x2

    fun read(): String? = try { File("/proc/net/arp").readText() } catch (_: Exception) { null }

    fun parse(text: String): Map<String, String> = text.lineSequence().drop(1).mapNotNull { line ->
        val cols = line.trim().split(Regex("\\s+"))
        if (cols.size < 4) return@mapNotNull null
        val flags = cols[2].removePrefix("0x").toIntOrNull(16) ?: return@mapNotNull null
        val mac = cols[3].lowercase()
        if (flags and FLAG_COMPLETE == 0 || mac == "00:00:00:00:00:00" || IpLiteral.parseV4(cols[0]) == null) null
        else cols[0] to mac
    }.toMap()
}
