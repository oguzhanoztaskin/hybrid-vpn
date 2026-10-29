package com.oguzhanstech.hybridvpn.discovery.mdns

import com.oguzhanstech.hybridvpn.discovery.NetworkBinding
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessage
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessageWriter
import com.oguzhanstech.hybridvpn.engine.dns.DnsQuestion
import com.oguzhanstech.hybridvpn.engine.dns.DnsType
import com.oguzhanstech.hybridvpn.engine.dns.RData
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.SocketTimeoutException
import kotlin.coroutines.coroutineContext

data class MdnsService(val instance: String, val type: String, val port: Int, val txt: Map<String, String>)

data class MdnsHost(val address: String, val hostname: String?, val services: List<MdnsService>)

/**
 * Accumulates mDNS records from many responses and works out which follow-up questions are
 * still needed (types → instances → SRV/TXT → addresses).
 */
class MdnsRecordCollector {
    private val types = LinkedHashSet<String>()
    private val instancesByType = HashMap<String, MutableSet<String>>()
    private val srv = HashMap<String, RData.Srv>()
    private val txt = HashMap<String, Map<String, String>>()
    private val addresses = HashMap<String, MutableSet<String>>()
    private val sourceOf = HashMap<String, String>()
    private val asked = HashSet<Pair<String, Int>>()

    /** Ingests one response; returns questions worth asking next. */
    fun add(message: DnsMessage, source: String): List<DnsQuestion> {
        for (r in message.allRecords) {
            sourceOf.putIfAbsent(r.name, source)
            when (val d = r.data) {
                is RData.Name -> if (r.type == DnsType.PTR && !r.name.endsWith(".arpa")) {
                    if (r.name.equals(SERVICES_ENUMERATION, ignoreCase = true)) types += d.name
                    else {
                        types += r.name
                        instancesByType.getOrPut(r.name) { LinkedHashSet() } += d.name
                        sourceOf.putIfAbsent(d.name, source)
                    }
                }
                is RData.Srv -> srv[r.name] = d
                is RData.Txt -> txt[r.name] = parseTxt(d.strings)
                is RData.Address -> addresses.getOrPut(r.name.lowercase()) { LinkedHashSet() } += IpLiteral.format(d.bytes)
                else -> Unit
            }
        }
        val followUps = ArrayList<DnsQuestion>()
        fun ask(name: String, type: Int) { if (asked.add(name to type)) followUps += DnsQuestion(name, type, QU_CLASS) }
        types.forEach { ask(it, DnsType.PTR) }
        instancesByType.values.flatten().forEach { instance ->
            if (instance !in srv) ask(instance, DnsType.SRV)
            if (instance !in txt) ask(instance, DnsType.TXT)
        }
        srv.values.forEach { if (it.target.lowercase() !in addresses) ask(it.target, DnsType.A) }
        return followUps
    }

    /** Marks questions already sent so they are not proposed again. */
    fun markAsked(questions: List<DnsQuestion>) = questions.forEach { asked += it.name to it.type }

    fun hosts(): List<MdnsHost> {
        val services = HashMap<String, MutableList<MdnsService>>()
        val hostnames = HashMap<String, String>()
        for ((type, instances) in instancesByType) for (instance in instances) {
            val s = srv[instance] ?: continue
            val ip = addresses[s.target.lowercase()]?.firstOrNull { !it.contains(':') } ?: sourceOf[instance] ?: continue
            services.getOrPut(ip) { ArrayList() } += MdnsService(instance.removeSuffix(".$type"), type.removeSuffix(".local"), s.port, txt[instance].orEmpty())
            hostnames.putIfAbsent(ip, s.target.lowercase())
        }
        for ((host, ips) in addresses) {
            ips.firstOrNull { !it.contains(':') }?.let { hostnames.putIfAbsent(it, host) }
        }
        return (services.keys + hostnames.keys).map { ip ->
            MdnsHost(ip, hostnames[ip], services[ip].orEmpty().distinct().sortedBy { it.type })
        }
    }

    companion object {
        const val SERVICES_ENUMERATION = "_services._dns-sd._udp.local"
        /** IN class with the "unicast response" bit (RFC 6762 §5.4). */
        const val QU_CLASS = 0x8001

        fun parseTxt(strings: List<String>): Map<String, String> = strings
            .filter { it.isNotEmpty() }
            .associate { s -> s.substringBefore('=').lowercase() to s.substringAfter('=', "") }
    }
}

/**
 * One-shot mDNS browser (RFC 6762 §5.1 "legacy unicast"): queries go to 224.0.0.251:5353 from
 * an ephemeral port and responders answer us directly. That avoids competing with the system's
 * own mDNS daemon for port 5353. IPv4 only for now.
 */
class MdnsBrowser(private val binding: NetworkBinding) {

    suspend fun browse(durationMs: Long = 4000): List<MdnsHost> = withContext(Dispatchers.IO) {
        val collector = MdnsRecordCollector()
        MulticastSocket(0).use { socket ->
            binding.networkInterface?.let { socket.networkInterface = it }
            socket.timeToLive = 255
            binding.bind(socket)
            val group = InetAddress.getByName(MDNS_GROUP)

            fun send(questions: List<DnsQuestion>) {
                questions.chunked(QUESTIONS_PER_PACKET).forEach { chunk ->
                    val bytes = DnsMessageWriter.query(0, chunk, recursionDesired = false)
                    socket.send(DatagramPacket(bytes, bytes.size, group, MDNS_PORT))
                }
                collector.markAsked(questions)
            }

            val initial = (listOf(MdnsRecordCollector.SERVICES_ENUMERATION) + COMMON_TYPES)
                .map { DnsQuestion(it, DnsType.PTR, MdnsRecordCollector.QU_CLASS) }
            send(initial)
            val start = System.currentTimeMillis()
            var resent = false
            val buf = ByteArray(9000)
            while (true) {
                coroutineContext.ensureActive()
                val elapsed = System.currentTimeMillis() - start
                if (elapsed >= durationMs) break
                if (!resent && elapsed > durationMs / 3) {
                    // Multicast is lossy on Wi-Fi; one repeat noticeably improves coverage.
                    resent = true
                    initial.chunked(QUESTIONS_PER_PACKET).forEach { chunk ->
                        val bytes = DnsMessageWriter.query(0, chunk, recursionDesired = false)
                        socket.send(DatagramPacket(bytes, bytes.size, group, MDNS_PORT))
                    }
                }
                socket.soTimeout = minOf(250L, durationMs - elapsed).toInt().coerceAtLeast(1)
                val packet = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(packet)
                } catch (_: SocketTimeoutException) {
                    continue
                }
                val message = DnsMessage.parseOrNull(buf, packet.length) ?: continue
                if (!message.isResponse) continue
                val followUps = collector.add(message, packet.address.hostAddress)
                if (followUps.isNotEmpty()) send(followUps)
            }
        }
        collector.hosts()
    }

    companion object {
        const val MDNS_GROUP = "224.0.0.251"
        const val MDNS_PORT = 5353
        private const val QUESTIONS_PER_PACKET = 12

        /** Asked directly because not every responder answers the service-enumeration query. */
        val COMMON_TYPES = listOf(
            "_device-info._tcp.local", "_workstation._tcp.local", "_ssh._tcp.local", "_sftp-ssh._tcp.local",
            "_smb._tcp.local", "_afpovertcp._tcp.local", "_adisk._tcp.local", "_rfb._tcp.local",
            "_http._tcp.local", "_https._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local",
            "_pdl-datastream._tcp.local", "_scanner._tcp.local", "_uscan._tcp.local",
            "_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local", "_spotify-connect._tcp.local",
            "_amzn-wplay._tcp.local", "_hap._tcp.local", "_matter._tcp.local", "_matterc._udp.local",
            "_companion-link._tcp.local", "_sleep-proxy._udp.local", "_home-assistant._tcp.local", "_hue._tcp.local",
        )
    }
}
