package com.oguzhanstech.hybridvpn.discovery

import com.oguzhanstech.hybridvpn.discovery.identity.HostObservation
import com.oguzhanstech.hybridvpn.discovery.mdns.MdnsBrowser
import com.oguzhanstech.hybridvpn.discovery.mdns.MdnsHost
import com.oguzhanstech.hybridvpn.discovery.ssdp.SsdpDevice
import com.oguzhanstech.hybridvpn.discovery.ssdp.SsdpDiscoverer
import com.oguzhanstech.hybridvpn.discovery.subnet.ArpTable
import com.oguzhanstech.hybridvpn.discovery.subnet.ProbeResult
import com.oguzhanstech.hybridvpn.discovery.subnet.ScanPlanner
import com.oguzhanstech.hybridvpn.discovery.subnet.SubnetSweeper
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress

data class ScanTarget(val subnet: Cidr, val selfAddress: String?, val gateway: String?)

data class ScanOptions(
    val ports: List<Int> = SubnetSweeper.DEFAULT_PORTS,
    val mdnsDurationMs: Long = 4000,
    val ssdpDurationMs: Long = 3500,
    val reverseDns: Boolean = true,
    val reverseDnsTimeoutMs: Long = 1500,
    val maxHosts: Int = ScanPlanner.MAX_HOSTS,
)

sealed interface ScanProgress {
    data class Phase(val name: String) : ScanProgress
    data class Sweep(val done: Int, val total: Int) : ScanProgress
}

data class ScanReport(
    val observations: List<HostObservation>,
    val startedAt: Long,
    val finishedAt: Long,
    /** Techniques that failed; the scan still returns whatever the others found. */
    val warnings: List<String>,
)

fun interface HostnameResolver {
    suspend fun reverse(ip: String): String?

    companion object {
        val System = HostnameResolver { ip ->
            val bytes = IpLiteral.parse(ip) ?: return@HostnameResolver null
            runInterruptible(Dispatchers.IO) { InetAddress.getByAddress(bytes).canonicalHostName }.takeIf { it != ip }
        }
    }
}

/** Runs every discovery technique concurrently and merges their evidence per IP address. */
class NetworkScanner(
    private val binding: NetworkBinding,
    private val options: ScanOptions = ScanOptions(),
    private val hostnames: HostnameResolver = HostnameResolver.System,
    private val arpTable: () -> String? = ArpTable::read,
) {

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun scan(target: ScanTarget, onProgress: (ScanProgress) -> Unit = {}): ScanReport = coroutineScope {
        val started = System.currentTimeMillis()
        val warnings = ArrayList<String>()
        val hosts = ScanPlanner.hosts(target.subnet, target.selfAddress, options.maxHosts)
        if (ScanPlanner.isNarrowed(target.subnet, options.maxHosts)) {
            warnings += "Subnet ${target.subnet} is large; only the /24 around ${target.selfAddress} was swept"
        }

        onProgress(ScanProgress.Phase("Discovering"))
        val mdns = async { attempt("mDNS", warnings) { MdnsBrowser(binding).browse(options.mdnsDurationMs) } }
        val ssdp = async { attempt("SSDP", warnings) { SsdpDiscoverer(binding).discover(options.ssdpDurationMs) } }
        val sweep = async {
            attempt("Subnet sweep", warnings) {
                SubnetSweeper(binding, options.ports).sweep(hosts) { done, total -> onProgress(ScanProgress.Sweep(done, total)) }
            }
        }
        val mdnsHosts = mdns.await().orEmpty()
        val ssdpDevices = ssdp.await().orEmpty()
        val probes = sweep.await().orEmpty()
        val arp = arpTable()?.let { ArpTable.parse(it) }.orEmpty()

        val inSubnet = { ip: String -> IpLiteral.parseV4(ip)?.let { target.subnet.contains(it) } == true }
        val addresses = (probes.map { it.address } + mdnsHosts.map { it.address } + ssdpDevices.map { it.address } +
            listOfNotNull(target.selfAddress, target.gateway)).filter(inSubnet).toSortedSet(compareBy { ipSortKey(it) })

        onProgress(ScanProgress.Phase("Resolving names"))
        val reverse: Map<String, String?> = if (options.reverseDns) {
            val limited = Dispatchers.IO.limitedParallelism(16)
            addresses.map { ip ->
                async(limited) { ip to withTimeoutOrNull(options.reverseDnsTimeoutMs) { runCatching { hostnames.reverse(ip) }.getOrNull() } }
            }.awaitAll().toMap()
        } else emptyMap()

        val observations = aggregate(addresses, probes, mdnsHosts, ssdpDevices, arp, reverse, target)
        ScanReport(observations, started, System.currentTimeMillis(), warnings.toList())
    }

    private suspend fun <T> attempt(name: String, warnings: MutableList<String>, block: suspend () -> T): T? = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        synchronized(warnings) { warnings += "$name failed: ${e.message ?: e.javaClass.simpleName}" }
        null
    }

    companion object {
        fun aggregate(
            addresses: Collection<String>,
            probes: List<ProbeResult>,
            mdns: List<MdnsHost>,
            ssdp: List<SsdpDevice>,
            arp: Map<String, String>,
            reverse: Map<String, String?>,
            target: ScanTarget,
        ): List<HostObservation> {
            val probeBy = probes.associateBy { it.address }
            val mdnsBy = mdns.associateBy { it.address }
            val ssdpBy = ssdp.associateBy { it.address }
            return addresses.map { ip ->
                val m = mdnsBy[ip]
                HostObservation(
                    ip = ip,
                    mac = arp[ip],
                    mdnsHostname = m?.hostname,
                    reverseDnsName = reverse[ip]?.trimEnd('.')?.lowercase()?.takeIf { it.isNotEmpty() && IpLiteral.parse(it) == null },
                    mdnsServices = m?.services.orEmpty(),
                    ssdp = ssdpBy[ip],
                    openPorts = probeBy[ip]?.openPorts.orEmpty(),
                    reachable = ip in probeBy || m != null || ip in ssdpBy || ip == target.selfAddress,
                    isGateway = ip == target.gateway,
                    isSelf = ip == target.selfAddress,
                )
            }
        }

        private fun ipSortKey(ip: String): Long =
            IpLiteral.parseV4(ip)?.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) } ?: Long.MAX_VALUE
    }
}
