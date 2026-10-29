package com.oguzhanstech.hybridvpn.vpn

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import com.oguzhanstech.hybridvpn.MainActivity
import com.oguzhanstech.hybridvpn.Notifications
import com.oguzhanstech.hybridvpn.R
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.CompiledLists
import com.oguzhanstech.hybridvpn.data.EngineMode
import com.oguzhanstech.hybridvpn.data.OpenVpnProfile
import com.oguzhanstech.hybridvpn.data.TailnetConfig
import com.oguzhanstech.hybridvpn.data.PolicyRepository
import com.oguzhanstech.hybridvpn.data.ProxyConfig
import com.oguzhanstech.hybridvpn.data.ProxyKind
import com.oguzhanstech.hybridvpn.data.UpstreamMode
import com.oguzhanstech.hybridvpn.engine.dns.DnsCache
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessageWriter
import com.oguzhanstech.hybridvpn.engine.dns.DnsProxy
import com.oguzhanstech.hybridvpn.engine.dns.DnsProxyConfig
import com.oguzhanstech.hybridvpn.engine.dns.DnsUpstream
import com.oguzhanstech.hybridvpn.engine.dns.DohUpstream
import com.oguzhanstech.hybridvpn.engine.dns.DotUpstream
import com.oguzhanstech.hybridvpn.engine.dns.QueryOrigin
import com.oguzhanstech.hybridvpn.engine.dns.UdpUpstream
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import com.oguzhanstech.hybridvpn.engine.net.LanBypass
import com.oguzhanstech.hybridvpn.engine.packet.IpPacket
import com.oguzhanstech.hybridvpn.engine.packet.IpProtocol
import com.oguzhanstech.hybridvpn.engine.packet.TcpResetBuilder
import com.oguzhanstech.hybridvpn.engine.packet.UdpDatagram
import com.oguzhanstech.hybridvpn.engine.packet.UdpPacketBuilder
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.engine.policy.CompiledPolicy
import com.oguzhanstech.hybridvpn.engine.policy.FlowPolicy
import com.oguzhanstech.hybridvpn.engine.policy.FlowPolicyExporter
import com.oguzhanstech.hybridvpn.engine.policy.PolicyCompiler
import com.oguzhanstech.hybridvpn.engine.policy.PolicyEngine
import com.oguzhanstech.hybridvpn.engine.policy.PolicyRule
import com.oguzhanstech.hybridvpn.engine.policy.RoutingTable
import com.oguzhanstech.hybridvpn.engine.policy.RoutePath
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The one VpnService (ADR 0001). By default it routes everything into the Go engine (ADR 0007),
 * which forwards flows by policy and sends DNS back here; the DNS-only fallback (ADR 0002) routes
 * only the virtual resolver into the tunnel. Either way DNS is filtered by [DnsProxy] and resolved
 * over protected sockets on the physical network.
 */
class HybridVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val configLock = Mutex()
    private val outputLock = Any()
    private val cache = DnsCache()

    private var startJob: Job? = null
    private var tun: ParcelFileDescriptor? = null
    private var tunOut: FileOutputStream? = null
    private var reader: Thread? = null
    /** Write end of the reader's wake-up pipe; lets shutdown interrupt an indefinite poll(). */
    @Volatile private var readerWake: java.io.FileDescriptor? = null
    private var workers: ExecutorService? = null
    private var tracker: UnderlyingNetworkTracker? = null
    private var attribution: AppAttribution? = null
    @Volatile private var proxy: DnsProxy? = null
    @Volatile private var running = false

    private var lists: CompiledLists? = null
    private var policyWarnings: List<String> = emptyList()
    private var compiledPolicy: CompiledPolicy? = null
    /** Saved rules skipped because the connection they route to is off or not running, with that transport. */
    private var switchedOffRules: List<Pair<PolicyRule, String>> = emptyList()
    /** The saved policy failed to compile; the DNS stage uses the default policy. */
    private var policyInvalid = false
    /** Per-flow rules as last exported for the current profile and network. */
    private var flowPolicy: FlowPolicy? = null
    private var upstreams: List<DnsUpstream> = emptyList()
    private var startedAt = 0L

    /** The full-tunnel engine was chosen for this session (set before the first config is built). */
    @Volatile private var fullTunnel = false
    /** True while the Go engine owns packet forwarding. */
    @Volatile private var goEngine = false
    @Volatile private var engineFailure: String? = null
    /** Why this session runs DNS-only although the full tunnel was chosen, or null. */
    private var engineFallback: String? = null
    /** Tailnets, OpenVPN profiles and proxies handed to the engine at start, by id. */
    private var startedTailnets: List<String> = emptyList()
    private var startedOpenVpn: List<String> = emptyList()
    private var startedProxies: List<String> = emptyList()
    /** Performance settings the engine was started with (Settings → Performance). */
    private var startedMtu = TunConfig.MTU
    private var startedTcpLossDetection = true
    private var startedPacketForwarding = true
    private var startedIcmp = false
    private var startedIcmpv6 = false
    private var startedLanBypass = false
    private var startedLanExclusions: List<Cidr> = emptyList()
    private var lanRestartPending = false

    private val engineHost = object : GoBridge.Host {
        override fun protect(fd: Int): Boolean = this@HybridVpnService.protect(fd)

        override fun dnsQuery(query: ByteArray, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int, tcp: Boolean): ByteArray? {
            val p = proxy ?: return null
            val protocol = if (tcp) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP
            val origin = attribution?.origin(protocol, source, sourcePort, destination, destinationPort) ?: QueryOrigin(null, null)
            return p.handle(query, origin)
        }

        override fun ownerUid(protocol: Int, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int): Int =
            attribution?.ownerUid(protocol, source, sourcePort, destination, destinationPort) ?: -1

        override fun interfaces(): String = physicalInterfacesJson(this@HybridVpnService)

        override fun onEngineStopped(reason: String) {
            if (!running) return
            // Keep the TUN: with the engine gone, traffic is blackholed instead of leaking (fail closed).
            engineFailure = reason
            scope.launch { publishRunning() }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown(null)
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> if (running) scope.launch { reconfigure(recompileLists = true) }
            // ACTION_START, the always-on SERVICE_INTERFACE intent, or a sticky restart (null intent).
            else -> if (!running && startJob?.isActive != true) begin()
        }
        return START_STICKY
    }

    private fun begin() {
        startForegroundCompat(getString(R.string.vpn_starting))
        VpnController.publish(VpnState.Starting)
        startJob = scope.launch {
            try {
                val container = appContainer
                container.filterLists.ensureDefaults()
                container.dnsLog.prune()
                attribution = AppAttribution(this@HybridVpnService)
                val t = UnderlyingNetworkTracker(this@HybridVpnService) { onUnderlyingChanged() }
                tracker = t
                t.start()

                val wantsGo = container.settings.settings.value.engineMode == EngineMode.FULL_TUNNEL
                val useGo = wantsGo && GoBridge.available
                engineFallback = if (wantsGo && !useGo) "this build has no Go engine (${GoBridge.loadError})" else null
                fullTunnel = useGo
                val tailnets = if (useGo) container.tailnets.tailnets.value.filter { it.enabled } else emptyList()
                val profiles = if (useGo) container.openvpn.profiles.value.filter { it.enabled } else emptyList()
                val proxies = if (useGo) container.proxies.proxies.value.filter { it.enabled } else emptyList()
                startedTailnets = tailnets.map { it.id }
                startedOpenVpn = profiles.map { it.id }
                startedProxies = proxies.map { it.transportId }
                val settings = container.settings.settings.value
                startedMtu = if (useGo && settings.largeTunnelPackets) TunConfig.FULL_TUNNEL_MTU else TunConfig.MTU
                startedTcpLossDetection = settings.tcpLossDetection
                startedPacketForwarding = settings.openvpnPacketForwarding
                startedIcmp = settings.allowIcmp
                startedIcmpv6 = settings.allowIcmpv6
                startedLanBypass = useGo && settings.lanBypass
                lanRestartPending = false
                val config = configLock.withLock { buildConfig(recompileLists = true) }
                engineStopThread?.join() // a previous session's engine must be fully stopped
                engineFailure = null
                startedLanExclusions = if (startedLanBypass) LanBypass.exclusions(t.lanPrefixes) else emptyList()
                val pfd = establishTun(fullTunnel = useGo, mtu = startedMtu) ?: error("VPN permission was not granted or has been revoked")
                tun = pfd
                proxy = DnsProxy(config, cache, container.dnsLog::record)
                startedAt = System.currentTimeMillis()
                if (useGo) {
                    // Go gets its own duplicate of the fd and closes it on stop; we keep ours for the
                    // VPN's lifetime, so the interface stays up (blackholing) even if Go dies.
                    GoBridge.host = engineHost
                    val rules = configLock.withLock { exportFlowPolicy() }
                    GoBridge.start(pfd.dup().detachFd(), TunConfig.engineConfigJson(
                        rules.json,
                        mtu = startedMtu,
                        disableRack = !startedTcpLossDetection,
                        disablePacketForwarding = !startedPacketForwarding,
                        allowIcmp = startedIcmp,
                        allowIcmpv6 = startedIcmpv6,
                        tailnets = tailnetsJson(tailnets),
                        openvpn = openvpnJson(profiles),
                        http = proxiesJson(proxies.filter { it.kind == ProxyKind.HTTP }),
                        socks5 = proxiesJson(proxies.filter { it.kind == ProxyKind.SOCKS5 }),
                        crashLog = java.io.File(filesDir, "go-crash.log").absolutePath,
                        logsDir = java.io.File(filesDir, "tailscale-logs").absolutePath,
                        tempDir = cacheDir.absolutePath,
                    ))?.let { error("Go engine: $it") }
                    goEngine = true
                    running = true
                } else {
                    configLock.withLock { exportFlowPolicy() } // only to report rules DNS-only mode can't enforce
                    tunOut = FileOutputStream(pfd.fileDescriptor)
                    workers = Executors.newFixedThreadPool(WORKER_THREADS)
                    running = true
                    reader = Thread(::readLoop, "tun-reader").apply { start() }
                }
                publishRunning()
                refreshLanRoutesIfNeeded()
            } catch (e: Exception) {
                fail(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    /**
     * Full tunnel: all IPv4/IPv6 traffic, except optional connected LAN/discovery destinations.
     * DNS-only (fallback): only the virtual resolver is routed into the tunnel.
     */
    private fun establishTun(fullTunnel: Boolean, mtu: Int): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(mtu)
            .addAddress(TunConfig.ADDRESS_V4, TunConfig.PREFIX_V4)
            .addAddress(TunConfig.ADDRESS_V6, TunConfig.PREFIX_V6)
            .addDnsServer(TunConfig.DNS_V4)
            .addDnsServer(TunConfig.DNS_V6)
            .setBlocking(true)
            .setConfigureIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            )
        if (fullTunnel) {
            LanBypass.tunnelRoutes(startedLanExclusions).forEach { route ->
                builder.addRoute(java.net.InetAddress.getByAddress(route.address), route.prefixLength)
            }
            // Keep system DNS inside the firewall even if a physical prefix overlaps these addresses.
            builder.addRoute(TunConfig.DNS_V4, 32).addRoute(TunConfig.DNS_V6, 128)
        } else {
            builder.addRoute(TunConfig.DNS_V4, 32).addRoute(TunConfig.DNS_V6, 128)
        }
        // Inherit metering from the physical network instead of looking metered to every app.
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        return builder.establish()
    }

    /** Builds a complete proxy configuration; throws if settings are unusable. Caller holds [configLock]. */
    private suspend fun buildConfig(recompileLists: Boolean): DnsProxyConfig {
        val container = appContainer
        val settings = container.settings.settings.value
        val compiledLists = if (recompileLists || lists == null) container.filterLists.compile(settings.dnsFiltering).also { lists = it } else lists!!
        val policy = compilePolicy(compiledLists)
        val t = tracker ?: error("network tracker not running")
        val sockets = AndroidUpstreamSockets(this, t)
        val network = NetworkDnsUpstream(t, sockets)
        val upstream = when (settings.upstreamMode) {
            UpstreamMode.NETWORK -> network
            UpstreamMode.UDP -> UdpUpstream(parseServers(settings.udpServers), sockets)
            UpstreamMode.DOT -> DotUpstream(settings.dotHost.trim(), 853, sockets)
            UpstreamMode.DOH -> DohUpstream(URL(settings.dohUrl.trim()), sockets)
        }
        upstreams.forEach { it.close() }
        upstreams = listOf(upstream)
        return DnsProxyConfig(
            policy = PolicyEngine(policy, compiledLists.index),
            upstream = upstream,
            localUpstream = network,
            blockResponse = settings.blockResponse,
            network = t.current?.kind,
            networkId = null,
            profile = settings.profile,
            // Tailnet names stay inside the tailnets; only the Go engine runs tailnets.
            localNames = if (fullTunnel && startedTailnets.isNotEmpty()) GoTailnetNames else null,
        )
    }

    private fun compilePolicy(compiledLists: CompiledLists): CompiledPolicy {
        val repo = appContainer.policy
        // The engine knows only the transports it was started with; a policy naming others is rejected.
        val running = if (fullTunnel) {
            startedTailnets.map { TailnetConfig.TRANSPORT_PREFIX + it } + startedOpenVpn.map { OpenVpnProfile.TRANSPORT_PREFIX + it } +
                startedProxies
        } else null
        val forRun = repo.loadForRun(running?.toSet())
        val runningRules = forRun.rules.associateBy { it.id }
        switchedOffRules = repo.load().rules.mapNotNull { rule ->
            val route = rule.action.route
            if (rule.enabled && route != null && runningRules[rule.id]?.enabled == false) rule to route else null
        }
        return when (val result = repo.compile(forRun, compiledLists.allIds)) {
            is CompileResult.Ok -> result.policy.also { policyWarnings = it.warnings; policyInvalid = false }
            is CompileResult.Failed -> {
                policyInvalid = true
                policyWarnings = listOf(
                    "Saved policy is invalid (${result.errors.first()}). DNS filtering uses the default policy; " +
                        "in the Go engine all other traffic is blocked until the policy is fixed."
                )
                (repo.compile(PolicyRepository.DEFAULT, compiledLists.allIds) as CompileResult.Ok).policy
            }
        }.also { compiledPolicy = it }
    }

    /** Tailnets for the Go engine: each becomes transport "tailnet:<id>" with its own state directory. */
    private fun tailnetsJson(tailnets: List<TailnetConfig>): JSONArray {
        val repo = appContainer.tailnets
        return JSONArray().apply {
            tailnets.forEach { t ->
                put(JSONObject().put("id", t.id).put("dir", repo.stateDir(t.id).absolutePath).put("control_url", t.controlUrl).put("hostname", t.hostname))
            }
        }
    }

    /**
     * OpenVPN profiles for the Go engine: each becomes transport "openvpn:<id>". Profiles and
     * passwords are decrypted only here, to hand them to the engine.
     */
    private fun openvpnJson(profiles: List<OpenVpnProfile>): JSONArray {
        val repo = appContainer.openvpn
        return JSONArray().apply {
            profiles.forEach { p ->
                put(
                    JSONObject().put("id", p.id).put("profile", repo.profileText(p.id).orEmpty())
                        .put("username", p.username).put("password", if (p.needsCredentials) repo.password(p.id) else "")
                        .put("key_password", if (p.needsKeyPassword) repo.keyPassword(p.id) else "")
                )
            }
        }
    }

    /** Proxies for the Go engine. Passwords are decrypted only here. */
    private fun proxiesJson(proxies: List<ProxyConfig>): JSONArray {
        val repo = appContainer.proxies
        return JSONArray().apply {
            proxies.forEach { p ->
                put(
                    JSONObject().put("id", p.id).put("server", p.server).put("username", p.username)
                        .put("password", if (p.username.isNotEmpty()) repo.password(p.id) else "")
                )
            }
        }
    }

    /**
     * Per-flow rules for the current profile and physical network. If the saved policy is invalid,
     * routing intent is unknown, so the engine blocks every flow (DNS still works) rather than
     * sending traffic somewhere the user did not choose.
     */
    private fun exportFlowPolicy(): FlowPolicy {
        if (policyInvalid) return FlowPolicy(BLOCK_ALL_POLICY, 1, emptyList()).also { flowPolicy = it }
        val policy = compiledPolicy ?: error("policy not compiled")
        return FlowPolicyExporter.export(
            policy,
            profile = appContainer.settings.settings.value.profile,
            network = tracker?.current?.kind,
            networkId = null,
            apps = AndroidAppResolver(packageManager),
        ).also { flowPolicy = it }
    }

    private fun parseServers(text: String): List<InetSocketAddress> {
        val servers = text.split(',', ' ', '\n').filter { it.isNotBlank() }.map { token ->
            val bytes = IpLiteral.parse(token) ?: throw IllegalArgumentException("'$token' is not an IP address")
            InetSocketAddress(InetAddress.getByAddress(bytes), 53)
        }
        require(servers.isNotEmpty()) { "No DNS servers configured" }
        return servers
    }

    /** Swaps in a new configuration atomically; on failure the previous one stays active. */
    private suspend fun reconfigure(recompileLists: Boolean) {
        val p = proxy ?: return
        configLock.withLock {
            try {
                p.config = buildConfig(recompileLists)
                cache.clear()
                if (goEngine) {
                    // Profile, network or policy may have changed which per-flow rules apply.
                    GoBridge.updatePolicy(exportFlowPolicy().json)?.let { error("routing policy rejected by the engine: $it") }
                }
                publishRunning()
            } catch (e: Exception) {
                publishRunning(extraWarning = "Settings not applied: ${e.message}")
            }
        }
    }

    private fun onUnderlyingChanged() {
        cache.clear()
        if (goEngine) GoBridge.networkChanged()
        refreshLanRoutesIfNeeded()
        if (running) scope.launch { reconfigure(recompileLists = false) }
    }

    /** VPN routes are immutable: a changed LAN needs a new TUN, not just a policy reload. */
    private fun refreshLanRoutesIfNeeded() {
        if (!running || !startedLanBypass) return
        val wanted = LanBypass.exclusions(tracker?.lanPrefixes.orEmpty())
        if (wanted == startedLanExclusions) return
        Handler(Looper.getMainLooper()).post {
            if (running && !lanRestartPending && startedLanBypass &&
                LanBypass.exclusions(tracker?.lanPrefixes.orEmpty()) != startedLanExclusions) {
                lanRestartPending = true
                VpnController.restart(this)
            }
        }
    }

    private fun readLoop() {
        val pfd = tun ?: return
        val input = FileInputStream(pfd.fileDescriptor)
        val buf = ByteArray(MAX_PACKET)
        // Block indefinitely: an idle tunnel costs no wake-ups. Shutdown writes to the pipe instead.
        val (wakeRead, wakeWrite) = Os.pipe()
        readerWake = wakeWrite
        val polls = arrayOf(
            StructPollfd().apply { fd = pfd.fileDescriptor; events = OsConstants.POLLIN.toShort() },
            StructPollfd().apply { fd = wakeRead; events = OsConstants.POLLIN.toShort() },
        )
        try {
            while (running) {
                try {
                    if (Os.poll(polls, -1) <= 0) continue
                    if (polls[1].revents.toInt() != 0) break
                    if (polls[0].revents.toInt() and OsConstants.POLLIN == 0) {
                        if (polls[0].revents.toInt() != 0) break // POLLERR/POLLHUP/POLLNVAL: interface gone
                        continue
                    }
                    val n = input.read(buf)
                    if (n > 0) handlePacket(buf, n)
                } catch (e: ErrnoException) {
                    if (e.errno != OsConstants.EINTR) break
                } catch (_: IOException) {
                    break
                }
            }
        } finally {
            readerWake = null
            try { Os.close(wakeRead) } catch (_: ErrnoException) { }
            try { Os.close(wakeWrite) } catch (_: ErrnoException) { }
        }
        if (running) scope.launch { fail("Tunnel interface closed unexpectedly") }
    }

    private fun handlePacket(buf: ByteArray, length: Int) {
        val ip = IpPacket.parse(buf, length) ?: return
        // Only the virtual resolver is routed to us; anything else is unexpected and dropped.
        if (!TunConfig.isVirtualDns(ip.destination)) return
        when (ip.protocol) {
            IpProtocol.UDP -> {
                val udp = UdpDatagram.parse(ip) ?: return
                if (udp.destinationPort != 53) return
                val query = udp.payload()
                val source = ip.source
                val destination = ip.destination
                val sourcePort = udp.sourcePort
                val version = ip.version
                try {
                    workers?.execute { answer(query, source, sourcePort, destination, version) }
                } catch (_: RejectedExecutionException) {
                    // shutting down
                }
            }
            // DNS-over-TCP and the Private DNS (853) probe: refuse immediately rather than time out.
            IpProtocol.TCP -> TcpResetBuilder.resetFor(ip)?.let(::write)
        }
    }

    private fun answer(query: ByteArray, source: ByteArray, sourcePort: Int, destination: ByteArray, version: Int) {
        val p = proxy ?: return
        val origin = attribution?.udpOrigin(source, sourcePort, destination, 53) ?: QueryOrigin(null, null)
        val response = p.handle(query, origin) ?: return
        val payload = if (response.size > TunConfig.maxDnsPayload(version)) DnsMessageWriter.truncated(response) else response
        write(UdpPacketBuilder.build(destination, 53, source, sourcePort, payload))
    }

    private fun write(packet: ByteArray) {
        synchronized(outputLock) {
            try {
                tunOut?.write(packet)
            } catch (_: IOException) {
                // The interface is going away; the read loop will notice.
            }
        }
    }

    private fun publishRunning(extraWarning: String? = null) {
        val container = appContainer
        val settings = container.settings.settings.value
        val u = tracker?.current
        val l = lists
        val warnings = buildList {
            u?.strictPrivateDns?.let {
                add("Private DNS is set to \"$it\". Android sends DNS there directly, bypassing filtering. Set Private DNS to Automatic or Off.")
            }
            if (u == null) add("No physical network is available; DNS queries will fail closed.")
            engineFailure?.let { add("Go engine stopped ($it). All traffic is blocked until protection is restarted.") }
            engineFallback?.let { add("Running DNS-only: $it. Tailscale, OpenVPN, proxies and routing rules need the full tunnel.") }
            flowPolicy?.let { fp ->
                if (goEngine) addAll(fp.warnings)
                else if (fp.packetRules > 0) add(
                    "${fp.packetRules} routing rule(s) match apps, addresses or ports. They are enforced only by the " +
                        "full-tunnel engine; in DNS-only mode just their DNS effects apply."
                )
            }
            addAll(policyWarnings)
            if (startedLanBypass) add("LAN discovery & connections bypass VPN rules: ${startedLanExclusions.joinToString()}. " +
                "Local traffic, including DNS sent directly to LAN devices, is outside the firewall.")
            extraWarning?.let(::add)
        }
        val info = VpnInfo(
            since = startedAt,
            transport = if (goEngine) "Full tunnel: TCP/UDP by policy; IPv4 ping ${if (startedIcmp) "on" else "off"}, IPv6 ping ${if (startedIcmpv6) "on" else "off"}"
            else "DNS only: other traffic bypasses the VPN",
            resolver = upstreams.firstOrNull()?.description ?: "?",
            underlying = u?.let { "${it.kind.name.lowercase()} ${it.interfaceName ?: ""}".trim() },
            ruleCount = l?.ruleCount ?: 0,
            listCount = l?.enabledCount ?: 0,
            blockResponse = settings.blockResponse,
            failurePolicy = "Fail closed: upstream errors return SERVFAIL",
            profile = settings.profile,
            warnings = warnings,
            goEngine = goEngine,
            packetRules = flowPolicy?.packetRules ?: 0,
            dnsFiltering = settings.dnsFiltering,
            tailnets = startedTailnets,
            openvpn = startedOpenVpn,
            proxies = startedProxies,
            tunnelMtu = startedMtu,
            tcpLossDetection = startedTcpLossDetection,
            openvpnPacketForwarding = startedPacketForwarding,
            allowIcmp = startedIcmp,
            allowIcmpv6 = startedIcmpv6,
            lanBypass = startedLanBypass,
            lanBypassPrefixes = startedLanExclusions.map { it.toString() },
            routing = compiledPolicy?.takeIf { goEngine && !policyInvalid }
                ?.let { policy ->
                    val bypass = if (startedLanBypass) listOf(RoutePath(
                        id = "lan-bypass", kind = RoutePath.Kind.BUILTIN, description = "LAN discovery & connections",
                        conditions = startedLanExclusions.map { it.toString() }, cidrs = startedLanExclusions,
                        target = "physical network outside VPN; VPN rules do not apply", onFailure = null,
                    )) else emptyList()
                    bypass + RoutingTable.build(policy, settings.profile, u?.kind, null, switchedOffRules, startedIcmp, startedIcmpv6)
                }.orEmpty(),
        )
        VpnController.publish(VpnState.Running(info))
        Notifications.updateVpn(this, getString(R.string.vpn_running_detail, info.ruleCount, info.resolver))
    }

    private fun fail(message: String) {
        shutdown(null)
        VpnController.publish(VpnState.Failed(message))
    }

    private fun shutdown(reason: String?) {
        running = false
        startJob?.cancel()
        readerWake?.let { fd -> try { Os.write(fd, byteArrayOf(1), 0, 1) } catch (_: Exception) { } }
        reader?.interrupt()
        reader = null
        workers?.shutdownNow()
        workers = null
        startedTailnets = emptyList()
        startedOpenVpn = emptyList()
        startedProxies = emptyList()
        if (goEngine) {
            goEngine = false
            // Stopping waits for flows to close; keep it off the main thread.
            engineStopThread = Thread({
                GoBridge.stop()
                GoBridge.host = null
            }, "go-engine-stop").apply { start() }
        }
        tracker?.stop()
        tracker = null
        // shutdown() runs on the main thread; closing TLS connections performs network I/O.
        val closing = upstreams
        upstreams = emptyList()
        if (closing.isNotEmpty()) Thread({ closing.forEach { it.close() } }, "upstream-close").start()
        proxy = null
        synchronized(outputLock) {
            try { tun?.close() } catch (_: IOException) { }
            tun = null
            tunOut = null
        }
        cache.clear()
        VpnController.publish(VpnState.Stopped(reason))
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        shutdown(getString(R.string.vpn_revoked))
    }

    override fun onDestroy() {
        if (running || tun != null) shutdown(null)
        scope.cancel()
        super.onDestroy()
    }

    private fun startForegroundCompat(text: String) {
        val notification = Notifications.vpn(this, text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(Notifications.VPN_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(Notifications.VPN_ID, notification)
        }
    }

    companion object {
        const val ACTION_START = "com.oguzhanstech.hybridvpn.START"
        const val ACTION_STOP = "com.oguzhanstech.hybridvpn.STOP"
        const val ACTION_RELOAD = "com.oguzhanstech.hybridvpn.RELOAD"
        private const val MAX_PACKET = 32767
        private const val BLOCK_ALL_POLICY = """{"version":1,"transports":[{"id":"direct","type":"direct"}],""" +
            """"default":{"transport":"direct","on_failure":"block"},"rules":[{"id":"invalid-policy","any_app":true,"action":"block"}]}"""
        private const val WORKER_THREADS = 8

        /**
         * Stops the previous session's engine. Static, because a restart may start a new service
         * instance before the old engine has finished stopping.
         */
        @Volatile private var engineStopThread: Thread? = null
    }
}
