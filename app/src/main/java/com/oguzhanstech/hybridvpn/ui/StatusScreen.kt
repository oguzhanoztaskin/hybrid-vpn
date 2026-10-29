package com.oguzhanstech.hybridvpn.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.DnsCounters
import com.oguzhanstech.hybridvpn.data.EngineMode
import com.oguzhanstech.hybridvpn.data.UpstreamMode
import com.oguzhanstech.hybridvpn.engine.policy.RoutePath
import com.oguzhanstech.hybridvpn.engine.policy.Routes
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import com.oguzhanstech.hybridvpn.vpn.TunConfig
import com.oguzhanstech.hybridvpn.vpn.VpnController
import com.oguzhanstech.hybridvpn.vpn.VpnInfo
import com.oguzhanstech.hybridvpn.vpn.VpnState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** Protection on/off, then one card per module (DNS, Tailscale, OpenVPN, proxies) with its own switches. */
@Composable
fun StatusScreen(
    onDns: () -> Unit,
    onTailnets: () -> Unit,
    onOpenVpn: () -> Unit,
    onProxies: () -> Unit,
    onLogs: () -> Unit,
    onRouting: () -> Unit,
    onTailnetDevices: () -> Unit,
) {
    val context = LocalContext.current
    val container = context.appContainer
    val state by VpnController.state.collectAsStateWithLifecycle()
    val settings by container.settings.settings.collectAsStateWithLifecycle()
    val tailnets by container.tailnets.tailnets.collectAsStateWithLifecycle()
    val profiles by container.openvpn.profiles.collectAsStateWithLifecycle()
    val proxies by container.proxies.proxies.collectAsStateWithLifecycle()
    val counters by container.dnsLog.counters.collectAsStateWithLifecycle()
    val info = (state as? VpnState.Running)?.info

    // Live session status from the engine, polled only while visible and only while it runs.
    var tailnetStatus by remember { mutableStateOf<Map<String, JSONObject>>(emptyMap()) }
    var openvpnStatus by remember { mutableStateOf<Map<String, JSONObject>>(emptyMap()) }
    var proxyStatus by remember { mutableStateOf<Map<String, JSONObject>>(emptyMap()) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle, info?.goEngine) {
        tailnetStatus = emptyMap()
        openvpnStatus = emptyMap()
        proxyStatus = emptyMap()
        if (info?.goEngine != true) return@LaunchedEffect
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                val (t, o, p) = withContext(Dispatchers.Default) {
                    Triple(GoBridge.tailnets().byId(), GoBridge.openvpnSessions().byId(), GoBridge.proxies().byId())
                }
                tailnetStatus = t
                openvpnStatus = o
                proxyStatus = p
                delay(2000)
            }
        }
    }

    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) VpnController.start(context)
    }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    fun start() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        val intent = VpnService.prepare(context)
        if (intent == null) VpnController.start(context) else consent.launch(intent)
    }

    val wantsGo = settings.engineMode == EngineMode.FULL_TUNNEL && GoBridge.available
    val needsRestart = info != null && (
        info.goEngine != wantsGo ||
            (info.goEngine && (info.tailnets.toSet() != tailnets.filter { it.enabled }.map { it.id }.toSet() ||
                info.openvpn.toSet() != profiles.filter { it.enabled }.map { it.id }.toSet() ||
                info.proxies.toSet() != proxies.filter { it.enabled }.map { it.transportId }.toSet() ||
                info.tunnelMtu != (if (settings.largeTunnelPackets) TunConfig.FULL_TUNNEL_MTU else TunConfig.MTU) ||
                info.tcpLossDetection != settings.tcpLossDetection ||
                info.openvpnPacketForwarding != settings.openvpnPacketForwarding ||
                info.allowIcmp != settings.allowIcmp ||
                info.allowIcmpv6 != settings.allowIcmpv6 ||
                info.lanBypass != settings.lanBypass))
        )

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val (title, detail) = when (val s = state) {
            is VpnState.Stopped -> "Protection off" to (s.reason ?: "Nothing is filtered or routed.")
            VpnState.Starting -> "Starting…" to "Compiling filter lists and opening the tunnel."
            is VpnState.Running -> "Protection on" to "Running since ${formatAgo(s.info.since)}"
            is VpnState.Failed -> "Could not start" to s.message
        }
        SectionCard(null) {
            Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            Text(detail, style = MaterialTheme.typography.bodyMedium)
            if (info != null) {
                InfoRow("Engine", info.transport)
                if (info.goEngine) InfoRow("LAN discovery & connections", if (info.lanBypass) "Outside VPN" else "VPN rules apply")
                InfoRow("Physical network", info.underlying ?: "none")
                InfoRow("Profile", info.profile)
            } else {
                InfoRow("Engine", if (wantsGo) "Full tunnel" else "DNS only")
            }
            if (needsRestart) {
                Text(
                    "Some changes (engine, tailnets, OpenVPN profiles, proxies, network compatibility, performance) apply after a restart. Connections drop for a moment.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                when (state) {
                    is VpnState.Running, VpnState.Starting -> Button(onClick = { VpnController.stop(context) }) { Text("Stop") }
                    else -> Button(onClick = ::start) { Text("Start") }
                }
                if (needsRestart) OutlinedButton(onClick = { VpnController.restart(context) }) { Text("Restart now") }
            }
        }

        info?.warnings?.forEach { WarningCard(it) }

        DnsModuleCard(
            info, counters,
            onToggle = { on ->
                container.settings.update { it.copy(dnsFiltering = on) }
                VpnController.reload(context)
            },
            onDns = onDns, onLogs = onLogs,
        )

        ModuleCard(
            title = "Tailscale",
            summary = when {
                !GoBridge.available -> "Not in this build (needs the Go engine)"
                tailnets.isEmpty() -> "No tailnets yet"
                else -> "${tailnets.count { it.enabled }} of ${tailnets.size} on"
            },
            manageLabel = if (tailnets.isEmpty()) "Add tailnet" else "Manage",
            manageEnabled = GoBridge.available,
            onManage = onTailnets,
            extraAction = if (info?.tailnets?.isNotEmpty() == true) ({ TextButton(onClick = onTailnetDevices) { Text("Devices") } }) else null,
        ) {
            tailnets.forEach { t ->
                val s = tailnetStatus[t.id]
                val (line, color) = sessionLine(
                    enabled = t.enabled, info = info, started = info?.tailnets?.contains(t.id) == true,
                    session = s, state = s?.optString("state")?.let(::prettyTailnetState),
                    healthy = s?.optString("state") == "Running",
                    detail = s?.optString("error")?.ifBlank { null }
                        ?: s?.optJSONArray("ips")?.takeIf { it.length() > 0 }?.let { "${it.getString(0)} · ${peerCount(s.optInt("peers"))}" },
                )
                ModuleRow(t.name.ifBlank { t.id }, line, color, t.enabled, enabled = GoBridge.available) { on ->
                    container.tailnets.setEnabled(t.id, on)
                    VpnController.reload(context)
                }
            }
        }

        ModuleCard(
            title = "OpenVPN",
            summary = when {
                !GoBridge.openvpnAvailable -> "Not in this build (needs OpenVPN 3 Core)"
                profiles.isEmpty() -> "No profiles yet"
                else -> "${profiles.count { it.enabled }} of ${profiles.size} on"
            },
            manageLabel = if (profiles.isEmpty()) "Import profile" else "Manage",
            manageEnabled = GoBridge.available,
            onManage = onOpenVpn,
        ) {
            profiles.forEach { p ->
                val s = openvpnStatus[p.id]
                val (line, color) = sessionLine(
                    enabled = p.enabled, info = info, started = info?.openvpn?.contains(p.id) == true,
                    session = s, state = s?.optString("state")?.replaceFirstChar { it.uppercase() },
                    healthy = s?.optString("state") == "connected",
                    detail = s?.optString("error")?.ifBlank { null } ?: s?.optString("vpn_ipv4")?.ifBlank { null } ?: p.remote.ifBlank { null },
                )
                ModuleRow(p.name.ifBlank { p.id }, line, color, p.enabled, enabled = GoBridge.openvpnAvailable) { on ->
                    container.openvpn.setEnabled(p.id, on)
                    VpnController.reload(context)
                }
            }
        }

        ModuleCard(
            title = "HTTP / SOCKS5 proxies",
            summary = when {
                !GoBridge.available -> "Not in this build (needs the Go engine)"
                proxies.isEmpty() -> "No proxies yet"
                else -> "${proxies.count { it.enabled }} of ${proxies.size} on"
            },
            manageLabel = if (proxies.isEmpty()) "Add proxy" else "Manage",
            manageEnabled = GoBridge.available,
            onManage = onProxies,
        ) {
            proxies.forEach { p ->
                val s = proxyStatus[p.id]
                val (line, color) = sessionLine(
                    enabled = p.enabled, info = info, started = info?.proxies?.contains(p.transportId) == true,
                    session = s,
                    state = when (s?.optString("state")) {
                        "ready" -> if (s.optBoolean("no_udp")) "Reachable, TCP only" else "Reachable"
                        "error" -> "Not working"
                        "idle" -> "Checking"
                        else -> null
                    },
                    healthy = s?.optString("state") == "ready",
                    detail = s?.optString("error")?.ifBlank { null }
                        ?: s?.let { "${it.optLong("tcp_active") + it.optLong("udp_active")} open flows" } ?: p.server,
                )
                ModuleRow("${p.kind.label} · ${p.name}", line, color, p.enabled, enabled = GoBridge.available) { on ->
                    container.proxies.setEnabled(p.id, on)
                    VpnController.reload(context)
                }
            }
        }

        if (info?.goEngine == true) RoutingCard(info, onRouting)

        if (info?.goEngine == true) EngineStatsCard()

        SectionCard("Kill switch") {
            Text(
                "This app can only block traffic while its VPN is running. For device-wide protection, enable " +
                    "\"Always-on VPN\" and \"Block connections without VPN\" for Hybrid VPN in Android settings.",
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }) { Text("Open VPN settings") }
        }
    }
}

@Composable
private fun DnsModuleCard(info: VpnInfo?, counters: DnsCounters, onToggle: (Boolean) -> Unit, onDns: () -> Unit, onLogs: () -> Unit) {
    val settings by LocalContext.current.appContainer.settings.settings.collectAsStateWithLifecycle()
    val on = settings.dnsFiltering
    ModuleCard(
        title = "DNS",
        summary = when {
            !on -> "Off: names are resolved, nothing is blocked"
            info == null -> "Filters when protection runs"
            else -> "Filtering · ${info.ruleCount} rules from ${info.listCount} lists"
        },
        switch = on,
        onSwitch = onToggle,
        manageLabel = "Lists & resolver",
        onManage = onDns,
        extraAction = { TextButton(onClick = onLogs) { Text("Query log") } },
    ) {
        InfoRow(
            "Resolver",
            info?.resolver ?: when (settings.upstreamMode) {
                UpstreamMode.NETWORK -> "Network default"
                UpstreamMode.UDP -> settings.udpServers
                UpstreamMode.DOT -> "DoT ${settings.dotHost}"
                UpstreamMode.DOH -> "DoH ${settings.dohUrl}"
            },
        )
        if (info != null) InfoRow("Blocked answer", prettyEnum(info.blockResponse.name))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Counter("Queries", counters.queries)
            Counter("Blocked", counters.blocked)
            Counter("Cached", counters.cached)
            Counter("Errors", counters.errors)
        }
    }
}

/** A module: title and one-line summary, an optional master switch, its rows, and a way to manage it. */
@Composable
private fun ModuleCard(
    title: String,
    summary: String,
    switch: Boolean? = null,
    onSwitch: (Boolean) -> Unit = {},
    manageLabel: String? = null,
    manageEnabled: Boolean = true,
    onManage: () -> Unit = {},
    extraAction: (@Composable () -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    SectionCard(null) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(summary, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (switch != null) Switch(switch, onSwitch)
        }
        content()
        if (manageLabel != null || extraAction != null) Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (manageLabel != null) OutlinedButton(onClick = onManage, enabled = manageEnabled) { Text(manageLabel) }
            extraAction?.invoke()
        }
    }
}

/** One tailnet or OpenVPN profile: name, live state, and its own on/off switch. */
@Composable
private fun ModuleRow(name: String, line: String, color: Color, checked: Boolean, enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge)
            Text(line, style = MaterialTheme.typography.bodySmall, color = color, maxLines = 2)
        }
        Switch(checked, onToggle, enabled = enabled)
    }
}

/** What a tailnet or OpenVPN session is doing, and the colour to show it in. */
@Composable
private fun sessionLine(enabled: Boolean, info: VpnInfo?, started: Boolean, session: JSONObject?, state: String?, healthy: Boolean, detail: String?): Pair<String, Color> {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    return when {
        !enabled -> (if (started) "Off · not used; disconnects at restart" else "Off") to muted
        info == null -> "Connects when protection starts" to muted
        !info.goEngine -> "Needs the full-tunnel engine" to MaterialTheme.colorScheme.error
        !started -> "On · connects at restart" to MaterialTheme.colorScheme.primary
        session == null -> "Starting…" to muted
        else -> listOfNotNull(state, detail).joinToString(" · ") to when {
            healthy -> MaterialTheme.colorScheme.primary
            session.optString("error").isNotBlank() -> MaterialTheme.colorScheme.error
            else -> muted
        }
    }
}

/** Right after connecting the machine list may not have arrived yet; "0 peers" would read as an empty tailnet. */
private fun peerCount(n: Int) = if (n == 0) "no other machines yet" else "$n peers"

/** Rules the engine applies to flows right now, and the way to the full routing view. */
@Composable
private fun RoutingCard(info: VpnInfo, onRouting: () -> Unit) {
    val rules = info.routing.filter { it.kind == RoutePath.Kind.FLOW }
    val default = info.routing.lastOrNull { it.kind == RoutePath.Kind.DEFAULT }
    ModuleCard(
        title = "Routing",
        summary = if (info.routing.isEmpty()) "Policy invalid: everything but DNS is blocked"
        else "${rules.count { it.inactive == null }} active rules · everything else → ${default?.target ?: "?"}",
        manageLabel = "Routing paths",
        onManage = onRouting,
    ) {
        rules.filter { it.inactive == null }.take(4).forEach {
            InfoRow(it.description ?: it.id, if (it.target == Routes.BLOCK) "blocked" else it.target)
        }
    }
}

private fun prettyTailnetState(state: String) = when (state) {
    "Running" -> "Connected"
    "NeedsLogin" -> "Needs login (open Manage)"
    "NeedsMachineAuth" -> "Waiting for admin approval"
    "NoState", "" -> "Starting"
    else -> state
}

private fun JSONArray.byId(): Map<String, JSONObject> = (0 until length()).map { getJSONObject(it) }.associateBy { it.optString("id") }

@Composable
private fun Counter(label: String, value: Long) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value.toString(), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        Text(label, style = MaterialTheme.typography.labelMedium)
    }
}

/** Live Go engine counters, polled only while the screen is visible (no background wake-ups). */
@Composable
private fun EngineStatsCard() {
    var stats by remember { mutableStateOf<JSONObject?>(null) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                stats = withContext(Dispatchers.Default) { GoBridge.stats() }
                delay(2000)
            }
        }
    }
    SectionCard("Traffic") {
        val s = stats
        if (s == null) {
            Text("No statistics yet", style = MaterialTheme.typography.bodySmall)
            return@SectionCard
        }
        InfoRow("TCP", "${s.optLong("tcpActive")} active · ${s.optLong("tcpTotal")} total · ${s.optLong("tcpFailed")} failed")
        InfoRow("UDP", "${s.optLong("udpActive")} active · ${s.optLong("udpTotal")} total")
        InfoRow("UDP datagrams", "↑ ${s.optLong("udpDatagramsUp")} · ↓ ${s.optLong("udpDatagramsDown")} · buffer drops ${s.optLong("udpReceiveBufferDrops")}")
        InfoRow("Packets", "from apps ${s.optLong("packetsIn")} · to apps ${s.optLong("packetsOut")}")
        InfoRow("DNS answered", "${s.optLong("dnsQueries")} (${s.optLong("dnsFailures")} without answer)")
        if (s.optLong("fastPacketsOut") > 0) {
            InfoRow(
                "OpenVPN packet forwarding",
                "${s.optLong("fastActive")} TCP active · ↑ ${s.optLong("fastPacketsOut")} ↓ ${s.optLong("fastPacketsIn")} packets " +
                    "(${s.optLong("fastCoalesced")} merged) · ${s.optLong("fastDropped")} dropped",
            )
        }
        InfoRow("Traffic", "↑ ${s.optLong("bytesUp") / 1024} KiB · ↓ ${s.optLong("bytesDown") / 1024} KiB")
        val dropped = s.optJSONObject("dropped")
        val routed = s.optJSONObject("routed")
        InfoRow("Flows by transport", routed?.keys()?.asSequence()?.joinToString { "$it ${routed.optLong(it)}" }?.ifEmpty { null } ?: "none")
        InfoRow("Dropped", dropped?.keys()?.asSequence()?.joinToString { "$it ${dropped.optLong(it)}" }?.ifEmpty { null } ?: "none")
        InfoRow("Go memory", "heap ${s.optLong("goHeapBytes") / 1024} KiB · sys ${s.optLong("goSysBytes") / 1048576} MiB · ${s.optInt("goroutines")} goroutines")
    }
}
