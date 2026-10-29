package com.oguzhanstech.hybridvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.oguzhanstech.hybridvpn.data.OpenVpnProfile
import com.oguzhanstech.hybridvpn.data.TailnetConfig
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import com.oguzhanstech.hybridvpn.engine.policy.RoutePath
import com.oguzhanstech.hybridvpn.engine.policy.Routes
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import com.oguzhanstech.hybridvpn.vpn.VpnController
import com.oguzhanstech.hybridvpn.vpn.VpnInfo
import com.oguzhanstech.hybridvpn.vpn.VpnState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** A transport's live state, for the routing view. */
private data class Live(val text: String, val healthy: Boolean, val routes: List<String>? = null)

/**
 * The routing the running engine applies: rules in evaluation order with where matching traffic
 * goes and whether that connection is up. Built-in guards and DNS-only rules are hidden by default.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RoutingScreen(onBack: () -> Unit) {
    val state by VpnController.state.collectAsStateWithLifecycle()
    val info = (state as? VpnState.Running)?.info
    var showAll by rememberSaveable { mutableStateOf(false) }
    var live by remember { mutableStateOf<Map<String, Live>>(emptyMap()) }
    var flows by remember { mutableStateOf<JSONObject?>(null) }

    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle, info?.goEngine) {
        if (info?.goEngine != true) return@LaunchedEffect
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                val (l, f) = withContext(Dispatchers.Default) { liveTransports(info) to GoBridge.stats()?.optJSONObject("routed") }
                live = l
                flows = f
                delay(2000)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Routing") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "How each new connection is routed right now. Rules are checked top to bottom and the first match " +
                    "decides; a connection that can't be delivered goes to its fallback, never silently to the internet. " +
                    "Edit rules under Settings → Edit policy.",
                style = MaterialTheme.typography.bodySmall,
            )
            when {
                info == null -> {
                    SectionCard(null) { Text("Protection is off: nothing is routed.", style = MaterialTheme.typography.bodyMedium) }
                    return@Column
                }
                !info.goEngine -> {
                    SectionCard(null) {
                        Text("DNS-only mode: only DNS passes through the app, so these rules don't route traffic. " +
                            "Choose the full-tunnel engine under Settings → Engine.", style = MaterialTheme.typography.bodyMedium)
                    }
                    return@Column
                }
                info.routing.isEmpty() -> {
                    info.warnings.forEach { WarningCard(it) }
                    return@Column
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Show DNS and built-in rules", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Fixed guards (DNS interception, loop guard, …) and rules that act on names when they're resolved",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(showAll, { showAll = it })
            }
            val rows = info.routing.filter { showAll || (it.kind != RoutePath.Kind.BUILTIN && it.kind != RoutePath.Kind.DNS) }
            rows.forEachIndexed { i, row -> RouteCard(i + 1, row, info, live, flows) }
        }
    }
}

@Composable
private fun RouteCard(number: Int, row: RoutePath, info: VpnInfo, live: Map<String, Live>, flows: JSONObject?) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val inactive = row.inactive != null
    SectionCard(null) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "$number. ${row.description ?: row.id}", Modifier.weight(1f),
                style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold,
                color = if (inactive) muted else Color.Unspecified,
            )
            Text(
                when (row.kind) {
                    RoutePath.Kind.BUILTIN -> "built-in"
                    RoutePath.Kind.DNS -> "DNS"
                    RoutePath.Kind.DEFAULT -> "default"
                    RoutePath.Kind.FLOW -> row.id.takeIf { row.description != null } ?: ""
                },
                style = MaterialTheme.typography.labelSmall, color = muted,
            )
        }
        Text(
            if (row.kind == RoutePath.Kind.DEFAULT) "Anything no rule above matched" else row.conditions.joinToString(" · ").ifEmpty { "All traffic" },
            style = MaterialTheme.typography.bodyMedium, color = if (inactive) muted else Color.Unspecified,
        )
        val (targetText, targetColor) = targetLine(row.target, info, live, flows, row.kind)
        Text("→ $targetText", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium, color = if (inactive) muted else targetColor)
        row.onFailure?.let { fb ->
            Text(
                "If unavailable: " + if (fb == Routes.BLOCK) "blocked" else fb,
                style = MaterialTheme.typography.bodySmall, color = muted,
            )
        }
        row.inactive?.let { Text("Not applied: $it", style = MaterialTheme.typography.bodySmall, color = muted) }
        // An OpenVPN transport carries only what its server routes; say which destinations it won't.
        val routes = live[row.target]?.routes
        if (!inactive && routes != null && row.cidrs.isNotEmpty()) {
            val notRouted = row.cidrs.filterNot { serverRoutes(routes, it) }
            if (notRouted.isNotEmpty()) {
                Text(
                    "Not routed by this server, so blocked: ${notRouted.joinToString()}",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun targetLine(target: String, info: VpnInfo, live: Map<String, Live>, flows: JSONObject?, kind: RoutePath.Kind): Pair<String, Color> {
    val ok = MaterialTheme.colorScheme.primary
    val bad = MaterialTheme.colorScheme.error
    val count = flows?.optLong(target)?.takeIf { it > 0 }?.let { " · $it flows" }.orEmpty()
    return when {
        kind == RoutePath.Kind.BUILTIN -> target.replaceFirstChar { it.uppercase() } to Color.Unspecified
        target == Routes.BLOCK -> "Blocked" to bad
        target == Routes.DIRECT -> "Direct (${info.underlying ?: "no physical network"})$count" to if (info.underlying != null) ok else bad
        else -> live[target]?.let { "$target · ${it.text}$count" to if (it.healthy) ok else bad } ?: ("$target · not running" to bad)
    }
}

/** Whether a server's routes ("0.0.0.0/0", "10.8.0.0/24", "!excluded") cover all of [cidr]. */
private fun serverRoutes(routes: List<String>, cidr: Cidr): Boolean {
    val excluded = routes.filter { it.startsWith("!") }.mapNotNull { Cidr.parse(it.drop(1)) }
    if (excluded.any { it.overlaps(cidr) }) return false
    return routes.filterNot { it.startsWith("!") }.mapNotNull(Cidr::parse).any { it.contains(cidr) }
}

/** Live state of every transport the engine was started with, by transport id. */
private fun liveTransports(info: VpnInfo): Map<String, Live> {
    val out = HashMap<String, Live>()
    GoBridge.tailnets().objects().forEach { s ->
        val running = s.optString("state") == "Running"
        out[TailnetConfig.TRANSPORT_PREFIX + s.optString("id")] = Live(
            if (running) "connected" else s.optString("error").ifBlank { s.optString("state").ifBlank { "starting" } }, running,
        )
    }
    GoBridge.openvpnSessions().objects().forEach { s ->
        val state = s.optString("state")
        val routes = s.optJSONArray("routes")?.let { a -> List(a.length()) { a.getString(it) } }
        out[OpenVpnProfile.TRANSPORT_PREFIX + s.optString("id")] = Live(
            listOfNotNull(state, s.optString("error").ifBlank { null }).joinToString(": "), state == "connected",
            routes = if (state == "connected") routes.orEmpty() else null,
        )
    }
    GoBridge.proxies().objects().forEach { s ->
        val ready = s.optString("state") == "ready"
        out[s.optString("type", "socks5") + ":" + s.optString("id")] = Live(
            if (ready) "reachable" else s.optString("error").ifBlank { "checking" }, ready,
        )
    }
    // Started but not reported yet (still starting).
    (info.tailnets.map { TailnetConfig.TRANSPORT_PREFIX + it } + info.openvpn.map { OpenVpnProfile.TRANSPORT_PREFIX + it } +
        info.proxies).forEach { out.putIfAbsent(it, Live("starting", false)) }
    return out
}

private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
