package com.oguzhanstech.hybridvpn.ui

import android.content.Intent
import android.content.pm.PackageManager
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.ProxyConfig
import com.oguzhanstech.hybridvpn.data.ProxyKind
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import com.oguzhanstech.hybridvpn.vpn.VpnController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** HTTP and SOCKS5 proxies: add, edit, switch on or off, and send all traffic or chosen apps through one. */
@OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun ProxiesScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val container = context.appContainer
    val proxies by container.proxies.proxies.collectAsStateWithLifecycle()
    val lists by container.filterLists.lists.collectAsStateWithLifecycle(emptyList())
    var status by remember { mutableStateOf<Map<String, JSONObject>>(emptyMap()) }
    var message by remember { mutableStateOf<String?>(null) }
    // null: closed; "": adding; otherwise the id being edited.
    var editing by remember { mutableStateOf<String?>(null) }
    var addingKind by remember { mutableStateOf(ProxyKind.HTTP) }
    var pickingAppsFor by remember { mutableStateOf<ProxyConfig?>(null) }

    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                val arr = withContext(Dispatchers.Default) { GoBridge.proxies() }
                status = (0 until arr.length()).map { arr.getJSONObject(it) }.associateBy { it.optString("id") }
                delay(2000)
            }
        }
    }

    fun route(p: ProxyConfig, apps: List<String>) {
        message = when (val r = container.policy.addProxyRoute(p, apps, lists.map { it.id }.toSet())) {
            is CompileResult.Ok -> {
                VpnController.reload(context)
                (if (apps.isEmpty()) "All traffic now goes to ${p.transportId}" else "${apps.size} app(s) now go to ${p.transportId}") +
                    ". If the proxy can't be reached, that traffic is blocked." + r.policy.warnings.joinToString("") { "\n⚠ $it" }
            }
            is CompileResult.Failed -> "Not saved: ${r.errors.joinToString()}"
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("HTTP / SOCKS5 proxies") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "HTTP proxies carry TCP through CONNECT; SOCKS5 carries TCP and, where supported, UDP. Traffic goes " +
                    "there only where a policy rule names it; if the proxy can't be reached, that traffic is blocked, never sent " +
                    "directly. Proxies switched on are used while protection runs with the full-tunnel engine; adding or switching " +
                    "one applies at the next start. DNS stays with the DNS firewall and is not sent to the proxy.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "HTTP proxy connections and SOCKS5 are not encrypted: the proxy, and the networks on the way to it, see where you connect, the proxy " +
                    "password, and anything apps send without TLS.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
            )
            Text(
                "mitmproxy defaults to an HTTP proxy on port 8080: start mitmproxy or mitmdump and add an HTTP proxy here. " +
                    "For SOCKS5, use --mode socks5. Both accept --proxyauth user:pass. To inspect HTTPS, the app must " +
                    "trust the proxy's certificate. HTTP authentication is checked on the first connection. " +
                    "Routing follows your existing policy order; failures block unless the policy names a fallback.",
                style = MaterialTheme.typography.bodySmall,
            )
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ProxyKind.entries.forEach { kind ->
                    Button(onClick = { addingKind = kind; editing = "" }, enabled = GoBridge.available) { Text("Add ${kind.label} proxy") }
                }
            }

            proxies.forEach { p ->
                val s = status[p.id]
                SectionCard("${p.kind.label} · ${p.name}") {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(if (p.enabled) "On" else "Off", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        Switch(p.enabled, { on -> container.proxies.setEnabled(p.id, on); VpnController.reload(context) })
                    }
                    InfoRow("Transport", p.transportId)
                    InfoRow("Server", p.server)
                    InfoRow("Login", p.username.ifEmpty { "none" })
                    InfoRow("State", s?.let { proxyState(it) } ?: "not running")
                    s?.optString("error")?.takeIf { it.isNotBlank() }?.let {
                        Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                    if (s?.optBoolean("no_udp") == true) {
                        Text(
                            "TCP only: the proxy does not support UDP, so UDP routed here is blocked. Apps then fall back " +
                                "from QUIC to TCP, which the proxy carries.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    s?.let {
                        InfoRow("Flows", "${it.optLong("tcp_active")} TCP · ${it.optLong("udp_active")} UDP open · ${it.optLong("flows")} total · ${it.optLong("failures")} failed")
                    }
                    if (s == null && p.enabled) {
                        Text(
                            "Used while protection runs with the full-tunnel engine. If protection is already on, restart it " +
                                "from the Status page.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    val apps = container.policy.proxyRouteApps(p)
                    Text(
                        when {
                            !container.policy.routesTo(p.transportId) -> "No policy rule sends traffic here yet."
                            apps != null -> "Routed: ${apps.size} app(s)."
                            else -> "Routed: all traffic (or a rule in the policy)."
                        },
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
                    )
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { pickingAppsFor = p }) { Text("Route apps") }
                        OutlinedButton(onClick = { route(p, emptyList()) }) { Text("Route all traffic") }
                        TextButton(onClick = { editing = p.id }) { Text("Edit") }
                        TextButton(onClick = { container.policy.retireTransport(p.transportId); container.proxies.remove(p.id); VpnController.reload(context); message = "Removed ${p.id}. Routes that used it now block; edit the policy to choose another path." }) {
                            Text("Remove")
                        }
                    }
                }
            }
        }
    }

    editing?.let { id ->
        ProxyDialog(
            existing = proxies.firstOrNull { it.id == id },
            kind = proxies.firstOrNull { it.id == id }?.kind ?: addingKind,
            onDismiss = { editing = null },
            onSave = { name, host, port, user, pass ->
                container.proxies.save(id.ifEmpty { null }, name, host, port, user, pass, proxies.firstOrNull { it.id == id }?.kind ?: addingKind).fold(
                    { p -> editing = null; message = "Saved ${p.transportId}. It is used from the next start."; null },
                    { it.message },
                )
            },
        )
    }
    pickingAppsFor?.let { p ->
        AppPickerDialog(
            initial = container.policy.proxyRouteApps(p).orEmpty().toSet(),
            onDismiss = { pickingAppsFor = null },
            onConfirm = { apps -> pickingAppsFor = null; if (apps.isNotEmpty()) route(p, apps.sorted()) },
        )
    }
}

private fun proxyState(s: JSONObject): String = when (s.optString("state")) {
    "ready" -> "Reachable" + s.optLong("last_seen").takeIf { it > 0 }?.let { " (${formatAgo(it)})" }.orEmpty()
    "error" -> "Not working"
    "idle" -> "Checking…"
    else -> s.optString("state")
}

/**
 * Adds or edits a proxy; [onSave] gets (name, host, port, username, password or null to keep the
 * stored one) and returns an error to show, or null when saved.
 */
@Composable
private fun ProxyDialog(existing: ProxyConfig?, kind: ProxyKind, onDismiss: () -> Unit, onSave: (String, String, Int?, String, String?) -> String?) {
    var name by remember { mutableStateOf(existing?.name.orEmpty()) }
    var host by remember { mutableStateOf(existing?.host.orEmpty()) }
    var port by remember { mutableStateOf(existing?.port?.toString() ?: kind.defaultPort.toString()) }
    var user by remember { mutableStateOf(existing?.username.orEmpty()) }
    var pass by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (existing == null) "Add ${kind.label} proxy" else "Edit ${existing.name}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(name, { name = it }, label = { Text("Name (optional)") }, singleLine = true)
                OutlinedTextField(host, { host = it.trim() }, label = { Text("Host name or IP address") }, singleLine = true)
                OutlinedTextField(
                    port, { port = it.filter(Char::isDigit).take(5) }, label = { Text("Port") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                OutlinedTextField(user, { user = it }, label = { Text("Username (optional)") }, singleLine = true)
                OutlinedTextField(
                    pass, { pass = it }, label = { Text("Password") }, singleLine = true, enabled = user.isNotBlank(),
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    supportingText = if (existing?.username?.isNotEmpty() == true) ({ Text("Leave empty to keep the saved one") }) else null,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val keep = existing?.username?.isNotEmpty() == true && pass.isEmpty()
                error = onSave(name, host, port.toIntOrNull(), user, if (keep) null else pass)
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private data class AppEntry(val packageName: String, val label: String)

/** Picks launchable apps by name; [onConfirm] gets their package names. */
@Composable
private fun AppPickerDialog(initial: Set<String>, onDismiss: () -> Unit, onConfirm: (Set<String>) -> Unit) {
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<AppEntry>?>(null) }
    var chosen by remember { mutableStateOf(initial) }
    var filter by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(launcher, PackageManager.MATCH_ALL)
                .map { AppEntry(it.activityInfo.packageName, it.loadLabel(pm).toString()) }
                .filter { it.packageName != context.packageName }
                .distinctBy { it.packageName }
                .sortedBy { it.label.lowercase() }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Apps to send through the proxy") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(filter, { filter = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("Search") })
                val list = apps
                if (list == null) {
                    Text("Loading apps…", style = MaterialTheme.typography.bodySmall)
                } else {
                    val shown = list.filter { filter.isBlank() || it.label.contains(filter, true) || it.packageName.contains(filter, true) }
                    LazyColumn(Modifier.heightIn(max = 400.dp)) {
                        items(shown, key = { it.packageName }) { app ->
                            Row(
                                Modifier.fillMaxWidth().clickable { chosen = if (app.packageName in chosen) chosen - app.packageName else chosen + app.packageName },
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(app.packageName in chosen, null)
                                Column(Modifier.padding(start = 8.dp)) {
                                    Text(app.label, style = MaterialTheme.typography.bodyMedium)
                                    Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(chosen) }, enabled = chosen.isNotEmpty()) { Text("Route ${chosen.size}") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
