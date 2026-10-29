package com.oguzhanstech.hybridvpn.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.TailnetConfig
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import com.oguzhanstech.hybridvpn.vpn.VpnController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TailnetsScreen(onBack: () -> Unit, onDevices: () -> Unit) {
    val context = LocalContext.current
    val container = context.appContainer
    val tailnets by container.tailnets.tailnets.collectAsStateWithLifecycle()
    val lists by container.filterLists.lists.collectAsStateWithLifecycle(emptyList())
    var status by remember { mutableStateOf<Map<String, JSONObject>>(emptyMap()) }
    var showAdd by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                val arr = withContext(Dispatchers.Default) { GoBridge.tailnets() }
                status = (0 until arr.length()).map { arr.getJSONObject(it) }.associateBy { it.optString("id") }
                delay(2000)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Tailnets") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Each tailnet is a separate Tailscale identity with its own state, login and status. Tailnets that are " +
                    "switched on connect while protection runs with the full-tunnel engine; adding or switching one applies " +
                    "at the next start. Traffic reaches a tailnet only through a policy rule naming it (tailnet:<id>), never " +
                    "by address alone; while a tailnet is off, its rules are skipped.",
                style = MaterialTheme.typography.bodySmall,
            )
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
            Button(onClick = { showAdd = true }) { Text("Add tailnet") }

            tailnets.forEach { t ->
                val s = status[t.id]
                SectionCard(t.name.ifBlank { t.id }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(if (t.enabled) "On" else "Off", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        Switch(t.enabled, { on -> container.tailnets.setEnabled(t.id, on); VpnController.reload(context) })
                    }
                    InfoRow("Transport", t.transportId)
                    InfoRow("Control server", t.controlUrl.ifBlank { "Tailscale" })
                    InfoRow("State", s?.optString("state") ?: "not running")
                    if (s == null && t.enabled) {
                        Text(
                            "Connects while protection runs with the full-tunnel engine (Settings → Engine). If protection is " +
                                "already on, restart it from the Status page.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    } else if (s != null && s.optString("state") == "NeedsLogin" && s.optString("auth_url").isBlank()) {
                        Text("Waiting for the login link…", style = MaterialTheme.typography.bodySmall)
                    }
                    if (!container.policy.routesTo(t.transportId)) {
                        Text(
                            "No policy rule sends traffic here yet. Tap \"Route tailnet addresses here\", then restart protection.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    s?.optJSONArray("ips")?.let { ips -> if (ips.length() > 0) InfoRow("Addresses", (0 until ips.length()).joinToString { ips.getString(it) }) }
                    s?.let { InfoRow("Peers", it.optInt("peers").toString()) }
                    if (s != null) OutlinedButton(onClick = onDevices) { Text("Show devices") }
                    s?.optString("error")?.takeIf { it.isNotBlank() }?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        s?.optString("auth_url")?.takeIf { it.isNotBlank() }?.let { url ->
                            Button(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }) { Text("Open login page") }
                        }
                        OutlinedButton(onClick = {
                            message = when (val r = container.policy.addTailnetRoute(t, lists.map { it.id }.toSet())) {
                                is CompileResult.Ok -> "Policy updated: Tailscale addresses go to ${t.transportId}" +
                                    r.policy.warnings.joinToString("") { "\n⚠ $it" }
                                is CompileResult.Failed -> "Not saved: ${r.errors.joinToString()}"
                            }
                        }) { Text("Route tailnet addresses here") }
                        TextButton(onClick = { container.policy.retireTransport(t.transportId); container.tailnets.remove(t.id); VpnController.reload(context); message = "Removed ${t.id} and its state. Routes that used it now block; edit the policy to choose another path." }) {
                            Text("Remove")
                        }
                    }
                }
            }
        }
    }

    if (showAdd) {
        var id by remember { mutableStateOf("") }
        var name by remember { mutableStateOf("") }
        var url by remember { mutableStateOf("") }
        var error by remember { mutableStateOf<String?>(null) }
        AlertDialog(
            onDismissRequest = { showAdd = false },
            title = { Text("Add tailnet") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(name, { name = it }, label = { Text("Name, e.g. Work") }, singleLine = true)
                    OutlinedTextField(id, { id = it.lowercase().trim() }, label = { Text("Id, e.g. work") }, singleLine = true)
                    OutlinedTextField(
                        url, { url = it.trim() }, label = { Text("Control server (optional)") }, singleLine = true,
                        isError = error != null, supportingText = { Text(error ?: "Leave empty for Tailscale; set for Headscale or a test server") },
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    container.tailnets.add(TailnetConfig(id, name, url)).fold({ showAdd = false }, { error = it.message })
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { showAdd = false }) { Text("Cancel") } },
        )
    }
}
