package com.oguzhanstech.hybridvpn.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** Machines in each running tailnet, live from the tailnet nodes (polled only while visible). */
@Composable
fun TailnetDevicesScreen(onOpenTailnets: () -> Unit) {
    val container = LocalContext.current.appContainer
    val configured by container.tailnets.tailnets.collectAsStateWithLifecycle()
    var machines by remember { mutableStateOf(JSONObject()) }
    var selected by remember { mutableStateOf<JSONObject?>(null) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                machines = withContext(Dispatchers.Default) { GoBridge.tailnetMachines() }
                delay(5000)
            }
        }
    }

    if (machines.length() == 0) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionCard("No tailnet is running") {
                Text(
                    when {
                        !GoBridge.available -> "This build does not include the Go engine."
                        configured.isEmpty() -> "Add a tailnet first (Status → Tailscale)."
                        else -> "Tailnets that are switched on run while protection is on with the full-tunnel engine " +
                            "(Settings → Engine). Log in from the Tailnets screen if asked."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedButton(onClick = onOpenTailnets, enabled = GoBridge.available) { Text("Open Tailnets") }
            }
        }
        return
    }

    LazyColumn(Modifier.fillMaxSize()) {
        for (id in machines.keys().asSequence().toList().sorted()) {
            val peers = machines.optJSONArray(id) ?: JSONArray()
            val name = configured.firstOrNull { it.id == id }?.name?.ifBlank { null } ?: id
            item(key = "h-$id") {
                Text(
                    "$name · ${(0 until peers.length()).count { peers.getJSONObject(it).optBoolean("online") }} online of ${peers.length()}",
                    style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
                )
            }
            if (peers.length() == 0) item(key = "w-$id") {
                Text(
                    "Waiting for the machine list. It arrives once the tailnet has connected; if it stays empty, check the " +
                        "tailnet's state on Status.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
            items((0 until peers.length()).map { peers.getJSONObject(it) }, key = { "$id-${it.optString("id")}" }) { p ->
                MachineRow(p) { selected = p }
                HorizontalDivider()
            }
        }
    }

    selected?.let { MachineDetails(it) { selected = null } }
}

private fun JSONObject.strings(key: String): List<String> = optJSONArray(key)?.let { a -> (0 until a.length()).map { a.getString(it) } }.orEmpty()

private fun machineName(p: JSONObject) = p.optString("hostname").ifBlank { p.optString("dns_name").substringBefore('.') }

@Composable
private fun MachineRow(p: JSONObject, onClick: () -> Unit) {
    val badges = listOfNotNull(
        "this device".takeIf { p.optBoolean("self") },
        "exit node".takeIf { p.optBoolean("exit_node") },
        "shared".takeIf { p.optBoolean("shared") },
    )
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        headlineContent = { Text(machineName(p) + if (badges.isEmpty()) "" else "  (${badges.joinToString()})") },
        supportingContent = {
            Text(
                listOfNotNull(p.optString("os").ifBlank { null }, p.strings("ips").firstOrNull(), p.optString("connection").ifBlank { null })
                    .joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
            )
        },
        trailingContent = {
            Text(
                if (p.optBoolean("online")) "Online" else p.optLong("last_seen").takeIf { it > 0 }?.let { formatAgo(it) } ?: "Offline",
                style = MaterialTheme.typography.labelSmall,
                color = if (p.optBoolean("online")) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
    )
}

@Composable
private fun MachineDetails(p: JSONObject, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf<String?>(null) }
    @Composable
    fun Copyable(label: String, value: String) {
        Column(Modifier.clickable { clipboard.setText(AnnotatedString(value)); copied = value }.padding(vertical = 4.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyMedium)
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(machineName(p)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                p.optString("dns_name").ifBlank { null }?.let { Copyable("MagicDNS name", it) }
                p.strings("ips").forEach { Copyable("Tailscale address", it) }
                p.strings("subnet_routes").forEach { Copyable("Subnet route", it) }
                InfoRow("Status", if (p.optBoolean("online")) "Online" else "Offline" + (p.optLong("last_seen").takeIf { it > 0 }?.let { ", last seen ${formatAgo(it)}" } ?: ""))
                InfoRow("Connection", p.optString("connection").ifBlank { null })
                InfoRow("OS", p.optString("os").ifBlank { null })
                InfoRow("Owner", p.optString("user").ifBlank { null })
                p.strings("tags").takeIf { it.isNotEmpty() }?.let { InfoRow("Tags", it.joinToString()) }
                InfoRow("Exit node", when { p.optBoolean("exit_node") -> "in use"; p.optBoolean("exit_node_option") -> "available"; else -> "no" })
                if (p.optBoolean("shared")) InfoRow("Shared", "from another tailnet")
                p.optLong("key_expiry").takeIf { it > 0 }?.let { InfoRow("Key expires", formatTime(it)) }
                p.optLong("created").takeIf { it > 0 }?.let { InfoRow("Added", formatTime(it)) }
                p.optLong("last_handshake").takeIf { it > 0 }?.let { InfoRow("Last handshake", formatAgo(it)) }
                if (p.optLong("rx_bytes") + p.optLong("tx_bytes") > 0) InfoRow("Traffic", "↓ ${p.optLong("rx_bytes") / 1024} KiB · ↑ ${p.optLong("tx_bytes") / 1024} KiB")
                InfoRow("Node id", p.optString("id").ifBlank { null })
                copied?.let { Text("Copied $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
                Text("Tap a name or address to copy it.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
