package com.oguzhanstech.hybridvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceDetailScreen(deviceId: String, onBack: () -> Unit) {
    val repo = LocalContext.current.appContainer.devices
    val scope = rememberCoroutineScope()
    val device by remember(deviceId) { repo.device(deviceId) }.collectAsStateWithLifecycle(null)
    val identifiers by remember(deviceId) { repo.identifiers(deviceId) }.collectAsStateWithLifecycle(emptyList())
    val history by remember(deviceId) { repo.history(deviceId) }.collectAsStateWithLifecycle(emptyList())
    var confirmDelete by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(device?.displayName ?: "Device") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                actions = { IconButton(onClick = { confirmDelete = true }) { Icon(Icons.Filled.Delete, "Delete") } },
            )
        },
    ) { padding ->
        val d = device ?: return@Scaffold
        var name by remember(d.id) { mutableStateOf(if (d.userAssignedName) d.displayName else "") }
        var group by remember(d.id) { mutableStateOf(d.groupName.orEmpty()) }
        var notes by remember(d.id) { mutableStateOf(d.notes.orEmpty()) }
        LaunchedEffect(d.userAssignedName, d.displayName) { if (d.userAssignedName) name = d.displayName }

        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SectionCard("Details") {
                InfoRow("Type", prettyEnum(d.deviceType))
                InfoRow("Last IP", d.lastIp)
                InfoRow("Vendor", d.vendor)
                InfoRow("Model", d.model)
                InfoRow("First seen", formatTime(d.firstSeen))
                InfoRow("Last seen", formatAgo(d.lastSeen))
                InfoRow("Identity confidence", confidenceLabel(d.confidence))
                if (d.manual) InfoRow("Source", "Added manually")
            }

            SectionCard("Your labels") {
                OutlinedTextField(
                    name, { name = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text("Name") }, placeholder = { Text(d.displayName) },
                    supportingText = { Text("Leave empty to use the discovered name") },
                )
                OutlinedTextField(group, { group = it }, modifier = Modifier.fillMaxWidth(), singleLine = true, label = { Text("Group") })
                OutlinedTextField(notes, { notes = it }, modifier = Modifier.fillMaxWidth(), minLines = 2, label = { Text("Notes") })
                OutlinedButton(onClick = {
                    scope.launch {
                        repo.rename(d.id, name)
                        repo.updateNotes(d.id, notes, group)
                    }
                }) { Text("Save") }
            }

            SectionCard("Identifiers") {
                if (identifiers.isEmpty()) Text("None", style = MaterialTheme.typography.bodySmall)
                identifiers.forEach { InfoRow(prettyEnum(it.kind), "${it.value} · ${formatAgo(it.lastSeen)}") }
                Text(
                    "Devices are linked across scans by MAC, UPnP UUID or mDNS name. An IP address alone is only trusted " +
                        "when nothing else is known and the device looks the same.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            val latest = history.firstOrNull()
            SectionCard("Services") {
                val services = latest?.services?.split(' ')?.filter { it.isNotBlank() }.orEmpty()
                if (services.isEmpty()) Text("None observed", style = MaterialTheme.typography.bodySmall)
                services.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }

            SectionCard("History") {
                if (history.isEmpty()) Text("No observations", style = MaterialTheme.typography.bodySmall)
                history.forEach { o ->
                    InfoRow(formatTime(o.timestamp), "${o.ipAddress} · ${if (o.reachable) "seen" else "not seen"}")
                }
            }
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete device?") },
            text = { Text("Its history and identifiers are removed. It will reappear as a new device if seen again.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch { repo.delete(deviceId); onBack() }
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
}
