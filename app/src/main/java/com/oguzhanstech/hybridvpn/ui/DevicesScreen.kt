package com.oguzhanstech.hybridvpn.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.DeviceListItem
import com.oguzhanstech.hybridvpn.scanner.AndroidLan
import com.oguzhanstech.hybridvpn.scanner.ScanState
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch

@Composable
fun DevicesScreen(onOpen: (String) -> Unit) {
    val context = LocalContext.current
    val container = context.appContainer
    val scope = rememberCoroutineScope()
    val networks by container.devices.allNetworks.collectAsStateWithLifecycle(emptyList())
    val scan by container.scanner.scanState.collectAsStateWithLifecycle()
    var selectedNetwork by rememberSaveable { mutableStateOf<String?>(null) }
    var lan by remember { mutableStateOf(AndroidLan.current(context)) }
    LaunchedEffect(scan) { if (scan is ScanState.Idle) lan = AndroidLan.current(context) }

    val currentNetworkId = networks.firstOrNull { it.key == lan?.key }?.id
    val networkId = selectedNetwork ?: currentNetworkId ?: networks.firstOrNull()?.id
    val network = networks.firstOrNull { it.id == networkId }
    val devices by remember(networkId) { networkId?.let { container.devices.devicesOn(it) } ?: flowOf(emptyList()) }
        .collectAsStateWithLifecycle(emptyList())

    var pendingRange by remember { mutableStateOf<String?>(null) }
    val scanPermissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        container.scanner.start(pendingRange)
    }
    fun startScan(range: String? = null) {
        val missing = requiredScanPermissions().filter {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }
        selectedNetwork = null
        if (missing.isEmpty()) container.scanner.start(range) else {
            pendingRange = range
            scanPermissions.launch(missing.toTypedArray())
        }
    }
    val locationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        lan = AndroidLan.current(context)
    }

    var exportFormat by remember { mutableStateOf("json") }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        if (uri != null) scope.launch {
            val text = if (exportFormat == "csv") container.devices.exportCsv(devices) else container.devices.exportJson(devices)
            context.contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
        }
    }

    var showAdd by remember { mutableStateOf(false) }
    var showRange by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(Modifier.fillMaxWidth().padding(top = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                NetworkPicker(network?.displayName ?: lan?.displayName ?: "No network", networks.map { it.id to it.displayName }) {
                    selectedNetwork = it
                }
                Text(
                    network?.let { "${it.subnet ?: ""} · last scan ${formatAgo(it.lastScanAt)}" } ?: "Not scanned yet",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (scan is ScanState.Running) OutlinedButton(onClick = { container.scanner.cancel() }) { Text("Cancel") }
            else Button(onClick = { startScan() }, enabled = lan != null) { Text("Scan") }
        }

        when (val s = scan) {
            is ScanState.Running -> {
                Text(s.phase + if (s.total > 0) " ${s.done}/${s.total}" else "", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
                if (s.total > 0) LinearProgressIndicator(progress = { s.done.toFloat() / s.total }, modifier = Modifier.fillMaxWidth())
                else LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            is ScanState.Failed -> Text(s.message, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
            is ScanState.Idle -> s.last?.let { summary ->
                Text(
                    "Found ${summary.seen} devices, ${summary.newDevices.size} new" +
                        if (summary.possibleDuplicates > 0) ", ${summary.possibleDuplicates} possible duplicates" else "",
                    style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp),
                )
                summary.warnings.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            }
        }

        if (lan?.isWifi == true && lan?.ssid == null) {
            TextButton(onClick = { locationPermission.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)) }) {
                Text("Allow location access to tell Wi-Fi networks apart by name")
            }
        }

        Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { showAdd = true }, enabled = network != null) { Text("Add") }
            OutlinedButton(onClick = { showRange = true }, enabled = lan != null && scan !is ScanState.Running) { Text("Range…") }
            OutlinedButton(onClick = { exportFormat = "json"; export.launch("devices.json") }, enabled = devices.isNotEmpty()) { Text("JSON") }
            OutlinedButton(onClick = { exportFormat = "csv"; export.launch("devices.csv") }, enabled = devices.isNotEmpty()) { Text("CSV") }
        }
        HorizontalDivider()

        if (devices.isEmpty()) {
            Text(
                if (lan == null) "Connect to Wi-Fi or Ethernet to scan." else "No devices yet. Tap Scan.",
                modifier = Modifier.padding(vertical = 24.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(devices, key = { it.device.id }) { item -> DeviceRow(item) { onOpen(item.device.id) } }
        }
    }

    if (showAdd && network != null) {
        var name by remember { mutableStateOf("") }
        var ip by remember { mutableStateOf("") }
        var error by remember { mutableStateOf<String?>(null) }
        AlertDialog(
            onDismissRequest = { showAdd = false },
            title = { Text("Add device") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true)
                    OutlinedTextField(ip, { ip = it }, label = { Text("IPv4 address") }, singleLine = true, isError = error != null, supportingText = error?.let { { Text(it) } })
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        container.devices.addManual(network, name, ip).fold({ showAdd = false }, { error = it.message })
                    }
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { showAdd = false }) { Text("Cancel") } },
        )
    }

    if (showRange) {
        var range by remember { mutableStateOf(lan?.subnet?.toString().orEmpty()) }
        AlertDialog(
            onDismissRequest = { showRange = false },
            title = { Text("Scan a range") },
            text = {
                Column {
                    Text("An IPv4 range reachable on this network. Ranges larger than /22 are narrowed to the /24 around this device.", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(range, { range = it }, label = { Text("CIDR, e.g. 192.168.1.0/24") }, singleLine = true)
                }
            },
            confirmButton = { TextButton(onClick = { showRange = false; startScan(range) }) { Text("Scan") } },
            dismissButton = { TextButton(onClick = { showRange = false }) { Text("Cancel") } },
        )
    }
}

private fun requiredScanPermissions(): List<String> = buildList {
    // Android 17 gates LAN access (multicast, connections to local addresses) behind a runtime permission.
    if (Build.VERSION.SDK_INT >= 37) add(Manifest.permission.ACCESS_LOCAL_NETWORK)
    if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.POST_NOTIFICATIONS)
}

@Composable
private fun NetworkPicker(current: String, options: List<Pair<String, String>>, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { open = true }, enabled = options.size > 1, contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp)) {
            Text(current, style = MaterialTheme.typography.titleMedium)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { (id, name) -> DropdownMenuItem(text = { Text(name) }, onClick = { open = false; onPick(id) }) }
        }
    }
}

@Composable
private fun DeviceRow(item: DeviceListItem, onClick: () -> Unit) {
    val d = item.device
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        leadingContent = {
            Box(Modifier.size(10.dp).background(if (item.online) Color(0xFF2E7D32) else Color(0xFF9E9E9E), CircleShape))
        },
        headlineContent = { Text(d.displayName) },
        supportingContent = {
            Text(listOfNotNull(prettyEnum(d.deviceType), item.ip, d.vendor ?: d.model, d.groupName).joinToString(" · "))
        },
        trailingContent = { Text(if (item.online) "Online" else formatAgo(d.lastSeen), style = MaterialTheme.typography.labelSmall) },
    )
}
