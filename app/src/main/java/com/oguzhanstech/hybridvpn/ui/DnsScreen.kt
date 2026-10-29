package com.oguzhanstech.hybridvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.FilterListEntity
import com.oguzhanstech.hybridvpn.data.Settings
import com.oguzhanstech.hybridvpn.data.UpstreamMode
import com.oguzhanstech.hybridvpn.engine.dns.BlockResponse
import com.oguzhanstech.hybridvpn.engine.dns.FilterListParser
import com.oguzhanstech.hybridvpn.vpn.VpnController
import kotlinx.coroutines.launch

/** DNS module settings: filter lists, my rules, and the resolver. Changes apply to a running VPN at once. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DnsScreen(onBack: () -> Unit) {
    var tab by rememberSaveable { mutableStateOf(0) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("DNS") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            PrimaryTabRow(selectedTabIndex = tab) {
                listOf("Lists", "My rules", "Resolver").forEachIndexed { i, title ->
                    Tab(selected = tab == i, onClick = { tab = i }, text = { Text(title) })
                }
            }
            when (tab) {
                0 -> ListsTab()
                1 -> UserRulesTab()
                else -> ResolverTab()
            }
        }
    }
}

@Composable
private fun ResolverTab() {
    val context = LocalContext.current
    val container = context.appContainer
    val settings by container.settings.settings.collectAsStateWithLifecycle()

    fun apply(transform: (Settings) -> Settings) {
        container.settings.update(transform)
        VpnController.reload(context)
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard("Resolver") {
            var udp by remember(settings.udpServers) { mutableStateOf(settings.udpServers) }
            var dot by remember(settings.dotHost) { mutableStateOf(settings.dotHost) }
            var doh by remember(settings.dohUrl) { mutableStateOf(settings.dohUrl) }
            Choice("Network default (plain DNS from your Wi-Fi or carrier)", settings.upstreamMode == UpstreamMode.NETWORK) { apply { it.copy(upstreamMode = UpstreamMode.NETWORK) } }
            Choice("Custom servers (plain DNS)", settings.upstreamMode == UpstreamMode.UDP) { apply { it.copy(upstreamMode = UpstreamMode.UDP) } }
            if (settings.upstreamMode == UpstreamMode.UDP) {
                OutlinedTextField(udp, { udp = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("IP addresses, comma separated") })
            }
            Choice("DNS over TLS", settings.upstreamMode == UpstreamMode.DOT) { apply { it.copy(upstreamMode = UpstreamMode.DOT) } }
            if (settings.upstreamMode == UpstreamMode.DOT) {
                OutlinedTextField(dot, { dot = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("Hostname, e.g. dns.quad9.net") })
            }
            Choice("DNS over HTTPS", settings.upstreamMode == UpstreamMode.DOH) { apply { it.copy(upstreamMode = UpstreamMode.DOH) } }
            if (settings.upstreamMode == UpstreamMode.DOH) {
                OutlinedTextField(
                    doh, { doh = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("https:// URL") },
                    supportingText = { Text("The server must accept HTTP/1.1") },
                )
            }
            if (settings.upstreamMode != UpstreamMode.NETWORK) {
                Button(onClick = { apply { it.copy(udpServers = udp.trim(), dotHost = dot.trim(), dohUrl = doh.trim()) } }) { Text("Save resolver") }
            }
            Text("Local names (.lan, home.arpa, private reverse lookups) always go to your network's own resolver.", style = MaterialTheme.typography.bodySmall)
        }

        SectionCard("Blocked domains are answered with") {
            Choice("0.0.0.0 / :: (fastest for apps)", settings.blockResponse == BlockResponse.NULL_IP) { apply { it.copy(blockResponse = BlockResponse.NULL_IP) } }
            Choice("NXDOMAIN (domain does not exist)", settings.blockResponse == BlockResponse.NXDOMAIN) { apply { it.copy(blockResponse = BlockResponse.NXDOMAIN) } }
            Choice("REFUSED", settings.blockResponse == BlockResponse.REFUSED) { apply { it.copy(blockResponse = BlockResponse.REFUSED) } }
        }
    }
}

@Composable
private fun ListsTab() {
    val context = LocalContext.current
    val repo = context.appContainer.filterLists
    val scope = rememberCoroutineScope()
    val lists by repo.lists.collectAsStateWithLifecycle(emptyList())
    var busy by remember { mutableStateOf(false) }
    var showAdd by remember { mutableStateOf(false) }

    fun run(block: suspend () -> Unit) {
        busy = true
        scope.launch {
            try { block() } finally {
                busy = false
                VpnController.reload(context)
            }
        }
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(Modifier.padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { showAdd = true }, enabled = !busy) { Text("Add list") }
            OutlinedButton(onClick = { run { repo.refreshAll() } }, enabled = !busy) { Text(if (busy) "Updating…" else "Update all") }
        }
        Text("Lists are downloaded only when you enable or update them. Changes apply to a running VPN immediately.", style = MaterialTheme.typography.bodySmall)
        LazyColumn(Modifier.fillMaxSize()) {
            items(lists, key = { it.id }) { list -> FilterListRow(list, busy, onToggle = { on -> run { repo.setEnabled(list.id, on) } }, onUpdate = { run { repo.refresh(list.id) } }, onRemove = { run { repo.remove(list.id) } }) }
        }
    }

    if (showAdd) {
        var name by remember { mutableStateOf("") }
        var url by remember { mutableStateOf("https://") }
        var error by remember { mutableStateOf<String?>(null) }
        AlertDialog(
            onDismissRequest = { showAdd = false },
            title = { Text("Add filter list") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true)
                    OutlinedTextField(url, { url = it }, label = { Text("HTTPS URL (AdGuard, hosts or domain list)") }, singleLine = true, isError = error != null, supportingText = error?.let { { Text(it) } })
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    try {
                        require(url.trim().startsWith("https://")) { "Only https:// URLs are accepted" }
                        java.net.URL(url.trim())
                        showAdd = false
                        run { repo.add(name, url.trim()) }
                    } catch (e: Exception) {
                        error = e.message
                    }
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { showAdd = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun FilterListRow(list: FilterListEntity, busy: Boolean, onToggle: (Boolean) -> Unit, onUpdate: () -> Unit, onRemove: () -> Unit) {
    ListItem(
        headlineContent = { Text(list.name) },
        supportingContent = {
            Column {
                Text(
                    "${list.ruleCount} rules" +
                        (if (list.unsupportedCount > 0) " · ${list.unsupportedCount} unsupported" else "") +
                        (if (list.url != null) " · updated ${formatAgo(list.lastUpdated)}" else ""),
                    style = MaterialTheme.typography.bodySmall,
                )
                list.lastError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                if (list.url != null) Row {
                    TextButton(onClick = onUpdate, enabled = !busy) { Text("Update") }
                    TextButton(onClick = onRemove, enabled = !busy) { Text("Remove") }
                }
            }
        },
        trailingContent = { Switch(list.enabled, onToggle, enabled = !busy) },
    )
}

@Composable
private fun UserRulesTab() {
    val context = LocalContext.current
    val repo = context.appContainer.filterLists
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf(repo.userRules()) }
    var status by remember { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            text, { text = it; status = null }, Modifier.fillMaxWidth(), minLines = 12,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = {
                scope.launch {
                    val parsed = FilterListParser.parse(text)
                    repo.saveUserRules(text)
                    VpnController.reload(context)
                    status = "Saved: ${parsed.rules.size} rules" +
                        (if (parsed.unsupported > 0) ", ${parsed.unsupported} unsupported" else "") +
                        (if (parsed.invalid > 0) ", ${parsed.invalid} invalid" else "")
                }
            }) { Text("Save") }
            status?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

