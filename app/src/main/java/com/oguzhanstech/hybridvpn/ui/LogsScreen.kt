package com.oguzhanstech.hybridvpn.ui

import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.LogMode
import com.oguzhanstech.hybridvpn.engine.dns.DnsOutcome
import com.oguzhanstech.hybridvpn.engine.dns.DnsType
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Everything the modules record: DNS queries, OpenVPN session logs, and engine errors. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen() {
    var tab by rememberSaveable { mutableStateOf(0) }
    Column(Modifier.fillMaxSize()) {
        PrimaryTabRow(selectedTabIndex = tab) {
            listOf("DNS", "OpenVPN", "Engine").forEachIndexed { i, title ->
                Tab(selected = tab == i, onClick = { tab = i }, text = { Text(title) })
            }
        }
        when (tab) {
            0 -> DnsLogTab()
            1 -> OpenVpnLogTab()
            else -> EngineLogTab()
        }
    }
}

private data class LogLine(val time: Long, val domain: String, val type: Int, val outcome: String, val app: String?, val detail: String?, val latency: Long)

@Composable
private fun DnsLogTab() {
    val container = LocalContext.current.appContainer
    val scope = rememberCoroutineScope()
    val settings by container.settings.settings.collectAsStateWithLifecycle()
    val memory by container.dnsLog.recent.collectAsStateWithLifecycle()
    val stored by container.dnsLog.persisted.collectAsStateWithLifecycle(emptyList())
    var filter by rememberSaveable { mutableStateOf("") }
    var blockedOnly by rememberSaveable { mutableStateOf(false) }

    val lines = if (settings.logMode == LogMode.PERSISTENT) {
        stored.map { LogLine(it.timestamp, it.domain, it.type, it.outcome, it.packageName, it.detail, it.latencyMs) }
    } else {
        memory.map { LogLine(it.timestamp, it.domain, it.type, it.outcome.name, it.packages?.firstOrNull(), it.detail, it.latencyMs) }
    }.filter { (!blockedOnly || it.outcome == DnsOutcome.BLOCKED.name) && (filter.isBlank() || it.domain.contains(filter.trim(), true) || it.app?.contains(filter.trim(), true) == true) }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        if (settings.logMode == LogMode.OFF) {
            Text("Query logging is off (Settings → Privacy). Only counters are kept.", modifier = Modifier.padding(vertical = 16.dp))
            return@Column
        }
        OutlinedTextField(filter, { filter = it }, Modifier.fillMaxWidth().padding(top = 8.dp), singleLine = true, label = { Text("Filter by domain or app") })
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(blockedOnly, { blockedOnly = it })
            Text("Blocked only", Modifier.weight(1f))
            TextButton(onClick = { scope.launch { container.dnsLog.clear() } }) { Text("Clear") }
        }
        HorizontalDivider()
        LazyColumn(Modifier.fillMaxSize()) {
            items(lines) { line ->
                val color = when (line.outcome) {
                    DnsOutcome.BLOCKED.name, DnsOutcome.ERROR.name -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                }
                ListItem(
                    headlineContent = { Text(line.domain, maxLines = 1) },
                    supportingContent = {
                        Text(
                            listOfNotNull(DnsType.name(line.type), line.app ?: "unknown app", line.detail, "${line.latency} ms").joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall, maxLines = 2,
                        )
                    },
                    trailingContent = {
                        Column(horizontalAlignment = Alignment.End) {
                            Text(prettyEnum(line.outcome), color = color, style = MaterialTheme.typography.labelMedium)
                            Text(formatAgo(line.time), style = MaterialTheme.typography.labelSmall)
                        }
                    },
                )
            }
        }
    }
}

/** Recent log lines of each running OpenVPN session; the engine keeps them in memory only. */
@Composable
private fun OpenVpnLogTab() {
    val profiles by LocalContext.current.appContainer.openvpn.profiles.collectAsStateWithLifecycle()
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    val id = selected ?: profiles.firstOrNull { it.enabled }?.id ?: profiles.firstOrNull()?.id
    var lines by remember { mutableStateOf<List<String>>(emptyList()) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle, id) {
        lines = emptyList()
        if (id == null) return@LaunchedEffect
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                lines = withContext(Dispatchers.Default) { GoBridge.openvpnLogLines(id) }
                delay(2000)
            }
        }
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        if (profiles.isEmpty()) {
            Text("No OpenVPN profiles. Import one from Status → OpenVPN.", Modifier.padding(vertical = 16.dp))
            return@Column
        }
        Row(Modifier.horizontalScroll(rememberScrollState()).padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            profiles.forEach { p -> FilterChip(selected = p.id == id, onClick = { selected = p.id }, label = { Text(p.name.ifBlank { p.id }) }) }
        }
        LogText(lines, "No log for this profile. Logs exist only while it runs, and are cleared when protection stops.")
    }
}

/**
 * Connections a transport could not deliver (from the running engine, memory only, the same
 * error counted rather than repeated), then fatal errors and panics of the Go engine (its stderr
 * is discarded on Android).
 */
@Composable
private fun EngineLogTab() {
    val context = LocalContext.current
    val file = remember { File(context.filesDir, "go-crash.log") }
    var lines by remember { mutableStateOf<List<String>?>(null) }
    var reload by remember { mutableStateOf(0) }
    LaunchedEffect(reload) {
        lines = withContext(Dispatchers.IO) {
            val clock = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            val failures = GoBridge.stats()?.optJSONArray("failures")?.let { a ->
                (0 until a.length()).map { a.getJSONObject(it) }.map { f ->
                    val count = f.optLong("count").takeIf { it > 1 }?.let { " (×$it)" }.orEmpty()
                    "${clock.format(Date(f.optLong("last")))} ${f.optString("transport")} ${f.optString("protocol")} failed$count: ${f.optString("error")}"
                }
            }.orEmpty()
            val crashes = if (file.exists()) file.readLines().takeLast(400) else emptyList()
            // LogText shows the last line first.
            crashes + failures.asReversed()
        }
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Go engine: ${remember { GoBridge.describe() }}", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = { reload++ }) { Text("Refresh") }
            TextButton(onClick = { file.delete(); reload++ }, enabled = lines != null && file.exists()) { Text("Clear") }
        }
        lines?.let { LogText(it, "No engine errors recorded.") }
    }
}

/** Newest line first, like the DNS log, so polling never has to fight the reader's scroll position. */
@Composable
private fun LogText(lines: List<String>, empty: String) {
    Text(
        lines.takeLast(400).asReversed().joinToString("\n").ifBlank { empty },
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 16.dp),
        style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
    )
}
