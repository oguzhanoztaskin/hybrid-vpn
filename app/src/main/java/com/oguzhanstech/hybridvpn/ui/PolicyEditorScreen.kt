package com.oguzhanstech.hybridvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.vpn.VpnController

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PolicyEditorScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val container = context.appContainer
    val lists by container.filterLists.lists.collectAsStateWithLifecycle(emptyList())
    val listIds = lists.map { it.id }.toSet()
    var text by remember { mutableStateOf(container.policy.text()) }
    var result by remember { mutableStateOf<CompileResult?>(null) }
    var saved by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Policy") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Rules are evaluated by priority (lowest first); the first match decides. Available lists: " +
                    (listOf("@all") + listIds).joinToString() + ". Routes: \"direct\" and declared transports (debug builds: \"tailnet:<id>\" for configured tailnets). " +
                    "See docs/ROUTING.md for the format.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                text, { text = it; result = null; saved = false }, Modifier.fillMaxWidth(), minLines = 16,
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { result = container.policy.validate(text, listIds); saved = false }) { Text("Validate") }
                Button(onClick = {
                    val r = container.policy.save(text, listIds)
                    result = r
                    saved = r is CompileResult.Ok
                    if (saved) VpnController.reload(context)
                }) { Text("Save") }
                OutlinedButton(onClick = {
                    container.policy.reset()
                    text = container.policy.text()
                    result = null
                    VpnController.reload(context)
                }) { Text("Reset") }
            }
            when (val r = result) {
                is CompileResult.Ok -> SectionCard(if (saved) "Saved and applied" else "Valid") {
                    Text("${r.policy.rules.size} active rules", style = MaterialTheme.typography.bodyMedium)
                    r.policy.warnings.forEach { Text("⚠ $it", style = MaterialTheme.typography.bodySmall) }
                }
                is CompileResult.Failed -> SectionCard("Not saved — fix these errors", containerColor = MaterialTheme.colorScheme.errorContainer) {
                    r.errors.forEach { Text(it, color = MaterialTheme.colorScheme.onErrorContainer, style = MaterialTheme.typography.bodySmall) }
                }
                null -> Unit
            }
        }
    }
}
