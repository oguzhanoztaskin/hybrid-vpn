package com.oguzhanstech.hybridvpn.ui

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.OpenVpnProfile
import com.oguzhanstech.hybridvpn.data.OpenVpnRepository
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import com.oguzhanstech.hybridvpn.vpn.VpnController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** A profile picked for import, waiting for a login and/or the private key's password. */
private data class PendingImport(
    val fileName: String,
    val text: String,
    val needsLogin: Boolean,
    val needsKeyPassword: Boolean,
    val lockedUser: String,
)

@OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun OpenVpnScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val container = context.appContainer
    val scope = rememberCoroutineScope()
    val profiles by container.openvpn.profiles.collectAsStateWithLifecycle()
    val lists by container.filterLists.lists.collectAsStateWithLifecycle(emptyList())
    var status by remember { mutableStateOf<Map<String, JSONObject>>(emptyMap()) }
    var message by remember { mutableStateOf<String?>(null) }
    var pending by remember { mutableStateOf<PendingImport?>(null) }
    var editing by remember { mutableStateOf<OpenVpnProfile?>(null) }
    var logFor by remember { mutableStateOf<String?>(null) }
    var importError by remember { mutableStateOf<String?>(null) }
    val available = remember { GoBridge.openvpnAvailable }

    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                val arr = withContext(Dispatchers.Default) { GoBridge.openvpnSessions() }
                status = (0 until arr.length()).map { arr.getJSONObject(it) }.associateBy { it.optString("id") }
                delay(2000)
            }
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val picked = withContext(Dispatchers.IO) {
                runCatching {
                    val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                        if (c.moveToFirst()) c.getString(0) else null
                    } ?: "profile.ovpn"
                    val bytes = context.contentResolver.openInputStream(uri)?.use { it.readAtMost(256 * 1024 + 1) } ?: error("cannot read the file")
                    if (bytes.size > 256 * 1024) error("the file is larger than 256 KB")
                    name to bytes.toString(Charsets.UTF_8)
                }
            }
            picked.fold({ (name, text) ->
                val eval = withContext(Dispatchers.Default) { GoBridge.openvpnEval(text) }
                val needsLogin = !eval.optBoolean("error", true) && !eval.optBoolean("autologin")
                val needsKey = !eval.optBoolean("error", true) && eval.optBoolean("private_key_password")
                if (needsLogin || needsKey) {
                    pending = PendingImport(name, text, needsLogin, needsKey, eval.optString("username"))
                } else {
                    // Import (or report why not) right away: nothing to ask for.
                    container.openvpn.import(name, text, "", "").fold(
                        { message = "Imported ${it.name} as ${it.transportId}." + scriptNote(text) },
                        { importError = it.message },
                    )
                }
            }, { importError = it.message })
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("OpenVPN") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Each profile is an OpenVPN connection (OpenVPN 3 Core) that runs, when switched on, while protection uses " +
                    "the full-tunnel engine; adding or switching one applies at the next start. Traffic goes through a profile " +
                    "only where a policy rule names it (openvpn:<id>), and only to networks its server routes; anything else " +
                    "sent there is blocked, never leaked to the internet. While a profile is off, its rules are skipped. " +
                    "Profiles must be self-contained (.ovpn with inline certificates); they and passwords are stored " +
                    "encrypted. Scripts in profiles are never run.",
                style = MaterialTheme.typography.bodySmall,
            )
            if (!available) {
                WarningCard("This build does not include OpenVPN (it needs the Go engine built with scripts/openvpn3-deps.sh).")
            }
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
            Button(onClick = { picker.launch(arrayOf("*/*")) }, enabled = available) { Text("Import .ovpn profile") }

            profiles.forEach { p ->
                val s = status[p.id]
                SectionCard(p.name.ifBlank { p.id }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(if (p.enabled) "On" else "Off", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        Switch(p.enabled, { on -> container.openvpn.setEnabled(p.id, on); VpnController.reload(context) }, enabled = available)
                    }
                    InfoRow("Transport", p.transportId)
                    InfoRow("Server", p.remote.ifBlank { null })
                    if (p.needsCredentials) InfoRow("Username", p.username)
                    InfoRow("State", s?.optString("state")?.let { st -> s.optString("event").takeIf { it.isNotBlank() && st != "connected" }?.let { "$st ($it)" } ?: st } ?: "not running")
                    if (s == null && p.enabled) {
                        Text(
                            "Connects while protection runs with the full-tunnel engine (Settings → Engine). If protection is " +
                                "already on, restart it from the Status page.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    s?.optString("error")?.takeIf { it.isNotBlank() }?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    s?.optString("vpn_ipv4")?.takeIf { it.isNotBlank() }?.let { InfoRow("VPN address", listOf(it, s.optString("vpn_ipv6")).filter(String::isNotBlank).joinToString()) }
                    val routes = s?.optJSONArray("routes")?.let { a -> List(a.length()) { a.getString(it) } }.orEmpty()
                    if (routes.isNotEmpty()) InfoRow("Server routes", routes.joinToString())
                    s?.optJSONArray("dns_servers")?.takeIf { it.length() > 0 }?.let { a ->
                        val domains = s.optJSONArray("dns_domains")?.let { d -> List(d.length()) { d.getString(it) } }.orEmpty()
                        InfoRow("Pushed DNS", List(a.length()) { a.getString(it) }.joinToString() + domains.takeIf { it.isNotEmpty() }?.joinToString(prefix = " for ").orEmpty())
                    }
                    s?.takeIf { it.optLong("bytes_in") > 0 }?.let { InfoRow("Traffic", "↓ ${formatBytes(it.optLong("bytes_in"))} ↑ ${formatBytes(it.optLong("bytes_out"))}") }
                    if (!container.policy.routesTo(p.transportId)) {
                        Text(
                            "No policy rule sends traffic here yet. Connect once, then tap \"Route its networks\" (or \"Route all " +
                                "traffic\"), and restart protection.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        // Routes the server pushed, minus redirect-gateway and exclusions.
                        val networks = routes.filter { !it.startsWith("!") && it != "0.0.0.0/0" && it != "::/0" }
                        OutlinedButton(enabled = networks.isNotEmpty(), onClick = {
                            message = routeResult(container.policy.addOpenVpnRoute(p, networks, lists.map { it.id }.toSet()), "${networks.joinToString()} go to ${p.transportId}")
                        }) { Text("Route its networks") }
                        OutlinedButton(onClick = {
                            message = routeResult(
                                container.policy.addOpenVpnRoute(p, listOf("0.0.0.0/0", "::/0"), lists.map { it.id }.toSet()),
                                "all traffic goes to ${p.transportId}; destinations its server does not route are blocked",
                            )
                        }) { Text("Route all traffic") }
                        TextButton(onClick = { logFor = p.id }, enabled = s != null) { Text("Log") }
                        if (p.needsCredentials || p.needsKeyPassword) TextButton(onClick = { editing = p }) { Text("Passwords") }
                        TextButton(onClick = { container.policy.retireTransport(p.transportId); container.openvpn.remove(p.id); VpnController.reload(context); message = "Removed ${p.id}. Routes that used it now block; edit the policy to choose another path." }) {
                            Text("Remove")
                        }
                    }
                }
            }
        }
    }

    pending?.let { imp ->
        CredentialsDialog(
            title = "Import ${imp.fileName}",
            askLogin = imp.needsLogin,
            askKeyPassword = imp.needsKeyPassword,
            initialUser = imp.lockedUser,
            userLocked = imp.lockedUser.isNotBlank(),
            onDismiss = { pending = null },
            onConfirm = { user, pass, keyPass ->
                container.openvpn.import(imp.fileName, imp.text, user, pass, keyPass).fold(
                    { message = "Imported ${it.name} as ${it.transportId}." + scriptNote(imp.text); pending = null; null },
                    { it.message },
                )
            },
        )
    }
    editing?.let { p ->
        CredentialsDialog(
            title = "Passwords for ${p.name}",
            askLogin = p.needsCredentials,
            askKeyPassword = p.needsKeyPassword,
            initialUser = p.username,
            userLocked = false,
            keepIfEmpty = true,
            onDismiss = { editing = null },
            onConfirm = { user, pass, keyPass ->
                container.openvpn.setCredentials(p.id, user, pass.ifEmpty { null }, keyPass.ifEmpty { null })?.let { return@CredentialsDialog it }
                message = "Saved. They apply at the next start."
                editing = null
                null
            },
        )
    }
    importError?.let { err ->
        AlertDialog(
            onDismissRequest = { importError = null },
            title = { Text("Profile not imported") },
            text = { Text(err) },
            confirmButton = { TextButton(onClick = { importError = null }) { Text("OK") } },
        )
    }
    logFor?.let { id ->
        val lines = remember(id) { GoBridge.openvpnLogLines(id) }
        AlertDialog(
            onDismissRequest = { logFor = null },
            title = { Text("Log: $id") },
            text = {
                Text(
                    lines.takeLast(120).joinToString("\n").ifBlank { "No log yet." },
                    Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState(Int.MAX_VALUE)),
                    style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                )
            },
            confirmButton = { TextButton(onClick = { logFor = null }) { Text("Close") } },
        )
    }
}

/** Reads up to [limit] bytes (InputStream.readNBytes needs API 33). */
private fun java.io.InputStream.readAtMost(limit: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(8192)
    while (out.size() < limit) {
        val n = read(buf, 0, minOf(buf.size, limit - out.size()))
        if (n < 0) break
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}

private fun scriptNote(text: String) = OpenVpnRepository.ignoredScriptDirectives(text).takeIf { it.isNotEmpty() }
    ?.let { "\nIgnored (scripts are never run): ${it.joinToString()}." }.orEmpty()

private fun routeResult(r: CompileResult, what: String) = when (r) {
    is CompileResult.Ok -> "Policy updated: $what. Restart protection to apply." + r.policy.warnings.joinToString("") { "\n⚠ $it" }
    is CompileResult.Failed -> "Not saved: ${r.errors.joinToString()}"
}

private fun formatBytes(n: Long): String = when {
    n >= 1L shl 30 -> "%.1f GB".format(n / (1L shl 30).toDouble())
    n >= 1L shl 20 -> "%.1f MB".format(n / (1L shl 20).toDouble())
    n >= 1L shl 10 -> "%.0f KB".format(n / 1024.0)
    else -> "$n B"
}

/**
 * Asks for a username and password and/or the private key's password; [onConfirm] gets
 * (username, password, key password) and returns an error to show, or null when done.
 */
@Composable
private fun CredentialsDialog(
    title: String,
    askLogin: Boolean,
    askKeyPassword: Boolean,
    initialUser: String,
    userLocked: Boolean,
    keepIfEmpty: Boolean = false,
    onDismiss: () -> Unit,
    onConfirm: (String, String, String) -> String?,
) {
    var user by remember { mutableStateOf(initialUser) }
    var pass by remember { mutableStateOf("") }
    var keyPass by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val hint = if (keepIfEmpty) "Leave empty to keep the saved one" else null
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (askLogin) {
                    OutlinedTextField(user, { user = it }, label = { Text("Username") }, singleLine = true, enabled = !userLocked)
                    PasswordField(pass, { pass = it }, "Password", hint)
                }
                if (askKeyPassword) {
                    Text("The profile's private key is encrypted.", style = MaterialTheme.typography.bodySmall)
                    PasswordField(keyPass, { keyPass = it }, "Private key password", hint)
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { TextButton(onClick = { error = onConfirm(user, pass, keyPass) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PasswordField(value: String, onChange: (String) -> Unit, label: String, hint: String?) {
    OutlinedTextField(
        value, onChange, label = { Text(label) }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        supportingText = hint?.let { { Text(it) } },
    )
}
