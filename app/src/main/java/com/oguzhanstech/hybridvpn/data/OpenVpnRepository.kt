package com.oguzhanstech.hybridvpn.data

import android.content.Context
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * An imported OpenVPN profile. The profile text (it contains the client's private key) and the
 * password are stored encrypted (see [SecretStore]); only this metadata is plain.
 */
data class OpenVpnProfile(
    val id: String,
    val name: String,
    /** "host:port/proto" of the first remote, for display. */
    val remote: String,
    /** The server asks for a username and password. */
    val needsCredentials: Boolean,
    val username: String = "",
    /** The private key is encrypted; its password is stored encrypted too. */
    val needsKeyPassword: Boolean = false,
    /** Switched off, the profile does not connect and rules routing to it are skipped. */
    val enabled: Boolean = true,
) {
    val transportId: String get() = TRANSPORT_PREFIX + id

    companion object {
        const val TRANSPORT_PREFIX = "openvpn:"
        val ID = Regex("^[a-z0-9][a-z0-9-]{0,31}$")
    }
}

class OpenVpnRepository(context: Context) {
    private val file = File(context.filesDir, "openvpn.json")
    private val secrets = SecretStore(File(context.filesDir, "openvpn"))
    private val state = MutableStateFlow(load())
    val profiles: StateFlow<List<OpenVpnProfile>> = state.asStateFlow()

    /**
     * Imports a profile after OpenVPN 3 Core has parsed it. Only self-contained profiles work:
     * certificates and keys must be inline. Credentials are required when the server asks for them,
     * and [keyPassword] when the private key is encrypted; it is checked here, not at connect time.
     */
    fun import(fileName: String, text: String, username: String, password: String, keyPassword: String = ""): Result<OpenVpnProfile> {
        if (!GoBridge.openvpnAvailable) return Result.failure(IllegalStateException("This build does not include OpenVPN"))
        if (text.length > MAX_PROFILE_BYTES) return Result.failure(IllegalArgumentException("Profile is larger than 256 KB"))
        val eval = GoBridge.openvpnEval(text)
        if (eval.optBoolean("error", true)) {
            val msg = eval.optString("message").ifBlank { "unknown error" }
            val hint = if (msg.contains("file", ignoreCase = true)) " (certificates and keys must be inline in the .ovpn file)" else ""
            return Result.failure(IllegalArgumentException("OpenVPN rejected the profile: $msg$hint"))
        }
        if (eval.optBoolean("external_pki")) return Result.failure(IllegalArgumentException("The profile has no client key; external certificates are not supported"))
        val needsKeyPass = eval.optBoolean("private_key_password")
        if (needsKeyPass) {
            when (GoBridge.openvpnCheckKeyPassword(text, keyPassword)) {
                1 -> Unit
                0 -> return Result.failure(IllegalArgumentException(
                    if (keyPassword.isEmpty()) "The private key is encrypted: enter its password" else "The private key password is wrong"))
                else -> return Result.failure(IllegalArgumentException("Could not read the profile's private key"))
            }
        }
        if (eval.optString("static_challenge").isNotBlank()) return Result.failure(IllegalArgumentException("Challenge/response logins are not supported yet"))
        val needsCreds = !eval.optBoolean("autologin")
        val user = eval.optString("username").ifBlank { username.trim() }
        if (needsCreds && (user.isBlank() || password.isEmpty())) {
            return Result.failure(IllegalArgumentException("This server needs a username and password"))
        }
        val name = eval.optString("friendly_name").ifBlank { fileName.substringBeforeLast('.') }
            .ifBlank { eval.optString("profile_name") }.ifBlank { "OpenVPN" }
        val profile = OpenVpnProfile(
            id = uniqueId(fileName.substringBeforeLast('.').ifBlank { name }),
            name = name,
            remote = listOf(eval.optString("remote_host"), eval.optString("remote_port")).filter { it.isNotBlank() }.joinToString(":") +
                eval.optString("remote_proto").takeIf { it.isNotBlank() }?.let { "/${it.lowercase()}" }.orEmpty(),
            needsCredentials = needsCreds,
            username = if (needsCreds) user else "",
            needsKeyPassword = needsKeyPass,
        )
        secrets.write("${profile.id}.ovpn", text.toByteArray())
        if (needsCreds) secrets.write("${profile.id}.pass", password.toByteArray())
        if (needsKeyPass) secrets.write("${profile.id}.keypass", keyPassword.toByteArray())
        save(state.value + profile)
        return Result.success(profile)
    }

    fun profileText(id: String): String? = secrets.read("$id.ovpn")?.toString(Charsets.UTF_8)

    fun password(id: String): String = secrets.read("$id.pass")?.toString(Charsets.UTF_8).orEmpty()

    fun keyPassword(id: String): String = secrets.read("$id.keypass")?.toString(Charsets.UTF_8).orEmpty()

    /**
     * Replaces the stored credentials; null leaves one unchanged. A key password is checked against
     * the stored profile first. Returns an error message, or null when saved.
     */
    fun setCredentials(id: String, username: String?, password: String?, keyPassword: String?): String? {
        val p = state.value.firstOrNull { it.id == id } ?: return "Unknown profile"
        if (keyPassword != null && p.needsKeyPassword) {
            val text = profileText(id) ?: return "The stored profile can't be read; import it again"
            if (GoBridge.openvpnCheckKeyPassword(text, keyPassword) != 1) return "The private key password is wrong"
            secrets.write("$id.keypass", keyPassword.toByteArray())
        }
        if (password != null && p.needsCredentials) secrets.write("$id.pass", password.toByteArray())
        if (username != null && p.needsCredentials) save(state.value.map { if (it.id == id) p.copy(username = username.trim()) else it })
        return null
    }

    fun setEnabled(id: String, enabled: Boolean) = save(state.value.map { if (it.id == id) it.copy(enabled = enabled) else it })

    fun remove(id: String) {
        save(state.value.filterNot { it.id == id })
        secrets.delete("$id.ovpn")
        secrets.delete("$id.pass")
        secrets.delete("$id.keypass")
    }

    private fun uniqueId(base: String): String {
        val slug = base.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').take(24).ifBlank { "vpn" }
        val taken = state.value.map { it.id }.toSet()
        if (slug !in taken) return slug
        return (2..999).map { "$slug-$it" }.first { it !in taken }
    }

    private fun save(list: List<OpenVpnProfile>) {
        val arr = JSONArray()
        list.forEach {
            arr.put(
                JSONObject().put("id", it.id).put("name", it.name).put("remote", it.remote)
                    .put("needsCredentials", it.needsCredentials).put("username", it.username)
                    .put("needsKeyPassword", it.needsKeyPassword).put("enabled", it.enabled)
            )
        }
        file.writeText(arr.toString(2))
        state.value = list
    }

    private fun load(): List<OpenVpnProfile> = try {
        val arr = JSONArray(file.readText())
        List(arr.length()) { i ->
            arr.getJSONObject(i).let {
                OpenVpnProfile(
                    it.getString("id"), it.optString("name"), it.optString("remote"), it.optBoolean("needsCredentials"),
                    it.optString("username"), it.optBoolean("needsKeyPassword"), it.optBoolean("enabled", true),
                )
            }
        }.filter { OpenVpnProfile.ID.matches(it.id) }
    } catch (_: Exception) {
        emptyList()
    }

    companion object {
        private const val MAX_PROFILE_BYTES = 256 * 1024
        private val SCRIPT_DIRECTIVES = setOf(
            "up", "down", "route-up", "route-pre-down", "ipchange", "script-security", "plugin",
            "tls-verify", "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address",
        )

        /**
         * Directives in [text] that run programs. OpenVPN 3 Core has no script support and ignores
         * them; the user is told so on import rather than left assuming they ran.
         */
        fun ignoredScriptDirectives(text: String): List<String> = text.lineSequence()
            .map { it.trim().substringBefore(' ').substringBefore('\t').removePrefix("--") }
            .filter { it in SCRIPT_DIRECTIVES }
            .distinct().toList()
    }
}
