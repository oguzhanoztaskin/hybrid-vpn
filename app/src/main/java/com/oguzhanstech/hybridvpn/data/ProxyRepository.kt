package com.oguzhanstech.hybridvpn.data

import android.content.Context
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import com.oguzhanstech.hybridvpn.engine.policy.TransportType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

enum class ProxyKind(val wire: String, val label: String, val defaultPort: Int, val transportType: TransportType) {
    HTTP("http", "HTTP", 8080, TransportType.HTTP),
    SOCKS5("socks5", "SOCKS5", 1080, TransportType.SOCKS5),
}

/**
 * An HTTP or SOCKS5 proxy. The password is stored encrypted (see [SecretStore]); only this metadata is
 * plain. The proxy connection is not encrypted on the wire: the proxy and the network on the way see the
 * destinations, the credentials and any unencrypted payload.
 */
data class ProxyConfig(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    /** Empty: no authentication is offered. */
    val username: String = "",
    /** Switched off, the proxy is not used and rules routing to it are skipped. */
    val enabled: Boolean = true,
    /** Missing in older metadata: always SOCKS5, preserving existing transport identities. */
    val kind: ProxyKind = ProxyKind.SOCKS5,
) {
    val transportId: String get() = "${kind.wire}:$id"
    val ruleId: String get() = "${kind.wire}-$id"

    /** "host:port", with brackets around an IPv6 literal. */
    val server: String get() = (if (':' in host) "[$host]" else host) + ":$port"

    companion object {
        val ID = Regex("^[a-z0-9][a-z0-9-]{0,31}$")
        private val HOSTNAME = Regex("^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\\.?$")

        /** An error message for unusable connection settings, or null. */
        fun validate(host: String, port: Int?, username: String, password: String, kind: ProxyKind = ProxyKind.SOCKS5): String? = when {
            host.isBlank() -> "Enter the proxy's host name or IP address"
            IpLiteral.parse(host) == null && !HOSTNAME.matches(host) -> "'$host' is not a host name or IP address"
            port == null || port !in 1..65535 -> "Port must be 1–65535"
            username.toByteArray().size > 255 || password.toByteArray().size > 255 -> "Username and password are limited to 255 bytes"
            kind == ProxyKind.HTTP && ":" in username -> "HTTP Basic usernames cannot contain a colon"
            username.isEmpty() && password.isNotEmpty() -> "A password needs a username"
            else -> null
        }
    }
}

class ProxyRepository(context: Context) {
    private val file = File(context.filesDir, "socks.json")
    private val secrets = SecretStore(File(context.filesDir, "socks"))
    private val state = MutableStateFlow(load())
    val proxies: StateFlow<List<ProxyConfig>> = state.asStateFlow()

    /** Adds a proxy, or replaces [existingId]'s settings; [password] null keeps the stored one. */
    fun save(existingId: String?, name: String, host: String, port: Int?, username: String, password: String?, kind: ProxyKind = ProxyKind.SOCKS5): Result<ProxyConfig> {
        val h = host.trim().removePrefix("[").removeSuffix("]")
        val user = username.trim()
        val keptPassword = password ?: existingId?.let(::password).orEmpty()
        ProxyConfig.validate(h, port, user, if (user.isEmpty()) "" else keptPassword, kind)?.let { return Result.failure(IllegalArgumentException(it)) }
        val old = state.value.firstOrNull { it.id == existingId }
        if (old != null && old.kind != kind) return Result.failure(IllegalArgumentException("Create a new proxy to change its type"))
        val proxy = ProxyConfig(
            id = old?.id ?: uniqueId(name.ifBlank { h }),
            name = name.trim().ifBlank { h },
            host = h,
            port = port!!,
            username = user,
            enabled = old?.enabled ?: true,
            kind = kind,
        )
        if (user.isEmpty()) secrets.delete("${proxy.id}.pass")
        else if (password != null) secrets.write("${proxy.id}.pass", password.toByteArray())
        save(if (old == null) state.value + proxy else state.value.map { if (it.id == old.id) proxy else it })
        return Result.success(proxy)
    }

    fun password(id: String): String = secrets.read("$id.pass")?.toString(Charsets.UTF_8).orEmpty()

    fun setEnabled(id: String, enabled: Boolean) = save(state.value.map { if (it.id == id) it.copy(enabled = enabled) else it })

    fun remove(id: String) {
        save(state.value.filterNot { it.id == id })
        secrets.delete("$id.pass")
    }

    private fun uniqueId(base: String): String {
        val slug = base.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').take(24).ifBlank { "proxy" }
        val taken = state.value.map { it.id }.toSet()
        if (slug !in taken) return slug
        return (2..999).map { "$slug-$it" }.first { it !in taken }
    }

    private fun save(list: List<ProxyConfig>) {
        val arr = JSONArray()
        list.forEach {
            arr.put(
                JSONObject().put("id", it.id).put("name", it.name).put("host", it.host).put("port", it.port)
                    .put("username", it.username).put("enabled", it.enabled).put("type", it.kind.wire)
            )
        }
        file.writeText(arr.toString(2))
        state.value = list.sortedBy { it.kind.ordinal }
    }

    private fun load(): List<ProxyConfig> = try {
        val arr = JSONArray(file.readText())
        List(arr.length()) { i ->
            arr.getJSONObject(i).let {
                ProxyConfig(
                    it.getString("id"), it.optString("name"), it.getString("host"), it.getInt("port"),
                    it.optString("username"), it.optBoolean("enabled", true),
                    ProxyKind.entries.first { kind -> kind.wire == it.optString("type", "socks5") },
                )
            }
        }.filter { ProxyConfig.ID.matches(it.id) }.sortedBy { it.kind.ordinal }
    } catch (_: Exception) {
        emptyList()
    }
}
