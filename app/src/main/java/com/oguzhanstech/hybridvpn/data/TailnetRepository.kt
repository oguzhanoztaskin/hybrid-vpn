package com.oguzhanstech.hybridvpn.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * A configured tailnet. No credentials are stored here: login is interactive (a URL shown in the
 * app). Each tailnet's node state lives in its own app-private directory and is never shared.
 */
data class TailnetConfig(
    val id: String,
    val name: String,
    /** Empty means Tailscale's default coordination server. */
    val controlUrl: String = "",
    val hostname: String = "hybridvpn-$id",
    /** Switched off, the tailnet does not connect and rules routing to it are skipped. */
    val enabled: Boolean = true,
) {
    val transportId: String get() = TRANSPORT_PREFIX + id

    companion object {
        const val TRANSPORT_PREFIX = "tailnet:"
        val ID = Regex("^[a-z0-9][a-z0-9-]{0,31}$")
    }
}

class TailnetRepository(private val context: Context) {
    private val file = File(context.filesDir, "tailnets.json")
    private val state = MutableStateFlow(load())
    val tailnets: StateFlow<List<TailnetConfig>> = state.asStateFlow()

    fun stateDir(id: String): File = File(context.filesDir, "tailnets/$id")

    fun add(config: TailnetConfig): Result<Unit> {
        if (!TailnetConfig.ID.matches(config.id)) return Result.failure(IllegalArgumentException("Id must be lower-case letters, digits or '-' (max 32)"))
        if (state.value.any { it.id == config.id }) return Result.failure(IllegalArgumentException("A tailnet with id '${config.id}' exists"))
        if (config.controlUrl.isNotBlank() && !config.controlUrl.matches(Regex("^https?://\\S+$"))) {
            return Result.failure(IllegalArgumentException("Control URL must start with http:// or https://"))
        }
        save(state.value + config)
        return Result.success(Unit)
    }

    fun setEnabled(id: String, enabled: Boolean) = save(state.value.map { if (it.id == id) it.copy(enabled = enabled) else it })

    /** Removes the tailnet and deletes its node state (this device logs out of it). */
    fun remove(id: String) {
        save(state.value.filterNot { it.id == id })
        stateDir(id).deleteRecursively()
    }

    private fun save(list: List<TailnetConfig>) {
        val arr = JSONArray()
        list.forEach { arr.put(JSONObject().put("id", it.id).put("name", it.name).put("controlUrl", it.controlUrl).put("hostname", it.hostname).put("enabled", it.enabled)) }
        file.writeText(arr.toString(2))
        state.value = list
    }

    private fun load(): List<TailnetConfig> = try {
        val arr = JSONArray(file.readText())
        List(arr.length()) { i ->
            arr.getJSONObject(i).let {
                TailnetConfig(
                    it.getString("id"), it.optString("name"), it.optString("controlUrl"),
                    it.optString("hostname", "hybridvpn-${it.getString("id")}"), it.optBoolean("enabled", true),
                )
            }
        }
    } catch (_: Exception) {
        emptyList()
    }
}
