package com.oguzhanstech.hybridvpn.data

import android.content.Context
import com.oguzhanstech.hybridvpn.engine.dns.DomainList
import com.oguzhanstech.hybridvpn.engine.dns.DomainListIndex
import com.oguzhanstech.hybridvpn.engine.dns.FilterListParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

data class CompiledLists(val index: DomainListIndex, val allIds: Set<String>, val ruleCount: Int, val enabledCount: Int)

/**
 * Filter lists are plain text files under filesDir/filters, fetched only when the user asks.
 * Nothing is downloaded by default: suggested lists are added disabled.
 */
class FilterListRepository(private val context: Context, private val dao: FilterListDao) {

    private val dir = File(context.filesDir, "filters").apply { mkdirs() }

    val lists: Flow<List<FilterListEntity>> = dao.all()

    suspend fun ensureDefaults() {
        if (dao.get(USER_LIST_ID) == null) {
            dao.upsert(FilterListEntity(USER_LIST_ID, "My rules", null, true, null, 0, 0, 0, null))
            file(USER_LIST_ID).writeText(USER_RULES_TEMPLATE)
        }
        for ((id, name, url) in SUGGESTED) {
            if (dao.get(id) == null) dao.upsert(FilterListEntity(id, name, url, false, null, 0, 0, 0, null))
        }
    }

    suspend fun setEnabled(id: String, enabled: Boolean) {
        val list = dao.get(id) ?: return
        dao.upsert(list.copy(enabled = enabled))
        if (enabled && list.url != null && !file(id).exists()) refresh(id)
    }

    suspend fun add(name: String, url: String): String {
        require(url.startsWith("https://")) { "Only https:// list URLs are accepted" }
        URL(url) // validates syntax
        val id = "list-" + UUID.randomUUID().toString().take(8)
        dao.upsert(FilterListEntity(id, name.ifBlank { URL(url).host }, url, true, null, 0, 0, 0, null))
        refresh(id)
        return id
    }

    suspend fun remove(id: String) {
        if (id == USER_LIST_ID) return
        dao.delete(id)
        file(id).delete()
    }

    /** Downloads one list. Failures are recorded on the list rather than thrown. */
    suspend fun refresh(id: String) {
        val list = dao.get(id) ?: return
        val url = list.url ?: return
        val result = withContext(Dispatchers.IO) {
            runCatching {
                val text = download(url)
                val parsed = FilterListParser.parse(text)
                file(id).writeText(text)
                parsed
            }
        }
        val now = System.currentTimeMillis()
        dao.upsert(
            result.fold(
                onSuccess = { list.copy(lastUpdated = now, ruleCount = it.rules.size, unsupportedCount = it.unsupported, invalidCount = it.invalid, lastError = null) },
                onFailure = { list.copy(lastError = it.message ?: it.javaClass.simpleName) },
            )
        )
    }

    suspend fun refreshAll() = dao.snapshot().filter { it.enabled && it.url != null }.forEach { refresh(it.id) }

    fun userRules(): String = file(USER_LIST_ID).takeIf { it.exists() }?.readText().orEmpty()

    suspend fun saveUserRules(text: String) {
        val parsed = FilterListParser.parse(text)
        withContext(Dispatchers.IO) { file(USER_LIST_ID).writeText(text) }
        dao.get(USER_LIST_ID)?.let {
            dao.upsert(it.copy(lastUpdated = System.currentTimeMillis(), ruleCount = parsed.rules.size, unsupportedCount = parsed.unsupported, invalidCount = parsed.invalid))
        }
    }

    /**
     * Parses every enabled list into the matcher used by the DNS proxy. CPU and memory heavy; call
     * off the main thread. With [filtering] off (the DNS module switched off) no list is loaded.
     */
    suspend fun compile(filtering: Boolean = true): CompiledLists = withContext(Dispatchers.Default) {
        val all = dao.snapshot()
        val enabled = if (filtering) all.filter { it.enabled } else emptyList()
        var rules = 0
        val compiled = enabled.mapNotNull { entity ->
            val f = file(entity.id)
            if (!f.exists()) return@mapNotNull null
            val parsed = FilterListParser.parse(f.readText())
            rules += parsed.rules.size
            DomainList.from(entity.id, parsed)
        }
        CompiledLists(DomainListIndex(compiled), all.map { it.id }.toSet(), rules, compiled.size)
    }

    private fun file(id: String) = File(dir, "$id.txt")

    private fun download(url: String): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", "HybridVPN/0.1")
            if (connection.responseCode != 200) throw IOException("HTTP ${connection.responseCode}")
            if (connection.url.protocol != "https") throw IOException("Redirected to a non-HTTPS URL")
            val bytes = connection.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_LIST_BYTES) throw IOException("List larger than ${MAX_LIST_BYTES / 1_000_000} MB")
                }
                out.toByteArray()
            }
            return String(bytes, Charsets.UTF_8)
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        const val USER_LIST_ID = "user"
        private const val MAX_LIST_BYTES = 25_000_000

        private val SUGGESTED = listOf(
            Triple("adguard-dns", "AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
            Triple("stevenblack-hosts", "StevenBlack unified hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
        )

        private val USER_RULES_TEMPLATE = """
            ! My rules. One rule per line.
            !   ||ads.example.com^       block a domain and its subdomains
            !   0.0.0.0 tracker.example  block exactly one name (hosts syntax)
            !   @@||cdn.example.com^     never block this domain, whatever other lists say
        """.trimIndent() + "\n"
    }
}
