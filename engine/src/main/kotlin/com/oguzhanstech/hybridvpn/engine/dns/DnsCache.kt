package com.oguzhanstech.hybridvpn.engine.dns

/**
 * Small LRU cache of upstream responses keyed by question. Stored TTLs are aged on every hit so
 * clients never cache an answer for longer than the upstream allowed.
 */
class DnsCache(
    private val maxEntries: Int = 4096,
    private val maxTtlSeconds: Long = 3600,
    private val negativeTtlSeconds: Long = 60,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    data class Key(val name: String, val type: Int, val clazz: Int)

    private class Entry(val bytes: ByteArray, val ttlOffsets: IntArray, val ttls: LongArray, val storedAt: Long, val expiresAt: Long)

    private val entries = object : LinkedHashMap<Key, Entry>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, Entry>) = size > maxEntries
    }

    @Synchronized
    fun get(key: Key, id: Int): ByteArray? {
        val entry = entries[key] ?: return null
        val now = clock()
        if (now >= entry.expiresAt) {
            entries.remove(key)
            return null
        }
        val elapsed = (now - entry.storedAt) / 1000
        val out = DnsMessageWriter.withId(entry.bytes, id)
        for (i in entry.ttlOffsets.indices) {
            val ttl = maxOf(0L, entry.ttls[i] - elapsed)
            val o = entry.ttlOffsets[i]
            out[o] = (ttl shr 24).toByte(); out[o + 1] = (ttl shr 16).toByte()
            out[o + 2] = (ttl shr 8).toByte(); out[o + 3] = ttl.toByte()
        }
        return out
    }

    @Synchronized
    fun put(key: Key, response: ByteArray, parsed: DnsMessage) {
        if (parsed.isTruncated) return
        val records = parsed.allRecords.filter { it.type != DnsType.OPT }
        val ttlSeconds = when (parsed.rcode) {
            DnsRcode.NOERROR -> if (parsed.answers.isEmpty()) negativeTtl(parsed) else records.minOf { it.ttl }
            DnsRcode.NXDOMAIN -> negativeTtl(parsed)
            else -> return
        }.coerceAtMost(maxTtlSeconds)
        if (ttlSeconds <= 0) return
        val now = clock()
        entries[key] = Entry(
            bytes = response.copyOf(),
            ttlOffsets = records.map { it.ttlOffset }.toIntArray(),
            ttls = records.map { it.ttl }.toLongArray(),
            storedAt = now,
            expiresAt = now + ttlSeconds * 1000,
        )
    }

    private fun negativeTtl(parsed: DnsMessage): Long {
        val soa = parsed.authorities.firstOrNull { it.type == DnsType.SOA }
        val fromSoa = soa?.let { minOf(it.ttl, (it.data as? RData.Soa)?.minimum ?: it.ttl) }
        return minOf(fromSoa ?: negativeTtlSeconds, negativeTtlSeconds)
    }

    @Synchronized
    fun clear() = entries.clear()

    @get:Synchronized
    val size: Int get() = entries.size
}
