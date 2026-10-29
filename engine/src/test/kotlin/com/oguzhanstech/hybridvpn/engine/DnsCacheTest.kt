package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.dns.DnsCache
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessage
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessageWriter
import com.oguzhanstech.hybridvpn.engine.dns.DnsQuestion
import com.oguzhanstech.hybridvpn.engine.dns.DnsRcode
import com.oguzhanstech.hybridvpn.engine.dns.DnsType
import com.oguzhanstech.hybridvpn.engine.dns.RData
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsCacheTest {

    private var now = 1_000_000L
    private val cache = DnsCache(clock = { now })
    private val key = DnsCache.Key("cdn.example", DnsType.A, 1)

    private fun answer(ttl: Long, rcode: Int = DnsRcode.NOERROR): ByteArray {
        val q = DnsMessage.parse(DnsMessageWriter.query(1, listOf(DnsQuestion("cdn.example", DnsType.A))))
        val answers = if (rcode == DnsRcode.NOERROR) listOf(q.questions[0] to RData.Address(byteArrayOf(1, 2, 3, 4))) else emptyList()
        return DnsMessageWriter.response(q, rcode, answers, ttl)
    }

    @Test fun agesTtlAndRewritesId() {
        val response = answer(ttl = 300)
        cache.put(key, response, DnsMessage.parse(response))
        now += 100_000
        val hit = DnsMessage.parse(cache.get(key, id = 4242)!!)
        assertEquals(4242, hit.id)
        assertEquals(200L, hit.answers.single().ttl)
    }

    @Test fun expires() {
        val response = answer(ttl = 10)
        cache.put(key, response, DnsMessage.parse(response))
        now += 10_000
        assertNull(cache.get(key, 1))
        assertEquals(0, cache.size)
    }

    @Test fun negativeAnswersAreCachedBriefly() {
        val response = answer(ttl = 0, rcode = DnsRcode.NXDOMAIN)
        cache.put(key, response, DnsMessage.parse(response))
        now += 59_000
        assertEquals(DnsRcode.NXDOMAIN, DnsMessage.parse(cache.get(key, 1)!!).rcode)
        now += 2_000
        assertNull(cache.get(key, 1))
    }

    @Test fun servfailIsNeverCached() {
        val response = answer(ttl = 300, rcode = DnsRcode.SERVFAIL)
        cache.put(key, response, DnsMessage.parse(response))
        assertNull(cache.get(key, 1))
    }
}
