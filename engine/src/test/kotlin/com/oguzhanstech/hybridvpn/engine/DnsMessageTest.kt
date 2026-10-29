package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.dns.DnsFormatException
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessage
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessageWriter
import com.oguzhanstech.hybridvpn.engine.dns.DnsQuestion
import com.oguzhanstech.hybridvpn.engine.dns.DnsRcode
import com.oguzhanstech.hybridvpn.engine.dns.DnsType
import com.oguzhanstech.hybridvpn.engine.dns.RData
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsMessageTest {

    @Test fun queryRoundTrip() {
        val bytes = DnsMessageWriter.query(0x1234, listOf(DnsQuestion("ads.example.com", DnsType.AAAA)))
        val msg = DnsMessage.parse(bytes)
        assertEquals(0x1234, msg.id)
        assertTrue(msg.recursionDesired)
        assertEquals(DnsQuestion("ads.example.com", DnsType.AAAA), msg.questions.single())
        assertEquals(DnsQuestion("ads.example.com", DnsType.AAAA), DnsMessage.parseQuestion(bytes))
    }

    @Test fun synthesisedAddressAnswer() {
        val query = DnsMessage.parse(DnsMessageWriter.query(7, listOf(DnsQuestion("x.test", DnsType.A))))
        val response = DnsMessage.parse(DnsMessageWriter.response(query, DnsRcode.NOERROR, listOf(query.questions[0] to RData.Address(ByteArray(4))), ttl = 30))
        assertTrue(response.isResponse)
        assertEquals(7, response.id)
        assertEquals(DnsRcode.NOERROR, response.rcode)
        assertEquals(RData.Address(ByteArray(4)), response.answers.single().data)
        assertEquals(30L, response.answers.single().ttl)
    }

    @Test fun parsesCompressedMdnsStyleResponse() {
        val out = ByteArrayOutputStream()
        fun u16(v: Int) { out.write(v shr 8); out.write(v) }
        fun u32(v: Long) { u16((v shr 16).toInt()); u16(v.toInt()) }
        fun name(vararg labels: String) { labels.forEach { out.write(it.length); out.write(it.toByteArray()) }; out.write(0) }
        u16(0); u16(0x8400); u16(0); u16(3); u16(0); u16(0)
        // PTR _ssh._tcp.local -> ubuntu._ssh._tcp.local
        val typeOffset = out.size()
        name("_ssh", "_tcp", "local"); u16(DnsType.PTR); u16(1); u32(4500)
        u16(9); out.write(6); out.write("ubuntu".toByteArray()); out.write(0xC0); out.write(typeOffset)
        val instanceOffset = typeOffset + 17 + 10
        // SRV instance -> ubuntu.local:22
        out.write(0xC0); out.write(instanceOffset); u16(DnsType.SRV); u16(0x8001); u32(120)
        u16(6 + 14); u16(0); u16(0); u16(22); name("ubuntu", "local")
        // A ubuntu.local
        name("ubuntu", "local"); u16(DnsType.A); u16(0x8001); u32(120); u16(4); out.write(byteArrayOf(192.toByte(), 168.toByte(), 1, 35))

        val msg = DnsMessage.parse(out.toByteArray())
        assertEquals(RData.Name("ubuntu._ssh._tcp.local"), msg.answers[0].data)
        assertEquals("ubuntu._ssh._tcp.local", msg.answers[1].name)
        assertEquals(RData.Srv(0, 0, 22, "ubuntu.local"), msg.answers[1].data)
        assertEquals(RData.Address(byteArrayOf(192.toByte(), 168.toByte(), 1, 35)), msg.answers[2].data)
    }

    @Test(expected = DnsFormatException::class)
    fun rejectsPointerLoops() {
        val bytes = byteArrayOf(0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0.toByte(), 12, 0, 1, 0, 1)
        DnsMessage.parse(bytes)
    }

    @Test fun errorResponseFromUnparseableQuery() {
        val query = DnsMessageWriter.query(99, listOf(DnsQuestion("a.b", DnsType.A))) + byteArrayOf(1, 2, 3)
        val response = DnsMessage.parse(DnsMessageWriter.errorResponse(query, query.size, DnsRcode.SERVFAIL)!!)
        assertEquals(99, response.id)
        assertEquals(DnsRcode.SERVFAIL, response.rcode)
        assertEquals("a.b", response.questions.single().name)
        assertNull(DnsMessageWriter.errorResponse(ByteArray(5), 5, DnsRcode.SERVFAIL))
    }

    @Test fun truncationKeepsQuestionAndSetsTc() {
        val query = DnsMessage.parse(DnsMessageWriter.query(5, listOf(DnsQuestion("big.test", DnsType.TXT))))
        val full = DnsMessageWriter.response(query, DnsRcode.NOERROR, listOf(query.questions[0].copy(type = DnsType.A) to RData.Address(ByteArray(4))))
        val truncated = DnsMessage.parse(DnsMessageWriter.truncated(full))
        assertTrue(truncated.isTruncated)
        assertEquals(0, truncated.answers.size)
        assertEquals("big.test", truncated.questions.single().name)
    }
}
