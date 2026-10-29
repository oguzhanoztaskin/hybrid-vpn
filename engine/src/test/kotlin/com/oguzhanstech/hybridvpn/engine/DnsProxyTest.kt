package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.dns.BlockResponse
import com.oguzhanstech.hybridvpn.engine.dns.DnsCache
import com.oguzhanstech.hybridvpn.engine.dns.DnsEvent
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessage
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessageWriter
import com.oguzhanstech.hybridvpn.engine.dns.DnsOutcome
import com.oguzhanstech.hybridvpn.engine.dns.DnsProxy
import com.oguzhanstech.hybridvpn.engine.dns.DnsProxyConfig
import com.oguzhanstech.hybridvpn.engine.dns.DnsQuestion
import com.oguzhanstech.hybridvpn.engine.dns.DnsRcode
import com.oguzhanstech.hybridvpn.engine.dns.DnsType
import com.oguzhanstech.hybridvpn.engine.dns.DnsUpstream
import com.oguzhanstech.hybridvpn.engine.dns.DomainList
import com.oguzhanstech.hybridvpn.engine.dns.DomainListIndex
import com.oguzhanstech.hybridvpn.engine.dns.FilterListParser
import com.oguzhanstech.hybridvpn.engine.dns.LocalAnswer
import com.oguzhanstech.hybridvpn.engine.dns.LocalNames
import com.oguzhanstech.hybridvpn.engine.dns.QueryOrigin
import com.oguzhanstech.hybridvpn.engine.dns.RData
import com.oguzhanstech.hybridvpn.engine.dns.UpstreamException
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.engine.policy.PolicyCompiler
import com.oguzhanstech.hybridvpn.engine.policy.PolicyConfig
import com.oguzhanstech.hybridvpn.engine.policy.PolicyEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsProxyTest {

    private class FakeUpstream(override val description: String, var fail: Boolean = false) : DnsUpstream {
        val seen = ArrayList<String>()
        override fun exchange(query: ByteArray, timeoutMs: Int): ByteArray {
            val q = DnsMessage.parse(query)
            seen += q.questions[0].name
            if (fail) throw UpstreamException("down")
            return DnsMessageWriter.response(q, DnsRcode.NOERROR, listOf(q.questions[0] to RData.Address(byteArrayOf(9, 9, 9, 9))), ttl = 120)
        }
    }

    private val public = FakeUpstream("public")
    private val local = FakeUpstream("local")
    private val events = ArrayList<DnsEvent>()
    private val lists = DomainListIndex(
        listOf(
            DomainList.from("ads", FilterListParser.parse("||ads.example^")),
            DomainList.from("user", FilterListParser.parse("@@||allowed.ads.example^")),
        )
    )

    private fun proxy(policyJson: String = DEFAULT, mode: BlockResponse = BlockResponse.NULL_IP): DnsProxy {
        val policy = (PolicyCompiler.compile(PolicyConfig.fromJson(policyJson), lists.ids) as CompileResult.Ok).policy
        return DnsProxy(DnsProxyConfig(PolicyEngine(policy, lists), public, local, mode, null, null, null), DnsCache(), { events += it })
    }

    private fun query(name: String, type: Int = DnsType.A, id: Int = 77) = DnsMessageWriter.query(id, listOf(DnsQuestion(name, type)))
    private val app = QueryOrigin(10123, listOf("com.example.app"))

    @Test fun blocksWithNullIp() {
        val response = DnsMessage.parse(proxy().handle(query("x.ads.example"), app)!!)
        assertEquals(77, response.id)
        assertEquals(RData.Address(ByteArray(4)), response.answers.single().data)
        assertEquals(DnsOutcome.BLOCKED, events.single().outcome)
        assertEquals("block-lists", events.single().ruleId)
        assertEquals(emptyList<String>(), public.seen)
    }

    @Test fun blockModes() {
        assertEquals(DnsRcode.NXDOMAIN, DnsMessage.parse(proxy(mode = BlockResponse.NXDOMAIN).handle(query("ads.example"), app)!!).rcode)
        val https = DnsMessage.parse(proxy().handle(query("ads.example", DnsType.HTTPS), app)!!)
        assertEquals(DnsRcode.NOERROR, https.rcode)
        assertEquals(0, https.answers.size)
    }

    @Test fun exceptionsAreForwarded() {
        val response = DnsMessage.parse(proxy().handle(query("allowed.ads.example"), app)!!)
        assertEquals(RData.Address(byteArrayOf(9, 9, 9, 9)), response.answers.single().data)
        assertEquals(listOf("allowed.ads.example"), public.seen)
    }

    @Test fun cachesAndRewritesId() {
        val p = proxy()
        p.handle(query("news.example", id = 1), app)
        val second = DnsMessage.parse(p.handle(query("news.example", id = 2), app)!!)
        assertEquals(2, second.id)
        assertEquals(1, public.seen.size)
        assertEquals(listOf(DnsOutcome.FORWARDED, DnsOutcome.CACHED), events.map { it.outcome })
    }

    @Test fun splitHorizon() {
        val p = proxy()
        p.handle(query("printer.lan"), app)
        p.handle(query("35.1.168.192.in-addr.arpa", DnsType.PTR), app)
        assertEquals(listOf("printer.lan", "35.1.168.192.in-addr.arpa"), local.seen)
        assertEquals(DnsRcode.NXDOMAIN, DnsMessage.parse(p.handle(query("ubuntu.local"), app)!!).rcode)
        assertEquals(emptyList<String>(), public.seen)
    }

    @Test fun upstreamFailureIsServfail() {
        public.fail = true
        val response = DnsMessage.parse(proxy().handle(query("news.example"), app)!!)
        assertEquals(DnsRcode.SERVFAIL, response.rcode)
        assertEquals(DnsOutcome.ERROR, events.single().outcome)
    }

    @Test fun perAppRules() {
        val json = """{"rules":[{"id":"no-social","priority":1,"match":{"apps":["com.example.app"],"domains":["social.example"]},"action":{"type":"block"}}]}"""
        val p = proxy(json)
        p.handle(query("cdn.social.example"), app)
        assertEquals(DnsOutcome.BLOCKED, events.last().outcome)
        p.handle(query("cdn.social.example"), QueryOrigin(null, null))
        assertEquals(DnsOutcome.FORWARDED, events.last().outcome)
    }

    @Test fun ignoresResponsesAndRejectsGarbage() {
        val response = DnsMessageWriter.response(DnsMessage.parse(query("a.example")), DnsRcode.NOERROR)
        assertNull(proxy().handle(response, app))
        assertNull(proxy().handle(ByteArray(3), app))
    }

    private fun proxyWithNames(names: LocalNames): DnsProxy {
        val policy = (PolicyCompiler.compile(PolicyConfig.fromJson(DEFAULT), lists.ids) as CompileResult.Ok).policy
        return DnsProxy(DnsProxyConfig(PolicyEngine(policy, lists), public, local, BlockResponse.NULL_IP, null, null, null, localNames = names), DnsCache(), { events += it })
    }

    @Test fun tailnetNamesAreAnsweredLocallyAndNeverSentUpstream() {
        val nas4 = byteArrayOf(100, 64, 0, 2)
        val nas6 = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 2 }
        val p = proxyWithNames { name ->
            when {
                name == "nas.tail1.ts.net" -> LocalAnswer.Found("tailnet:home", listOf(nas4, nas6))
                name.endsWith(".tail1.ts.net") -> LocalAnswer.NoSuchName("tailnet:home")
                name.endsWith(".shared.ts.net") -> LocalAnswer.Ambiguous(listOf("tailnet:a", "tailnet:b"))
                else -> LocalAnswer.NotLocal
            }
        }
        val a = DnsMessage.parse(p.handle(query("nas.tail1.ts.net", DnsType.A), app)!!)
        assertEquals(RData.Address(nas4), a.answers.single().data)
        assertEquals(30L, a.answers.single().ttl)
        assertEquals(RData.Address(nas6), DnsMessage.parse(p.handle(query("nas.tail1.ts.net", DnsType.AAAA), app)!!).answers.single().data)
        assertEquals(0, DnsMessage.parse(p.handle(query("nas.tail1.ts.net", DnsType.HTTPS), app)!!).answers.size)
        assertEquals(DnsRcode.NXDOMAIN, DnsMessage.parse(p.handle(query("printer.tail1.ts.net"), app)!!).rcode)
        assertEquals(DnsRcode.SERVFAIL, DnsMessage.parse(p.handle(query("x.shared.ts.net"), app)!!).rcode)
        assertEquals(emptyList<String>(), public.seen)
        assertEquals("tailnet:home", events.first().detail)
        // Ordinary names still go upstream and list blocks still apply (the block decision runs first).
        p.handle(query("news.example"), app)
        assertEquals(listOf("news.example"), public.seen)
        assertEquals(DnsOutcome.BLOCKED, events.also { p.handle(query("ads.example"), app) }.last().outcome)
    }

    private companion object {
        val DEFAULT = """{"rules":[{"id":"block-lists","priority":100,"match":{"domain_lists":["@all"]},"action":{"type":"block"}}]}"""
    }
}
