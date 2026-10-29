package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.dns.DomainList
import com.oguzhanstech.hybridvpn.engine.dns.DomainListIndex
import com.oguzhanstech.hybridvpn.engine.dns.DomainRule
import com.oguzhanstech.hybridvpn.engine.dns.DomainScope
import com.oguzhanstech.hybridvpn.engine.dns.FilterListParser
import com.oguzhanstech.hybridvpn.engine.dns.FilterListParser.LineResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class FilterRulesTest {

    private fun rules(line: String) = (FilterListParser.parseLine(line) as LineResult.Rules).rules

    @Test fun adblockSyntax() {
        assertEquals(listOf(DomainRule("ads.example.com", DomainScope.SUBDOMAINS, false)), rules("||ads.example.com^"))
        assertEquals(listOf(DomainRule("ads.example.com", DomainScope.SUBDOMAINS, true)), rules("@@||ads.example.com^"))
        assertEquals(listOf(DomainRule("exact.example.com", DomainScope.EXACT, false)), rules("|exact.example.com^"))
        assertEquals(listOf(DomainRule("x.example", DomainScope.SUBDOMAINS, false)), rules("||x.example^\$important"))
        assertEquals(listOf(DomainRule("tracker.example", DomainScope.SUBDOMAINS, false)), rules("||TRACKER.example.^"))
    }

    @Test fun hostsSyntax() {
        assertEquals(
            listOf(DomainRule("a.example", DomainScope.EXACT, false), DomainRule("b.example", DomainScope.EXACT, false)),
            rules("0.0.0.0 a.example b.example # trailing comment"),
        )
        assertEquals(LineResult.Ignored, FilterListParser.parseLine("127.0.0.1 localhost"))
        assertEquals(LineResult.Unsupported, FilterListParser.parseLine("1.2.3.4 rewrite.example"))
    }

    @Test fun plainDomainsAndComments() {
        assertEquals(listOf(DomainRule("plain.example", DomainScope.EXACT, false)), rules("plain.example"))
        assertEquals(LineResult.Ignored, FilterListParser.parseLine("! comment"))
        assertEquals(LineResult.Ignored, FilterListParser.parseLine("# hosts comment"))
        assertEquals(LineResult.Ignored, FilterListParser.parseLine("##.banner"))
        assertEquals(LineResult.Ignored, FilterListParser.parseLine("[Adblock Plus 2.0]"))
    }

    @Test fun unsupportedIsCountedNotApproximated() {
        listOf(
            "||ads.example^\$third-party",
            "||ads.example^\$dnstype=AAAA",
            "/ads[0-9]+\\.example/",
            "||ads*.example^",
            "example.com##.ad",
            "||example.com/path^",
        ).forEach { assertEquals(it, LineResult.Unsupported, FilterListParser.parseLine(it)) }
        assertEquals(LineResult.Invalid, FilterListParser.parseLine("||bad domain^".replace(" ", "!")))
    }

    @Test fun idnIsPunycoded() {
        assertEquals("xn--bcher-kva.example", FilterListParser.normalizeDomain("bücher.example"))
        assertNull(FilterListParser.normalizeDomain("a..b"))
        assertNull(FilterListParser.normalizeDomain("-".repeat(64) + ".com"))
    }

    @Test fun parseCountsEverything() {
        val parsed = FilterListParser.parse(
            """
            ! Title: test
            ||a.example^
            @@||ok.a.example^
            0.0.0.0 b.example
            ||c.example^${'$'}third-party
            """.trimIndent()
        )
        assertEquals(3, parsed.rules.size)
        assertEquals(1, parsed.unsupported)
        assertEquals(0, parsed.invalid)
    }

    @Test fun exceptionsApplyAcrossLists() {
        val ads = DomainList.from("ads", FilterListParser.parse("||ads.example^\n0.0.0.0 exact.example"))
        val user = DomainList.from("user", FilterListParser.parse("@@||good.ads.example^"))
        val index = DomainListIndex(listOf(ads, user))
        assertNotNull(index.match("ads", "x.ads.example"))
        assertNotNull(index.match(DomainListIndex.ANY_LIST, "ads.example"))
        assertNull(index.match("ads", "good.ads.example"))
        assertNull(index.match("ads", "deep.good.ads.example"))
        assertNotNull(index.match("ads", "exact.example"))
        assertNull(index.match("ads", "sub.exact.example"))
        assertNull(index.match("missing", "ads.example"))
        assertNull(index.match("ads", "notads.example"))
    }
}
