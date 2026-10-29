package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.net.Cidr
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetTest {

    @Test fun parsesIpv4() {
        assertArrayEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 35), IpLiteral.parse("192.168.1.35"))
        assertNull(IpLiteral.parse("256.1.1.1"))
        assertNull(IpLiteral.parse("1.2.3"))
        assertNull(IpLiteral.parse("01234.1.1.1"))
        assertNull(IpLiteral.parse("example.com"))
    }

    @Test fun parsesAndFormatsIpv6() {
        val cases = mapOf(
            "::" to "::",
            "::1" to "::1",
            "2001:db8::1" to "2001:db8::1",
            "2001:0db8:0000:0000:0001:0000:0000:0001" to "2001:db8::1:0:0:1",
            "fe80::1%wlan0" to "fe80::1",
            "::ffff:192.0.2.1" to "::ffff:c000:201",
            "1:2:3:4:5:6:7:8" to "1:2:3:4:5:6:7:8",
            "2001:db8:0:1:1:1:1:1" to "2001:db8:0:1:1:1:1:1",
        )
        for ((input, expected) in cases) {
            val bytes = IpLiteral.parse(input)
            assertEquals(input, 16, bytes?.size)
            assertEquals(input, expected, IpLiteral.format(bytes!!))
        }
        assertNull(IpLiteral.parse("1::2::3"))
        assertNull(IpLiteral.parse("1:2:3:4:5:6:7:8:9"))
        assertNull(IpLiteral.parse("g::1"))
        assertNull(IpLiteral.parse("12345::"))
    }

    @Test fun cidrContainsAndMasks() {
        val tailnet = Cidr.parse("100.64.0.0/10")!!
        assertTrue(tailnet.contains(IpLiteral.parse("100.101.102.103")!!))
        assertFalse(tailnet.contains(IpLiteral.parse("100.128.0.1")!!))
        assertEquals("10.20.0.0/16", Cidr.parse("10.20.30.40/16").toString())
        assertEquals("fd7a:115c:a1e0::/48", Cidr.parse("fd7a:115c:a1e0:ab12::1/48").toString())
        assertTrue(Cidr.parse("0.0.0.0/0")!!.contains(IpLiteral.parse("8.8.8.8")!!))
        assertFalse(Cidr.parse("0.0.0.0/0")!!.contains(IpLiteral.parse("::1")!!))
        assertNull(Cidr.parse("10.0.0.0/33"))
        assertNull(Cidr.parse("10.0.0.0/x"))
    }

    @Test fun cidrOverlap() {
        assertTrue(Cidr.parse("10.0.0.0/8")!!.overlaps(Cidr.parse("10.20.0.0/16")!!))
        assertFalse(Cidr.parse("10.0.0.0/16")!!.overlaps(Cidr.parse("10.1.0.0/16")!!))
        assertTrue(Cidr.parse("10.0.0.0/8")!!.contains(Cidr.parse("10.20.0.0/16")!!))
        assertFalse(Cidr.parse("10.20.0.0/16")!!.contains(Cidr.parse("10.0.0.0/8")!!))
    }
}
