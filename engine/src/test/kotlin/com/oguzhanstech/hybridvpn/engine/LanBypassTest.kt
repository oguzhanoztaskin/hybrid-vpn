package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.net.Cidr
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import com.oguzhanstech.hybridvpn.engine.net.LanBypass
import org.junit.Assert.*
import org.junit.Test

class LanBypassTest {
    private fun cidr(s: String) = Cidr.parse(s)!!
    private fun captured(routes: List<Cidr>, ip: String) = routes.any { it.contains(IpLiteral.parse(ip)!!) }

    @Test fun disabledKeepsFullTunnel() {
        assertEquals(listOf(cidr("0.0.0.0/0"), cidr("::/0")), LanBypass.tunnelRoutes(emptyList()))
    }

    @Test fun excludesOnlyConnectedLanAndDiscovery() {
        val excluded = LanBypass.exclusions(listOf(cidr("192.168.1.23/24"), cidr("2001:db8:1234::7/64")))
        val routes = LanBypass.tunnelRoutes(excluded)
        for (ip in listOf("192.168.1.106", "192.168.1.255", "224.0.0.251", "239.255.255.250", "255.255.255.255", "169.254.1.2", "fe80::1", "ff02::fb", "2001:db8:1234::123")) {
            assertFalse(ip, captured(routes, ip))
        }
        for (ip in listOf("192.168.2.106", "10.9.0.1", "100.101.216.89", "fd7a:115c:a1e0::1", "1.1.1.1", "2606:4700:4700::1111", "10.215.173.2", "fdc1:7e57:dead::2")) {
            assertTrue(ip, captured(routes, ip))
        }
        assertTrue(routes.size < 256)
        for (route in routes) assertFalse(excluded.any { it.overlaps(route) })
    }

    @Test fun ignoresDefaultPrefixesAndRemovesStaleLanOnRebuild() {
        val a = LanBypass.tunnelRoutes(LanBypass.exclusions(listOf(cidr("192.168.1.0/24"), cidr("0.0.0.0/0"), cidr("::/0"))))
        val b = LanBypass.tunnelRoutes(LanBypass.exclusions(listOf(cidr("192.168.2.0/24"))))
        assertTrue(captured(a, "1.1.1.1"))
        assertFalse(captured(a, "192.168.1.106"))
        assertTrue(captured(b, "192.168.1.106"))
        assertFalse(captured(b, "192.168.2.106"))
    }

    @Test fun overlappingAndHostExclusionsPreserveExactCoverage() {
        val cuts = listOf(cidr("192.168.1.0/25"), cidr("192.168.1.0/26"), cidr("192.168.1.200/32"), cidr("2001:db8::1/128"))
        val routes = LanBypass.tunnelRoutes(cuts)
        for (last in 0..255) assertEquals(last >= 128 && last != 200, captured(routes, "192.168.1.$last"))
        assertFalse(captured(routes, "2001:db8::1"))
        assertTrue(captured(routes, "2001:db8::2"))
    }
}
