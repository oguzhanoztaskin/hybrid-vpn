package com.oguzhanstech.hybridvpn.data

import org.junit.Assert.*
import org.junit.Test

class ProxyConfigTest {
    @Test fun existingMetadataDefaultsToSocksWithoutChangingIdentity() {
        val old = ProxyConfig("office", "Office", "proxy.example", 1080)
        assertEquals(ProxyKind.SOCKS5, old.kind)
        assertEquals("socks5:office", old.transportId)
        assertEquals("socks5-office", old.ruleId)
    }

    @Test fun httpUsesDistinctTransportAndDefaultPortBeforeSocksInUi() {
        val http = ProxyConfig("office", "Office", "::1", 8080, kind = ProxyKind.HTTP)
        assertEquals("http:office", http.transportId)
        assertEquals("http-office", http.ruleId)
        assertEquals("[::1]:8080", http.server)
        assertEquals(ProxyKind.HTTP, ProxyKind.entries.first())
        assertEquals(8080, ProxyKind.HTTP.defaultPort)
        assertEquals(1080, ProxyKind.SOCKS5.defaultPort)
    }

    @Test fun basicAuthenticationRejectsAmbiguousUsername() {
        assertNotNull(ProxyConfig.validate("proxy.example", 8080, "a:b", "secret", ProxyKind.HTTP))
        assertNull(ProxyConfig.validate("proxy.example", 1080, "a:b", "secret", ProxyKind.SOCKS5))
        assertNull(ProxyConfig.validate("proxy.example", 8080, "", "", ProxyKind.HTTP))
        assertNotNull(ProxyConfig.validate("proxy.example", 0, "", "", ProxyKind.HTTP))
    }
}
