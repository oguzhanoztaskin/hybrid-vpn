package com.oguzhanstech.hybridvpn.data

import org.junit.Assert.assertEquals
import org.junit.Test

class OpenVpnScriptsTest {
    @Test
    fun findsDirectivesThatWouldRunPrograms() {
        val profile = """
            client
            remote vpn.example 1194
            script-security 2
            up /etc/openvpn/update-resolv-conf
            --down /etc/openvpn/update-resolv-conf
              plugin /usr/lib/openvpn/plugin.so
            # up commented-out lines are not directives
            setenv opt block-outside-dns
            upstream-is-not-up 1
        """.trimIndent()
        assertEquals(listOf("script-security", "up", "down", "plugin"), OpenVpnRepository.ignoredScriptDirectives(profile))
    }

    @Test
    fun cleanProfileHasNone() {
        assertEquals(emptyList<String>(), OpenVpnRepository.ignoredScriptDirectives("client\ndev tun\nremote a 1194\nauth-user-pass\n"))
    }
}
