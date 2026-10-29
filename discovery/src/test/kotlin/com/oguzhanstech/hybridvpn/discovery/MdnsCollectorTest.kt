package com.oguzhanstech.hybridvpn.discovery

import com.oguzhanstech.hybridvpn.discovery.mdns.MdnsHost
import com.oguzhanstech.hybridvpn.discovery.mdns.MdnsRecordCollector
import com.oguzhanstech.hybridvpn.discovery.mdns.MdnsService
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessage
import com.oguzhanstech.hybridvpn.engine.dns.DnsQuestion
import com.oguzhanstech.hybridvpn.engine.dns.DnsRecord
import com.oguzhanstech.hybridvpn.engine.dns.DnsType
import com.oguzhanstech.hybridvpn.engine.dns.RData
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MdnsCollectorTest {

    private fun response(vararg records: DnsRecord) = DnsMessage(0, 0x8400, emptyList(), records.toList(), emptyList(), emptyList())
    private fun rec(name: String, type: Int, data: RData) = DnsRecord(name, type, 1, 120, data, 0)

    @Test fun walksTypesInstancesAndAddresses() {
        val c = MdnsRecordCollector()
        val first = c.add(response(rec(MdnsRecordCollector.SERVICES_ENUMERATION, DnsType.PTR, RData.Name("_ssh._tcp.local"))), "192.168.1.35")
        assertEquals(listOf(DnsQuestion("_ssh._tcp.local", DnsType.PTR, MdnsRecordCollector.QU_CLASS)), first)

        val second = c.add(response(rec("_ssh._tcp.local", DnsType.PTR, RData.Name("ubuntu._ssh._tcp.local"))), "192.168.1.35")
        assertEquals(setOf(DnsType.SRV, DnsType.TXT), second.map { it.type }.toSet())

        val third = c.add(
            response(
                rec("ubuntu._ssh._tcp.local", DnsType.SRV, RData.Srv(0, 0, 22, "ubuntu.local")),
                rec("ubuntu._ssh._tcp.local", DnsType.TXT, RData.Txt(listOf("os=linux"))),
            ),
            "192.168.1.35",
        )
        assertEquals(listOf(DnsQuestion("ubuntu.local", DnsType.A, MdnsRecordCollector.QU_CLASS)), third)
        c.add(response(rec("ubuntu.local", DnsType.A, RData.Address(byteArrayOf(192.toByte(), 168.toByte(), 1, 35)))), "192.168.1.35")

        assertEquals(
            listOf(MdnsHost("192.168.1.35", "ubuntu.local", listOf(MdnsService("ubuntu", "_ssh._tcp", 22, mapOf("os" to "linux"))))),
            c.hosts(),
        )
    }

    @Test fun fallsBackToPacketSourceWithoutAddressRecords() {
        val c = MdnsRecordCollector()
        c.add(
            response(
                rec("_googlecast._tcp.local", DnsType.PTR, RData.Name("Chromecast-abc._googlecast._tcp.local")),
                rec("Chromecast-abc._googlecast._tcp.local", DnsType.SRV, RData.Srv(0, 0, 8009, "abc.local")),
            ),
            "192.168.1.50",
        )
        val host = c.hosts().single()
        assertEquals("192.168.1.50", host.address)
        assertEquals("_googlecast._tcp", host.services.single().type)
    }

    @Test fun doesNotRepeatQuestions() {
        val c = MdnsRecordCollector()
        c.markAsked(listOf(DnsQuestion("_ssh._tcp.local", DnsType.PTR)))
        assertTrue(c.add(response(rec(MdnsRecordCollector.SERVICES_ENUMERATION, DnsType.PTR, RData.Name("_ssh._tcp.local"))), "x").isEmpty())
    }

    @Test fun txtParsing() {
        assertEquals(mapOf("md" to "Chromecast", "fn" to "Living Room", "flag" to ""), MdnsRecordCollector.parseTxt(listOf("md=Chromecast", "FN=Living Room", "flag", "")))
    }
}
