package com.oguzhanstech.hybridvpn.discovery

import com.oguzhanstech.hybridvpn.discovery.subnet.ArpTable
import com.oguzhanstech.hybridvpn.discovery.subnet.ScanPlanner
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import org.junit.Assert.assertEquals
import org.junit.Test

class SubnetTest {

    @Test fun enumeratesUsableHosts() {
        val hosts = ScanPlanner.hosts(Cidr.parse("192.168.1.0/24")!!, "192.168.1.20")
        assertEquals(254, hosts.size)
        assertEquals("192.168.1.1", hosts.first())
        assertEquals("192.168.1.254", hosts.last())
        assertEquals(listOf("10.0.0.1", "10.0.0.2"), ScanPlanner.hosts(Cidr.parse("10.0.0.0/30")!!, null))
        assertEquals(listOf("10.0.0.0", "10.0.0.1"), ScanPlanner.hosts(Cidr.parse("10.0.0.0/31")!!, null))
    }

    @Test fun narrowsLargeSubnets() {
        val hosts = ScanPlanner.hosts(Cidr.parse("10.1.0.0/16")!!, "10.1.7.9")
        assertEquals(254, hosts.size)
        assertEquals("10.1.7.1", hosts.first())
        assertEquals(1022, ScanPlanner.hosts(Cidr.parse("10.1.0.0/22")!!, "10.1.0.9").size)
        assertEquals(emptyList<String>(), ScanPlanner.hosts(Cidr.parse("10.0.0.0/8")!!, null))
    }

    @Test fun parsesArpTable() {
        val text = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.1.1      0x1         0x2         AA:BB:CC:00:11:22     *        wlan0
            192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
            192.168.1.35     0x1         0x2         de:ad:be:ef:00:01     *        wlan0
        """.trimIndent()
        assertEquals(mapOf("192.168.1.1" to "aa:bb:cc:00:11:22", "192.168.1.35" to "de:ad:be:ef:00:01"), ArpTable.parse(text))
    }
}
