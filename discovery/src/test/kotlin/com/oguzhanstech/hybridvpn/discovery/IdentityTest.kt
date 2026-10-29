package com.oguzhanstech.hybridvpn.discovery

import com.oguzhanstech.hybridvpn.discovery.identity.Confidence
import com.oguzhanstech.hybridvpn.discovery.identity.DeviceClassifier
import com.oguzhanstech.hybridvpn.discovery.identity.DeviceType
import com.oguzhanstech.hybridvpn.discovery.identity.HostObservation
import com.oguzhanstech.hybridvpn.discovery.identity.IdentifierKind
import com.oguzhanstech.hybridvpn.discovery.identity.IdentityResolver
import com.oguzhanstech.hybridvpn.discovery.identity.KnownDevice
import com.oguzhanstech.hybridvpn.discovery.identity.KnownIdentifier
import com.oguzhanstech.hybridvpn.discovery.identity.Resolution
import com.oguzhanstech.hybridvpn.discovery.mdns.MdnsService
import com.oguzhanstech.hybridvpn.discovery.ssdp.SsdpDescription
import com.oguzhanstech.hybridvpn.discovery.ssdp.SsdpDevice
import com.oguzhanstech.hybridvpn.discovery.subnet.ProbeResult
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityTest {

    private val now = 1_700_000_000_000L
    private val day = IdentityResolver.DAY_MS
    private val resolver = IdentityResolver()

    private fun obs(
        ip: String = "192.168.1.35",
        mac: String? = null,
        mdns: String? = null,
        rdns: String? = null,
        ports: Set<Int> = setOf(22),
        services: List<MdnsService> = emptyList(),
        ssdp: SsdpDevice? = null,
        gateway: Boolean = false,
    ) = HostObservation(ip, mac, mdns, rdns, services, ssdp, ports, true, gateway, false)

    private fun known(id: String, vararg ids: Pair<IdentifierKind, String>, lastSeen: Long = now - day, fingerprint: String? = "p22") =
        KnownDevice(id, ids.map { KnownIdentifier(it.first, it.second, lastSeen) }, fingerprint)

    @Test fun strongIdentifierWins() {
        val r = resolver.resolve(obs(ip = "192.168.1.99", mdns = "ubuntu.local"), listOf(known("a", IdentifierKind.IP to "192.168.1.35", IdentifierKind.MDNS to "ubuntu.local")), now)
        assertEquals(Resolution.Matched("a", Confidence.HIGH, com.oguzhanstech.hybridvpn.discovery.identity.Identifier(IdentifierKind.MDNS, "ubuntu.local")), r)
    }

    @Test fun macConflictPreventsHostnameMerge() {
        // Two different Raspberry Pis both called raspberrypi.local.
        val existing = known("pi1", IdentifierKind.MDNS to "raspberrypi.local", IdentifierKind.MAC to "aa:aa:aa:aa:aa:01")
        val r = resolver.resolve(obs(mac = "aa:aa:aa:aa:aa:02", mdns = "raspberrypi.local"), listOf(existing), now)
        assertTrue(r is Resolution.New)
    }

    @Test fun globallyUniqueIdOverridesMacChange() {
        val existing = known("tv", IdentifierKind.SSDP to "uuid-1", IdentifierKind.MAC to "aa:aa:aa:aa:aa:01")
        val r = resolver.resolve(obs(mac = "aa:aa:aa:aa:aa:02", ssdp = SsdpDevice("192.168.1.35", "uuid-1", null, null, emptySet(), null)), listOf(existing), now)
        assertEquals("tv", (r as Resolution.Matched).deviceId)
    }

    @Test fun ipOnlyMatchNeedsRecencyAndSameFingerprint() {
        val existing = known("d", IdentifierKind.IP to "192.168.1.35")
        assertEquals(Confidence.LOW, (resolver.resolve(obs(), listOf(existing), now) as Resolution.Matched).confidence)
        // Same IP, different services: a different device took the lease.
        assertTrue(resolver.resolve(obs(ports = setOf(80, 443)), listOf(existing), now) is Resolution.New)
        // Same IP, but last seen long ago.
        assertTrue(resolver.resolve(obs(), listOf(known("d", IdentifierKind.IP to "192.168.1.35", lastSeen = now - 30 * day)), now) is Resolution.New)
    }

    @Test fun ipNeverOverridesBetterEvidence() {
        val existing = known("laptop", IdentifierKind.IP to "192.168.1.35", IdentifierKind.MDNS to "laptop.local")
        assertTrue(resolver.resolve(obs(), listOf(existing), now) is Resolution.New)
    }

    @Test fun hostnameMatchIsMedium() {
        val existing = known("nas", IdentifierKind.HOSTNAME to "nas.lan")
        val r = resolver.resolve(obs(ip = "192.168.1.77", rdns = "nas.lan"), listOf(existing), now) as Resolution.Matched
        assertEquals(Confidence.MEDIUM, r.confidence)
    }

    @Test fun conflictsAreReportedNotMerged() {
        val a = known("a", IdentifierKind.MDNS to "dup.local", lastSeen = now - 2 * day)
        val b = known("b", IdentifierKind.MDNS to "dup.local", lastSeen = now - day)
        val r = resolver.resolve(obs(mdns = "dup.local"), listOf(a, b), now) as Resolution.Matched
        assertEquals("b", r.deviceId)
        assertEquals(listOf("a"), r.conflictsWith)
    }

    @Test fun newDeviceConfidenceReflectsEvidence() {
        assertEquals(Confidence.HIGH, resolver.resolve(obs(mac = "aa:bb:cc:dd:ee:ff"), emptyList(), now).confidence)
        assertEquals(Confidence.MEDIUM, resolver.resolve(obs(mdns = "x.local"), emptyList(), now).confidence)
        assertEquals(Confidence.LOW, resolver.resolve(obs(), emptyList(), now).confidence)
    }

    @Test fun classifiesCommonDevices() {
        assertEquals(DeviceType.ROUTER, DeviceClassifier.classify(obs(gateway = true)).type)
        val ubuntu = DeviceClassifier.classify(obs(mdns = "ubuntu.local", services = listOf(MdnsService("ubuntu", "_ssh._tcp", 22, emptyMap()))))
        assertEquals(DeviceType.COMPUTER, ubuntu.type)
        assertEquals("ubuntu", ubuntu.suggestedName)
        val cast = DeviceClassifier.classify(obs(ports = setOf(8008, 8009), services = listOf(MdnsService("Chromecast-1", "_googlecast._tcp", 8009, mapOf("fn" to "Living Room TV", "md" to "Chromecast")))))
        assertEquals(DeviceType.TV, cast.type)
        assertEquals("Living Room TV", cast.suggestedName)
        assertEquals("Chromecast", cast.model)
        assertEquals(DeviceType.PRINTER, DeviceClassifier.classify(obs(ports = setOf(9100, 80))).type)
        val airplay = DeviceClassifier.classify(obs(services = listOf(MdnsService("AA11BB22CC33@Kitchen", "_raop._tcp", 7000, emptyMap()))))
        assertEquals(DeviceType.SPEAKER, airplay.type)
        assertEquals("Kitchen", airplay.suggestedName)
        val upnp = DeviceClassifier.classify(obs(ssdp = SsdpDevice("192.168.1.35", "u", null, null, emptySet(), SsdpDescription("Bedroom", "Sony", "BRAVIA", null, null, null))))
        assertEquals("Bedroom", upnp.suggestedName)
        assertEquals("Sony", upnp.vendor)
        assertEquals("Device 192.168.1.35", DeviceClassifier.classify(obs(ports = emptySet())).suggestedName)
    }

    @Test fun aggregatesEvidencePerAddress() {
        val target = ScanTarget(Cidr.parse("192.168.1.0/24")!!, "192.168.1.20", "192.168.1.1")
        val result = NetworkScanner.aggregate(
            addresses = listOf("192.168.1.1", "192.168.1.20", "192.168.1.35"),
            probes = listOf(ProbeResult("192.168.1.35", setOf(22), true), ProbeResult("192.168.1.1", setOf(53, 80), false)),
            mdns = emptyList(),
            ssdp = emptyList(),
            arp = mapOf("192.168.1.1" to "aa:bb:cc:00:11:22"),
            reverse = mapOf("192.168.1.35" to "ubuntu.lan.", "192.168.1.1" to "192.168.1.1"),
            target = target,
        )
        val (router, self, ubuntu) = result
        assertTrue(router.isGateway)
        assertEquals("aa:bb:cc:00:11:22", router.mac)
        assertEquals(null, router.reverseDnsName)
        assertTrue(self.isSelf && self.reachable)
        assertEquals("ubuntu.lan", ubuntu.reverseDnsName)
        assertEquals("p22", ubuntu.fingerprint)
    }
}
