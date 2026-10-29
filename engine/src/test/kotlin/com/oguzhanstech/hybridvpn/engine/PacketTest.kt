package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import com.oguzhanstech.hybridvpn.engine.packet.IpPacket
import com.oguzhanstech.hybridvpn.engine.packet.IpPacketBuilder
import com.oguzhanstech.hybridvpn.engine.packet.IpProtocol
import com.oguzhanstech.hybridvpn.engine.packet.TcpResetBuilder
import com.oguzhanstech.hybridvpn.engine.packet.UdpDatagram
import com.oguzhanstech.hybridvpn.engine.packet.UdpPacketBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketTest {

    private val payload = "hello dns".toByteArray()

    @Test fun ipv4UdpRoundTrip() {
        val src = IpLiteral.parse("10.215.173.1")!!
        val dst = IpLiteral.parse("10.215.173.2")!!
        val bytes = UdpPacketBuilder.build(src, 40000, dst, 53, payload)
        val ip = IpPacket.parse(bytes)!!
        assertEquals(4, ip.version)
        assertEquals(IpProtocol.UDP, ip.protocol)
        assertArrayEquals(dst, ip.destination)
        val udp = UdpDatagram.parse(ip)!!
        assertEquals(40000, udp.sourcePort)
        assertEquals(53, udp.destinationPort)
        assertArrayEquals(payload, udp.payload())
        assertTrue(UdpPacketBuilder.checksumValid(udp))
    }

    @Test fun ipv4HeaderChecksumIsValid() {
        val bytes = UdpPacketBuilder.build(IpLiteral.parse("1.2.3.4")!!, 1, IpLiteral.parse("5.6.7.8")!!, 2, payload)
        var sum = 0L
        for (i in 0 until 20 step 2) sum += ((bytes[i].toInt() and 0xFF) shl 8) or (bytes[i + 1].toInt() and 0xFF)
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum.toInt())
    }

    @Test fun ipv6UdpRoundTrip() {
        val src = IpLiteral.parse("fdc1:7e57::1")!!
        val dst = IpLiteral.parse("fdc1:7e57::2")!!
        val bytes = UdpPacketBuilder.build(src, 5353, dst, 53, payload)
        val udp = UdpDatagram.parse(IpPacket.parse(bytes)!!)!!
        assertEquals(53, udp.destinationPort)
        assertArrayEquals(payload, udp.payload())
        assertTrue(UdpPacketBuilder.checksumValid(udp))
    }

    @Test fun ipv6ExtensionHeadersAreWalked() {
        val base = UdpPacketBuilder.build(IpLiteral.parse("fdc1:7e57::1")!!, 1000, IpLiteral.parse("fdc1:7e57::2")!!, 53, payload)
        // Insert an 8-byte hop-by-hop header between the fixed header and UDP.
        val withHbh = ByteArray(base.size + 8)
        base.copyInto(withHbh, 0, 0, 40)
        withHbh[6] = 0 // next header: hop-by-hop
        withHbh[40] = IpProtocol.UDP.toByte()
        withHbh[41] = 0
        base.copyInto(withHbh, 48, 40)
        val newPayloadLen = base.size - 40 + 8
        withHbh[4] = (newPayloadLen shr 8).toByte(); withHbh[5] = newPayloadLen.toByte()
        val ip = IpPacket.parse(withHbh)!!
        assertEquals(IpProtocol.UDP, ip.protocol)
        assertEquals(48, ip.payloadOffset)
        assertNotNull(UdpDatagram.parse(ip))
    }

    @Test fun fragmentsAreNotParsedAsUdp() {
        val bytes = UdpPacketBuilder.build(IpLiteral.parse("1.2.3.4")!!, 1, IpLiteral.parse("5.6.7.8")!!, 53, payload)
        bytes[6] = 0x20 // more fragments
        val ip = IpPacket.parse(bytes)!!
        assertTrue(ip.isFragment)
        assertNull(UdpDatagram.parse(ip))
    }

    @Test fun rejectsTruncatedPackets() {
        val bytes = UdpPacketBuilder.build(IpLiteral.parse("1.2.3.4")!!, 1, IpLiteral.parse("5.6.7.8")!!, 53, payload)
        assertNull(IpPacket.parse(bytes, bytes.size - 1))
        assertNull(IpPacket.parse(byteArrayOf(0x45, 0, 0)))
        assertNull(IpPacket.parse(byteArrayOf(0x75)))
    }

    private fun syn(src: String, dst: String, seq: Long, flags: Int = 0x02): ByteArray {
        val tcp = ByteArray(20)
        tcp[0] = (51000 shr 8).toByte(); tcp[1] = 51000.toByte(); tcp[2] = 0x03; tcp[3] = 0x55 // 853
        tcp[4] = (seq shr 24).toByte(); tcp[5] = (seq shr 16).toByte(); tcp[6] = (seq shr 8).toByte(); tcp[7] = seq.toByte()
        tcp[12] = 0x50
        tcp[13] = flags.toByte()
        return IpPacketBuilder.build(IpLiteral.parse(src)!!, IpLiteral.parse(dst)!!, IpProtocol.TCP, tcp, 16)
    }

    private fun tcpChecksumValid(ip: IpPacket): Boolean {
        var sum = 0L
        fun add(b: ByteArray, from: Int, len: Int) { var i = from; while (i < from + len) { sum += ((b[i].toInt() and 0xFF) shl 8) or (if (i + 1 < from + len) b[i + 1].toInt() and 0xFF else 0); i += 2 } }
        add(ip.source, 0, ip.source.size); add(ip.destination, 0, ip.destination.size)
        sum += IpProtocol.TCP + ip.payloadLength
        add(ip.buffer, ip.payloadOffset, ip.payloadLength)
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.toInt() == 0xFFFF
    }

    @Test fun resetsSynWithAck() {
        for ((src, dst) in listOf("10.215.173.1" to "10.215.173.2", "fdc1:7e57::1" to "fdc1:7e57::2")) {
            val rst = IpPacket.parse(TcpResetBuilder.resetFor(IpPacket.parse(syn(src, dst, seq = 0xFFFFFFFFL))!!)!!)!!
            assertArrayEquals(IpLiteral.parse(dst), rst.source)
            val o = rst.payloadOffset
            assertEquals(853, ((rst.buffer[o].toInt() and 0xFF) shl 8) or (rst.buffer[o + 1].toInt() and 0xFF))
            assertEquals(0x14, rst.buffer[o + 13].toInt()) // RST|ACK
            assertEquals(0L, (8..11).fold(0L) { acc, i -> (acc shl 8) or (rst.buffer[o + i].toLong() and 0xFF) }) // seq+1 wraps
            assertTrue(tcpChecksumValid(rst))
        }
    }

    @Test fun neverResetsAReset() {
        assertNull(TcpResetBuilder.resetFor(IpPacket.parse(syn("1.2.3.4", "5.6.7.8", 1, flags = 0x04))!!))
    }
}
