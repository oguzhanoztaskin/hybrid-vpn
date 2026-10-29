package com.oguzhanstech.hybridvpn.engine.packet

/** Wraps a transport segment in an IPv4 or IPv6 header and fills in both checksums. */
object IpPacketBuilder {

    fun build(source: ByteArray, destination: ByteArray, protocol: Int, transport: ByteArray, checksumOffset: Int): ByteArray {
        require(source.size == destination.size) { "Address family mismatch" }
        val headerLength = if (source.size == 4) 20 else 40
        val packet = ByteArray(headerLength + transport.size)
        if (source.size == 4) {
            packet[0] = 0x45
            put16(packet, 2, packet.size)
            put16(packet, 6, 0x4000) // don't fragment
            packet[8] = 64
            packet[9] = protocol.toByte()
            source.copyInto(packet, 12)
            destination.copyInto(packet, 16)
            put16(packet, 10, Checksum.fold(Checksum.sum(packet, 0, 20)))
        } else {
            packet[0] = 0x60
            put16(packet, 4, transport.size)
            packet[6] = protocol.toByte()
            packet[7] = 64
            source.copyInto(packet, 8)
            destination.copyInto(packet, 24)
        }
        transport.copyInto(packet, headerLength)
        put16(packet, headerLength + checksumOffset, 0)
        val sum = Checksum.sum(packet, headerLength, transport.size, Checksum.pseudoHeader(source, destination, protocol, transport.size))
        var checksum = Checksum.fold(sum)
        // For UDP a zero checksum means "none" (and is illegal on IPv6); 0xFFFF is the equivalent value.
        if (checksum == 0 && protocol == IpProtocol.UDP) checksum = 0xFFFF
        put16(packet, headerLength + checksumOffset, checksum)
        return packet
    }

    internal fun put16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = (value shr 8).toByte()
        buf[offset + 1] = value.toByte()
    }
}

/**
 * RFC 793 reset generation. Used to refuse TCP connections to addresses we capture but do not
 * serve (DNS-over-TCP and the Private DNS port 853 probe), so clients fail fast instead of
 * waiting for a timeout.
 */
object TcpResetBuilder {
    private const val FIN = 0x01
    private const val SYN = 0x02
    private const val RST = 0x04
    private const val ACK = 0x10

    fun resetFor(ip: IpPacket): ByteArray? {
        if (ip.protocol != IpProtocol.TCP || ip.isFragment || ip.payloadLength < 20) return null
        val b = ip.buffer
        val o = ip.payloadOffset
        val flags = b[o + 13].toInt() and 0xFF
        if (flags and RST != 0) return null // never answer a reset with a reset
        val dataOffset = ((b[o + 12].toInt() and 0xFF) ushr 4) * 4
        if (dataOffset < 20 || dataOffset > ip.payloadLength) return null
        val seq = u32(b, o + 4)
        val ack = u32(b, o + 8)
        val segmentLength = ip.payloadLength - dataOffset + (if (flags and SYN != 0) 1 else 0) + (if (flags and FIN != 0) 1 else 0)

        val tcp = ByteArray(20)
        tcp[0] = b[o + 2]; tcp[1] = b[o + 3] // ports swapped
        tcp[2] = b[o]; tcp[3] = b[o + 1]
        if (flags and ACK != 0) {
            put32(tcp, 4, ack)
            tcp[13] = RST.toByte()
        } else {
            put32(tcp, 8, (seq + segmentLength) and 0xFFFFFFFFL)
            tcp[13] = (RST or ACK).toByte()
        }
        tcp[12] = 0x50
        return IpPacketBuilder.build(ip.destination, ip.source, IpProtocol.TCP, tcp, checksumOffset = 16)
    }

    private fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)

    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v shr 24).toByte(); b[o + 1] = (v shr 16).toByte(); b[o + 2] = (v shr 8).toByte(); b[o + 3] = v.toByte()
    }
}
