package com.oguzhanstech.hybridvpn.engine.packet

/** A UDP datagram inside an [IpPacket]. */
class UdpDatagram private constructor(
    val ip: IpPacket,
    val sourcePort: Int,
    val destinationPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
) {
    fun payload(): ByteArray = ip.buffer.copyOfRange(payloadOffset, payloadOffset + payloadLength)

    companion object {
        fun parse(ip: IpPacket): UdpDatagram? {
            if (ip.protocol != IpProtocol.UDP || ip.isFragment || ip.payloadLength < 8) return null
            val o = ip.payloadOffset
            val udpLength = IpPacket.u16(ip.buffer, o + 4)
            if (udpLength < 8 || udpLength > ip.payloadLength) return null
            return UdpDatagram(
                ip = ip,
                sourcePort = IpPacket.u16(ip.buffer, o),
                destinationPort = IpPacket.u16(ip.buffer, o + 2),
                payloadOffset = o + 8,
                payloadLength = udpLength - 8,
            )
        }
    }
}

/** Builds complete IPv4/IPv6 UDP packets suitable for writing back into the TUN interface. */
object UdpPacketBuilder {

    fun build(
        source: ByteArray,
        sourcePort: Int,
        destination: ByteArray,
        destinationPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val udp = ByteArray(8 + payload.size)
        IpPacketBuilder.put16(udp, 0, sourcePort)
        IpPacketBuilder.put16(udp, 2, destinationPort)
        IpPacketBuilder.put16(udp, 4, udp.size)
        payload.copyInto(udp, 8)
        return IpPacketBuilder.build(source, destination, IpProtocol.UDP, udp, checksumOffset = 6)
    }

    /** Verifies the UDP checksum of a parsed datagram (used by tests and diagnostics). */
    fun checksumValid(d: UdpDatagram): Boolean {
        val ip = d.ip
        val udpLength = d.payloadLength + 8
        val o = d.payloadOffset - 8
        if (ip.version == 4 && IpPacket.u16(ip.buffer, o + 6) == 0) return true
        val sum = Checksum.sum(ip.buffer, o, udpLength, Checksum.pseudoHeader(ip.source, ip.destination, IpProtocol.UDP, udpLength))
        return Checksum.fold(sum) == 0
    }

}
