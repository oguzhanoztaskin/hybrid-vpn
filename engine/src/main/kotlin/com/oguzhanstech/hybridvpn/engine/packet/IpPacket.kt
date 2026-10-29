package com.oguzhanstech.hybridvpn.engine.packet

object IpProtocol {
    const val ICMP = 1
    const val TCP = 6
    const val UDP = 17
    const val ICMPV6 = 58
}

/**
 * A parsed view over an IPv4 or IPv6 packet read from the TUN interface.
 * The buffer is not copied; callers must not reuse it while the view is alive.
 */
class IpPacket private constructor(
    val buffer: ByteArray,
    val version: Int,
    val source: ByteArray,
    val destination: ByteArray,
    /** Transport protocol after walking any IPv6 extension headers. */
    val protocol: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    /** Non-first fragments carry no transport header; first fragments carry a partial payload. */
    val isFragment: Boolean,
) {

    companion object {
        private const val IPV6_HEADER = 40
        private const val MAX_EXTENSION_HEADERS = 8

        fun parse(buf: ByteArray, length: Int = buf.size): IpPacket? {
            if (length < 1) return null
            return when ((buf[0].toInt() and 0xFF) shr 4) {
                4 -> parseV4(buf, length)
                6 -> parseV6(buf, length)
                else -> null
            }
        }

        private fun parseV4(buf: ByteArray, length: Int): IpPacket? {
            if (length < 20) return null
            val ihl = (buf[0].toInt() and 0x0F) * 4
            val total = u16(buf, 2)
            if (ihl < 20 || total < ihl || total > length) return null
            val flagsFrag = u16(buf, 6)
            val moreFragments = flagsFrag and 0x2000 != 0
            val fragmentOffset = flagsFrag and 0x1FFF
            return IpPacket(
                buffer = buf,
                version = 4,
                source = buf.copyOfRange(12, 16),
                destination = buf.copyOfRange(16, 20),
                protocol = buf[9].toInt() and 0xFF,
                payloadOffset = ihl,
                payloadLength = total - ihl,
                isFragment = moreFragments || fragmentOffset != 0,
            )
        }

        private fun parseV6(buf: ByteArray, length: Int): IpPacket? {
            if (length < IPV6_HEADER) return null
            val payloadLength = u16(buf, 4)
            val end = IPV6_HEADER + payloadLength
            if (end > length) return null
            var next = buf[6].toInt() and 0xFF
            var offset = IPV6_HEADER
            var fragment = false
            repeat(MAX_EXTENSION_HEADERS) {
                when (next) {
                    0, 43, 60 -> { // hop-by-hop, routing, destination options
                        if (offset + 8 > end) return null
                        val len = ((buf[offset + 1].toInt() and 0xFF) + 1) * 8
                        next = buf[offset].toInt() and 0xFF
                        offset += len
                    }
                    44 -> { // fragment
                        if (offset + 8 > end) return null
                        fragment = true
                        next = buf[offset].toInt() and 0xFF
                        offset += 8
                    }
                    51 -> { // authentication header
                        if (offset + 8 > end) return null
                        val len = ((buf[offset + 1].toInt() and 0xFF) + 2) * 4
                        next = buf[offset].toInt() and 0xFF
                        offset += len
                    }
                    else -> {
                        if (offset > end) return null
                        return IpPacket(
                            buffer = buf,
                            version = 6,
                            source = buf.copyOfRange(8, 24),
                            destination = buf.copyOfRange(24, 40),
                            protocol = next,
                            payloadOffset = offset,
                            payloadLength = end - offset,
                            isFragment = fragment,
                        )
                    }
                }
            }
            return null
        }

        internal fun u16(buf: ByteArray, offset: Int): Int =
            ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
    }
}
