package com.oguzhanstech.hybridvpn.engine.packet

/** RFC 1071 Internet checksum helpers. */
internal object Checksum {

    fun sum(buf: ByteArray, offset: Int, length: Int, initial: Long = 0): Long {
        var sum = initial
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xFF) shl 8
        return sum
    }

    fun fold(sum: Long): Int {
        var s = sum
        while (s shr 16 != 0L) s = (s and 0xFFFF) + (s shr 16)
        return s.toInt().inv() and 0xFFFF
    }

    /** Pseudo-header sum for TCP/UDP over IPv4 or IPv6. */
    fun pseudoHeader(source: ByteArray, destination: ByteArray, protocol: Int, length: Int): Long {
        var sum = sum(source, 0, source.size) + sum(destination, 0, destination.size)
        sum += protocol.toLong()
        sum += length.toLong()
        return sum
    }
}
