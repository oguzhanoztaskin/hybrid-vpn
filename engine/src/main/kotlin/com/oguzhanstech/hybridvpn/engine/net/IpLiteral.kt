package com.oguzhanstech.hybridvpn.engine.net

/**
 * IP literal parsing and formatting that never touches a resolver.
 *
 * `InetAddress.getByName` silently performs a DNS lookup for anything that is not a valid
 * literal, which is unacceptable inside a DNS proxy (it can recurse into ourselves) and in
 * config validation (it leaks the string to the network). Everything here is pure.
 */
object IpLiteral {

    fun parse(text: String): ByteArray? {
        val s = text.trim().removePrefix("[").removeSuffix("]")
        return if (s.contains(':')) parseV6(s) else parseV4(s)
    }

    fun parseV4(s: String): ByteArray? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v.toByte()
        }
        return out
    }

    fun parseV6(input: String): ByteArray? {
        var s = input.substringBefore('%')
        val lastColon = s.lastIndexOf(':')
        if (lastColon < 0) return null
        var tailV4: ByteArray? = null
        if (s.indexOf('.', lastColon) >= 0) {
            tailV4 = parseV4(s.substring(lastColon + 1)) ?: return null
            s = s.substring(0, lastColon + 1) + "0:0"
        }
        val doubleColon = s.indexOf("::")
        if (doubleColon >= 0 && s.indexOf("::", doubleColon + 1) >= 0) return null

        fun groups(part: String): List<Int>? {
            if (part.isEmpty()) return emptyList()
            return part.split(':').map { g ->
                if (g.isEmpty() || g.length > 4 || !g.all { it.isHexDigit() }) return null
                g.toInt(16)
            }
        }

        val all: List<Int>
        if (doubleColon >= 0) {
            val head = groups(s.substring(0, doubleColon)) ?: return null
            val tail = groups(s.substring(doubleColon + 2)) ?: return null
            if (head.size + tail.size > 7) return null
            all = head + List(8 - head.size - tail.size) { 0 } + tail
        } else {
            all = groups(s) ?: return null
            if (all.size != 8) return null
        }
        val out = ByteArray(16)
        all.forEachIndexed { i, g ->
            out[2 * i] = (g shr 8).toByte()
            out[2 * i + 1] = g.toByte()
        }
        tailV4?.copyInto(out, 12)
        return out
    }

    fun format(address: ByteArray): String = when (address.size) {
        4 -> address.joinToString(".") { (it.toInt() and 0xFF).toString() }
        16 -> formatV6(address)
        else -> throw IllegalArgumentException("Not an IP address: ${address.size} bytes")
    }

    /** RFC 5952 canonical text form. */
    private fun formatV6(a: ByteArray): String {
        val g = IntArray(8) { ((a[2 * it].toInt() and 0xFF) shl 8) or (a[2 * it + 1].toInt() and 0xFF) }
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (g[i] == 0) {
                val start = i
                while (i < 8 && g[i] == 0) i++
                if (i - start > bestLen) { bestStart = start; bestLen = i - start }
            } else i++
        }
        if (bestLen < 2) bestStart = -1
        val sb = StringBuilder()
        i = 0
        while (i < 8) {
            if (i == bestStart) {
                sb.append("::")
                i += bestLen
                continue
            }
            if (sb.isNotEmpty() && !sb.endsWith(":")) sb.append(':')
            sb.append(Integer.toHexString(g[i]))
            i++
        }
        return sb.toString()
    }

    private fun Char.isHexDigit() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
}
