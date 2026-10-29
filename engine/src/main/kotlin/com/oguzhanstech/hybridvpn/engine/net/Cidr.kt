package com.oguzhanstech.hybridvpn.engine.net

/** An IPv4 or IPv6 prefix. Host bits are cleared on construction. */
class Cidr private constructor(private val network: ByteArray, val prefixLength: Int) {

    val isIpv4: Boolean get() = network.size == 4
    val address: ByteArray get() = network.copyOf()

    fun contains(ip: ByteArray): Boolean {
        if (ip.size != network.size) return false
        var bits = prefixLength
        var i = 0
        while (bits >= 8) {
            if (ip[i] != network[i]) return false
            i++
            bits -= 8
        }
        if (bits == 0) return true
        val mask = (0xFF shl (8 - bits)) and 0xFF
        return (ip[i].toInt() and mask) == (network[i].toInt() and mask)
    }

    fun contains(other: Cidr): Boolean = other.prefixLength >= prefixLength && contains(other.network)

    fun overlaps(other: Cidr): Boolean =
        network.size == other.network.size && (contains(other.network) || other.contains(network))

    override fun equals(other: Any?): Boolean =
        other is Cidr && prefixLength == other.prefixLength && network.contentEquals(other.network)

    override fun hashCode(): Int = network.contentHashCode() * 31 + prefixLength

    override fun toString(): String = "${IpLiteral.format(network)}/$prefixLength"

    companion object {
        fun parse(text: String): Cidr? {
            val slash = text.indexOf('/')
            val ip = IpLiteral.parse(if (slash < 0) text else text.substring(0, slash)) ?: return null
            val max = ip.size * 8
            val length = if (slash < 0) max else text.substring(slash + 1).trim().toIntOrNull() ?: return null
            if (length !in 0..max) return null
            return of(ip, length)
        }

        fun of(ip: ByteArray, prefixLength: Int): Cidr {
            require(ip.size == 4 || ip.size == 16) { "Not an IP address" }
            require(prefixLength in 0..ip.size * 8) { "Bad prefix length $prefixLength" }
            val masked = ip.copyOf()
            for (i in masked.indices) {
                val bitsBefore = i * 8
                masked[i] = when {
                    bitsBefore + 8 <= prefixLength -> masked[i]
                    bitsBefore >= prefixLength -> 0
                    else -> (masked[i].toInt() and (0xFF shl (8 - (prefixLength - bitsBefore)))).toByte()
                }
            }
            return Cidr(masked, prefixLength)
        }
    }
}
