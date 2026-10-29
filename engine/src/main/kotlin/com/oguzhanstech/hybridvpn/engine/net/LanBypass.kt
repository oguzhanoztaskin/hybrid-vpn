package com.oguzhanstech.hybridvpn.engine.net

/** Destination-based LAN bypass for Android's VPN routes (all IP protocols, not just UDP). */
object LanBypass {
    private val discovery = listOf("224.0.0.0/4", "255.255.255.255/32", "ff00::/8", "169.254.0.0/16", "fe80::/10")
        .map { Cidr.parse(it)!! }

    /** Only on-link networks supplied by Wi-Fi/Ethernet; never entire RFC1918 or tailnet ranges. */
    fun exclusions(connected: List<Cidr>): List<Cidr> = (discovery + connected.filter { it.prefixLength > 0 })
        .distinct().sortedBy { it.toString() }

    /**
     * Complement of the exclusions, usable with addRoute on every supported Android version.
     * DNS host routes are added by the caller and take precedence over any exclusion.
     */
    fun tunnelRoutes(excluded: List<Cidr>): List<Cidr> {
        fun subtract(prefix: Cidr, cuts: List<Cidr>): List<Cidr> {
            if (cuts.any { it.contains(prefix) }) return emptyList()
            val overlaps = cuts.filter { prefix.overlaps(it) }
            if (overlaps.isEmpty()) return listOf(prefix)
            val bits = prefix.prefixLength
            val right = prefix.address
            right[bits / 8] = (right[bits / 8].toInt() or (0x80 ushr (bits % 8))).toByte()
            return subtract(Cidr.of(prefix.address, bits + 1), overlaps) + subtract(Cidr.of(right, bits + 1), overlaps)
        }
        return listOf("0.0.0.0/0", "::/0").flatMap { subtract(Cidr.parse(it)!!, excluded) }
    }
}
