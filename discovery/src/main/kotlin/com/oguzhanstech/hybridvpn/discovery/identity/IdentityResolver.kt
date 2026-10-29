package com.oguzhanstech.hybridvpn.discovery.identity

import com.oguzhanstech.hybridvpn.discovery.identity.IdentifierKind.Strength

data class KnownIdentifier(val kind: IdentifierKind, val value: String, val lastSeen: Long)

/**
 * A previously recorded device, with the identifiers visible in the current scope: globally
 * unique identifiers plus identifiers recorded on the network being scanned.
 */
data class KnownDevice(val id: String, val identifiers: List<KnownIdentifier>, val fingerprint: String?)

enum class Confidence(val score: Float) { HIGH(0.9f), MEDIUM(0.6f), LOW(0.3f) }

sealed interface Resolution {
    val confidence: Confidence

    data class Matched(
        val deviceId: String,
        override val confidence: Confidence,
        val matchedOn: Identifier,
        /** Other devices that also shared a strong identifier; surfaced, never merged automatically. */
        val conflictsWith: List<String> = emptyList(),
    ) : Resolution

    data class New(override val confidence: Confidence) : Resolution
}

/**
 * Conservative identity matching (spec §9.2).
 *
 * - Strong identifiers (MAC, SSDP UUID, mDNS hostname, router role) link observations.
 * - A reverse-DNS hostname links only when nothing contradicts it.
 * - An IP address alone links only when neither side has better evidence, the IP was seen on this
 *   network recently, and the service fingerprint is identical. Otherwise a new device is created:
 *   a duplicate is easy to merge by hand, a wrong merge silently corrupts history.
 */
class IdentityResolver(private val ipMatchWindowMs: Long = 7 * DAY_MS) {

    fun resolve(observation: HostObservation, known: List<KnownDevice>, now: Long): Resolution {
        val ids = observation.identifiers
        val strong = ids.filter { it.kind.strength == Strength.STRONG }
        val obsMac = ids.firstOrNull { it.kind == IdentifierKind.MAC }?.value

        fun macConflict(d: KnownDevice): Boolean {
            if (obsMac == null) return false
            val macs = d.identifiers.filter { it.kind == IdentifierKind.MAC }.map { it.value }
            return macs.isNotEmpty() && obsMac !in macs
        }

        if (strong.isNotEmpty()) {
            val candidates = known.mapNotNull { d ->
                val shared = strong.filter { s -> d.identifiers.any { it.kind == s.kind && it.value == s.value } }
                if (shared.isEmpty()) return@mapNotNull null
                val globallyUnique = shared.any { it.kind.global }
                if (!globallyUnique && macConflict(d)) null else d to shared
            }
            if (candidates.isNotEmpty()) {
                val best = candidates.maxWith(
                    compareBy<Pair<KnownDevice, List<Identifier>>> { (_, shared) -> shared.count { it.kind.global } }
                        .thenBy { (_, shared) -> shared.size }
                        .thenBy { (d, _) -> d.identifiers.maxOfOrNull { it.lastSeen } ?: 0 }
                )
                return Resolution.Matched(
                    deviceId = best.first.id,
                    confidence = Confidence.HIGH,
                    matchedOn = best.second.first(),
                    conflictsWith = candidates.filter { it !== best }.map { it.first.id },
                )
            }
        }

        val hostname = ids.firstOrNull { it.kind == IdentifierKind.HOSTNAME }
        if (hostname != null) {
            known.firstOrNull { d ->
                d.identifiers.any { it.kind == IdentifierKind.HOSTNAME && it.value == hostname.value } && !macConflict(d)
            }?.let { return Resolution.Matched(it.id, Confidence.MEDIUM, hostname) }
        }

        val ip = ids.first { it.kind == IdentifierKind.IP }
        if (strong.isEmpty()) {
            known.firstOrNull { d ->
                val hasBetterEvidence = d.identifiers.any { it.kind.strength == Strength.STRONG }
                // A missing reverse-DNS answer is common (timeouts); only a different name contradicts.
                val otherHostname = hostname != null && d.identifiers.any { it.kind == IdentifierKind.HOSTNAME && it.value != hostname.value }
                val recentIp = d.identifiers.any { it.kind == IdentifierKind.IP && it.value == ip.value && now - it.lastSeen <= ipMatchWindowMs }
                !hasBetterEvidence && !otherHostname && recentIp && d.fingerprint == observation.fingerprint
            }?.let { return Resolution.Matched(it.id, Confidence.LOW, ip) }
        }

        return Resolution.New(
            when {
                ids.any { it.kind.global } -> Confidence.HIGH
                strong.isNotEmpty() || hostname != null -> Confidence.MEDIUM
                else -> Confidence.LOW
            }
        )
    }

    companion object {
        const val DAY_MS = 24L * 60 * 60 * 1000
    }
}
