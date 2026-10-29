package com.oguzhanstech.hybridvpn.engine.dns

object DnsType {
    const val A = 1
    const val NS = 2
    const val CNAME = 5
    const val SOA = 6
    const val PTR = 12
    const val TXT = 16
    const val AAAA = 28
    const val SRV = 33
    const val OPT = 41
    const val SVCB = 64
    const val HTTPS = 65
    const val ANY = 255

    fun name(type: Int): String = when (type) {
        A -> "A"; NS -> "NS"; CNAME -> "CNAME"; SOA -> "SOA"; PTR -> "PTR"; TXT -> "TXT"
        AAAA -> "AAAA"; SRV -> "SRV"; OPT -> "OPT"; SVCB -> "SVCB"; HTTPS -> "HTTPS"; ANY -> "ANY"
        else -> "TYPE$type"
    }
}

object DnsRcode {
    const val NOERROR = 0
    const val FORMERR = 1
    const val SERVFAIL = 2
    const val NXDOMAIN = 3
    const val NOTIMP = 4
    const val REFUSED = 5
}

class DnsFormatException(message: String) : Exception(message)

data class DnsQuestion(val name: String, val type: Int, val clazz: Int = 1) {
    /** mDNS "unicast response requested" bit lives in the top bit of the class field. */
    val classValue: Int get() = clazz and 0x7FFF
}

sealed interface RData {
    data class Address(val bytes: ByteArray) : RData {
        override fun equals(other: Any?) = other is Address && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }
    data class Name(val name: String) : RData
    data class Srv(val priority: Int, val weight: Int, val port: Int, val target: String) : RData
    data class Txt(val strings: List<String>) : RData
    data class Soa(val minimum: Long) : RData
    class Raw(val bytes: ByteArray) : RData
}

data class DnsRecord(
    val name: String,
    val type: Int,
    val clazz: Int,
    val ttl: Long,
    val data: RData,
    /** Byte offset of the TTL field inside the original message; lets caches age TTLs in place. */
    val ttlOffset: Int,
)

class DnsMessage(
    val id: Int,
    val flags: Int,
    val questions: List<DnsQuestion>,
    val answers: List<DnsRecord>,
    val authorities: List<DnsRecord>,
    val additionals: List<DnsRecord>,
) {
    val isResponse: Boolean get() = flags and 0x8000 != 0
    val opcode: Int get() = (flags shr 11) and 0xF
    val isTruncated: Boolean get() = flags and 0x0200 != 0
    val recursionDesired: Boolean get() = flags and 0x0100 != 0
    val rcode: Int get() = flags and 0xF

    val allRecords: List<DnsRecord> get() = answers + authorities + additionals

    companion object {
        private const val MAX_POINTER_JUMPS = 32
        private const val MAX_RECORDS = 512

        fun parseOrNull(buf: ByteArray, length: Int = buf.size): DnsMessage? =
            try { parse(buf, length) } catch (_: DnsFormatException) { null }

        fun parse(buf: ByteArray, length: Int = buf.size): DnsMessage {
            if (length < 12) throw DnsFormatException("short header")
            val r = Reader(buf, length)
            val id = r.u16()
            val flags = r.u16()
            val qd = r.u16()
            val an = r.u16()
            val ns = r.u16()
            val ar = r.u16()
            if (qd + an + ns + ar > MAX_RECORDS) throw DnsFormatException("too many records")
            val questions = List(qd) { DnsQuestion(r.name(), r.u16(), r.u16()) }
            val answers = List(an) { r.record() }
            val authorities = List(ns) { r.record() }
            val additionals = List(ar) { r.record() }
            return DnsMessage(id, flags, questions, answers, authorities, additionals)
        }

        /** Reads just the id and first question; enough for proxying and error synthesis. */
        fun parseQuestion(buf: ByteArray, length: Int = buf.size): DnsQuestion? = try {
            if (length < 12 || u16At(buf, 4) < 1) null
            else Reader(buf, length).apply { pos = 12 }.let { DnsQuestion(it.name(), it.u16(), it.u16()) }
        } catch (_: DnsFormatException) { null }

        private fun u16At(buf: ByteArray, o: Int) = ((buf[o].toInt() and 0xFF) shl 8) or (buf[o + 1].toInt() and 0xFF)
    }

    private class Reader(val buf: ByteArray, val limit: Int) {
        var pos = 0

        fun need(n: Int) { if (pos + n > limit) throw DnsFormatException("truncated at $pos") }
        fun u8(): Int { need(1); return buf[pos++].toInt() and 0xFF }
        fun u16(): Int { need(2); return ((buf[pos++].toInt() and 0xFF) shl 8) or (buf[pos++].toInt() and 0xFF) }
        fun u32(): Long = (u16().toLong() shl 16) or u16().toLong()

        fun name(): String {
            val labels = ArrayList<String>()
            var p = pos
            var jumped = false
            var jumps = 0
            var total = 0
            while (true) {
                if (p >= limit) throw DnsFormatException("name overruns message")
                val len = buf[p].toInt() and 0xFF
                when (len and 0xC0) {
                    0x00 -> {
                        if (len == 0) {
                            if (!jumped) pos = p + 1
                            return if (labels.isEmpty()) "." else labels.joinToString(".")
                        }
                        if (p + 1 + len > limit) throw DnsFormatException("label overruns message")
                        total += len + 1
                        if (total > 255) throw DnsFormatException("name too long")
                        labels += String(buf, p + 1, len, Charsets.ISO_8859_1)
                        p += 1 + len
                    }
                    0xC0 -> {
                        if (p + 1 >= limit) throw DnsFormatException("bad pointer")
                        if (++jumps > MAX_POINTER_JUMPS) throw DnsFormatException("pointer loop")
                        val target = ((len and 0x3F) shl 8) or (buf[p + 1].toInt() and 0xFF)
                        if (!jumped) pos = p + 2
                        jumped = true
                        p = target
                    }
                    else -> throw DnsFormatException("unsupported label type")
                }
            }
        }

        fun record(): DnsRecord {
            val name = name()
            val type = u16()
            val clazz = u16()
            val ttlOffset = pos
            val ttl = u32()
            val rdLength = u16()
            need(rdLength)
            val end = pos + rdLength
            val data: RData = when (type) {
                DnsType.A -> if (rdLength == 4) RData.Address(buf.copyOfRange(pos, end)) else raw(end)
                DnsType.AAAA -> if (rdLength == 16) RData.Address(buf.copyOfRange(pos, end)) else raw(end)
                DnsType.PTR, DnsType.CNAME, DnsType.NS -> RData.Name(name())
                DnsType.SRV -> RData.Srv(u16(), u16(), u16(), name())
                DnsType.TXT -> {
                    val strings = ArrayList<String>()
                    while (pos < end) {
                        val l = u8()
                        need(l)
                        strings += String(buf, pos, minOf(l, end - pos), Charsets.UTF_8)
                        pos += l
                    }
                    RData.Txt(strings)
                }
                DnsType.SOA -> { name(); name(); need(20); pos += 16; RData.Soa(u32()) }
                else -> raw(end)
            }
            if (pos > end) throw DnsFormatException("rdata overrun")
            pos = end
            return DnsRecord(name, type, clazz, ttl, data, ttlOffset)
        }

        fun raw(end: Int): RData = RData.Raw(buf.copyOfRange(pos, end))
    }
}

/** Serialises queries and synthetic responses. Names are written uncompressed. */
object DnsMessageWriter {

    fun query(id: Int, questions: List<DnsQuestion>, recursionDesired: Boolean = true): ByteArray {
        val out = Out()
        out.u16(id)
        out.u16(if (recursionDesired) 0x0100 else 0)
        out.u16(questions.size); out.u16(0); out.u16(0); out.u16(0)
        questions.forEach { out.question(it) }
        return out.toByteArray()
    }

    /**
     * A response to [query] carrying [answers]. Flags mirror the query (opcode, RD) with QR and RA set.
     */
    fun response(query: DnsMessage, rcode: Int, answers: List<Pair<DnsQuestion, RData>> = emptyList(), ttl: Long = 60): ByteArray {
        val out = Out()
        out.u16(query.id)
        out.u16(0x8000 or (query.flags and 0x7900) or 0x0080 or (rcode and 0xF))
        out.u16(query.questions.size); out.u16(answers.size); out.u16(0); out.u16(0)
        query.questions.forEach { out.question(it) }
        for ((q, data) in answers) {
            out.name(q.name)
            out.u16(q.type)
            out.u16(q.classValue)
            out.u32(ttl)
            when (data) {
                is RData.Address -> { out.u16(data.bytes.size); out.bytes(data.bytes) }
                else -> throw IllegalArgumentException("Only address answers are synthesised")
            }
        }
        return out.toByteArray()
    }

    /**
     * Minimal error response built from raw query bytes, usable even when the query could not be
     * fully parsed. Copies the header and first question if they can be located.
     */
    fun errorResponse(query: ByteArray, length: Int, rcode: Int): ByteArray? {
        if (length < 12) return null
        val questionEnd = questionEnd(query, length)
        val end = questionEnd ?: 12
        val out = query.copyOf(end)
        val flags = ((out[2].toInt() and 0xFF) shl 8) or (out[3].toInt() and 0xFF)
        val newFlags = 0x8000 or (flags and 0x7900) or 0x0080 or (rcode and 0xF)
        out[2] = (newFlags shr 8).toByte(); out[3] = newFlags.toByte()
        out[4] = 0; out[5] = if (questionEnd != null) 1 else 0
        for (i in 6 until 12) out[i] = 0
        return out
    }

    /** Header plus question with the TC bit set, telling the client the answer did not fit. */
    fun truncated(response: ByteArray): ByteArray {
        val end = questionEnd(response, response.size) ?: 12
        val out = response.copyOf(end)
        out[2] = (out[2].toInt() or 0x02).toByte()
        out[5] = if (end > 12) 1 else 0
        out[4] = 0
        for (i in 6 until 12) out[i] = 0
        return out
    }

    fun withId(message: ByteArray, id: Int): ByteArray = message.copyOf().also {
        it[0] = (id shr 8).toByte(); it[1] = id.toByte()
    }

    private fun questionEnd(buf: ByteArray, length: Int): Int? {
        var p = 12
        while (p < length) {
            val len = buf[p].toInt() and 0xFF
            if (len == 0) return (p + 5).takeIf { it <= length }
            if (len and 0xC0 != 0) return null
            p += len + 1
        }
        return null
    }

    private class Out {
        private val buf = java.io.ByteArrayOutputStream(512)
        fun u16(v: Int) { buf.write(v shr 8); buf.write(v) }
        fun u32(v: Long) { u16((v shr 16).toInt()); u16(v.toInt()) }
        fun bytes(b: ByteArray) = buf.write(b)
        fun name(name: String) {
            if (name != "." && name.isNotEmpty()) {
                for (label in name.trimEnd('.').split('.')) {
                    val bytes = label.toByteArray(Charsets.ISO_8859_1)
                    require(bytes.size in 1..63) { "Bad label in $name" }
                    buf.write(bytes.size)
                    buf.write(bytes)
                }
            }
            buf.write(0)
        }
        fun question(q: DnsQuestion) { name(q.name); u16(q.type); u16(q.clazz) }
        fun toByteArray(): ByteArray = buf.toByteArray()
    }
}
