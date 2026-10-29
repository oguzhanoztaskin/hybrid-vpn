package com.oguzhanstech.hybridvpn.engine.dns

import com.oguzhanstech.hybridvpn.engine.policy.Decision
import com.oguzhanstech.hybridvpn.engine.policy.FlowContext
import com.oguzhanstech.hybridvpn.engine.policy.NetworkKind
import com.oguzhanstech.hybridvpn.engine.policy.PolicyEngine

enum class BlockResponse {
    /** A: 0.0.0.0, AAAA: ::, other types: empty NOERROR. Clients fail fast without retrying. */
    NULL_IP,
    NXDOMAIN,
    REFUSED,
}

enum class DnsOutcome { BLOCKED, FORWARDED, CACHED, LOCAL, ERROR }

data class DnsEvent(
    val timestamp: Long,
    val uid: Int?,
    val packages: List<String>?,
    val domain: String,
    val type: Int,
    val outcome: DnsOutcome,
    val ruleId: String?,
    val detail: String?,
    val upstream: String?,
    val latencyMs: Long,
    val rcode: Int?,
)

/** Answers for names owned by a local namespace (tailnets' MagicDNS), never sent upstream. */
sealed interface LocalAnswer {
    object NotLocal : LocalAnswer
    /** [source] names the namespace, e.g. "tailnet:work". */
    class Found(val source: String, val addresses: List<ByteArray>) : LocalAnswer
    class NoSuchName(val source: String) : LocalAnswer
    /** Several namespaces claim the name; answering from any of them would be a guess. */
    class Ambiguous(val sources: List<String>) : LocalAnswer
}

fun interface LocalNames {
    fun resolve(name: String): LocalAnswer
}

/** Who sent a query, as far as the platform could tell. */
class QueryOrigin(val uid: Int?, val packages: List<String>?)

/**
 * Everything the proxy needs to answer a query. Swapped as a whole so a policy or profile change
 * is atomic from the point of view of in-flight queries.
 */
class DnsProxyConfig(
    val policy: PolicyEngine,
    val upstream: DnsUpstream,
    /** Resolver of the underlying network, used for local zones (split-horizon). Null when unknown. */
    val localUpstream: DnsUpstream?,
    val blockResponse: BlockResponse,
    val network: NetworkKind?,
    val networkId: String?,
    val profile: String?,
    val timeoutMs: Int = 4000,
    /** Tailnet names; consulted after the block decision, before any upstream. */
    val localNames: LocalNames? = null,
)

/**
 * Transport-independent DNS firewall: decides, resolves and synthesises answers for one query.
 * It is fed by the TUN packet loop today and can be reused unchanged by a full-tunnel data plane.
 */
class DnsProxy(
    @Volatile var config: DnsProxyConfig,
    private val cache: DnsCache,
    private val events: (DnsEvent) -> Unit,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    fun handle(query: ByteArray, origin: QueryOrigin): ByteArray? {
        val cfg = config
        val start = clock()
        val message = DnsMessage.parseOrNull(query)
            ?: return DnsMessageWriter.errorResponse(query, query.size, DnsRcode.FORMERR)
        if (message.isResponse) return null
        if (message.opcode != 0 || message.questions.size != 1) {
            return DnsMessageWriter.errorResponse(query, query.size, DnsRcode.NOTIMP)
        }
        val question = message.questions[0]
        val name = FilterListParser.normalizeDomain(question.name)
            ?: return DnsMessageWriter.response(message, DnsRcode.FORMERR)

        fun emit(outcome: DnsOutcome, ruleId: String?, detail: String?, upstream: String?, rcode: Int?) =
            events(DnsEvent(start, origin.uid, origin.packages, name, question.type, outcome, ruleId, detail, upstream, clock() - start, rcode))

        val decision = cfg.policy.evaluate(
            FlowContext(
                packages = origin.packages,
                domain = name,
                network = cfg.network,
                networkId = cfg.networkId,
                profile = cfg.profile,
            )
        )
        if (decision is Decision.Block) {
            val response = blockedResponse(message, question, cfg.blockResponse)
            emit(DnsOutcome.BLOCKED, decision.ruleId, decision.reason, null, rcodeOf(response))
            return response
        }

        cfg.localNames?.let { names ->
            when (val answer = names.resolve(name)) {
                LocalAnswer.NotLocal -> Unit
                is LocalAnswer.Found -> {
                    val wanted = when (question.type) { DnsType.A -> 4; DnsType.AAAA -> 16; else -> 0 }
                    val records = answer.addresses.filter { it.size == wanted }.map { question to RData.Address(it) }
                    emit(DnsOutcome.LOCAL, decision.ruleId, answer.source, null, DnsRcode.NOERROR)
                    return DnsMessageWriter.response(message, DnsRcode.NOERROR, records, ttl = LOCAL_TTL)
                }
                is LocalAnswer.NoSuchName -> {
                    emit(DnsOutcome.LOCAL, decision.ruleId, "${answer.source}: no such node", null, DnsRcode.NXDOMAIN)
                    return DnsMessageWriter.response(message, DnsRcode.NXDOMAIN)
                }
                is LocalAnswer.Ambiguous -> {
                    emit(DnsOutcome.ERROR, decision.ruleId, "claimed by ${answer.sources.joinToString()}; refusing to guess", null, DnsRcode.SERVFAIL)
                    return DnsMessageWriter.response(message, DnsRcode.SERVFAIL)
                }
            }
        }

        val upstream = when (LocalZones.classify(name)) {
            LocalZones.Zone.MDNS_ONLY -> {
                val response = DnsMessageWriter.response(message, DnsRcode.NXDOMAIN)
                emit(DnsOutcome.LOCAL, null, ".local is resolved by mDNS, not unicast DNS", null, DnsRcode.NXDOMAIN)
                return response
            }
            LocalZones.Zone.PRIVATE -> cfg.localUpstream ?: run {
                val response = DnsMessageWriter.response(message, DnsRcode.NXDOMAIN)
                emit(DnsOutcome.LOCAL, null, "private zone, no local resolver", null, DnsRcode.NXDOMAIN)
                return response
            }
            LocalZones.Zone.PUBLIC -> cfg.upstream
        }

        val key = DnsCache.Key(name, question.type, question.classValue)
        cache.get(key, message.id)?.let { cached ->
            emit(DnsOutcome.CACHED, null, null, null, rcodeOf(cached))
            return cached
        }

        return try {
            val response = upstream.exchange(query, cfg.timeoutMs)
            val parsed = DnsMessage.parse(response)
            cache.put(key, response, parsed)
            emit(DnsOutcome.FORWARDED, decision.ruleId, null, upstream.description, parsed.rcode)
            response
        } catch (e: Exception) {
            // Fail closed: answer SERVFAIL rather than letting the client fall back to another resolver.
            emit(DnsOutcome.ERROR, null, e.message ?: e.javaClass.simpleName, upstream.description, DnsRcode.SERVFAIL)
            DnsMessageWriter.response(message, DnsRcode.SERVFAIL)
        }
    }

    fun clearCache() = cache.clear()

    private fun blockedResponse(message: DnsMessage, question: DnsQuestion, mode: BlockResponse): ByteArray = when (mode) {
        BlockResponse.NXDOMAIN -> DnsMessageWriter.response(message, DnsRcode.NXDOMAIN)
        BlockResponse.REFUSED -> DnsMessageWriter.response(message, DnsRcode.REFUSED)
        BlockResponse.NULL_IP -> when (question.type) {
            DnsType.A -> DnsMessageWriter.response(message, DnsRcode.NOERROR, listOf(question to RData.Address(ByteArray(4))))
            DnsType.AAAA -> DnsMessageWriter.response(message, DnsRcode.NOERROR, listOf(question to RData.Address(ByteArray(16))))
            else -> DnsMessageWriter.response(message, DnsRcode.NOERROR)
        }
    }

    private fun rcodeOf(response: ByteArray) = if (response.size >= 4) response[3].toInt() and 0xF else null

    private companion object {
        /** Short: tailnet membership changes without a DNS TTL of its own. */
        const val LOCAL_TTL = 30L
    }
}

/** Names that must not be sent to a public resolver (RFC 6761, RFC 6762, RFC 6303, RFC 8375). */
object LocalZones {
    enum class Zone { PUBLIC, PRIVATE, MDNS_ONLY }

    private val privateSuffixes = listOf(
        "home.arpa", "lan", "internal", "localdomain", "intranet", "corp", "home",
        "10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa",
        "d.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa",
    ) + (16..31).map { "$it.172.in-addr.arpa" }

    fun classify(name: String): Zone {
        if (name == "local" || name.endsWith(".local")) return Zone.MDNS_ONLY
        if (privateSuffixes.any { name == it || name.endsWith(".$it") }) return Zone.PRIVATE
        // Single-label names never resolve publicly; let the local network try.
        if (!name.contains('.')) return Zone.PRIVATE
        return Zone.PUBLIC
    }
}
