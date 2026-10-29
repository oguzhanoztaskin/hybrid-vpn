package com.oguzhanstech.hybridvpn.engine.policy

import com.oguzhanstech.hybridvpn.engine.dns.DomainListIndex

/**
 * What is known about a flow when it is evaluated. Unknown attributes are null and never match
 * a rule that constrains them, so a rule cannot accidentally capture traffic it cannot identify.
 */
class FlowContext(
    /** Packages sharing the owning UID; null when attribution failed. */
    val packages: List<String>?,
    val destination: ByteArray? = null,
    /** Normalised domain name, when known (DNS queries, or DNS-derived associations). */
    val domain: String? = null,
    val protocol: Protocol? = null,
    val port: Int? = null,
    val network: NetworkKind? = null,
    val networkId: String? = null,
    val profile: String? = null,
)

sealed interface Decision {
    /** Id of the rule that decided, or null for the default policy. */
    val ruleId: String?

    data class Block(override val ruleId: String?, val reason: String) : Decision
    data class Route(override val ruleId: String?, val route: String, val fellBack: Boolean = false) : Decision
}

/** Health of transports, consulted only for rules that route somewhere. */
fun interface TransportHealth {
    fun isAvailable(route: String): Boolean
}

class PolicyEngine(private val policy: CompiledPolicy, private val lists: DomainListIndex) {

    fun evaluate(flow: FlowContext, health: TransportHealth = TransportHealth { true }): Decision {
        for (rule in policy.rules) {
            val listHit = matches(rule, flow) ?: continue
            return when (rule.action.type) {
                ActionType.BLOCK -> Decision.Block(rule.id, listHit.ifEmpty { "rule ${rule.id}" })
                ActionType.ROUTE -> resolve(rule.id, rule.action.route!!, rule.action.onFailure ?: policy.defaultOnFailure, health)
            }
        }
        return resolve(null, policy.defaultRoute, policy.defaultOnFailure, health)
    }

    private fun resolve(ruleId: String?, route: String, onFailure: String, health: TransportHealth): Decision {
        if (route == Routes.DIRECT || health.isAvailable(route)) return Decision.Route(ruleId, route)
        if (onFailure == Routes.BLOCK) return Decision.Block(ruleId, "transport '$route' unavailable")
        if (onFailure == Routes.DIRECT || health.isAvailable(onFailure)) return Decision.Route(ruleId, onFailure, fellBack = true)
        return Decision.Block(ruleId, "transports '$route' and '$onFailure' unavailable")
    }

    /** Null when the rule does not match; otherwise a (possibly empty) description of the list hit. */
    private fun matches(rule: CompiledRule, flow: FlowContext): String? {
        if (rule.apps.isNotEmpty()) {
            val pkgs = flow.packages
            val hit = if (pkgs == null) RuleMatch.UNKNOWN_APP in rule.apps else pkgs.any { it in rule.apps }
            if (!hit) return null
        }
        if (rule.profiles.isNotEmpty() && flow.profile !in rule.profiles) return null
        if (rule.networks.isNotEmpty() && flow.network !in rule.networks) return null
        if (rule.networkIds.isNotEmpty() && flow.networkId !in rule.networkIds) return null
        if (rule.protocol != null && flow.protocol != rule.protocol) return null
        if (rule.ports.isNotEmpty()) {
            val port = flow.port ?: return null
            if (rule.ports.none { port in it }) return null
        }
        if (rule.cidrs.isNotEmpty()) {
            val dst = flow.destination ?: return null
            if (rule.cidrs.none { it.contains(dst) }) return null
        }
        if (rule.domains.isNotEmpty()) {
            val domain = flow.domain ?: return null
            if (rule.domains.none { domain == it || domain.endsWith(".$it") }) return null
        }
        if (rule.domainLists.isNotEmpty()) {
            val domain = flow.domain ?: return null
            val hit = rule.domainLists.firstNotNullOfOrNull { lists.match(it, domain) } ?: return null
            return "${hit.listId}: ${hit.rule}"
        }
        return ""
    }
}
