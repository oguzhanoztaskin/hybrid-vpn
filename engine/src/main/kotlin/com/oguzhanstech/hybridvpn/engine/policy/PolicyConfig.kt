package com.oguzhanstech.hybridvpn.engine.policy

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Versioned, user-editable policy document (docs/ROUTING.md, schemas/policy.v1.schema.json).
 *
 * Within one [RuleMatch] every non-empty field must match (AND); within a list any entry may
 * match (OR). An empty field is a wildcard.
 */
@Serializable
data class PolicyConfig(
    val version: Int = CURRENT_VERSION,
    /** Transports routes may name, besides the implicit `direct`. */
    val transports: List<TransportConfig> = emptyList(),
    val default: DefaultPolicy = DefaultPolicy(),
    val rules: List<PolicyRule> = emptyList(),
) {
    fun toJson(): String = json.encodeToString(serializer(), this)

    /**
     * This policy with the transports in [off] switched off by the user: their declarations go,
     * rules routing to them are skipped (traffic falls through to later rules), and a fallback
     * naming one blocks instead. A default route naming one becomes `direct`, since switching a
     * connection off means not using it. The saved document is unchanged; this is for running.
     */
    fun withoutTransports(off: Set<String>): PolicyConfig {
        if (off.isEmpty()) return this
        return copy(
            transports = transports.filterNot { it.id in off },
            default = DefaultPolicy(
                route = if (default.route in off) Routes.DIRECT else default.route,
                onFailure = if (default.onFailure in off) Routes.BLOCK else default.onFailure,
            ),
            rules = rules.map { rule ->
                when {
                    rule.action.route in off -> rule.copy(enabled = false)
                    rule.action.onFailure in off -> rule.copy(action = rule.action.copy(onFailure = Routes.BLOCK))
                    else -> rule
                }
            },
        )
    }

    /** Permanently remove transports without silently sending their traffic elsewhere. */
    fun retireTransports(removed: Set<String>): PolicyConfig {
        if (removed.isEmpty()) return this
        val updated = rules.map { rule ->
            when {
                rule.action.route in removed -> rule.copy(
                    description = "${rule.description ?: rule.id} (transport removed; blocked)",
                    action = RuleAction(ActionType.BLOCK),
                )
                rule.action.onFailure in removed -> rule.copy(action = rule.action.copy(onFailure = Routes.BLOCK))
                else -> rule
            }
        }.toMutableList()
        if (default.route in removed) {
            // The schema requires a transport in default.route. A last IP-only
            // block preserves the deleted default's fail-closed intent without
            // changing DNS or any earlier explicit rule, even at MAX priority.
            updated += PolicyRule(
                id = "${rules.maxOfOrNull { it.id }.orEmpty()}-removed-default",
                priority = Int.MAX_VALUE,
                description = "Default transport ${default.route} removed; unmatched traffic blocked",
                match = RuleMatch(destinationCidrs = listOf("0.0.0.0/0", "::/0")),
                action = RuleAction(ActionType.BLOCK),
            )
        }
        return copy(
            transports = transports.filterNot { it.id in removed },
            default = DefaultPolicy(
                route = if (default.route in removed) Routes.DIRECT else default.route,
                onFailure = if (default.onFailure in removed) Routes.BLOCK else default.onFailure,
            ),
            rules = updated,
        )
    }

    companion object {
        const val CURRENT_VERSION = 1

        val json = Json {
            prettyPrint = true
            encodeDefaults = false
            ignoreUnknownKeys = false
        }

        fun fromJson(text: String): PolicyConfig = json.decodeFromString(serializer(), text)
    }
}

/**
 * A named way out of the device. The id is what routes reference, and it carries identity: two
 * tailnets are two transports (e.g. "tailnet:work", "tailnet:home"), never one.
 */
@Serializable
data class TransportConfig(
    val id: String,
    val type: TransportType,
    val description: String? = null,
)

@Serializable
enum class TransportType(val wire: String) {
    @SerialName("direct") DIRECT("direct"),
    @SerialName("tailnet") TAILNET("tailnet"),
    @SerialName("socks5") SOCKS5("socks5"),
    @SerialName("http") HTTP("http"),
    @SerialName("openvpn") OPENVPN("openvpn"),
}

@Serializable
data class DefaultPolicy(
    val route: String = Routes.DIRECT,
    @SerialName("on_failure") val onFailure: String = Routes.BLOCK,
)

@Serializable
data class PolicyRule(
    val id: String,
    val priority: Int,
    val enabled: Boolean = true,
    val description: String? = null,
    val match: RuleMatch = RuleMatch(),
    val action: RuleAction,
)

@Serializable
data class RuleMatch(
    /** Package names. The token [UNKNOWN_APP] matches flows whose owner could not be attributed. */
    val apps: List<String> = emptyList(),
    /** Domain list ids, or `@all` for any enabled list. Exceptions (`@@`) are honoured. */
    @SerialName("domain_lists") val domainLists: List<String> = emptyList(),
    /** A domain matches itself and all of its subdomains. */
    val domains: List<String> = emptyList(),
    @SerialName("destination_cidrs") val destinationCidrs: List<String> = emptyList(),
    val protocol: Protocol? = null,
    /** Single ports ("443") or inclusive ranges ("8000-8100"). */
    val ports: List<String> = emptyList(),
    val networks: List<NetworkKind> = emptyList(),
    @SerialName("network_ids") val networkIds: List<String> = emptyList(),
    val profiles: List<String> = emptyList(),
) {
    companion object {
        const val UNKNOWN_APP = "@unknown"
    }
}

@Serializable
data class RuleAction(
    val type: ActionType,
    val route: String? = null,
    /** "block" or another route id to fall back to when [route] is unavailable. */
    @SerialName("on_failure") val onFailure: String? = null,
)

@Serializable
enum class ActionType {
    @SerialName("block") BLOCK,
    @SerialName("route") ROUTE,
}

@Serializable
enum class Protocol {
    @SerialName("icmp") ICMP,
    @SerialName("icmpv6") ICMPV6,
    @SerialName("tcp") TCP,
    @SerialName("udp") UDP,
}

@Serializable
enum class NetworkKind {
    @SerialName("wifi") WIFI,
    @SerialName("cellular") CELLULAR,
    @SerialName("ethernet") ETHERNET,
    @SerialName("other") OTHER,
}

object Routes {
    const val DIRECT = "direct"
    /** Pseudo-route used in `on_failure` meaning "drop the flow". */
    const val BLOCK = "block"
}
