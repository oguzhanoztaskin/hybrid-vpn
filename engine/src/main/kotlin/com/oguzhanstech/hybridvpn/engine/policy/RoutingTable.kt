package com.oguzhanstech.hybridvpn.engine.policy

import com.oguzhanstech.hybridvpn.engine.net.Cidr

/** One row of the routing view: what a rule matches and where matching traffic goes. */
data class RoutePath(
    val id: String,
    val kind: Kind,
    val description: String?,
    /** Human-readable conditions, all of which must hold; empty means every flow. */
    val conditions: List<String>,
    val cidrs: List<Cidr>,
    /** A transport id, or [Routes.BLOCK]; built-in rows name what handles the flow. */
    val target: String,
    /** Tried when [target] can't deliver; null for blocks and built-in rows. */
    val onFailure: String?,
    /** Why the rule doesn't apply right now (another profile or network, connection switched off), or null. */
    val inactive: String? = null,
) {
    enum class Kind {
        /** Fixed guards evaluated before the policy (go/engine/router.go). */
        BUILTIN,
        /** A policy rule acting on IP flows, in evaluation order. */
        FLOW,
        /** A policy rule matching domains: applied when names are resolved, never to IP flows. */
        DNS,
        /** What a flow matching no rule gets. */
        DEFAULT,
    }
}

/**
 * The effective routing as the full-tunnel engine applies it (docs/ROUTING.md): built-in guards,
 * then the policy's rules in order (first match decides), then the default. Rules for another
 * profile or network, and rules whose connection is switched off, are listed as inactive so the
 * view explains why they don't apply.
 */
object RoutingTable {

    val BUILTIN: List<RoutePath> = listOf(
        builtin("non-unicast", "Non-unicast guard", "Loopback, multicast, broadcast or unspecified destination", "drop"),
        builtin("dns", "DNS interception", "Port 53, UDP or TCP, any address", "DNS firewall"),
        builtin("virtual-resolver", "Virtual resolver", "The tunnel's resolver on any other port (e.g. DoT probe)", "drop"),
        builtin("loop-guard", "Loop guard", "The tunnel's own addresses", "drop"),
        builtin("icmp", "IPv4 ping", "ICMP echo requests", "drop"),
        builtin("icmpv6", "IPv6 ping", "ICMPv6 echo requests", "drop"),
        builtin("other-protocols", "Other protocols", "Non-echo ICMP and other unsupported IP protocols", "drop"),
    )

    fun build(
        policy: CompiledPolicy,
        profile: String?,
        network: NetworkKind?,
        networkId: String?,
        /** Rules of the saved policy skipped because the transport they route to is off, with that transport. */
        switchedOff: List<Pair<PolicyRule, String>> = emptyList(),
        allowIcmp: Boolean = false,
        allowIcmpv6: Boolean = false,
    ): List<RoutePath> {
        val rows = ArrayList(BUILTIN.map { row ->
            when {
                row.id == "icmp" && allowIcmp -> row.copy(target = "policy")
                row.id == "icmpv6" && allowIcmpv6 -> row.copy(target = "policy")
                else -> row
            }
        })
        val active = policy.rules.map { rule ->
            val inactive = when {
                rule.profiles.isNotEmpty() && profile !in rule.profiles -> "only in profile ${rule.profiles.sorted().joinToString()}"
                rule.networks.isNotEmpty() && network !in rule.networks ->
                    "only on ${rule.networks.map { it.name.lowercase() }.sorted().joinToString()}"
                rule.networkIds.isNotEmpty() && networkId !in rule.networkIds -> "only on network ${rule.networkIds.sorted().joinToString()}"
                else -> null
            }
            rule.priority to RoutePath(
                id = rule.id,
                kind = if (rule.domains.isNotEmpty() || rule.domainLists.isNotEmpty()) RoutePath.Kind.DNS else RoutePath.Kind.FLOW,
                description = rule.description,
                conditions = conditions(rule.apps, rule.domains, rule.domainLists, rule.cidrs, rule.protocol, rule.ports.map(::portText)),
                cidrs = rule.cidrs,
                target = target(rule.action),
                onFailure = onFailure(rule.action, policy.defaultOnFailure),
                inactive = inactive,
            )
        }
        val off = switchedOff.map { (rule, transport) ->
            val m = rule.match
            rule.priority to RoutePath(
                id = rule.id,
                kind = if (m.domains.isNotEmpty() || m.domainLists.isNotEmpty()) RoutePath.Kind.DNS else RoutePath.Kind.FLOW,
                description = rule.description,
                conditions = conditions(m.apps.toSet(), m.domains, m.domainLists, m.destinationCidrs.mapNotNull(Cidr::parse), m.protocol, m.ports),
                cidrs = m.destinationCidrs.mapNotNull(Cidr::parse),
                target = target(rule.action),
                onFailure = onFailure(rule.action, policy.defaultOnFailure),
                inactive = "$transport is off; matching traffic falls through to later rules",
            )
        }
        // Same order as the compiler: priority, then id.
        (active + off).sortedWith(compareBy<Pair<Int, RoutePath>> { it.first }.thenBy { it.second.id }).mapTo(rows) { it.second }
        rows += RoutePath(
            id = "default", kind = RoutePath.Kind.DEFAULT, description = "Everything no rule matched",
            conditions = emptyList(), cidrs = emptyList(), target = policy.defaultRoute, onFailure = policy.defaultOnFailure,
        )
        return rows
    }

    private fun builtin(id: String, title: String, what: String, handler: String) =
        RoutePath(id, RoutePath.Kind.BUILTIN, title, listOf(what), emptyList(), handler, null)

    private fun target(action: RuleAction) = if (action.type == ActionType.BLOCK) Routes.BLOCK else action.route ?: Routes.BLOCK

    private fun onFailure(action: RuleAction, defaultOnFailure: String) =
        if (action.type == ActionType.BLOCK) null else action.onFailure ?: defaultOnFailure

    private fun portText(r: IntRange) = if (r.first == r.last) "${r.first}" else "${r.first}-${r.last}"

    private fun conditions(
        apps: Set<String>,
        domains: List<String>,
        domainLists: List<String>,
        cidrs: List<Cidr>,
        protocol: Protocol?,
        ports: List<String>,
    ): List<String> = buildList {
        if (apps.isNotEmpty()) add("apps " + apps.sorted().joinToString { if (it == RuleMatch.UNKNOWN_APP) "unknown app" else it })
        if (domains.isNotEmpty()) add("domains " + domains.joinToString())
        if (domainLists.isNotEmpty()) add(domainLists.joinToString(prefix = "filter lists ") { if (it == "@all") "(all enabled)" else it })
        if (cidrs.isNotEmpty()) add("to " + cidrs.joinToString())
        if (protocol != null || ports.isNotEmpty()) {
            add(listOfNotNull(protocol?.name, ports.takeIf { it.isNotEmpty() }?.joinToString(prefix = "port ")).joinToString(" "))
        }
    }
}
