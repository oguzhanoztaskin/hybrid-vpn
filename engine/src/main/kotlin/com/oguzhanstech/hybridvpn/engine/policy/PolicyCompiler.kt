package com.oguzhanstech.hybridvpn.engine.policy

import com.oguzhanstech.hybridvpn.engine.dns.DomainListIndex
import com.oguzhanstech.hybridvpn.engine.dns.FilterListParser
import com.oguzhanstech.hybridvpn.engine.net.Cidr

class CompiledRule(
    val id: String,
    val priority: Int,
    val apps: Set<String>,
    val domainLists: List<String>,
    val domains: List<String>,
    val cidrs: List<Cidr>,
    val protocol: Protocol?,
    val ports: List<IntRange>,
    val networks: Set<NetworkKind>,
    val networkIds: Set<String>,
    val profiles: Set<String>,
    val action: RuleAction,
    val description: String? = null,
)

class CompiledPolicy(
    val rules: List<CompiledRule>,
    val defaultRoute: String,
    val defaultOnFailure: String,
    val warnings: List<String>,
    /** Declared transports plus the implicit `direct`. */
    val transports: List<TransportConfig> = listOf(TransportConfig(Routes.DIRECT, TransportType.DIRECT)),
)

sealed interface CompileResult {
    data class Ok(val policy: CompiledPolicy) : CompileResult
    data class Failed(val errors: List<String>) : CompileResult
}

/**
 * Validates a [PolicyConfig] and turns it into an ordered rule table.
 *
 * A policy either compiles completely or is rejected; there is no partially applied policy.
 * That is what makes profile switching atomic: the running engine keeps the previous table
 * until a new one compiles.
 */
object PolicyCompiler {

    /**
     * [supportedTransports] are the transport types this build can actually run. Declaring any
     * other type is an error rather than a rule that silently never applies.
     */
    fun compile(
        config: PolicyConfig,
        knownLists: Set<String>,
        supportedTransports: Set<TransportType> = setOf(TransportType.DIRECT),
        /** Ids of non-direct transports that actually exist (e.g. configured tailnets); null skips the check. */
        availableTransports: Set<String>? = null,
    ): CompileResult {
        val errors = ArrayList<String>()
        val warnings = ArrayList<String>()
        val transports = compileTransports(config.transports, supportedTransports, availableTransports, errors)
        val routes = transports.map { it.id }.toSet()

        if (config.version != PolicyConfig.CURRENT_VERSION) {
            errors += "Unsupported policy version ${config.version} (expected ${PolicyConfig.CURRENT_VERSION})"
        }
        checkRoute("default.route", config.default.route, routes, allowBlock = false, errors)
        checkRoute("default.on_failure", config.default.onFailure, routes, allowBlock = true, errors)

        config.rules.groupBy { it.id }.filterValues { it.size > 1 }.keys.forEach { errors += "Duplicate rule id '$it'" }

        val compiled = config.rules.filter { it.enabled }.mapNotNull { rule ->
            val where = "rule '${rule.id}'"
            val before = errors.size
            if (rule.id.isBlank()) errors += "A rule has an empty id"

            val action = rule.action
            when (action.type) {
                ActionType.BLOCK -> if (action.route != null || action.onFailure != null) {
                    errors += "$where: a block action takes no route or on_failure"
                }
                ActionType.ROUTE -> {
                    if (action.route == null) errors += "$where: route action needs 'route'"
                    else checkRoute("$where route", action.route, routes, allowBlock = false, errors)
                    action.onFailure?.let { checkRoute("$where on_failure", it, routes, allowBlock = true, errors) }
                }
            }

            val m = rule.match
            if (action.type == ActionType.ROUTE && (m.domains.isNotEmpty() || m.domainLists.isNotEmpty())) {
                errors += "$where: route rules cannot match domains yet (IP flows carry no domain); use destination_cidrs, or a block action"
            }
            val cidrs = m.destinationCidrs.mapNotNull { text ->
                Cidr.parse(text).also { if (it == null) errors += "$where: invalid CIDR '$text'" }
            }
            val ports = m.ports.mapNotNull { text ->
                parsePortRange(text).also { if (it == null) errors += "$where: invalid port or range '$text'" }
            }
            val domains = m.domains.mapNotNull { text ->
                FilterListParser.normalizeDomain(text).also { if (it == null) errors += "$where: invalid domain '$text'" }
            }
            m.domainLists.filter { it != DomainListIndex.ANY_LIST && it !in knownLists }.forEach {
                errors += "$where: unknown domain list '$it'"
            }
            if ((m.ports.isNotEmpty()) && m.protocol == null) {
                warnings += "$where: ports without a protocol match both TCP and UDP"
            }

            if (errors.size != before) null
            else CompiledRule(
                id = rule.id,
                priority = rule.priority,
                apps = m.apps.toSet(),
                domainLists = m.domainLists,
                domains = domains,
                cidrs = cidrs,
                protocol = m.protocol,
                ports = ports,
                networks = m.networks.toSet(),
                networkIds = m.networkIds.toSet(),
                profiles = m.profiles.toSet(),
                action = action,
                description = rule.description,
            )
        }.sortedWith(compareBy<CompiledRule> { it.priority }.thenBy { it.id })

        warnings += findCidrConflicts(compiled)

        return if (errors.isEmpty()) {
            CompileResult.Ok(CompiledPolicy(compiled, config.default.route, config.default.onFailure, warnings, transports))
        } else {
            CompileResult.Failed(errors)
        }
    }

    /**
     * Rules that only differ by destination prefix and send overlapping prefixes to different
     * routes are almost always a mistake (e.g. a tailnet route shadowing an OpenVPN subnet).
     */
    private fun findCidrConflicts(rules: List<CompiledRule>): List<String> {
        val warnings = ArrayList<String>()
        val cidrRules = rules.filter { it.cidrs.isNotEmpty() }
        for (i in cidrRules.indices) for (j in i + 1 until cidrRules.size) {
            val a = cidrRules[i]
            val b = cidrRules[j]
            if (target(a) == target(b)) continue
            if (a.apps != b.apps || a.protocol != b.protocol || a.profiles != b.profiles) continue
            for (ca in a.cidrs) for (cb in b.cidrs) {
                if (ca.overlaps(cb)) {
                    warnings += "Rules '${a.id}' ($ca → ${target(a)}) and '${b.id}' ($cb → ${target(b)}) overlap; '${a.id}' wins"
                }
            }
        }
        return warnings
    }

    private fun target(rule: CompiledRule) = if (rule.action.type == ActionType.BLOCK) Routes.BLOCK else rule.action.route

    private fun checkRoute(where: String, route: String, routes: Set<String>, allowBlock: Boolean, errors: MutableList<String>) {
        if (route == Routes.BLOCK && allowBlock) return
        if (route !in routes) errors += "$where: unknown route '$route'"
    }

    private val TRANSPORT_ID = Regex("^[a-z0-9][a-z0-9._:-]{0,63}$")

    private fun compileTransports(
        declared: List<TransportConfig>,
        supported: Set<TransportType>,
        available: Set<String>?,
        errors: MutableList<String>,
    ): List<TransportConfig> {
        val out = mutableListOf(TransportConfig(Routes.DIRECT, TransportType.DIRECT))
        declared.groupBy { it.id }.filterValues { it.size > 1 }.keys.forEach { errors += "Duplicate transport id '$it'" }
        for (t in declared) {
            when {
                t.id == Routes.DIRECT || t.id == Routes.BLOCK -> errors += "Transport id '${t.id}' is reserved"
                !TRANSPORT_ID.matches(t.id) -> errors += "Transport id '${t.id}' must be lower-case letters, digits, '.', '_', ':' or '-'"
                t.type !in supported -> errors += "Transport '${t.id}' has type ${t.type.wire}, which this build cannot run yet"
                available != null && t.type != TransportType.DIRECT && t.id !in available ->
                    errors += "Transport '${t.id}' is not configured (available: ${available.sorted().joinToString().ifEmpty { "none" }})"
                else -> out += t
            }
        }
        return out
    }

    internal fun parsePortRange(text: String): IntRange? {
        val parts = text.trim().split('-')
        val start = parts[0].trim().toIntOrNull() ?: return null
        val end = if (parts.size == 2) parts[1].trim().toIntOrNull() ?: return null else if (parts.size == 1) start else return null
        if (start !in 1..65535 || end !in start..65535) return null
        return start..end
    }
}
