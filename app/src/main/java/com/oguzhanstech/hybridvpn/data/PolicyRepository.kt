package com.oguzhanstech.hybridvpn.data

import android.content.Context
import com.oguzhanstech.hybridvpn.engine.dns.DomainListIndex
import com.oguzhanstech.hybridvpn.engine.policy.ActionType
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.engine.policy.PolicyCompiler
import com.oguzhanstech.hybridvpn.engine.policy.PolicyConfig
import com.oguzhanstech.hybridvpn.engine.policy.PolicyRule
import com.oguzhanstech.hybridvpn.engine.policy.RuleAction
import com.oguzhanstech.hybridvpn.engine.policy.RuleMatch
import com.oguzhanstech.hybridvpn.engine.policy.TransportConfig
import com.oguzhanstech.hybridvpn.engine.policy.Routes
import com.oguzhanstech.hybridvpn.engine.policy.TransportType
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import kotlinx.serialization.SerializationException
import java.io.File

/** The user's policy document (filesDir/policy.json). Only policies that compile are ever saved. */
class PolicyRepository(
    context: Context,
    private val tailnets: TailnetRepository,
    private val openvpn: OpenVpnRepository,
    private val proxies: ProxyRepository,
) {

    private val file = File(context.filesDir, "policy.json")

    fun text(): String = if (file.exists()) file.readText() else DEFAULT.toJson()

    fun load(): PolicyConfig = try {
        if (file.exists()) PolicyConfig.fromJson(file.readText()) else DEFAULT
    } catch (_: SerializationException) {
        DEFAULT
    } catch (_: IllegalArgumentException) {
        DEFAULT
    }

    /** Compiles against what this build can run and the tailnets, OpenVPN profiles and proxies that are configured. */
    fun compile(config: PolicyConfig, knownLists: Set<String>): CompileResult =
        PolicyCompiler.compile(config, knownLists, supportedTransports(), configured().map { it.first }.toSet())

    /** Configured non-direct transports with whether each is switched on. */
    private fun configured(): List<Pair<String, Boolean>> =
        tailnets.tailnets.value.map { it.transportId to it.enabled } +
            openvpn.profiles.value.map { it.transportId to it.enabled } +
            proxies.proxies.value.map { it.transportId to it.enabled }

    /**
     * The saved policy as it runs: tailnets, OpenVPN profiles and proxies that are switched off,
     * or (with [running], the transports a running engine was started with) not running, are left out.
     */
    fun loadForRun(running: Set<String>? = null): PolicyConfig {
        val available = configured()
        val ids = available.map { it.first }.toSet()
        val saved = load()
        // Repair references left by older versions after deleting a profile.
        val missing = saved.transports.filter { it.type != TransportType.DIRECT && it.id !in ids }
            .map { it.id }.toSet()
        val repaired = saved.retireTransports(missing)
        if (repaired != saved) file.writeText(repaired.toJson())
        return repaired.withoutTransports(available.filter { (id, on) -> !on || (running != null && id !in running) }.map { it.first }.toSet())
    }

    /** Called before deleting connection settings; matching routes remain as blocks. */
    fun retireTransport(id: String) {
        val saved = load()
        val repaired = saved.retireTransports(setOf(id))
        if (repaired != saved) file.writeText(repaired.toJson())
    }

    fun validate(text: String, knownLists: Set<String>): CompileResult = try {
        compile(PolicyConfig.fromJson(text), knownLists)
    } catch (e: SerializationException) {
        CompileResult.Failed(listOf("Invalid JSON: ${e.message}"))
    } catch (e: IllegalArgumentException) {
        CompileResult.Failed(listOf("Invalid policy: ${e.message}"))
    }

    /** Saves [text] only if it compiles; returns the compile result either way. */
    fun save(text: String, knownLists: Set<String>): CompileResult {
        val result = validate(text, knownLists)
        if (result is CompileResult.Ok) file.writeText(text)
        return result
    }

    /**
     * Adds (or replaces) a rule routing Tailscale's address ranges to [tailnet], declaring its
     * transport if needed. Saved only if the result compiles.
     */
    fun addTailnetRoute(tailnet: TailnetConfig, knownLists: Set<String>): CompileResult {
        val config = load()
        val ruleId = "tailnet-${tailnet.id}"
        val transports = if (config.transports.any { it.id == tailnet.transportId }) config.transports
        else config.transports + TransportConfig(tailnet.transportId, TransportType.TAILNET, tailnet.name.ifBlank { null })
        val rule = PolicyRule(
            id = ruleId,
            priority = 100,
            description = "Tailscale addresses via ${tailnet.name.ifBlank { tailnet.id }}",
            match = RuleMatch(destinationCidrs = listOf("100.64.0.0/10", "fd7a:115c:a1e0::/48")),
            action = RuleAction(ActionType.ROUTE, route = tailnet.transportId, onFailure = Routes.BLOCK),
        )
        val updated = config.copy(transports = transports, rules = config.rules.filterNot { it.id == ruleId } + rule)
        return save(updated.toJson(), knownLists)
    }

    /**
     * Adds (or replaces) a rule routing [cidrs] (the networks an OpenVPN server pushed) to
     * [profile], declaring its transport if needed. With [cidrs] covering everything, the rule
     * sends all traffic through the VPN. Saved only if the result compiles.
     */
    fun addOpenVpnRoute(profile: OpenVpnProfile, cidrs: List<String>, knownLists: Set<String>): CompileResult {
        val config = load()
        val ruleId = "openvpn-${profile.id}"
        val transports = if (config.transports.any { it.id == profile.transportId }) config.transports
        else config.transports + TransportConfig(profile.transportId, TransportType.OPENVPN, profile.name.ifBlank { null })
        val rule = PolicyRule(
            id = ruleId,
            priority = 100,
            description = "Networks of ${profile.name.ifBlank { profile.id }} via OpenVPN",
            match = RuleMatch(destinationCidrs = cidrs),
            action = RuleAction(ActionType.ROUTE, route = profile.transportId, onFailure = Routes.BLOCK),
        )
        val updated = config.copy(transports = transports, rules = config.rules.filterNot { it.id == ruleId } + rule)
        return save(updated.toJson(), knownLists)
    }

    /**
     * Adds (or replaces) the rule sending traffic to [proxy]: everything from [apps], or all traffic
     * when [apps] is empty. Declares its transport if needed. Saved only if the result compiles.
     */
    fun addProxyRoute(proxy: ProxyConfig, apps: List<String>, knownLists: Set<String>): CompileResult {
        val config = load()
        val ruleId = proxy.ruleId
        val transports = if (config.transports.any { it.id == proxy.transportId }) config.transports
        else config.transports + TransportConfig(proxy.transportId, proxy.kind.transportType, proxy.name.ifBlank { null })
        val rule = PolicyRule(
            id = ruleId,
            priority = 100,
            description = if (apps.isEmpty()) "All traffic via proxy ${proxy.name}" else "${apps.size} app(s) via proxy ${proxy.name}",
            match = if (apps.isEmpty()) RuleMatch(destinationCidrs = listOf("0.0.0.0/0", "::/0")) else RuleMatch(apps = apps),
            action = RuleAction(ActionType.ROUTE, route = proxy.transportId, onFailure = Routes.BLOCK),
        )
        val updated = config.copy(transports = transports, rules = config.rules.filterNot { it.id == ruleId } + rule)
        return save(updated.toJson(), knownLists)
    }

    /** Apps the proxy rule written by [addProxyRoute] currently sends to [proxy]; null if it routes all traffic or there is none. */
    fun proxyRouteApps(proxy: ProxyConfig): List<String>? =
        load().rules.firstOrNull { it.id == proxy.ruleId }?.match?.apps?.takeIf { it.isNotEmpty() }

    /** Whether any enabled rule (or the default) routes to [transportId]. */
    fun routesTo(transportId: String): Boolean {
        val c = load()
        return c.default.route == transportId || c.rules.any { it.enabled && it.action.route == transportId }
    }

    fun reset() {
        file.delete()
    }

    companion object {
        /**
         * Transport types this build can run: `direct` always; `tailnet` and `socks5` in builds that
         * bundle the Go engine, and `openvpn` when that engine links OpenVPN 3 Core (all carry traffic
         * only in the full-tunnel engine). Other types are rejected with a clear error rather than a rule that
         * silently never applies.
         */
        fun supportedTransports(): Set<TransportType> = when {
            !GoBridge.available -> setOf(TransportType.DIRECT)
            GoBridge.openvpnAvailable -> setOf(TransportType.DIRECT, TransportType.TAILNET, TransportType.HTTP, TransportType.SOCKS5, TransportType.OPENVPN)
            else -> setOf(TransportType.DIRECT, TransportType.TAILNET, TransportType.HTTP, TransportType.SOCKS5)
        }

        val DEFAULT = PolicyConfig(
            rules = listOf(
                PolicyRule(
                    id = "filter-lists",
                    priority = 1000,
                    description = "Block domains on any enabled filter list (exceptions with @@ always win)",
                    match = RuleMatch(domainLists = listOf(DomainListIndex.ANY_LIST)),
                    action = RuleAction(ActionType.BLOCK),
                ),
            ),
        )
    }
}
