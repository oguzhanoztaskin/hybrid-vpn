package com.oguzhanstech.hybridvpn.engine.policy

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Maps package names to Android UIDs. Traffic is attributed per UID by the platform
 * (`ConnectivityManager.getConnectionOwnerUid`), so per-app rules are enforced per UID.
 */
interface AppResolver {
    /** The UID of an installed package, or null if it is not installed or not visible. */
    fun uidOf(packageName: String): Int?

    /** All packages sharing [uid] (more than one for shared-UID apps). */
    fun packagesFor(uid: Int): List<String>
}

/** The per-flow rule table for the Go engine, for one context (profile and network). */
class FlowPolicy(
    val json: String,
    /** Rules that act on IP flows (exported to the engine). */
    val packetRules: Int,
    val warnings: List<String>,
)

/**
 * Turns a [CompiledPolicy] into the Go engine's wire format (go/engine/policy.go).
 *
 * - Profile and network conditions are evaluated now; re-export when either changes.
 * - Rules matching domains apply in the DNS stage only and are not exported.
 * - Package names become UIDs. Unresolvable packages and shared UIDs produce warnings rather than
 *   silent behaviour: a rule naming only uninstalled apps matches nothing, and a rule naming one
 *   app of a shared UID applies to every package with that UID.
 */
object FlowPolicyExporter {

    fun export(
        policy: CompiledPolicy,
        profile: String?,
        network: NetworkKind?,
        networkId: String?,
        apps: AppResolver,
    ): FlowPolicy {
        val warnings = ArrayList<String>()
        var exported = 0
        val json: JsonObject = buildJsonObject {
            put("version", 1)
            putJsonArray("transports") {
                for (t in policy.transports) {
                    add(buildJsonObject { put("id", t.id); put("type", t.type.wire) })
                }
            }
            putJsonObject("default") {
                put("transport", policy.defaultRoute)
                put("on_failure", policy.defaultOnFailure)
            }
            putJsonArray("rules") {
                for (rule in policy.rules) {
                    if (rule.profiles.isNotEmpty() && profile !in rule.profiles) continue
                    if (rule.networks.isNotEmpty() && network !in rule.networks) continue
                    if (rule.networkIds.isNotEmpty() && networkId !in rule.networkIds) continue
                    if (rule.domains.isNotEmpty() || rule.domainLists.isNotEmpty()) continue
                    exported++
                    add(exportRule(rule, policy.defaultOnFailure, apps, warnings))
                }
            }
        }
        return FlowPolicy(json.toString(), exported, warnings)
    }

    private fun exportRule(rule: CompiledRule, defaultOnFailure: String, apps: AppResolver, warnings: MutableList<String>): JsonObject {
        val where = "Rule '${rule.id}'"
        val uids = sortedSetOf<Int>()
        var unknown = false
        for (pkg in rule.apps) {
            if (pkg == RuleMatch.UNKNOWN_APP) {
                unknown = true
                continue
            }
            val uid = apps.uidOf(pkg)
            if (uid == null) {
                warnings += "$where: app '$pkg' is not installed; it is ignored"
                continue
            }
            uids += uid
            val sharing = apps.packagesFor(uid).filter { it != pkg }
            if (sharing.isNotEmpty()) {
                warnings += "$where: '$pkg' shares UID $uid with ${sharing.joinToString()}; Android attributes traffic per UID, so the rule applies to all of them"
            }
        }
        if (rule.apps.isNotEmpty() && uids.isEmpty() && !unknown) {
            warnings += "$where: none of its apps is installed, so it matches nothing"
        }
        return buildJsonObject {
            put("id", rule.id)
            put("any_app", rule.apps.isEmpty())
            putJsonArray("uids") { uids.forEach { add(it) } }
            put("unknown_app", unknown)
            putJsonArray("cidrs") { rule.cidrs.forEach { add(it.toString()) } }
            rule.protocol?.let { put("protocol", it.name.lowercase()) }
            putJsonArray("ports") {
                rule.ports.forEach { r -> addJsonArray { add(r.first); add(r.last) } }
            }
            when (rule.action.type) {
                ActionType.BLOCK -> put("action", "block")
                ActionType.ROUTE -> {
                    put("action", "route")
                    put("transport", rule.action.route)
                    put("on_failure", rule.action.onFailure ?: defaultOnFailure)
                }
            }
        }
    }
}
