package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.policy.*
import org.junit.Assert.*
import org.junit.Test

class RetiredTransportTest {
    private val gone = "openvpn:removed"
    private fun route(id: String, target: String, enabled: Boolean = true) = PolicyRule(
        id, 100, enabled, match = RuleMatch(destinationCidrs = listOf("10.9.0.0/24")),
        action = RuleAction(ActionType.ROUTE, target, Routes.BLOCK),
    )

    @Test fun deletionBlocksOnlyAffectedRulesAndKeepsTheirMatches() {
        val vpn = route("vpn", gone)
        val direct = route("lan", Routes.DIRECT)
        val p = PolicyConfig(transports = listOf(TransportConfig(gone, TransportType.OPENVPN)), rules = listOf(vpn, direct))
        val fixed = p.retireTransports(setOf(gone))
        assertTrue(fixed.transports.isEmpty())
        assertEquals(vpn.match, fixed.rules[0].match)
        assertEquals(vpn.priority, fixed.rules[0].priority)
        assertEquals(RuleAction(ActionType.BLOCK), fixed.rules[0].action)
        assertEquals(direct, fixed.rules[1])
        assertTrue(PolicyCompiler.compile(fixed, emptySet()) is CompileResult.Ok)
        assertEquals(fixed, fixed.retireTransports(emptySet()))
    }

    @Test fun disabledRulesStayDisabledAndRemovedFallbacksBlock() {
        val disabled = route("off", gone, false)
        val fallback = route("fallback", Routes.DIRECT).copy(action = RuleAction(ActionType.ROUTE, Routes.DIRECT, gone))
        val p = PolicyConfig(rules = listOf(disabled, fallback), default = DefaultPolicy(onFailure = gone))
        val fixed = p.retireTransports(setOf(gone))
        assertFalse(fixed.rules[0].enabled)
        assertEquals(Routes.BLOCK, fixed.rules[1].action.onFailure)
        assertEquals(Routes.BLOCK, fixed.default.onFailure)
    }

    @Test fun deletedDefaultBlocksAfterEveryExplicitRule() {
        val explicit = route("zzzz", Routes.DIRECT).copy(priority = Int.MAX_VALUE)
        val p = PolicyConfig(transports = listOf(TransportConfig(gone, TransportType.OPENVPN)),
            default = DefaultPolicy(gone), rules = listOf(explicit))
        val fixed = p.retireTransports(setOf(gone))
        assertEquals(Routes.DIRECT, fixed.default.route)
        val compiled = PolicyCompiler.compile(fixed, emptySet()) as CompileResult.Ok
        assertEquals(listOf(explicit.id, fixed.rules.last().id), compiled.policy.rules.map { it.id })
        assertEquals(ActionType.BLOCK, fixed.rules.last().action.type)
        assertEquals(listOf("0.0.0.0/0", "::/0"), fixed.rules.last().match.destinationCidrs)
    }

    @Test fun temporarilySwitchingOffStillSkipsRatherThanDeletes() {
        val p = PolicyConfig(rules = listOf(route("vpn", gone)))
        assertFalse(p.withoutTransports(setOf(gone)).rules.single().enabled)
        assertEquals(ActionType.ROUTE, p.rules.single().action.type)
    }
}
