package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.engine.policy.NetworkKind
import com.oguzhanstech.hybridvpn.engine.policy.PolicyCompiler
import com.oguzhanstech.hybridvpn.engine.policy.PolicyConfig
import com.oguzhanstech.hybridvpn.engine.policy.RoutePath
import com.oguzhanstech.hybridvpn.engine.policy.RoutingTable
import com.oguzhanstech.hybridvpn.engine.policy.TransportType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingTableTest {

    private val saved = PolicyConfig.fromJson(
        """
        {
          "transports": [
            {"id": "openvpn:office", "type": "openvpn"},
            {"id": "tailnet:home", "type": "tailnet"}
          ],
          "rules": [
            {"id": "filter-lists", "priority": 1000, "match": {"domain_lists": ["@all"]}, "action": {"type": "block"}},
            {"id": "office", "priority": 100, "description": "Office networks",
             "match": {"destination_cidrs": ["10.8.0.0/24", "35.76.37.226/32"]},
             "action": {"type": "route", "route": "openvpn:office", "on_failure": "block"}},
            {"id": "home", "priority": 100, "match": {"destination_cidrs": ["100.64.0.0/10"]},
             "action": {"type": "route", "route": "tailnet:home"}},
            {"id": "no-smtp", "priority": 10, "match": {"protocol": "tcp", "ports": ["25", "465-587"]}, "action": {"type": "block"}},
            {"id": "cell-only", "priority": 20, "match": {"networks": ["cellular"], "apps": ["com.example.app"]}, "action": {"type": "block"}}
          ]
        }
        """
    )

    private fun table(running: PolicyConfig, switchedOff: List<Pair<com.oguzhanstech.hybridvpn.engine.policy.PolicyRule, String>> = emptyList()): List<RoutePath> {
        val policy = (PolicyCompiler.compile(running, emptySet(), TransportType.entries.toSet()) as CompileResult.Ok).policy
        return RoutingTable.build(policy, profile = "default", network = NetworkKind.WIFI, networkId = null, switchedOff = switchedOff)
    }

    @Test fun builtinsThenRulesInEvaluationOrderThenDefault() {
        val rows = table(saved)
        assertEquals(RoutingTable.BUILTIN, rows.take(RoutingTable.BUILTIN.size))
        val rest = rows.drop(RoutingTable.BUILTIN.size)
        assertEquals(listOf("no-smtp", "cell-only", "home", "office", "filter-lists", "default"), rest.map { it.id })
        assertEquals(RoutePath.Kind.DEFAULT, rest.last().kind)
        assertEquals("direct", rest.last().target)
        assertEquals("block", rest.last().onFailure)
    }

    @Test fun describesEachRule() {
        val rows = table(saved).associateBy { it.id }
        val office = rows.getValue("office")
        assertEquals(RoutePath.Kind.FLOW, office.kind)
        assertEquals("Office networks", office.description)
        assertEquals(listOf("to 10.8.0.0/24, 35.76.37.226/32"), office.conditions)
        assertEquals("openvpn:office", office.target)
        assertEquals("block", office.onFailure)
        assertNull(office.inactive)

        val smtp = rows.getValue("no-smtp")
        assertEquals(listOf("TCP port 25, 465-587"), smtp.conditions)
        assertEquals("block", smtp.target)
        assertNull(smtp.onFailure)

        assertEquals(RoutePath.Kind.DNS, rows.getValue("filter-lists").kind)
        assertEquals("block", rows.getValue("home").onFailure) // the default's on_failure
    }

    @Test fun rulesForAnotherNetworkAreInactive() {
        val row = table(saved).single { it.id == "cell-only" }
        assertEquals("only on cellular", row.inactive)
        assertEquals(listOf("apps com.example.app"), row.conditions)
    }

    @Test fun rulesOfASwitchedOffConnectionAreListedAsSkipped() {
        val running = saved.withoutTransports(setOf("openvpn:office"))
        val skipped = saved.rules.filter { r -> r.enabled && running.rules.single { it.id == r.id }.enabled.not() }
            .map { it to "openvpn:office" }
        val rows = table(running, skipped)
        val office = rows.single { it.id == "office" }
        assertTrue(office.inactive!!.startsWith("openvpn:office is off"))
        assertEquals(listOf("no-smtp", "cell-only", "home", "office", "filter-lists", "default"), rows.drop(RoutingTable.BUILTIN.size).map { it.id })
    }
}
