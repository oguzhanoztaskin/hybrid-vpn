package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.dns.DomainList
import com.oguzhanstech.hybridvpn.engine.dns.DomainListIndex
import com.oguzhanstech.hybridvpn.engine.dns.FilterListParser
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.engine.policy.CompiledPolicy
import com.oguzhanstech.hybridvpn.engine.policy.Decision
import com.oguzhanstech.hybridvpn.engine.policy.FlowContext
import com.oguzhanstech.hybridvpn.engine.policy.PolicyCompiler
import com.oguzhanstech.hybridvpn.engine.policy.PolicyConfig
import com.oguzhanstech.hybridvpn.engine.policy.PolicyEngine
import com.oguzhanstech.hybridvpn.engine.policy.Protocol
import com.oguzhanstech.hybridvpn.engine.policy.TransportConfig
import com.oguzhanstech.hybridvpn.engine.policy.TransportHealth
import com.oguzhanstech.hybridvpn.engine.policy.TransportType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyTest {

    /** The example from the specification, §4.2, expressed as JSON. */
    private val specExample = """
        {
          "version": 1,
          "default": { "route": "direct", "on_failure": "block" },
          "rules": [
            { "id": "block-trackers", "priority": 100, "match": { "domain_lists": ["trackers"] }, "action": { "type": "block" } },
            { "id": "tailnet", "priority": 200, "match": { "destination_cidrs": ["100.64.0.0/10"] }, "action": { "type": "route", "route": "tailscale" } },
            { "id": "work-vpn", "priority": 300, "match": { "destination_cidrs": ["10.20.0.0/16"] }, "action": { "type": "route", "route": "openvpn" } },
            { "id": "browser-proxy", "priority": 400, "match": { "apps": ["com.example.browser"], "protocol": "tcp" },
              "action": { "type": "route", "route": "socks5-primary", "on_failure": "block" } }
          ]
        }
    """.trimIndent()

    private val lists = DomainListIndex(listOf(DomainList.from("trackers", FilterListParser.parse("||tracker.example^"))))
    private val specTransports = listOf(
        TransportConfig("tailscale", TransportType.TAILNET),
        TransportConfig("openvpn", TransportType.OPENVPN),
        TransportConfig("socks5-primary", TransportType.SOCKS5),
    )
    private val allTypes = TransportType.entries.toSet()

    /** Compiles with the spec example's transports declared and every transport type supported. */
    private fun compile(json: String): CompiledPolicy {
        val config = PolicyConfig.fromJson(json).let { if (it.transports.isEmpty()) it.copy(transports = specTransports) else it }
        return (PolicyCompiler.compile(config, lists.ids, allTypes) as CompileResult.Ok).policy
    }

    private fun flow(
        packages: List<String>? = listOf("com.other"),
        ip: String? = null,
        domain: String? = null,
        protocol: Protocol? = Protocol.TCP,
        port: Int? = 443,
    ) = FlowContext(packages, ip?.let { IpLiteral.parse(it) }, domain, protocol, port)

    @Test fun specExampleRoutesFlows() {
        val engine = PolicyEngine(compile(specExample), lists)
        assertEquals("block-trackers", (engine.evaluate(flow(domain = "a.tracker.example")) as Decision.Block).ruleId)
        assertEquals(Decision.Route("tailnet", "tailscale"), engine.evaluate(flow(ip = "100.100.1.1")))
        assertEquals(Decision.Route("work-vpn", "openvpn"), engine.evaluate(flow(ip = "10.20.5.5")))
        assertEquals(Decision.Route("browser-proxy", "socks5-primary"), engine.evaluate(flow(packages = listOf("com.example.browser"), ip = "93.184.216.34")))
        assertEquals(Decision.Route(null, "direct"), engine.evaluate(flow(packages = listOf("com.example.browser"), ip = "93.184.216.34", protocol = Protocol.UDP)))
        assertEquals(Decision.Route(null, "direct"), engine.evaluate(flow(ip = "8.8.8.8")))
    }

    @Test fun unknownOwnerNeverMatchesAppRulesImplicitly() {
        val engine = PolicyEngine(compile(specExample), lists)
        assertEquals(Decision.Route(null, "direct"), engine.evaluate(flow(packages = null, ip = "93.184.216.34")))
        val explicit = compile("""{"rules":[{"id":"u","priority":1,"match":{"apps":["@unknown"]},"action":{"type":"block"}}]}""")
        assertTrue(PolicyEngine(explicit, lists).evaluate(flow(packages = null)) is Decision.Block)
    }

    @Test fun failurePolicies() {
        val down = TransportHealth { false }
        val engine = PolicyEngine(compile(specExample), lists)
        // Rule says block when its transport is down.
        assertTrue(engine.evaluate(flow(packages = listOf("com.example.browser"), ip = "1.1.1.1"), down) is Decision.Block)
        // No rule-level on_failure: falls back to the default on_failure, which is block.
        assertTrue(engine.evaluate(flow(ip = "100.100.1.1"), down) is Decision.Block)
        val fallback = compile("""{"rules":[{"id":"t","priority":1,"match":{},"action":{"type":"route","route":"tailscale","on_failure":"direct"}}]}""")
        assertEquals(Decision.Route("t", "direct", fellBack = true), PolicyEngine(fallback, lists).evaluate(flow(), down))
    }

    @Test fun rulesAreOrderedByPriorityThenId() {
        val p = compile(
            """{"rules":[
              {"id":"b","priority":10,"action":{"type":"route","route":"openvpn"}},
              {"id":"a","priority":10,"action":{"type":"block"}},
              {"id":"z","priority":1,"enabled":false,"action":{"type":"route","route":"tailscale"}}
            ]}"""
        )
        assertEquals(listOf("a", "b"), p.rules.map { it.id })
    }

    @Test fun portsDomainsAndProfiles() {
        val p = compile(
            """{"rules":[
              {"id":"ports","priority":1,"match":{"protocol":"udp","ports":["443","8000-8100"]},"action":{"type":"block"}},
              {"id":"dom","priority":2,"match":{"domains":["corp.example"],"profiles":["work"]},"action":{"type":"block"}}
            ]}"""
        )
        val engine = PolicyEngine(p, lists)
        assertTrue(engine.evaluate(flow(protocol = Protocol.UDP, port = 8050)) is Decision.Block)
        assertTrue(engine.evaluate(flow(protocol = Protocol.UDP, port = 8101)) is Decision.Route)
        assertEquals("direct", (engine.evaluate(flow(domain = "git.corp.example")) as Decision.Route).route)
        val work = FlowContext(listOf("x"), domain = "git.corp.example", profile = "work")
        assertTrue(engine.evaluate(work) is Decision.Block)
        assertEquals("direct", (engine.evaluate(FlowContext(listOf("x"), domain = "notcorp.example", profile = "work")) as Decision.Route).route)
    }

    @Test fun invalidPoliciesAreRejectedWhole() {
        val result = PolicyCompiler.compile(
            PolicyConfig.fromJson(
                """{"version":2,"rules":[
                  {"id":"dup","priority":1,"action":{"type":"block"}},
                  {"id":"dup","priority":2,"action":{"type":"block"}},
                  {"id":"r","priority":3,"match":{"destination_cidrs":["10.0.0.0/40"],"ports":["0"],"domain_lists":["nope"]},
                   "action":{"type":"route","route":"wireguard"}},
                  {"id":"b","priority":4,"action":{"type":"block","route":"direct"}}
                ]}"""
            ).copy(transports = specTransports),
            lists.ids, allTypes,
        )
        val errors = (result as CompileResult.Failed).errors
        // version, duplicate id, CIDR, port, unknown list, unknown route, domain-matching route, block with route
        assertEquals(errors.toString(), 8, errors.size)
    }

    @Test fun overlappingCidrRoutesWarn() {
        val p = compile(
            """{"rules":[
              {"id":"tailnet","priority":1,"match":{"destination_cidrs":["10.0.0.0/8"]},"action":{"type":"route","route":"tailscale"}},
              {"id":"work","priority":2,"match":{"destination_cidrs":["10.20.0.0/16"]},"action":{"type":"route","route":"openvpn"}}
            ]}"""
        )
        assertEquals(1, p.warnings.size)
        assertTrue(p.warnings[0].contains("'tailnet' wins"))
    }

    @Test fun jsonRoundTrip() {
        val config = PolicyConfig.fromJson(specExample)
        assertEquals(config, PolicyConfig.fromJson(config.toJson()))
    }

    @Test fun switchedOffTransportsAreSkippedNotUsedAsFallback() {
        val config = PolicyConfig.fromJson(
            """
            {
              "version": 1,
              "transports": [
                { "id": "tailnet:work", "type": "tailnet" },
                { "id": "openvpn:office", "type": "openvpn" }
              ],
              "default": { "route": "openvpn:office", "on_failure": "tailnet:work" },
              "rules": [
                { "id": "work", "priority": 10, "match": { "destination_cidrs": ["100.64.0.0/10"] },
                  "action": { "type": "route", "route": "tailnet:work" } },
                { "id": "office", "priority": 20, "match": { "destination_cidrs": ["10.20.0.0/16"] },
                  "action": { "type": "route", "route": "openvpn:office", "on_failure": "tailnet:work" } }
              ]
            }
            """.trimIndent()
        )
        val running = config.withoutTransports(setOf("tailnet:work"))
        assertEquals(listOf("openvpn:office"), running.transports.map { it.id })
        assertEquals(false, running.rules.first { it.id == "work" }.enabled)
        assertEquals("block", running.rules.first { it.id == "office" }.action.onFailure)
        assertEquals("openvpn:office", running.default.route)
        assertEquals("block", running.default.onFailure)

        val both = config.withoutTransports(setOf("tailnet:work", "openvpn:office"))
        assertEquals("direct", both.default.route)
        assertTrue(both.rules.none { it.enabled })
        // What remains compiles with none of the switched-off transports available.
        val compiled = PolicyCompiler.compile(both, emptySet(), TransportType.entries.toSet(), emptySet())
        assertTrue(compiled.toString(), compiled is CompileResult.Ok)
        assertEquals(config, config.withoutTransports(emptySet()))
    }
}
