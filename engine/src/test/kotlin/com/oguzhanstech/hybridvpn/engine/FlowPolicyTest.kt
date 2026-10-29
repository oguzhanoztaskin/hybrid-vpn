package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.policy.AppResolver
import com.oguzhanstech.hybridvpn.engine.policy.CompileResult
import com.oguzhanstech.hybridvpn.engine.policy.CompiledPolicy
import com.oguzhanstech.hybridvpn.engine.policy.FlowPolicyExporter
import com.oguzhanstech.hybridvpn.engine.policy.NetworkKind
import com.oguzhanstech.hybridvpn.engine.policy.PolicyCompiler
import com.oguzhanstech.hybridvpn.engine.policy.PolicyConfig
import com.oguzhanstech.hybridvpn.engine.policy.TransportType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowPolicyTest {

    private val resolver = object : AppResolver {
        val uids = mapOf("com.example.browser" to 10100, "com.example.mail" to 10200, "com.vendor.a" to 10300, "com.vendor.b" to 10300)
        override fun uidOf(packageName: String) = uids[packageName]
        override fun packagesFor(uid: Int) = uids.filterValues { it == uid }.keys.sorted()
    }

    private fun compile(json: String, supported: Set<TransportType> = setOf(TransportType.DIRECT)): CompileResult =
        PolicyCompiler.compile(PolicyConfig.fromJson(json), emptySet(), supported)

    private fun ok(json: String, supported: Set<TransportType> = TransportType.entries.toSet()): CompiledPolicy =
        (compile(json, supported) as CompileResult.Ok).policy

    private fun errors(json: String, supported: Set<TransportType> = setOf(TransportType.DIRECT)) =
        (compile(json, supported) as CompileResult.Failed).errors

    @Test fun transportsAreValidated() {
        assertTrue(errors("""{"transports":[{"id":"tailnet:work","type":"tailnet"}]}""").single().contains("cannot run yet"))
        assertTrue(errors("""{"transports":[{"id":"direct","type":"direct"}]}""").single().contains("reserved"))
        assertTrue(errors("""{"transports":[{"id":"Work VPN","type":"openvpn"}]}""", TransportType.entries.toSet()).single().contains("lower-case"))
        assertTrue(errors("""{"transports":[{"id":"p","type":"socks5"},{"id":"p","type":"http"}]}""", TransportType.entries.toSet()).single().contains("Duplicate transport"))
        assertTrue(errors("""{"rules":[{"id":"r","priority":1,"action":{"type":"route","route":"tailnet:work"}}]}""").single().contains("unknown route"))
        // Two tailnets are two transports: identity is the id, never the address range.
        ok("""{"transports":[{"id":"tailnet:work","type":"tailnet"},{"id":"tailnet:home","type":"tailnet"}],
              "rules":[{"id":"w","priority":1,"match":{"destination_cidrs":["100.64.0.0/10"],"apps":["com.example.mail"]},"action":{"type":"route","route":"tailnet:work"}},
                       {"id":"h","priority":2,"match":{"destination_cidrs":["100.64.0.0/10"]},"action":{"type":"route","route":"tailnet:home"}}]}""")
    }

    @Test fun routeRulesCannotMatchDomains() {
        val e = errors("""{"rules":[{"id":"r","priority":1,"match":{"domains":["corp.example"]},"action":{"type":"route","route":"direct"}}]}""")
        assertTrue(e.single(), e.single().contains("cannot match domains"))
    }

    private fun export(policy: CompiledPolicy, profile: String? = "home", network: NetworkKind? = NetworkKind.WIFI) =
        FlowPolicyExporter.export(policy, profile, network, null, resolver)

    private fun rules(json: String): List<JsonObject> = Json.parseToJsonElement(json).jsonObject["rules"]!!.jsonArray.map { it.jsonObject }

    @Test fun exportsUidsUnknownAndWarnings() {
        val policy = ok(
            """{"transports":[{"id":"proxy","type":"socks5"}],
                "rules":[
                  {"id":"browser","priority":1,"match":{"apps":["com.example.browser","com.example.gone"],"protocol":"tcp","ports":["443","8000-8100"],"destination_cidrs":["203.0.113.0/24","2001:db8::/32"]},
                   "action":{"type":"route","route":"proxy"}},
                  {"id":"shared","priority":2,"match":{"apps":["com.vendor.a"]},"action":{"type":"block"}},
                  {"id":"nobody","priority":3,"match":{"apps":["com.example.gone"]},"action":{"type":"block"}},
                  {"id":"unattributed","priority":4,"match":{"apps":["@unknown"]},"action":{"type":"block"}},
                  {"id":"trackers","priority":5,"match":{"domains":["tracker.example"]},"action":{"type":"block"}}
                ]}"""
        )
        val out = export(policy)
        val r = rules(out.json)
        assertEquals(listOf("browser", "shared", "nobody", "unattributed"), r.map { it["id"]!!.jsonPrimitive.content })
        assertEquals(4, out.packetRules)

        val browser = r[0]
        assertEquals(listOf(10100), browser["uids"]!!.jsonArray.map { it.jsonPrimitive.int })
        assertEquals(false, browser["any_app"]!!.jsonPrimitive.boolean)
        assertEquals("tcp", browser["protocol"]!!.jsonPrimitive.content)
        assertEquals(listOf(listOf(443, 443), listOf(8000, 8100)), browser["ports"]!!.jsonArray.map { p -> p.jsonArray.map { it.jsonPrimitive.int } })
        assertEquals(listOf("203.0.113.0/24", "2001:db8::/32"), browser["cidrs"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("proxy", browser["transport"]!!.jsonPrimitive.content)
        assertEquals("block", browser["on_failure"]!!.jsonPrimitive.content) // default on_failure, never implicit direct

        assertEquals(true, r[3]["unknown_app"]!!.jsonPrimitive.boolean)
        assertTrue(r[2]["uids"]!!.jsonArray.isEmpty() && !r[2]["unknown_app"]!!.jsonPrimitive.boolean)

        val w = out.warnings.joinToString("\n")
        assertTrue(w, w.contains("'com.example.gone' is not installed"))
        assertTrue(w, w.contains("shares UID 10300 with com.vendor.b"))
        assertTrue(w, w.contains("Rule 'nobody': none of its apps is installed"))
    }

    @Test fun contextConditionsAreEvaluatedAtExport() {
        val policy = ok(
            """{"rules":[
                  {"id":"work-only","priority":1,"match":{"profiles":["work"],"destination_cidrs":["10.0.0.0/8"]},"action":{"type":"block"}},
                  {"id":"cellular-only","priority":2,"match":{"networks":["cellular"],"ports":["5060"]},"action":{"type":"block"}}
                ]}"""
        )
        assertEquals(emptyList<String>(), rules(export(policy, "home", NetworkKind.WIFI).json).map { it["id"]!!.jsonPrimitive.content })
        assertEquals(listOf("work-only"), rules(export(policy, "work", NetworkKind.WIFI).json).map { it["id"]!!.jsonPrimitive.content })
        assertEquals(listOf("work-only", "cellular-only"), rules(export(policy, "work", NetworkKind.CELLULAR).json).map { it["id"]!!.jsonPrimitive.content })
    }

    @Test fun defaultsAndTransportsAreExported() {
        val json = Json.parseToJsonElement(export(ok("""{"default":{"route":"direct","on_failure":"block"}}""")).json).jsonObject
        assertEquals("direct", json["default"]!!.jsonObject["transport"]!!.jsonPrimitive.content)
        assertEquals("block", json["default"]!!.jsonObject["on_failure"]!!.jsonPrimitive.content)
        assertEquals("direct", json["transports"]!!.jsonArray.single().jsonObject["type"]!!.jsonPrimitive.content)
    }
}

class TransportAvailabilityTest {
    @org.junit.Test fun declaredTailnetsMustBeConfigured() {
        val json = """{"transports":[{"id":"tailnet:work","type":"tailnet"}]}"""
        val supported = setOf(TransportType.DIRECT, TransportType.TAILNET)
        val missing = PolicyCompiler.compile(PolicyConfig.fromJson(json), emptySet(), supported, availableTransports = setOf("tailnet:home"))
        org.junit.Assert.assertTrue((missing as CompileResult.Failed).errors.single().contains("not configured"))
        val present = PolicyCompiler.compile(PolicyConfig.fromJson(json), emptySet(), supported, availableTransports = setOf("tailnet:work"))
        org.junit.Assert.assertTrue(present is CompileResult.Ok)
    }
}
