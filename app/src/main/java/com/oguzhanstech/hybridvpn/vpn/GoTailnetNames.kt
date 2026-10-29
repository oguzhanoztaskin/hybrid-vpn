package com.oguzhanstech.hybridvpn.vpn

import com.oguzhanstech.hybridvpn.engine.dns.LocalAnswer
import com.oguzhanstech.hybridvpn.engine.dns.LocalNames
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import com.oguzhanstech.hybridvpn.gobridge.GoBridge

/**
 * MagicDNS names answered by the running tailnets (Go engine). A name is answered only by the one
 * tailnet owning its suffix; unknown names under that suffix are NXDOMAIN; a suffix claimed by
 * several tailnets is refused. Nothing here ever goes to a public resolver.
 */
object GoTailnetNames : LocalNames {
    override fun resolve(name: String): LocalAnswer {
        val r = GoBridge.resolveTailnet(name) ?: return LocalAnswer.NotLocal
        val source = "tailnet:" + r.optString("tailnet")
        return when (r.optString("status")) {
            "ok" -> {
                val addrs = r.optJSONArray("addrs") ?: return LocalAnswer.NoSuchName(source)
                LocalAnswer.Found(source, (0 until addrs.length()).mapNotNull { IpLiteral.parse(addrs.getString(it)) })
            }
            "nxdomain" -> LocalAnswer.NoSuchName(source)
            "ambiguous" -> {
                val c = r.optJSONArray("claimants")
                LocalAnswer.Ambiguous((0 until (c?.length() ?: 0)).map { "tailnet:" + c!!.getString(it) })
            }
            else -> LocalAnswer.NotLocal
        }
    }
}
