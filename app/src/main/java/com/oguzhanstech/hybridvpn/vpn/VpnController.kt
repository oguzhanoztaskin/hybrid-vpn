package com.oguzhanstech.hybridvpn.vpn

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.engine.dns.BlockResponse
import com.oguzhanstech.hybridvpn.engine.policy.RoutePath
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** What the user must always be able to see while the VPN runs (spec §14, last paragraph). */
data class VpnInfo(
    val since: Long,
    val transport: String,
    val resolver: String,
    val underlying: String?,
    val ruleCount: Int,
    val listCount: Int,
    val blockResponse: BlockResponse,
    val failurePolicy: String,
    val profile: String,
    val warnings: List<String>,
    /** True when the Go full-tunnel engine carries traffic; false in the DNS-only fallback. */
    val goEngine: Boolean = false,
    /** Exported per-flow routing rules (apps/CIDRs/ports) for the current context. */
    val packetRules: Int = 0,
    /** Filter lists and my rules apply (the DNS module is on). */
    val dnsFiltering: Boolean = true,
    /** Ids of tailnets/OpenVPN profiles and full transport ids of HTTP/SOCKS5 proxies the engine started with. */
    val tailnets: List<String> = emptyList(),
    val openvpn: List<String> = emptyList(),
    val proxies: List<String> = emptyList(),
    /** The TUN's MTU and whether RACK loss detection runs (Settings → Performance), as started. */
    val tunnelMtu: Int = 1500,
    val tcpLossDetection: Boolean = true,
    val openvpnPacketForwarding: Boolean = true,
    val allowIcmp: Boolean = false,
    val allowIcmpv6: Boolean = false,
    val lanBypass: Boolean = false,
    val lanBypassPrefixes: List<String> = emptyList(),
    /** The effective routing (built-in guards, rules in order, default); empty unless the Go engine runs a valid policy. */
    val routing: List<RoutePath> = emptyList(),
)

sealed interface VpnState {
    data class Stopped(val reason: String?) : VpnState
    object Starting : VpnState
    data class Running(val info: VpnInfo) : VpnState
    data class Failed(val message: String) : VpnState
}

object VpnController {
    private val mutableState = MutableStateFlow<VpnState>(VpnState.Stopped(null))
    val state: StateFlow<VpnState> = mutableState.asStateFlow()

    internal fun publish(state: VpnState) {
        mutableState.value = state
    }

    /** Caller must have obtained consent via VpnService.prepare() first. */
    fun start(context: Context) =
        ContextCompat.startForegroundService(context, Intent(context, HybridVpnService::class.java).setAction(HybridVpnService.ACTION_START))

    fun stop(context: Context) {
        if (state.value is VpnState.Stopped) return
        context.startService(Intent(context, HybridVpnService::class.java).setAction(HybridVpnService.ACTION_STOP))
    }

    /**
     * Stops and starts again, for changes the engine reads only at start: the engine itself,
     * tailnets, OpenVPN profiles and proxies. Connections are dropped for a moment.
     */
    fun restart(context: Context) {
        if (state.value !is VpnState.Running) return
        val app = context.applicationContext
        stop(app)
        app.appContainer.scope.launch {
            withTimeoutOrNull(10_000) { state.first { it is VpnState.Stopped } } ?: return@launch
            start(app)
        }
    }

    /** Applies changed settings, lists or policy to a running tunnel without dropping it. */
    fun reload(context: Context) {
        if (state.value !is VpnState.Running) return
        context.startService(Intent(context, HybridVpnService::class.java).setAction(HybridVpnService.ACTION_RELOAD))
    }
}
