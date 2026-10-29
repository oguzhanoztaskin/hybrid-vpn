package com.oguzhanstech.hybridvpn.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.oguzhanstech.hybridvpn.BuildConfig
import com.oguzhanstech.hybridvpn.appContainer
import com.oguzhanstech.hybridvpn.data.EngineMode
import com.oguzhanstech.hybridvpn.data.LogMode
import com.oguzhanstech.hybridvpn.data.Settings
import com.oguzhanstech.hybridvpn.gobridge.GoBridge
import com.oguzhanstech.hybridvpn.vpn.TunConfig
import com.oguzhanstech.hybridvpn.vpn.VpnController
import kotlinx.coroutines.launch

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
    onDns: () -> Unit,
    onEditPolicy: () -> Unit,
    onTailnets: () -> Unit,
    onOpenVpn: () -> Unit,
    onProxies: () -> Unit,
    onLicenses: () -> Unit,
) {
    val context = LocalContext.current
    val container = context.appContainer
    val scope = rememberCoroutineScope()
    val settings by container.settings.settings.collectAsStateWithLifecycle()

    fun apply(transform: (Settings) -> Settings) {
        container.settings.update(transform)
        VpnController.reload(context)
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionCard("Modules") {
            Text("Switch modules and connections on or off on the Status page.", style = MaterialTheme.typography.bodySmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onDns) { Text("DNS lists & resolver") }
                OutlinedButton(onClick = onTailnets, enabled = GoBridge.available) { Text("Tailnets") }
                OutlinedButton(onClick = onOpenVpn, enabled = GoBridge.available) { Text("OpenVPN") }
                OutlinedButton(onClick = onProxies, enabled = GoBridge.available) { Text("HTTP / SOCKS5 proxies") }
            }
        }

        SectionCard("Engine") {
            Choice("Full tunnel (default)", settings.engineMode == EngineMode.FULL_TUNNEL) {
                container.settings.update { it.copy(engineMode = EngineMode.FULL_TUNNEL) }
            }
            Choice("DNS only (fallback)", settings.engineMode == EngineMode.DNS_ONLY) {
                container.settings.update { it.copy(engineMode = EngineMode.DNS_ONLY) }
            }
            Text(
                "Full tunnel: all traffic enters the Go engine, which applies routing rules and runs Tailscale, " +
                    "OpenVPN and proxies; DNS on port 53 to any server is filtered; ping is optional below; other IP protocols are dropped. " +
                    "DNS only: just the DNS firewall, everything else bypasses the VPN. It is used automatically when the " +
                    "build has no Go engine (${GoBridge.loadError?.let { "not in this build: $it" } ?: "this build has it"}). " +
                    "Takes effect at the next start.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        SectionCard("Network compatibility") {
            Text("Full tunnel only; changes apply after restarting the VPN.", style = MaterialTheme.typography.bodySmall)
            PerformanceSwitch(
                "IPv4 ping (ICMP)",
                "Allow IPv4 reachability checks through direct, Tailscale or OpenVPN routes. Off by default.",
                settings.allowIcmp,
            ) { on -> container.settings.update { it.copy(allowIcmp = on) } }
            PerformanceSwitch(
                "IPv6 ping (ICMPv6)",
                "Allow IPv6 reachability checks through direct, Tailscale or OpenVPN routes. Off by default.",
                settings.allowIcmpv6,
            ) { on -> container.settings.update { it.copy(allowIcmpv6 = on) } }
            PerformanceSwitch(
                "LAN discovery & connections",
                "Use Wi-Fi/Ethernet directly for local connections, UDP discovery, broadcast and multicast. " +
                    "Helps apps such as KDE Connect receive connections from nearby devices. Off by default.",
                settings.lanBypass,
            ) { on -> container.settings.update { it.copy(lanBypass = on) } }
            Text(
                "When enabled, all traffic to connected LAN subnets, link-local addresses and multicast/broadcast " +
                    "destinations bypasses VPN routing and filtering rules, including DNS sent directly to LAN devices. " +
                    "The VPN's default DNS resolver stays filtered. Android's Block connections without VPN can prevent this bypass.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "Echo requests only: replies require a real response from the destination. HTTP and SOCKS5 proxies cannot carry ping. " +
                    "App identity is unknown for ICMP; use address or protocol rules. " +
                    "Ping does not enable traceroute or incoming connections from Tailscale.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        SectionCard("Performance") {
            Text(
                "Full tunnel only; changes apply at the next start (Status offers a restart).",
                style = MaterialTheme.typography.bodySmall,
            )
            PerformanceSwitch(
                "Large tunnel packets",
                "MTU ${TunConfig.FULL_TUNNEL_MTU} between apps and the engine instead of ${TunConfig.MTU}: about 3× less CPU " +
                    "per transferred byte, so faster downloads and less battery under load. The real network is unaffected. " +
                    "Turn off if an app misbehaves with it.",
                settings.largeTunnelPackets,
            ) { on -> container.settings.update { it.copy(largeTunnelPackets = on) } }
            PerformanceSwitch(
                "TCP loss detection (RACK)",
                "Detects lost packets between apps and the engine faster. That link rarely loses packets, so turning " +
                    "it off saves some CPU in large transfers; recovery then relies on classic duplicate ACKs and timeouts.",
                settings.tcpLossDetection,
            ) { on -> container.settings.update { it.copy(tcpLossDetection = on) } }
            PerformanceSwitch(
                "OpenVPN packet forwarding",
                "TCP connections routed to OpenVPN are passed to it as packets (addresses rewritten) instead of being " +
                    "re-sent by a second TCP stack inside the app. Less CPU and faster; routing and fallbacks are unchanged. " +
                    "UDP still takes the second stack.",
                settings.openvpnPacketForwarding,
            ) { on -> container.settings.update { it.copy(openvpnPacketForwarding = on) } }
        }

        SectionCard("Privacy") {
            Choice("Don't log queries (counters only)", settings.logMode == LogMode.OFF) { apply { it.copy(logMode = LogMode.OFF) } }
            Choice("Keep recent queries in memory only", settings.logMode == LogMode.MEMORY) { apply { it.copy(logMode = LogMode.MEMORY) } }
            Choice("Save query history on this device", settings.logMode == LogMode.PERSISTENT) { apply { it.copy(logMode = LogMode.PERSISTENT) } }
            if (settings.logMode == LogMode.PERSISTENT) {
                var days by remember(settings.retentionDays) { mutableStateOf(settings.retentionDays.toString()) }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(days, { days = it.filter(Char::isDigit).take(3) }, Modifier.weight(1f), singleLine = true, label = { Text("Keep history for (days)") })
                    OutlinedButton(onClick = { days.toIntOrNull()?.coerceIn(1, 365)?.let { d -> apply { it.copy(retentionDays = d) } } }) { Text("Save") }
                }
            }
            OutlinedButton(onClick = { scope.launch { container.dnsLog.clear() } }) { Text("Delete query history") }
            Text("Nothing leaves the device: no account, no analytics, no crash reporting.", style = MaterialTheme.typography.bodySmall)
        }

        SectionCard("Profile") {
            Text("Policy rules can be limited to a profile. Switching applies atomically.", style = MaterialTheme.typography.bodySmall)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PROFILES.forEach { p -> FilterChip(selected = settings.profile == p, onClick = { apply { it.copy(profile = p) } }, label = { Text(p) }) }
            }
        }

        SectionCard("Devices") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Notify about new devices after a scan", Modifier.weight(1f))
                Switch(settings.notifyNewDevices, { on -> container.settings.update { it.copy(notifyNewDevices = on) } })
            }
        }

        SectionCard("Advanced") {
            OutlinedButton(onClick = onEditPolicy) { Text("Edit policy (JSON)") }
        }

        SectionCard("About") {
            InfoRow("Version", "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            InfoRow("Go engine", remember { GoBridge.describe() })
            Text(
                "Free software under the GNU GPL v3 or later, with no warranty. No ads, no account, no analytics.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(onClick = onLicenses) { Text("Open-source licences") }
        }
    }
}

@Composable
private fun PerformanceSwitch(title: String, detail: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked, onChange)
    }
}

private val PROFILES = listOf("default", "home", "public-wifi", "work")
