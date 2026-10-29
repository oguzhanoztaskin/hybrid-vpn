package com.oguzhanstech.hybridvpn.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector

private enum class Tab(val label: String, val icon: ImageVector) {
    STATUS("Status", Icons.Filled.Lock),
    DEVICES("Devices", Icons.Filled.Home),
    LOGS("Logs", Icons.AutoMirrored.Filled.List),
    SETTINGS("Settings", Icons.Filled.Settings),
}

@Composable
fun AppRoot() {
    var tab by rememberSaveable { mutableStateOf(Tab.STATUS) }
    var openDevice by rememberSaveable { mutableStateOf<String?>(null) }
    var editingPolicy by rememberSaveable { mutableStateOf(false) }
    var showTailnets by rememberSaveable { mutableStateOf(false) }
    var showOpenVpn by rememberSaveable { mutableStateOf(false) }
    var showLicenses by rememberSaveable { mutableStateOf(false) }
    var showDns by rememberSaveable { mutableStateOf(false) }
    var showProxies by rememberSaveable { mutableStateOf(false) }
    var showRouting by rememberSaveable { mutableStateOf(false) }
    var devicesTab by rememberSaveable { mutableStateOf(0) }

    /** Devices → Tailnets: the machines of every running tailnet. */
    fun openTailnetDevices() {
        showTailnets = false
        tab = Tab.DEVICES
        devicesTab = 1
    }

    BackHandler(enabled = openDevice != null || editingPolicy || showTailnets || showOpenVpn || showLicenses || showDns || showProxies || showRouting) {
        openDevice = null
        editingPolicy = false
        showTailnets = false
        showOpenVpn = false
        showLicenses = false
        showDns = false
        showProxies = false
        showRouting = false
    }

    val device = openDevice
    when {
        device != null -> DeviceDetailScreen(device, onBack = { openDevice = null })
        editingPolicy -> PolicyEditorScreen(onBack = { editingPolicy = false })
        showTailnets -> TailnetsScreen(onBack = { showTailnets = false }, onDevices = ::openTailnetDevices)
        showOpenVpn -> OpenVpnScreen(onBack = { showOpenVpn = false })
        showLicenses -> LicensesScreen(onBack = { showLicenses = false })
        showDns -> DnsScreen(onBack = { showDns = false })
        showProxies -> ProxiesScreen(onBack = { showProxies = false })
        showRouting -> RoutingScreen(onBack = { showRouting = false })
        else -> Scaffold(
            bottomBar = {
                NavigationBar {
                    Tab.entries.forEach {
                        NavigationBarItem(
                            selected = tab == it,
                            onClick = { tab = it },
                            icon = { Icon(it.icon, contentDescription = null) },
                            label = { Text(it.label) },
                        )
                    }
                }
            },
        ) { padding ->
            Box(Modifier.padding(padding)) {
                when (tab) {
                    Tab.STATUS -> StatusScreen(
                        onDns = { showDns = true }, onTailnets = { showTailnets = true },
                        onOpenVpn = { showOpenVpn = true }, onProxies = { showProxies = true }, onLogs = { tab = Tab.LOGS },
                        onRouting = { showRouting = true }, onTailnetDevices = ::openTailnetDevices,
                    )
                    Tab.DEVICES -> DevicesHub(devicesTab, { devicesTab = it }, onOpen = { openDevice = it }, onOpenTailnets = { showTailnets = true })
                    Tab.LOGS -> LogsScreen()
                    Tab.SETTINGS -> SettingsScreen(
                        onDns = { showDns = true }, onEditPolicy = { editingPolicy = true }, onTailnets = { showTailnets = true },
                        onOpenVpn = { showOpenVpn = true }, onProxies = { showProxies = true }, onLicenses = { showLicenses = true },
                    )
                }
            }
        }
    }
}

/** LAN inventory and tailnet machines, side by side. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DevicesHub(tab: Int, onTab: (Int) -> Unit, onOpen: (String) -> Unit, onOpenTailnets: () -> Unit) {
    Column {
        PrimaryTabRow(selectedTabIndex = tab) {
            listOf("LAN", "Tailnets").forEachIndexed { i, title ->
                Tab(selected = tab == i, onClick = { onTab(i) }, text = { Text(title) })
            }
        }
        if (tab == 0) DevicesScreen(onOpen = onOpen) else TailnetDevicesScreen(onOpenTailnets = onOpenTailnets)
    }
}
