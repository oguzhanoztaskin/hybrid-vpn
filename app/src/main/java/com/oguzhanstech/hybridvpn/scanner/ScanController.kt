package com.oguzhanstech.hybridvpn.scanner

import android.content.Context
import android.net.wifi.WifiManager
import com.oguzhanstech.hybridvpn.Notifications
import com.oguzhanstech.hybridvpn.data.AppSettings
import com.oguzhanstech.hybridvpn.discovery.NetworkScanner
import com.oguzhanstech.hybridvpn.discovery.ScanProgress
import com.oguzhanstech.hybridvpn.discovery.ScanTarget
import com.oguzhanstech.hybridvpn.engine.net.Cidr
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface ScanState {
    data class Idle(val last: ScanSummary?) : ScanState
    data class Running(val phase: String, val done: Int, val total: Int) : ScanState
    data class Failed(val message: String) : ScanState
}

class ScanController(
    private val context: Context,
    private val repository: DeviceRepository,
    private val settings: AppSettings,
    private val scope: CoroutineScope,
) {
    private val state = MutableStateFlow<ScanState>(ScanState.Idle(null))
    val scanState: StateFlow<ScanState> = state.asStateFlow()
    private var job: Job? = null

    /** Starts a scan of the current LAN, or of [customRange] (a CIDR inside it) when given. */
    fun start(customRange: String? = null) {
        if (job?.isActive == true) return
        job = scope.launch {
            val lan = AndroidLan.current(context)
            if (lan == null) {
                state.value = ScanState.Failed("Not connected to Wi-Fi or Ethernet")
                return@launch
            }
            val subnet = if (customRange.isNullOrBlank()) lan.subnet else {
                val parsed = Cidr.parse(customRange.trim())
                if (parsed == null || !parsed.isIpv4) {
                    state.value = ScanState.Failed("'$customRange' is not an IPv4 range like 192.168.1.0/24")
                    return@launch
                }
                parsed
            }
            val wifi = context.applicationContext.getSystemService(WifiManager::class.java)
            val lock = wifi?.createMulticastLock("hybridvpn-scan")?.apply { setReferenceCounted(false) }
            try {
                state.value = ScanState.Running("Preparing", 0, 0)
                lock?.acquire()
                val network = repository.networkFor(lan)
                val scanner = NetworkScanner(AndroidLan.binding(lan))
                val report = scanner.scan(ScanTarget(subnet, lan.address, lan.gateway)) { p ->
                    state.value = when (p) {
                        is ScanProgress.Phase -> (state.value as? ScanState.Running)?.copy(phase = p.name) ?: ScanState.Running(p.name, 0, 0)
                        is ScanProgress.Sweep -> ScanState.Running("Probing hosts", p.done, p.total)
                    }
                }
                state.value = ScanState.Running("Saving", 0, 0)
                val summary = repository.applyScan(network, report)
                if (settings.settings.value.notifyNewDevices && !summary.firstScanOfNetwork && summary.newDevices.isNotEmpty()) {
                    Notifications.newDevices(context, summary)
                }
                state.value = ScanState.Idle(summary)
            } catch (e: CancellationException) {
                state.value = ScanState.Idle(null)
                throw e
            } catch (e: Exception) {
                state.value = ScanState.Failed(e.message ?: e.javaClass.simpleName)
            } finally {
                if (lock?.isHeld == true) lock.release()
            }
        }
    }

    fun cancel() {
        job?.cancel()
    }
}
