package com.oguzhanstech.hybridvpn

import android.app.Application
import android.content.Context
import com.oguzhanstech.hybridvpn.data.AppDatabase
import com.oguzhanstech.hybridvpn.data.AppSettings
import com.oguzhanstech.hybridvpn.data.DnsLogRepository
import com.oguzhanstech.hybridvpn.data.FilterListRepository
import com.oguzhanstech.hybridvpn.data.OpenVpnRepository
import com.oguzhanstech.hybridvpn.data.PolicyRepository
import com.oguzhanstech.hybridvpn.data.ProxyRepository
import com.oguzhanstech.hybridvpn.data.TailnetRepository
import com.oguzhanstech.hybridvpn.scanner.DeviceRepository
import com.oguzhanstech.hybridvpn.scanner.ScanController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Process-wide singletons. Small enough not to need a DI framework. */
class AppContainer(app: Application) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val db = AppDatabase.create(app)
    val settings = AppSettings(app)
    val filterLists = FilterListRepository(app, db.filterLists())
    val tailnets = TailnetRepository(app)
    val openvpn = OpenVpnRepository(app)
    val proxies = ProxyRepository(app)
    val policy = PolicyRepository(app, tailnets, openvpn, proxies)
    val dnsLog = DnsLogRepository(db.dnsEvents(), settings, scope)
    val devices = DeviceRepository(db)
    val scanner = ScanController(app, devices, settings, scope)
}

class HybridVpnApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        Notifications.createChannels(this)
        container.scope.launch { container.filterLists.ensureDefaults() }
    }
}

val Context.appContainer: AppContainer get() = (applicationContext as HybridVpnApp).container
