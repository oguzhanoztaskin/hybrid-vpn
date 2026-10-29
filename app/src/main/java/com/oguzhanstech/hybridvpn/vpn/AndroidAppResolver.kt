package com.oguzhanstech.hybridvpn.vpn

import android.content.pm.PackageManager
import com.oguzhanstech.hybridvpn.engine.policy.AppResolver

/** Package names to UIDs via PackageManager (visibility granted by QUERY_ALL_PACKAGES). */
class AndroidAppResolver(private val pm: PackageManager) : AppResolver {
    override fun uidOf(packageName: String): Int? = try {
        pm.getPackageUid(packageName, 0)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    override fun packagesFor(uid: Int): List<String> = pm.getPackagesForUid(uid)?.toList()?.sorted().orEmpty()
}
