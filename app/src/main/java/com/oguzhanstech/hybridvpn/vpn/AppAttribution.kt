package com.oguzhanstech.hybridvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import com.oguzhanstech.hybridvpn.engine.dns.QueryOrigin
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Maps a tunnelled flow to the app that owns it. Android's resolver tags its sockets with the
 * requesting app's UID, so this attributes DNS queries per app on Android 10+. Failure is normal
 * and reported as an unknown owner, never guessed.
 */
class AppAttribution(context: Context) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val pm = context.packageManager
    private val packages = ConcurrentHashMap<Int, List<String>>()

    fun udpOrigin(source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int): QueryOrigin =
        origin(OsConstants.IPPROTO_UDP, source, sourcePort, destination, destinationPort)

    /** [protocol] is OsConstants.IPPROTO_UDP or IPPROTO_TCP. */
    fun origin(protocol: Int, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int): QueryOrigin {
        val uid = ownerUid(protocol, source, sourcePort, destination, destinationPort)
        if (uid == Process.INVALID_UID) return UNKNOWN
        return QueryOrigin(uid, packages.getOrPut(uid) { pm.getPackagesForUid(uid)?.toList()?.sorted() ?: listOf(nameForUid(uid)) })
    }

    /** The UID owning a flow, or Process.INVALID_UID (-1). Android 10+ only; earlier versions are always unknown. */
    fun ownerUid(protocol: Int, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int): Int {
        if (Build.VERSION.SDK_INT < 29) return Process.INVALID_UID
        return try {
            cm.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByAddress(source), sourcePort),
                InetSocketAddress(InetAddress.getByAddress(destination), destinationPort),
            )
        } catch (_: SecurityException) {
            Process.INVALID_UID
        } catch (_: IllegalArgumentException) {
            Process.INVALID_UID
        }
    }

    private fun nameForUid(uid: Int) = pm.getNameForUid(uid) ?: "uid:$uid"

    private companion object {
        val UNKNOWN = QueryOrigin(null, null)
    }
}
