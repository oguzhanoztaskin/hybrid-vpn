package com.oguzhanstech.hybridvpn

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.oguzhanstech.hybridvpn.scanner.ScanSummary
import com.oguzhanstech.hybridvpn.vpn.HybridVpnService

object Notifications {
    const val VPN_ID = 1
    private const val DEVICES_ID = 2
    private const val VPN_CHANNEL = "vpn"
    private const val DEVICES_CHANNEL = "devices"

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(VPN_CHANNEL, context.getString(R.string.channel_vpn), NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(DEVICES_CHANNEL, context.getString(R.string.channel_devices), NotificationManager.IMPORTANCE_DEFAULT))
    }

    fun vpn(context: Context, text: String) = NotificationCompat.Builder(context, VPN_CHANNEL)
        .setSmallIcon(R.drawable.ic_stat_shield)
        .setContentTitle(context.getString(R.string.vpn_notification_title))
        .setContentText(text)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setContentIntent(openApp(context))
        .addAction(
            0, context.getString(R.string.action_stop),
            PendingIntent.getService(
                context, 1,
                Intent(context, HybridVpnService::class.java).setAction(HybridVpnService.ACTION_STOP),
                PendingIntent.FLAG_IMMUTABLE,
            ),
        )
        .build()

    fun updateVpn(context: Context, text: String) = post(context, VPN_ID, vpn(context, text))

    fun newDevices(context: Context, summary: ScanSummary) {
        val names = summary.newDevices.joinToString { it.displayName }
        val notification = NotificationCompat.Builder(context, DEVICES_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(context.resources.getQuantityString(R.plurals.new_devices, summary.newDevices.size, summary.newDevices.size, summary.networkName))
            .setContentText(names)
            .setStyle(NotificationCompat.BigTextStyle().bigText(names))
            .setContentIntent(openApp(context))
            .setAutoCancel(true)
            .build()
        post(context, DEVICES_ID, notification)
    }

    private fun post(context: Context, id: Int, notification: Notification) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        NotificationManagerCompat.from(context).notify(id, notification)
    }

    private fun openApp(context: Context) =
        PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
}
