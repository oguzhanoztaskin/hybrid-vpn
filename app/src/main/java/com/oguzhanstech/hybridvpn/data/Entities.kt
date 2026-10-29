package com.oguzhanstech.hybridvpn.data

import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/** A LAN the user has scanned. [key] is "wifi:<ssid>" when the SSID is known, else "lan:<subnet>|<gateway>". */
@Entity(tableName = "networks", indices = [Index(value = ["key"], unique = true)])
data class NetworkEntity(
    @PrimaryKey val id: String,
    val key: String,
    val displayName: String,
    val ssid: String?,
    val subnet: String?,
    val gateway: String?,
    val firstSeen: Long,
    val lastScanAt: Long?,
    val lastScanId: String?,
)

/** A physical device. Not tied to one network: a laptop can be observed at home and at work. */
@Entity(tableName = "devices")
data class DeviceEntity(
    @PrimaryKey val id: String,
    val displayName: String,
    /** User-assigned names always take precedence over discovered ones. */
    val userAssignedName: Boolean,
    val deviceType: String,
    val vendor: String?,
    val model: String?,
    val notes: String?,
    val groupName: String?,
    val firstSeen: Long,
    val lastSeen: Long,
    val lastIp: String?,
    val confidence: Float,
    val fingerprint: String?,
    val manual: Boolean,
)

/**
 * Evidence linking observations to a device. [scope] is "" for globally unique kinds (MAC, SSDP
 * UUID) and the network id for everything else, so "raspberrypi.local" at home and at a friend's
 * house never merge.
 */
@Entity(
    tableName = "device_identifiers",
    primaryKeys = ["deviceId", "kind", "value", "scope"],
    foreignKeys = [ForeignKey(entity = DeviceEntity::class, parentColumns = ["id"], childColumns = ["deviceId"], onDelete = ForeignKey.CASCADE)],
    indices = [Index(value = ["kind", "value", "scope"]), Index(value = ["scope"])],
)
data class DeviceIdentifierEntity(
    val deviceId: String,
    val kind: String,
    val value: String,
    val scope: String,
    val firstSeen: Long,
    val lastSeen: Long,
)

@Entity(
    tableName = "device_observations",
    foreignKeys = [ForeignKey(entity = DeviceEntity::class, parentColumns = ["id"], childColumns = ["deviceId"], onDelete = ForeignKey.CASCADE)],
    indices = [Index(value = ["deviceId"]), Index(value = ["networkId", "scanId"])],
)
data class DeviceObservationEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val deviceId: String,
    val networkId: String,
    val scanId: String,
    val timestamp: Long,
    val ipAddress: String,
    val reachable: Boolean,
    /** Space-separated "type:port" labels. */
    val services: String,
    val openPorts: String,
)

data class DeviceListItem(
    @Embedded val device: DeviceEntity,
    val ip: String?,
    val online: Boolean,
)

@Entity(tableName = "filter_lists")
data class FilterListEntity(
    @PrimaryKey val id: String,
    val name: String,
    /** Null for the built-in user rules list, whose text is edited in the app. */
    val url: String?,
    val enabled: Boolean,
    val lastUpdated: Long?,
    val ruleCount: Int,
    val unsupportedCount: Int,
    val invalidCount: Int,
    val lastError: String?,
)

@Entity(tableName = "dns_events", indices = [Index(value = ["timestamp"])])
data class DnsEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val uid: Int?,
    val packageName: String?,
    val domain: String,
    val type: Int,
    val outcome: String,
    val ruleId: String?,
    val detail: String?,
    val upstream: String?,
    val latencyMs: Long,
    val rcode: Int?,
)
