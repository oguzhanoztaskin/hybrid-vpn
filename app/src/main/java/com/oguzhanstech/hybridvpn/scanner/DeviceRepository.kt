package com.oguzhanstech.hybridvpn.scanner

import androidx.room.withTransaction
import com.oguzhanstech.hybridvpn.data.AppDatabase
import com.oguzhanstech.hybridvpn.data.DeviceEntity
import com.oguzhanstech.hybridvpn.data.DeviceIdentifierEntity
import com.oguzhanstech.hybridvpn.data.DeviceListItem
import com.oguzhanstech.hybridvpn.data.DeviceObservationEntity
import com.oguzhanstech.hybridvpn.data.NetworkEntity
import com.oguzhanstech.hybridvpn.discovery.ScanReport
import com.oguzhanstech.hybridvpn.discovery.identity.DeviceClassifier
import com.oguzhanstech.hybridvpn.discovery.identity.DeviceType
import com.oguzhanstech.hybridvpn.discovery.identity.IdentifierKind
import com.oguzhanstech.hybridvpn.discovery.identity.IdentityResolver
import com.oguzhanstech.hybridvpn.discovery.identity.KnownDevice
import com.oguzhanstech.hybridvpn.discovery.identity.KnownIdentifier
import com.oguzhanstech.hybridvpn.discovery.identity.Resolution
import com.oguzhanstech.hybridvpn.engine.net.IpLiteral
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class ScanSummary(
    val networkName: String,
    val seen: Int,
    val newDevices: List<DeviceEntity>,
    val possibleDuplicates: Int,
    val firstScanOfNetwork: Boolean,
    val warnings: List<String>,
)

class DeviceRepository(private val db: AppDatabase) {

    private val devices = db.devices()
    private val networks = db.networks()
    private val resolver = IdentityResolver()

    val allNetworks: Flow<List<NetworkEntity>> = networks.all()

    @OptIn(ExperimentalCoroutinesApi::class)
    fun devicesOn(networkId: String): Flow<List<DeviceListItem>> =
        networks.observe(networkId).flatMapLatest { n -> if (n == null) flowOf(emptyList()) else devices.onNetwork(n.id, n.lastScanId) }

    fun device(id: String) = devices.observe(id)
    fun identifiers(id: String) = devices.identifiers(id)
    fun history(id: String) = devices.observations(id, 50)

    /** Finds or creates the network row, upgrading a subnet-keyed row once the SSID becomes known. */
    suspend fun networkFor(lan: LanInfo): NetworkEntity = db.withTransaction {
        networks.byKey(lan.key)?.let { return@withTransaction it }
        val now = System.currentTimeMillis()
        val legacy = if (lan.ssid != null) networks.byKey(lan.fallbackKey)?.takeIf { it.ssid == null } else null
        val entity = legacy?.copy(key = lan.key, ssid = lan.ssid, displayName = lan.displayName)
            ?: NetworkEntity(UUID.randomUUID().toString(), lan.key, lan.displayName, lan.ssid, lan.subnet.toString(), lan.gateway, now, null, null)
        networks.upsert(entity)
        entity
    }

    suspend fun applyScan(network: NetworkEntity, report: ScanReport): ScanSummary = db.withTransaction {
        val now = report.finishedAt
        val scanId = UUID.randomUUID().toString()
        val firstScan = network.lastScanAt == null
        val byId = devices.all().associateBy { it.id }.toMutableMap()
        val identifierRows = devices.identifiersInScope(network.id).groupBy { it.deviceId }.toMutableMap()
        fun known(): List<KnownDevice> = identifierRows.map { (id, rows) ->
            KnownDevice(id, rows.map { KnownIdentifier(IdentifierKind.valueOf(it.kind), it.value, it.lastSeen) }, byId[id]?.fingerprint)
        }

        val created = ArrayList<DeviceEntity>()
        var duplicates = 0
        for (obs in report.observations) {
            val cls = DeviceClassifier.classify(obs)
            val resolution = resolver.resolve(obs, known(), now)
            val device = when (resolution) {
                is Resolution.Matched -> {
                    duplicates += resolution.conflictsWith.size
                    val old = byId.getValue(resolution.deviceId)
                    old.copy(
                        displayName = if (old.userAssignedName) old.displayName else cls.suggestedName,
                        deviceType = if (cls.type != DeviceType.UNKNOWN || old.deviceType == DeviceType.UNKNOWN.name) cls.type.name else old.deviceType,
                        vendor = cls.vendor ?: old.vendor,
                        model = cls.model ?: old.model,
                        lastSeen = now,
                        lastIp = obs.ip,
                        confidence = maxOf(old.confidence, resolution.confidence.score),
                        fingerprint = obs.fingerprint,
                    ).also { devices.update(it) }
                }
                is Resolution.New -> DeviceEntity(
                    id = UUID.randomUUID().toString(), displayName = cls.suggestedName, userAssignedName = false,
                    deviceType = cls.type.name, vendor = cls.vendor, model = cls.model, notes = null, groupName = null,
                    firstSeen = now, lastSeen = now, lastIp = obs.ip, confidence = resolution.confidence.score,
                    fingerprint = obs.fingerprint, manual = false,
                ).also { devices.insert(it); created += it }
            }
            byId[device.id] = device

            val rows = identifierRows.getOrPut(device.id) { mutableListOf() }.toMutableList()
            for (identifier in obs.identifiers) {
                val scope = if (identifier.kind.global) "" else network.id
                val row = DeviceIdentifierEntity(device.id, identifier.kind.name, identifier.value, scope, now, now)
                if (devices.insertIdentifier(row) == -1L) devices.touchIdentifier(device.id, row.kind, row.value, scope, now)
                rows.removeAll { it.kind == row.kind && it.value == row.value && it.scope == scope }
                rows += row
            }
            identifierRows[device.id] = rows

            devices.insertObservation(
                DeviceObservationEntity(
                    deviceId = device.id, networkId = network.id, scanId = scanId, timestamp = now, ipAddress = obs.ip,
                    reachable = obs.reachable, services = obs.serviceLabels.joinToString(" "), openPorts = obs.openPorts.sorted().joinToString(" "),
                )
            )
        }
        networks.upsert(network.copy(lastScanAt = now, lastScanId = scanId))
        devices.pruneObservations(now - HISTORY_RETENTION_MS)
        ScanSummary(network.displayName, report.observations.size, created, duplicates, firstScan, report.warnings)
    }

    suspend fun rename(id: String, name: String) {
        val d = devices.get(id) ?: return
        devices.update(if (name.isBlank()) d.copy(userAssignedName = false) else d.copy(displayName = name.trim(), userAssignedName = true))
    }

    suspend fun updateNotes(id: String, notes: String, group: String) {
        val d = devices.get(id) ?: return
        devices.update(d.copy(notes = notes.ifBlank { null }, groupName = group.ifBlank { null }))
    }

    suspend fun delete(id: String) = devices.delete(id)

    suspend fun addManual(network: NetworkEntity, name: String, ip: String): Result<Unit> {
        if (IpLiteral.parseV4(ip.trim()) == null) return Result.failure(IllegalArgumentException("Not an IPv4 address"))
        val now = System.currentTimeMillis()
        val id = UUID.randomUUID().toString()
        db.withTransaction {
            devices.insert(
                DeviceEntity(id, name.trim().ifEmpty { "Device ${ip.trim()}" }, name.isNotBlank(), DeviceType.UNKNOWN.name, null, null, null, null, now, now, ip.trim(), 1f, null, manual = true)
            )
            devices.insertIdentifier(DeviceIdentifierEntity(id, IdentifierKind.IP.name, ip.trim(), network.id, now, now))
            devices.insertObservation(DeviceObservationEntity(deviceId = id, networkId = network.id, scanId = "manual", timestamp = now, ipAddress = ip.trim(), reachable = false, services = "", openPorts = ""))
        }
        return Result.success(Unit)
    }

    fun exportJson(items: List<DeviceListItem>): String = JSONArray().apply {
        items.forEach { (d, ip, online) ->
            put(
                JSONObject()
                    .put("id", d.id).put("name", d.displayName).put("type", d.deviceType).put("ip", ip ?: JSONObject.NULL)
                    .put("online", online).put("vendor", d.vendor ?: JSONObject.NULL).put("model", d.model ?: JSONObject.NULL)
                    .put("group", d.groupName ?: JSONObject.NULL).put("notes", d.notes ?: JSONObject.NULL)
                    .put("firstSeen", d.firstSeen).put("lastSeen", d.lastSeen).put("confidence", d.confidence.toDouble())
            )
        }
    }.toString(2)

    fun exportCsv(items: List<DeviceListItem>): String = buildString {
        appendLine("id,name,type,ip,online,vendor,model,group,notes,first_seen,last_seen,confidence")
        items.forEach { (d, ip, online) ->
            appendLine(
                listOf(d.id, d.displayName, d.deviceType, ip, online, d.vendor, d.model, d.groupName, d.notes, d.firstSeen, d.lastSeen, d.confidence)
                    .joinToString(",") { csv(it?.toString()) }
            )
        }
    }

    private fun csv(value: String?): String {
        val v = value ?: return ""
        // Quote everything risky, and defuse spreadsheet formula injection from device-supplied names.
        val safe = if (v.firstOrNull() in setOf('=', '+', '-', '@')) "'$v" else v
        return if (safe.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"" + safe.replace("\"", "\"\"") + "\"" else safe
    }

    private companion object {
        const val HISTORY_RETENTION_MS = 180L * 24 * 60 * 60 * 1000
    }
}
