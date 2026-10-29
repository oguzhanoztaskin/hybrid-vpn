package com.oguzhanstech.hybridvpn.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Update
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

@Dao
interface NetworkDao {
    @Query("SELECT * FROM networks ORDER BY lastScanAt DESC")
    fun all(): Flow<List<NetworkEntity>>

    @Query("SELECT * FROM networks WHERE id = :id")
    fun observe(id: String): Flow<NetworkEntity?>

    @Query("SELECT * FROM networks WHERE `key` = :key")
    suspend fun byKey(key: String): NetworkEntity?

    @Upsert
    suspend fun upsert(network: NetworkEntity)
}

@Dao
interface DeviceDao {
    @Query(
        """
        SELECT d.*,
          (SELECT o.ipAddress FROM device_observations o WHERE o.deviceId = d.id AND o.networkId = :networkId
             ORDER BY o.timestamp DESC LIMIT 1) AS ip,
          EXISTS(SELECT 1 FROM device_observations o WHERE o.deviceId = d.id AND o.scanId = :scanId AND o.reachable = 1) AS online
        FROM devices d
        WHERE EXISTS(SELECT 1 FROM device_observations o WHERE o.deviceId = d.id AND o.networkId = :networkId)
        ORDER BY online DESC, d.displayName COLLATE NOCASE
        """
    )
    fun onNetwork(networkId: String, scanId: String?): Flow<List<DeviceListItem>>

    @Query("SELECT * FROM devices WHERE id = :id")
    fun observe(id: String): Flow<DeviceEntity?>

    @Query("SELECT * FROM devices")
    suspend fun all(): List<DeviceEntity>

    @Query("SELECT * FROM devices WHERE id = :id")
    suspend fun get(id: String): DeviceEntity?

    @Insert
    suspend fun insert(device: DeviceEntity)

    @Update
    suspend fun update(device: DeviceEntity)

    @Query("DELETE FROM devices WHERE id = :id")
    suspend fun delete(id: String)

    @Query("SELECT * FROM device_identifiers WHERE scope = '' OR scope = :networkId")
    suspend fun identifiersInScope(networkId: String): List<DeviceIdentifierEntity>

    @Query("SELECT * FROM device_identifiers WHERE deviceId = :deviceId ORDER BY kind, lastSeen DESC")
    fun identifiers(deviceId: String): Flow<List<DeviceIdentifierEntity>>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIdentifier(identifier: DeviceIdentifierEntity): Long

    @Query("UPDATE device_identifiers SET lastSeen = :lastSeen WHERE deviceId = :deviceId AND kind = :kind AND value = :value AND scope = :scope")
    suspend fun touchIdentifier(deviceId: String, kind: String, value: String, scope: String, lastSeen: Long)

    @Insert
    suspend fun insertObservation(observation: DeviceObservationEntity)

    @Query("SELECT * FROM device_observations WHERE deviceId = :deviceId ORDER BY timestamp DESC LIMIT :limit")
    fun observations(deviceId: String, limit: Int): Flow<List<DeviceObservationEntity>>

    @Query("DELETE FROM device_observations WHERE timestamp < :before")
    suspend fun pruneObservations(before: Long)
}

@Dao
interface FilterListDao {
    @Query("SELECT * FROM filter_lists ORDER BY url IS NOT NULL, name")
    fun all(): Flow<List<FilterListEntity>>

    @Query("SELECT * FROM filter_lists")
    suspend fun snapshot(): List<FilterListEntity>

    @Query("SELECT * FROM filter_lists WHERE id = :id")
    suspend fun get(id: String): FilterListEntity?

    @Upsert
    suspend fun upsert(list: FilterListEntity)

    @Query("DELETE FROM filter_lists WHERE id = :id")
    suspend fun delete(id: String)
}

@Dao
interface DnsEventDao {
    @Insert
    suspend fun insertAll(events: List<DnsEventEntity>)

    @Query("SELECT * FROM dns_events ORDER BY timestamp DESC LIMIT :limit")
    fun recent(limit: Int): Flow<List<DnsEventEntity>>

    @Query("DELETE FROM dns_events WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("DELETE FROM dns_events")
    suspend fun clear()
}

@Database(
    entities = [
        NetworkEntity::class, DeviceEntity::class, DeviceIdentifierEntity::class, DeviceObservationEntity::class,
        FilterListEntity::class, DnsEventEntity::class,
    ],
    version = 1,
    exportSchema = true,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun networks(): NetworkDao
    abstract fun devices(): DeviceDao
    abstract fun filterLists(): FilterListDao
    abstract fun dnsEvents(): DnsEventDao

    companion object {
        fun create(context: Context): AppDatabase =
            Room.databaseBuilder(context, AppDatabase::class.java, "hybridvpn.db").build()
    }
}
