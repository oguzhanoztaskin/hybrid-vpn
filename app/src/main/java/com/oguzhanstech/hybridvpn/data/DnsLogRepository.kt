package com.oguzhanstech.hybridvpn.data

import com.oguzhanstech.hybridvpn.engine.dns.DnsEvent
import com.oguzhanstech.hybridvpn.engine.dns.DnsOutcome
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

data class DnsCounters(val queries: Long = 0, val blocked: Long = 0, val cached: Long = 0, val errors: Long = 0)

/**
 * DNS activity, honouring the user's privacy setting:
 * OFF keeps only counters, MEMORY keeps a bounded in-memory ring, PERSISTENT also writes to the
 * database with retention-based pruning.
 */
class DnsLogRepository(private val dao: DnsEventDao, private val settings: AppSettings, private val scope: CoroutineScope) {

    private val ring = ArrayDeque<DnsEvent>()
    private val recentState = MutableStateFlow<List<DnsEvent>>(emptyList())
    private val counterState = MutableStateFlow(DnsCounters())
    private val pending = Channel<DnsEventEntity>(capacity = 4096)
    private val publishScheduled = AtomicBoolean(false)

    val recent: StateFlow<List<DnsEvent>> = recentState.asStateFlow()
    val counters: StateFlow<DnsCounters> = counterState.asStateFlow()
    val persisted: Flow<List<DnsEventEntity>> = dao.recent(500)

    init {
        scope.launch {
            val batch = ArrayList<DnsEventEntity>()
            while (true) {
                batch += pending.receive()
                delay(2000)
                while (true) batch += pending.tryReceive().getOrNull() ?: break
                runCatching { dao.insertAll(batch) }
                batch.clear()
            }
        }
    }

    fun record(event: DnsEvent) {
        counterState.value = counterState.value.let {
            it.copy(
                queries = it.queries + 1,
                blocked = it.blocked + if (event.outcome == DnsOutcome.BLOCKED) 1 else 0,
                cached = it.cached + if (event.outcome == DnsOutcome.CACHED) 1 else 0,
                errors = it.errors + if (event.outcome == DnsOutcome.ERROR) 1 else 0,
            )
        }
        val mode = settings.settings.value.logMode
        if (mode == LogMode.OFF) return
        synchronized(ring) {
            ring.addLast(event)
            while (ring.size > RING_SIZE) ring.removeFirst()
        }
        schedulePublish()
        if (mode == LogMode.PERSISTENT) {
            pending.trySend(
                DnsEventEntity(
                    timestamp = event.timestamp, uid = event.uid, packageName = event.packages?.firstOrNull(),
                    domain = event.domain, type = event.type, outcome = event.outcome.name, ruleId = event.ruleId,
                    detail = event.detail, upstream = event.upstream, latencyMs = event.latencyMs, rcode = event.rcode,
                )
            )
        }
    }

    /**
     * Publishes the ring at most twice a second, and only after something was recorded: a periodic
     * ticker here measurably dominated idle wake-ups (docs/benchmarks).
     */
    private fun schedulePublish() {
        if (!publishScheduled.compareAndSet(false, true)) return
        scope.launch {
            delay(500)
            publishScheduled.set(false)
            recentState.value = synchronized(ring) { ring.toList().asReversed() }
        }
    }

    fun resetCounters() {
        counterState.value = DnsCounters()
    }

    suspend fun prune() {
        val days = settings.settings.value.retentionDays
        dao.deleteOlderThan(System.currentTimeMillis() - days * 24L * 60 * 60 * 1000)
    }

    suspend fun clear() {
        synchronized(ring) { ring.clear() }
        recentState.value = emptyList()
        dao.clear()
    }

    private companion object {
        const val RING_SIZE = 1000
    }
}
