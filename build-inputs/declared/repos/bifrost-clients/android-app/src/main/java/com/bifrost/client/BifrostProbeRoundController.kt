package com.bifrost.client

import java.io.Closeable
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Debounced, generation-labelled probe rounds.  The caller owns the
 * executor; cancelling a round closes registered sockets/futures immediately
 * and a late result is discarded unless its generation is still current.
 */
internal class BifrostProbeRoundController(
    private val executor: ScheduledExecutorService,
    private val debounceMs: Long = 1_500L,
) : Closeable {
    private val generation = AtomicInteger(0)
    private val scheduled = AtomicReference<ScheduledFuture<*>?>(null)
    /** The scheduled or running task, cancelled with interruption on rollover. */
    private val active = AtomicReference<Future<*>?>(null)
    private val cancellation = AtomicReference<ProbeCancellation?>(null)

    fun request(round: (generation: Int, cancellation: ProbeCancellation) -> Unit): Int {
        cancel()
        val token = generation.incrementAndGet()
        val work = ProbeCancellation()
        cancellation.set(work)
        val holder = AtomicReference<Future<*>?>(null)
        val task = executor.schedule({
            if (!isCurrent(token)) return@schedule
            try {
                round(token, work)
            } finally {
                active.compareAndSet(holder.get(), null)
            }
        }, debounceMs, TimeUnit.MILLISECONDS)
        holder.set(task)
        scheduled.set(task)
        active.getAndSet(task)?.cancel(true)
        if (task.isDone) active.compareAndSet(task, null)
        return token
    }

    fun runNow(round: (generation: Int, cancellation: ProbeCancellation) -> Unit): Int {
        cancel()
        val token = generation.incrementAndGet()
        val work = ProbeCancellation()
        cancellation.set(work)
        val holder = AtomicReference<Future<*>?>(null)
        val task = executor.submit {
            if (!isCurrent(token)) return@submit
            try {
                round(token, work)
            } finally {
                active.compareAndSet(holder.get(), null)
            }
        }
        holder.set(task)
        active.getAndSet(task)?.cancel(true)
        if (task.isDone) active.compareAndSet(task, null)
        return token
    }

    fun isCurrent(token: Int): Boolean = generation.get() == token && !cancellation.get().orNullCancelled()

    fun cancel() {
        generation.incrementAndGet()
        scheduled.getAndSet(null)?.cancel(false)
        active.getAndSet(null)?.cancel(true)
        cancellation.getAndSet(null)?.cancel()
    }

    override fun close() = cancel()

    private fun ProbeCancellation?.orNullCancelled(): Boolean = this?.isCancelled() ?: true
}
