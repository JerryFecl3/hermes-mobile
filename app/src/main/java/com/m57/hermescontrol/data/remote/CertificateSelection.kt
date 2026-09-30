package com.m57.hermescontrol.data.remote

import java.io.IOException
import java.net.Socket
import java.security.Principal
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Serializes the system chooser and shares its result across concurrent TLS handshakes. */
internal class CertificateSelection(
    private val read: (CertificateOrigin) -> String?,
    private val write: (CertificateOrigin, String?) -> Unit,
    private val available: (String, Array<out String>?, Array<out Principal>?) -> Boolean,
    private val launch: (
        CertificateOrigin,
        Array<out String>?,
        Array<out Principal>?,
        (String?, Boolean) -> Unit,
    ) -> Boolean,
    private val changed: (CertificateOrigin, Set<Socket>) -> Unit,
    private val timeoutSeconds: Long = 90,
) {
    private data class Pending(
        val origin: CertificateOrigin,
        val result: CompletableFuture<String?> = CompletableFuture(),
        val handshakes: MutableSet<Socket> = mutableSetOf(),
    )

    private val lock = Any()
    private val suppressed = mutableSetOf<CertificateOrigin>()
    private var pending: Pending? = null
    private var revision = 0L

    fun choose(
        origin: CertificateOrigin,
        types: Array<out String>?,
        issuers: Array<out Principal>?,
        explicit: Boolean = false,
        socket: Socket? = null,
    ): String? {
        lateinit var request: Pending
        var owner = false
        while (true) {
            val (old, observedRevision) = synchronized(lock) { read(origin) to revision }
            // KeyChain IPC can block. Do not hold the state lock while checking access.
            val reusable = !explicit && old != null && available(old, types, issuers)
            val reserved =
                synchronized(lock) {
                    if (revision != observedRevision || read(origin) != old) {
                        false
                    } else {
                        if (reusable) return old
                        val active = pending
                        if (active != null && active.origin != origin) return null
                        if (active == null && !explicit && origin in suppressed) return null
                        owner = active == null
                        request = active ?: Pending(origin).also { pending = it }
                        socket?.let(request.handshakes::add)
                        true
                    }
                }
            if (reserved) break
        }
        if (owner) {
            val launched =
                launch(origin, types, issuers) { alias, prompted ->
                    // KeyChain callbacks may arrive after clear, timeout, or activity destruction.
                    // Validate before publishing, without holding the state lock during KeyChain IPC.
                    val valid = alias?.takeIf { available(it, types, issuers) }
                    synchronized(lock) {
                        if (pending !== request) return@synchronized
                        if (request.result.isDone) {
                            pending = null
                            return@synchronized
                        }
                        try {
                            if (valid != null) {
                                write(origin, valid)
                                revision++
                                suppressed.remove(origin)
                                // Retire old identities without closing handshakes awaiting this choice.
                                changed(origin, request.handshakes.toSet())
                            } else if (prompted) {
                                suppressed.add(origin)
                            }
                            request.result.complete(valid)
                        } catch (error: Exception) {
                            request.result.completeExceptionally(error)
                        } finally {
                            pending = null
                        }
                    }
                }
            if (!launched) {
                synchronized(lock) {
                    if (pending === request) {
                        pending = null
                        request.result.complete(null)
                    }
                }
            }
        }
        return try {
            val alias = request.result.get(timeoutSeconds, TimeUnit.SECONDS) ?: return null
            if (!available(alias, types, issuers)) return null
            synchronized(lock) { alias.takeIf { read(origin) == it } }
        } catch (_: TimeoutException) {
            abandon(request)
            null
        } catch (error: ExecutionException) {
            if (explicit) throw IOException("Could not save client certificate selection", error.cause)
            null
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }
    }

    private fun abandon(request: Pending) {
        synchronized(lock) {
            if (pending === request) {
                // Keep the chooser occupied until its callback arrives; a timeout must not
                // permit another system dialog over one the user has not dismissed yet.
                suppressed.add(request.origin)
                request.result.complete(null)
            }
        }
    }

    fun clear(origin: CertificateOrigin) {
        synchronized(lock) {
            write(origin, null)
            revision++
            suppressed.remove(origin)
            pending?.takeIf { it.origin == origin }?.result?.complete(null)
            changed(origin, emptySet())
        }
    }
}
