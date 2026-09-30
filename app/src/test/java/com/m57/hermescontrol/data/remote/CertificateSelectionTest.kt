package com.m57.hermescontrol.data.remote

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class CertificateSelectionTest {
    private val origin = CertificateOrigin("example.test", 443)
    private val other = CertificateOrigin("example.test", 8443)

    @Test
    fun `concurrent handshakes share one chooser and persist one alias`() {
        val aliases = mutableMapOf<CertificateOrigin, String>()
        val launched = CountDownLatch(1)
        val calls = AtomicInteger()
        lateinit var callback: (String?, Boolean) -> Unit
        val selection =
            CertificateSelection(
                read = aliases::get,
                write = { origin, alias -> if (alias == null) aliases.remove(origin) else aliases[origin] = alias },
                available = { _, _, _ -> true },
                launch = { _, _, _, result ->
                    calls.incrementAndGet()
                    callback = result
                    launched.countDown()
                    true
                },
                changed = { _, _ -> },
            )
        val first = CompletableFuture.supplyAsync { selection.choose(origin, arrayOf("RSA"), null) }
        assertTrue(launched.await(2, TimeUnit.SECONDS))
        val second = CompletableFuture.supplyAsync { selection.choose(origin, arrayOf("RSA"), null) }
        assertNull(selection.choose(other, null, null))
        callback("personal", true)
        assertEquals("personal", first.get(2, TimeUnit.SECONDS))
        assertEquals("personal", second.get(2, TimeUnit.SECONDS))
        assertEquals(1, calls.get())
        assertEquals(mapOf(origin to "personal"), aliases)
    }

    @Test
    fun `cancel suppresses automatic retries but explicit reselect recovers`() {
        var alias: String? = null
        var answer: String? = null
        var prompts = 0
        var invalidations = 0
        val selection =
            CertificateSelection(
                read = { alias },
                write = { _, value -> alias = value },
                available = { _, _, _ -> true },
                launch = { _, _, _, result ->
                    prompts++
                    result(answer, true)
                    true
                },
                changed = { _, _ -> invalidations++ },
            )
        assertNull(selection.choose(origin, null, null))
        assertNull(selection.choose(origin, null, null))
        assertEquals(1, prompts)
        answer = "new"
        assertEquals("new", selection.choose(origin, null, null, explicit = true))
        assertEquals(2, prompts)
        assertEquals(1, invalidations)
        assertEquals("new", selection.choose(origin, null, null))
        assertEquals(2, prompts)
    }

    @Test
    fun `background refusal does not suppress later foreground selection`() {
        var foreground = false
        var saved: String? = null
        val selection =
            CertificateSelection(
                read = { saved },
                write = { _, alias -> saved = alias },
                available = { _, _, _ -> true },
                launch = { _, _, _, result ->
                    if (foreground) result("key", true)
                    foreground
                },
                changed = { _, _ -> },
            )
        assertNull(selection.choose(origin, null, null))
        foreground = true
        assertEquals("key", selection.choose(origin, null, null))
    }

    @Test
    fun `background transition before chooser launch does not act like user cancellation`() {
        var saved: String? = null
        var foreground = false
        val selection =
            CertificateSelection(
                read = { saved },
                write = { _, alias -> saved = alias },
                available = { _, _, _ -> true },
                launch = { _, _, _, result ->
                    // Scheduling succeeded, but the activity paused before Android could launch.
                    if (foreground) result("key", true) else result(null, false)
                    true
                },
                changed = { _, _ -> },
            )
        assertNull(selection.choose(origin, null, null))
        foreground = true
        assertEquals("key", selection.choose(origin, null, null))
    }

    @Test
    fun `unavailable saved certificate asks again and rejects unusable selection`() {
        var alias: String? = "revoked"
        var answer = "also-revoked"
        val selection =
            CertificateSelection(
                read = { alias },
                write = { _, value -> alias = value },
                available = { candidate, _, _ -> candidate == "valid" },
                launch = { _, _, _, result ->
                    result(answer, true)
                    true
                },
                changed = { _, _ -> },
            )
        assertNull(selection.choose(origin, null, null))
        assertEquals("revoked", alias)
        answer = "valid"
        assertEquals("valid", selection.choose(origin, null, null, explicit = true))
    }

    @Test
    fun `clear invalidates sockets and ignores a late chooser result`() {
        var alias: String? = "old"
        var invalidated = false
        lateinit var callback: (String?, Boolean) -> Unit
        val launched = CountDownLatch(1)
        val selection =
            CertificateSelection(
                read = { alias },
                write = { _, value -> alias = value },
                available = { _, _, _ -> true },
                launch = { _, _, _, result ->
                    callback = result
                    launched.countDown()
                    true
                },
                changed = { _, _ -> invalidated = true },
            )
        val result = CompletableFuture.supplyAsync { selection.choose(origin, null, null, explicit = true) }
        assertTrue(launched.await(2, TimeUnit.SECONDS))
        selection.clear(origin)
        assertTrue(invalidated)
        assertNull(result.get(2, TimeUnit.SECONDS))
        callback("late", true)
        assertNull(alias)
    }

    @Test
    fun `persistence failure returns no TLS identity`() {
        val selection =
            CertificateSelection(
                read = { null },
                write = { _, _ -> throw java.io.IOException("disk full") },
                available = { _, _, _ -> true },
                launch = { _, _, _, result ->
                    result("key", true)
                    true
                },
                changed = { _, _ -> },
            )
        assertNull(selection.choose(origin, null, null))
        org.junit.Assert.assertThrows(java.io.IOException::class.java) {
            selection.choose(origin, null, null, explicit = true)
        }
    }

    @Test
    fun `clear during saved-key validation cannot return a stale alias`() {
        var alias: String? = "old"
        val validating = CountDownLatch(1)
        val resume = CountDownLatch(1)
        val selection =
            CertificateSelection(
                read = { alias },
                write = { _, value -> alias = value },
                available = { candidate, _, _ ->
                    if (candidate == "old") {
                        validating.countDown()
                        assertTrue(resume.await(2, TimeUnit.SECONDS))
                    }
                    true
                },
                launch = { _, _, _, result ->
                    result("replacement", true)
                    true
                },
                changed = { _, _ -> },
            )
        val result = CompletableFuture.supplyAsync { selection.choose(origin, null, null) }
        assertTrue(validating.await(2, TimeUnit.SECONDS))
        try {
            selection.clear(origin)
        } finally {
            resume.countDown()
        }
        assertEquals("replacement", result.get(2, TimeUnit.SECONDS))
        assertEquals("replacement", alias)
    }

    @Test
    fun `timeout never opens another chooser over the existing dialog`() {
        lateinit var callback: (String?, Boolean) -> Unit
        var written = false
        var prompts = 0
        val selection =
            CertificateSelection(
                read = { null },
                write = { _, _ -> written = true },
                available = { _, _, _ -> true },
                launch = { _, _, _, result ->
                    prompts++
                    callback = result
                    true
                },
                changed = { _, _ -> },
                timeoutSeconds = 0,
            )
        assertNull(selection.choose(origin, null, null))
        assertNull(selection.choose(origin, null, null, explicit = true))
        assertEquals(1, prompts)
        callback("too-late", true)
        assertFalse(written)
        assertNull(selection.choose(origin, null, null))
        assertEquals(1, prompts)
    }
}
