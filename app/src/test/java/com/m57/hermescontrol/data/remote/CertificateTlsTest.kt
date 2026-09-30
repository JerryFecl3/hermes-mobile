package com.m57.hermescontrol.data.remote

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class CertificateTlsTest {
    private val serverIdentity =
        HeldCertificate
            .Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .addSubjectAlternativeName("127.0.0.1")
            .build()
    private val firstIdentity = HeldCertificate.Builder().commonName("first-client").build()
    private val secondIdentity = HeldCertificate.Builder().commonName("second-client").build()
    private val serverTls =
        HandshakeCertificates
            .Builder()
            .heldCertificate(serverIdentity)
            .addTrustedCertificate(firstIdentity.certificate)
            .addTrustedCertificate(secondIdentity.certificate)
            .build()
    private val clientTrust = HandshakeCertificates.Builder().addTrustedCertificate(serverIdentity.certificate).build()
    private val aliases = mutableMapOf<CertificateOrigin, String>()
    private val selections = AtomicInteger()
    private val identities = mapOf("first" to firstIdentity, "second" to secondIdentity)
    private val sockets =
        CertificateSocketFactory(clientTrust.trustManager) { origin ->
            ClientCertificateKeyManager(
                choose = { _, _, _ ->
                    selections.incrementAndGet()
                    aliases[origin]
                },
                privateKey = { alias -> identities[alias]?.keyPair?.private },
                certificateChain = { alias -> identities[alias]?.let { arrayOf(it.certificate) } },
            )
        }
    private val client =
        OkHttpClient
            .Builder()
            .sslSocketFactory(sockets, clientTrust.trustManager)
            .hostnameVerifier { host, session -> OkHttpClient().hostnameVerifier.verify(host, session) }
            .readTimeout(3, TimeUnit.SECONDS)
            .build()

    private fun server(
        require: Boolean = false,
        request: Boolean = false,
    ): MockWebServer =
        MockWebServer().apply {
            useHttps(serverTls.sslSocketFactory(), false)
            if (require) {
                requireClientAuth()
            } else if (request) {
                requestClientAuth()
            }
            start()
        }

    private fun get(url: String): String =
        client.newCall(Request.Builder().url(url).build()).execute().use {
            assertTrue(it.isSuccessful)
            it.body.string()
        }

    @Test
    fun `automatic replacement retires old sockets but preserves choosing handshake until clear`() {
        lateinit var factory: CertificateSocketFactory
        val selection =
            CertificateSelection(
                read = aliases::get,
                write = { origin, alias -> if (alias == null) aliases.remove(origin) else aliases[origin] = alias },
                available = { alias, _, _ -> alias == "second" },
                launch = { _, _, _, result ->
                    result("second", true)
                    true
                },
                changed = { origin, preserve -> factory.invalidate(origin, preserve) },
            )
        factory =
            CertificateSocketFactory(clientTrust.trustManager) { origin ->
                ClientCertificateKeyManager(
                    choose = { types, issuers, socket -> selection.choose(origin, types, issuers, socket = socket) },
                    privateKey = { alias -> identities[alias]?.keyPair?.private },
                    certificateChain = { alias -> identities[alias]?.let { arrayOf(it.certificate) } },
                )
            }
        server(require = true).use { server ->
            val origin = CertificateOrigin.from(server.url("/"))!!
            aliases[origin] = "first"
            factory.createSocket("localhost", server.port).use { old ->
                factory.createSocket("localhost", server.port).use { pending ->
                    (pending as javax.net.ssl.SSLSocket).startHandshake()
                    assertTrue(old.isClosed)
                    assertEquals(secondIdentity.certificate, pending.session.localCertificates.single())
                    assertTrue(!pending.isClosed)
                    selection.clear(origin)
                    assertTrue(pending.isClosed)
                    assertNull(aliases[origin])
                }
            }
        }
    }

    @Test
    fun `origin canonicalizes hostname default port and excludes path credentials query`() {
        assertEquals(
            CertificateOrigin.from("https://EXAMPLE.com/a?b=c".toHttpUrl()),
            CertificateOrigin.from("https://example.com:443/elsewhere".toHttpUrl()),
        )
        assertNotEquals(CertificateOrigin("example.com", 443), CertificateOrigin("example.com", 8443))
        assertNull(CertificateOrigin.from("http://example.com/".toHttpUrl()))
    }

    @Test
    fun `mTLS requests a certificate while ordinary HTTPS and HTTP do not`() {
        server(require = true).use { server ->
            val url = server.url("/api/status")
            aliases[CertificateOrigin.from(url)!!] = "first"
            server.enqueue(MockResponse().setBody("mtls"))
            assertEquals("mtls", get(url.toString()))
            assertEquals(
                firstIdentity.certificate,
                server
                    .takeRequest()
                    .handshake!!
                    .peerCertificates
                    .single(),
            )
            assertTrue(selections.get() > 0)
        }
        selections.set(0)
        server().use { server ->
            aliases[CertificateOrigin.from(server.url("/"))!!] = "first"
            server.enqueue(MockResponse().setBody("https"))
            assertEquals("https", get(server.url("/").toString()))
            assertTrue(
                server
                    .takeRequest()
                    .handshake!!
                    .peerCertificates
                    .isEmpty(),
            )
        }
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("http"))
            assertEquals("http", get(server.url("/").toString()))
        }
        assertEquals(0, selections.get())
    }

    @Test
    fun `same address supports mTLS and ordinary HTTPS without a mode switch`() {
        server(require = true).use { server ->
            val url = server.url("/")
            val origin = CertificateOrigin.from(url)!!
            aliases[origin] = "first"
            server.enqueue(MockResponse().setBody("outside"))
            assertEquals("outside", get(url.toString()))
            assertEquals(
                firstIdentity.certificate,
                server
                    .takeRequest()
                    .handshake!!
                    .peerCertificates
                    .single(),
            )
            // Simulate a new TLS connection to a backend which does not request client auth.
            server.noClientAuth()
            sockets.invalidate(origin)
            selections.set(0)
            server.enqueue(MockResponse().setBody("inside"))
            assertEquals("inside", get(url.toString()))
            assertTrue(
                server
                    .takeRequest()
                    .handshake!!
                    .peerCertificates
                    .isEmpty(),
            )
            assertEquals(0, selections.get())
            assertEquals("first", aliases[origin])
        }
    }

    @Test
    fun `HTTP2 and redirects never reuse client identity for another host or port`() {
        server(request = true).use { first ->
            server(request = true).use { second ->
                val url = first.url("/")
                aliases[CertificateOrigin.from(url)!!] = "first"
                first.enqueue(MockResponse().setBody("selected"))
                client.newCall(Request.Builder().url(url).build()).execute().use { response ->
                    assertEquals(Protocol.HTTP_2, response.protocol)
                    assertEquals("selected", response.body.string())
                }
                assertEquals(
                    firstIdentity.certificate,
                    first
                        .takeRequest()
                        .handshake!!
                        .peerCertificates
                        .single(),
                )
                first.enqueue(MockResponse().setBody("other-host"))
                val otherHost = url.newBuilder().host("127.0.0.1").build()
                assertEquals("other-host", get(otherHost.toString()))
                val otherRequest = first.takeRequest()
                assertEquals(0, otherRequest.sequenceNumber)
                assertTrue(otherRequest.handshake!!.peerCertificates.isEmpty())
                first.enqueue(MockResponse().setResponseCode(302).setHeader("Location", second.url("/media")))
                second.enqueue(MockResponse().setBody("redirect"))
                assertEquals("redirect", get(url.toString()))
                assertTrue(
                    second
                        .takeRequest()
                        .handshake!!
                        .peerCertificates
                        .isEmpty(),
                )
            }
        }
    }

    @Test
    fun `reselect and clear retire existing sockets and TLS sessions`() {
        server(request = true).use { server ->
            val url = server.url("/")
            val origin = CertificateOrigin.from(url)!!
            listOf("first", "second", null).forEach { alias ->
                if (alias == null) aliases.remove(origin) else aliases[origin] = alias
                sockets.invalidate(origin)
                server.enqueue(MockResponse().setBody("ok"))
                assertEquals("ok", get(url.toString()))
                val peer = server.takeRequest().handshake!!.peerCertificates
                if (alias ==
                    null
                ) {
                    assertTrue(peer.isEmpty())
                } else {
                    assertEquals(identities[alias]!!.certificate, peer.single())
                }
            }
        }
    }

    @Test
    fun `server certificate and hostname are still verified`() {
        server().use { server ->
            val emptyTrust = HandshakeCertificates.Builder().build().trustManager
            val untrustedSockets =
                CertificateSocketFactory(emptyTrust) { origin ->
                    ClientCertificateKeyManager(
                        choose = { _, _, _ -> aliases[origin] },
                        privateKey = { null },
                        certificateChain = { null },
                    )
                }
            val untrusted = OkHttpClient.Builder().sslSocketFactory(untrustedSockets, emptyTrust).build()
            server.enqueue(MockResponse())
            assertThrows(IOException::class.java) {
                untrusted.newCall(Request.Builder().url(server.url("/")).build()).execute().close()
            }
            val wrongHost = client.newBuilder().dns { listOf(java.net.InetAddress.getByName("127.0.0.1")) }.build()
            server.enqueue(MockResponse())
            assertThrows(IOException::class.java) {
                wrongHost
                    .newCall(
                        Request
                            .Builder()
                            .url(
                                server
                                    .url("/")
                                    .newBuilder()
                                    .host("wrong.test")
                                    .build(),
                            ).build(),
                    ).execute()
                    .close()
            }
        }
    }

    @Test
    fun `required mTLS fails without selection and succeeds after choosing`() {
        server(require = true).use { server ->
            val url = server.url("/")
            server.enqueue(MockResponse().setBody("authorized"))
            assertThrows(IOException::class.java) { get(url.toString()) }
            aliases[CertificateOrigin.from(url)!!] = "first"
            assertEquals("authorized", get(url.toString()))
            assertEquals(
                firstIdentity.certificate,
                server
                    .takeRequest()
                    .handshake!!
                    .peerCertificates
                    .single(),
            )
        }
    }

    @Test
    fun `WebSocket handshake uses client identity`() {
        server(require = true).use { server ->
            val url = server.url("/ws")
            aliases[CertificateOrigin.from(url)!!] = "first"
            server.enqueue(
                MockResponse().withWebSocketUpgrade(
                    object : WebSocketListener() {
                        override fun onOpen(
                            webSocket: WebSocket,
                            response: Response,
                        ) {
                            webSocket.send("ready")
                        }
                    },
                ),
            )
            val received = CompletableFuture<String>()
            val socket =
                client.newWebSocket(
                    Request.Builder().url(url).build(),
                    object : WebSocketListener() {
                        override fun onMessage(
                            webSocket: WebSocket,
                            text: String,
                        ) {
                            received.complete(text)
                        }

                        override fun onFailure(
                            webSocket: WebSocket,
                            t: Throwable,
                            response: Response?,
                        ) {
                            received.completeExceptionally(t)
                        }
                    },
                )
            try {
                assertEquals("ready", received.get(5, TimeUnit.SECONDS))
                assertEquals(
                    firstIdentity.certificate,
                    server
                        .takeRequest()
                        .handshake!!
                        .peerCertificates
                        .single(),
                )
            } finally {
                socket.cancel()
            }
        }
    }
}
