package com.m57.hermescontrol.data.remote

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.Looper
import android.security.KeyChain
import androidx.core.content.ContextCompat
import com.m57.hermescontrol.ExternalActivityLifecycleGuard
import com.m57.hermescontrol.data.ws.HermesWsClient
import com.m57.hermescontrol.notification.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import java.io.IOException
import java.lang.ref.WeakReference
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Stores aliases only. Private keys stay in Android's KeyChain, including hardware-backed keys. */
object ClientCertificates {
    enum class Status { AUTOMATIC, SELECTED, UNAVAILABLE, CANCELLED, FOREGROUND_REQUIRED }

    data class State(
        val alias: String? = null,
        val status: Status = Status.AUTOMATIC,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val states = MutableStateFlow<Map<String, State>>(emptyMap())
    val state = states.asStateFlow()
    private val stateLock = Any()

    @Volatile
    private var activity = WeakReference<Activity>(null)
    private lateinit var app: Context
    private lateinit var selection: CertificateSelection
    private val trust: X509TrustManager by lazy {
        TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply {
                init(null as KeyStore?)
            }.trustManagers
            .filterIsInstance<X509TrustManager>()
            .single()
    }
    private val sockets by lazy { CertificateSocketFactory(trust, ::keyManager) }

    fun initialize(context: Context) {
        app = context.applicationContext
        val preferences = app.getSharedPreferences("client_certificate_aliases", Context.MODE_PRIVATE)
        states.value =
            preferences.all
                .mapNotNull { (origin, alias) ->
                    (alias as? String)?.let { origin to State(it, Status.SELECTED) }
                }.toMap()
        selection =
            CertificateSelection(
                read = { preferences.getString(it.storageKey, null) },
                write = { origin, alias ->
                    if (!preferences.edit().putString(origin.storageKey, alias).commit()) {
                        throw IOException("Could not save client certificate selection")
                    }
                    update(origin, State(alias, if (alias == null) Status.AUTOMATIC else Status.SELECTED))
                },
                available = ::available,
                launch = ::launchChooser,
                changed = sockets::invalidate,
            )
        ContextCompat.registerReceiver(
            app,
            object : BroadcastReceiver() {
                override fun onReceive(
                    context: Context,
                    intent: Intent,
                ) {
                    // Granting access is part of selection; keep the waiting handshake alive.
                    if (intent.action == KeyChain.ACTION_KEY_ACCESS_CHANGED &&
                        intent.getBooleanExtra(KeyChain.EXTRA_KEY_ACCESSIBLE, false)
                    ) {
                        return
                    }
                    scope.launch { sockets.invalidateAll() }
                }
            },
            IntentFilter().apply {
                addAction(KeyChain.ACTION_KEYCHAIN_CHANGED)
                addAction(KeyChain.ACTION_KEY_ACCESS_CHANGED)
            },
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    fun onResume(host: Activity) {
        activity = WeakReference(host)
    }

    fun onPause(host: Activity) {
        if (activity.get() === host) activity.clear()
    }

    internal fun configure(builder: OkHttpClient.Builder): OkHttpClient.Builder {
        val verifier = builder.build().hostnameVerifier
        return builder
            .sslSocketFactory(sockets, trust)
            // OkHttp permits HTTP/2 coalescing only with its singleton default verifier.
            // Delegate verification unchanged, but require a connection to its own TLS origin.
            .hostnameVerifier { host, session -> verifier.verify(host, session) }
    }

    /** Worker thread only; shared with TLS handshakes to prevent duplicate system dialogs. */
    fun reselect(url: HttpUrl) {
        CertificateOrigin.from(url)?.let { origin ->
            if (selection.choose(origin, null, null, explicit = true) == null) markUnavailable(origin)
        }
    }

    /** Unbind only; never remove a system certificate. The next handshake may ask again. */
    fun clear(url: HttpUrl) {
        CertificateOrigin.from(url)?.let(selection::clear)
    }

    fun stateFor(url: HttpUrl): State = CertificateOrigin.from(url)?.let { states.value[it.storageKey] } ?: State()

    private fun update(
        origin: CertificateOrigin,
        value: State,
    ) {
        synchronized(stateLock) { states.value = states.value + (origin.storageKey to value) }
    }

    private fun launchChooser(
        origin: CertificateOrigin,
        types: Array<out String>?,
        issuers: Array<out Principal>?,
        callback: (String?, Boolean) -> Unit,
    ): Boolean {
        val host = activity.get()
        if (host == null || host.isFinishing || host.isDestroyed) {
            update(origin, stateFor(origin.url).copy(status = Status.FOREGROUND_REQUIRED))
            return false
        }
        Handler(Looper.getMainLooper()).post {
            if (activity.get() !== host || host.isFinishing || host.isDestroyed) {
                update(origin, stateFor(origin.url).copy(status = Status.FOREGROUND_REQUIRED))
                scope.launch { callback(null, false) }
                return@post
            }
            try {
                ExternalActivityLifecycleGuard.launchExternalActivity(
                    acquireConnectionLease = HermesWsClient::acquireExternalActivityConnectionLease,
                    releaseConnectionLease = HermesWsClient::releaseExternalActivityConnectionLease,
                    prepareForBackground = { NotificationHelper.start(host) },
                    cleanupAfterLaunchFailure = { NotificationHelper.stop(host) },
                    launch = {
                        KeyChain.choosePrivateKeyAlias(
                            host,
                            { alias ->
                                scope.launch {
                                    ExternalActivityLifecycleGuard.externalActivityReturned()
                                    if (alias == null) {
                                        update(origin, stateFor(origin.url).copy(status = Status.CANCELLED))
                                    }
                                    callback(alias, true)
                                }
                            },
                            types,
                            issuers,
                            origin.host,
                            origin.port,
                            stateFor(origin.url).alias,
                        )
                    },
                )
            } catch (_: RuntimeException) {
                update(origin, stateFor(origin.url).copy(status = Status.UNAVAILABLE))
                scope.launch { callback(null, false) }
            }
        }
        return true
    }

    private fun key(alias: String): PrivateKey? =
        try {
            KeyChain.getPrivateKey(app, alias)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) {
            null
        }

    private fun chain(alias: String): Array<X509Certificate>? =
        try {
            KeyChain.getCertificateChain(app, alias)?.takeIf { it.isNotEmpty() }?.also { chain ->
                chain.forEach { it.checkValidity() }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) {
            null
        }

    private fun available(
        alias: String,
        types: Array<out String>?,
        issuers: Array<out Principal>?,
    ): Boolean {
        val chain = chain(alias) ?: return false
        if (!types.isNullOrEmpty() &&
            types.none { it.substringBefore('_') == chain[0].publicKey.algorithm }
        ) {
            return false
        }
        if (!issuers.isNullOrEmpty() && chain.none { it.issuerX500Principal in issuers }) return false
        return key(alias) != null
    }

    private fun markUnavailable(origin: CertificateOrigin) {
        val current = stateFor(origin.url)
        if (current.status == Status.SELECTED || current.status == Status.AUTOMATIC) {
            update(origin, current.copy(status = Status.UNAVAILABLE))
        }
    }

    private fun keyManager(origin: CertificateOrigin): ClientCertificateKeyManager =
        ClientCertificateKeyManager(
            choose = { types, issuers, socket ->
                check(Looper.myLooper() != Looper.getMainLooper()) { "TLS must run on a worker thread" }
                val alias = selection.choose(origin, types, issuers, socket = socket)
                if (alias == null) markUnavailable(origin)
                alias
            },
            privateKey = { alias -> if (stateFor(origin.url).alias == alias) key(alias) else null },
            certificateChain = { alias -> if (stateFor(origin.url).alias == alias) chain(alias) else null },
        )
}
