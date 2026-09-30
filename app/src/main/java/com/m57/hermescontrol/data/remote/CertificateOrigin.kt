package com.m57.hermescontrol.data.remote

import okhttp3.HttpUrl

/** TLS credentials belong to a host and port, never to a profile or URL path. */
internal data class CertificateOrigin(
    val host: String,
    val port: Int,
) {
    val url: HttpUrl =
        HttpUrl
            .Builder()
            .scheme("https")
            .host(host)
            .port(port)
            .build()
    val storageKey: String get() = url.toString()

    companion object {
        fun from(url: HttpUrl): CertificateOrigin? = if (url.isHttps) CertificateOrigin(url.host, url.port) else null
    }
}
