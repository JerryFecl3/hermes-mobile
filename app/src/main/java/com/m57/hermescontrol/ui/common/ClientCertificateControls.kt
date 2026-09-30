package com.m57.hermescontrol.ui.common

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.m57.hermescontrol.R
import com.m57.hermescontrol.data.remote.ClientCertificates
import com.m57.hermescontrol.data.remote.ServerEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Inline controls; Android owns the certificate list and private keys. */
@Composable
fun ClientCertificateControls(
    baseUrl: String,
    enabled: Boolean = true,
) {
    val url = remember(baseUrl) { runCatching { ServerEndpoint.parseForBuild(baseUrl).baseUrl }.getOrNull() }
    if (url == null || !url.isHttps) return
    val states by ClientCertificates.state.collectAsState()
    val state = remember(states, url) { ClientCertificates.stateFor(url) }
    var busy by remember(url) { mutableStateOf(false) }
    var failed by remember(url) { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val status =
        when (state.status) {
            ClientCertificates.Status.AUTOMATIC -> R.string.client_certificate_automatic
            ClientCertificates.Status.SELECTED -> R.string.client_certificate_selected
            ClientCertificates.Status.UNAVAILABLE -> R.string.client_certificate_unavailable
            ClientCertificates.Status.CANCELLED -> R.string.client_certificate_cancelled
            ClientCertificates.Status.FOREGROUND_REQUIRED -> R.string.client_certificate_foreground
        }
    Column {
        Text(stringResource(R.string.client_certificate_title), style = MaterialTheme.typography.labelLarge)
        Text(stringResource(status), style = MaterialTheme.typography.bodySmall)
        state.alias?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        Text(
            stringResource(R.string.client_certificate_scope, url.host, url.port),
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedButton(
            onClick = {
                busy = true
                failed = false
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) { ClientCertificates.reselect(url) }
                    } catch (_: java.io.IOException) {
                        failed = true
                    } catch (_: java.util.concurrent.ExecutionException) {
                        failed = true
                    } finally {
                        busy = false
                    }
                }
            },
            enabled = enabled && !busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.client_certificate_reselect)) }
        if (state.alias != null) {
            TextButton(
                onClick = {
                    busy = true
                    failed = false
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { ClientCertificates.clear(url) }
                        } catch (_: java.io.IOException) {
                            failed = true
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = enabled && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.client_certificate_clear)) }
        }
        if (failed) {
            Text(stringResource(R.string.client_certificate_error), color = MaterialTheme.colorScheme.error)
        }
    }
}
