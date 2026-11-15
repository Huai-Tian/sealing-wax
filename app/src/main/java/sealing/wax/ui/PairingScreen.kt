/* SPDX-License-Identifier: AGPL-3.0-or-later
 * 火漆 · Sealing Wax — https://github.com/Huai-Tian/sealing-wax
 * Copyright (C) 2026 Huai-Tian and contributors
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version. See the GNU Affero General Public License for
 * more details. You should have received a copy of the license along with
 * this program; if not, see <https://www.gnu.org/licenses/>.
 */
package sealing.wax.ui

import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Button
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import sealing.wax.R
import sealing.wax.SessionManager

/** 配对两屏(§5,PAKE 化):发起方(暗号→邀请码→粘回复→直接进对话)、
 *  接收方(粘邀请→同一暗号→回复码→直接进对话)。SAS 不再有独立确认页:
 *  配对完成即进入对话屏,9 位数字常驻顶栏,随时核对(仪表盘,非关卡)。
 */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewSessionScreen(
    onBack: () -> Unit,
    onPaired: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var secret by remember { mutableStateOf("") }
    var invite by remember { mutableStateOf<String?>(null) }
    var reply by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.pair_new_title)) },
                navigationIcon = {
                    IconButton(onClick = {
                        SessionManager.abortPairing()
                        onBack()
                    }) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.common_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (invite == null) {
                Text(
                    stringResource(R.string.pair_step1),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.pair_secret_label)) },
                    supportingText = { Text(stringResource(R.string.pair_secret_hint)) },
                    singleLine = true,
                )
                Button(
                    onClick = {
                        try {
                            invite = SessionManager.startInvite(secret.toByteArray(Charsets.UTF_8))
                        } catch (e: IllegalStateException) {
                            Log.w("SealingWax", "startInvite failed", e)
                            error = SessionManager.stableError(
                                context.getString(R.string.pair_invite_gen_fail), e,
                            )
                        }
                    },
                    enabled = secret.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.pair_invite_btn)) }
            } else {
                Text(
                    stringResource(R.string.pair_step2),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                CodeCard(
                    title = stringResource(R.string.pair_invite_code),
                    code = invite ?: "",
                    action = {
                        TextButton(onClick = {
                            clipboard.setText(AnnotatedString(invite ?: ""))
                        }) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null)
                            Text(stringResource(R.string.common_copy))
                        }
                    },
                )
                Text(
                    stringResource(R.string.pair_step3),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                OutlinedTextField(
                    value = reply,
                    onValueChange = { reply = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.pair_reply_label)) },
                    singleLine = true,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    onClick = {
                        try {
                            SessionManager.completeInvite(reply)
                            onPaired()
                        } catch (e: IllegalStateException) {
                            Log.w("SealingWax", "completeInvite failed", e)
                            error = when (e.message) {
                                "SWX_E_FORMAT" -> context.getString(R.string.pair_reply_bad_format)
                                "SWX_E_CRYPTO" -> context.getString(R.string.pair_reply_crypto)
                                "SWX_E_STATE" -> context.getString(R.string.pair_state_error_new)
                                else -> SessionManager.stableError(
                                    context.getString(R.string.pair_fail_new), e,
                                )
                            }
                        }
                    },
                    enabled = reply.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.pair_complete_btn)) }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun JoinSessionScreen(
    onBack: () -> Unit,
    onJoined: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var invite by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var reply by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.pair_join_title)) },
                navigationIcon = {
                    IconButton(onClick = {
                        SessionManager.abortPairing()
                        onBack()
                    }) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.common_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (reply == null) {
                Text(
                    stringResource(R.string.pair_paste_invite),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                OutlinedTextField(
                    value = invite,
                    onValueChange = { invite = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.pair_invite_code)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.pair_secret_same)) },
                    supportingText = { Text(stringResource(R.string.pair_secret_hint)) },
                    singleLine = true,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    onClick = {
                        try {
                            reply = SessionManager.startJoin(
                                invite,
                                secret.toByteArray(Charsets.UTF_8),
                            )
                        } catch (e: IllegalStateException) {
                            Log.w("SealingWax", "startJoin failed", e)
                            error = when (e.message) {
                                "SWX_E_FORMAT" -> context.getString(R.string.pair_invite_bad_format)
                                "SWX_E_CRYPTO" -> context.getString(R.string.pair_invite_crypto)
                                "SWX_E_STATE" -> context.getString(R.string.pair_state_error_join)
                                else -> SessionManager.stableError(
                                    context.getString(R.string.pair_fail_join), e,
                                )
                            }
                        }
                    },
                    enabled = invite.isNotBlank() && secret.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.pair_reply_btn)) }
            } else {
                Text(
                    stringResource(R.string.pair_reply_send_back),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                CodeCard(
                    title = stringResource(R.string.pair_reply_code),
                    code = reply ?: "",
                    action = {
                        TextButton(onClick = {
                            clipboard.setText(AnnotatedString(reply ?: ""))
                        }) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null)
                            Text(stringResource(R.string.common_copy))
                        }
                    },
                )
                Text(
                    stringResource(R.string.pair_done_hint),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(onClick = onJoined, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.pair_enter_chat))
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
