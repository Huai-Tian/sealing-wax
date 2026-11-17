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
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
import androidx.compose.material3.Switch
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
    onPublicCreated: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var secret by remember { mutableStateOf("") }
    var invite by remember { mutableStateOf<String?>(null) }
    var reply by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    /* 公共会话(§5,所有者定稿):同一入口的子集模式——开关只改变
     * 第一步的形态与按钮去向;普通配对流程一字不动 */
    var publicMode by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf("") }

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
                    /* 公共态下行头换词(所有者定稿):没有"对方",只有门禁暗号 */
                    stringResource(
                        if (publicMode) R.string.pair_step1_public
                        else R.string.pair_step1,
                    ),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                if (publicMode) {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(stringResource(R.string.public_name_label)) },
                        singleLine = true,
                        trailingIcon = { ClearFieldIcon(name) { name = "" } },
                    )
                }
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.pair_secret_label)) },
                    supportingText = { Text(stringResource(R.string.pair_secret_hint)) },
                    singleLine = true,
                    trailingIcon = { ClearFieldIcon(secret) { secret = "" } },
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        stringResource(R.string.public_switch),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(checked = publicMode, onCheckedChange = { publicMode = it })
                }
                Button(
                    onClick = {
                        if (publicMode) {
                            /* 创建即显式保存(§6);回首页见置顶卡(所有者定稿) */
                            try {
                                SessionManager.createPublicSession(
                                    name, secret.toByteArray(Charsets.UTF_8),
                                )
                                onPublicCreated()
                            } catch (e: Exception) {
                                Log.w("SealingWax", "createPublicSession failed", e)
                                error = SessionManager.stableError(
                                    context.getString(R.string.pair_fail_new), e,
                                )
                            }
                        } else {
                            try {
                                invite = SessionManager.startInvite(secret.toByteArray(Charsets.UTF_8))
                            } catch (e: IllegalStateException) {
                                Log.w("SealingWax", "startInvite failed", e)
                                error = SessionManager.stableError(
                                    context.getString(R.string.pair_invite_gen_fail), e,
                                )
                            }
                        }
                    },
                    enabled = secret.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        stringResource(
                            if (publicMode) R.string.public_create_btn
                            else R.string.pair_invite_btn,
                        ),
                    )
                }
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
                    trailingIcon = { ClearFieldIcon(reply) { reply = "" } },
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

    /* 回复页返回(第十批收尾3,取代原[重新填写暗号]按钮):焚毁(疑似)
     * 错误暗号派生的会话,回到第一阶段——邀请码与暗号保留,改暗号后
     * 重生成回复码即第九批既有协议路径(同一邀请码+新回复码,§4) */
    fun goBackToForm() {
        SessionManager.abortPairing()
        error = null
        reply = null
    }
    /* 系统返回与顶栏箭头同语义:回复页回表单,表单页(未启用)落到
     * MainActivity 的加入流程 BackHandler = 退出+回首页 */
    BackHandler(enabled = reply != null) { goBackToForm() }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.pair_join_title)) },
                navigationIcon = {
                    /* 回复页 = 回表单(会话焚毁,邀请码/暗号保留);
                     * 表单页 = 退出流程 + 回首页 */
                    IconButton(onClick = {
                        if (reply != null) {
                            goBackToForm()
                        } else {
                            SessionManager.abortPairing()
                            onBack()
                        }
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
                    trailingIcon = { ClearFieldIcon(invite) { invite = "" } },
                )
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.pair_secret_label)) },
                    singleLine = true,
                    trailingIcon = { ClearFieldIcon(secret) { secret = "" } },
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
                /* 回复页只留:回复码卡 + [进入对话]单按钮(收尾2 删两行
                 * 提示,收尾3 移除[重新填写暗号]按钮——重试闭环改由返回
                 * 操作接管,见 goBackToForm) */
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
                Button(onClick = onJoined, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.pair_enter_chat))
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
