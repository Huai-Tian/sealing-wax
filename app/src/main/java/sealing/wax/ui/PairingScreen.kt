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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import sealing.wax.SessionManager

/**
 * 配对三屏:发起方(邀请码→粘回复→SAS)、接收方(粘邀请→回复码→SAS)、
 * 以及 SAS 核对屏(唯一信任根,不可跳过)。
 */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewSessionScreen(
    onBack: () -> Unit,
    onPaired: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    var invite by remember { mutableStateOf<String?>(null) }
    var reply by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    if (invite == null) {
        invite = remember { SessionManager.startInvite() }
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("新建会话") },
                navigationIcon = {
                    IconButton(onClick = {
                        SessionManager.abortPairing()
                        onBack()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
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
            Text(
                "第一步:把邀请码发给对方",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            CodeCard(
                title = "邀请码",
                code = invite ?: "",
                action = {
                    TextButton(onClick = {
                        clipboard.setText(AnnotatedString(invite ?: ""))
                    }) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null)
                        Text("复制")
                    }
                },
            )
            Text(
                "第二步:粘贴对方的回复码",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            OutlinedTextField(
                value = reply,
                onValueChange = { reply = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("回复码") },
                singleLine = true,
            )
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(
                onClick = {
                    try {
                        SessionManager.completeInvite(reply)
                        onPaired()
                    } catch (e: IllegalStateException) {
                        error = when (e.message) {
                            "SWX_E_FORMAT" -> "这不是有效的回复码(格式错误)"
                            "SWX_E_TYPE" -> "这不是回复码——你贴的可能是邀请码"
                            "SWX_E_STATE" -> "这是你自己的邀请码"
                            else -> "配对失败(${e.message})"
                        }
                    }
                },
                enabled = reply.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("完成配对") }
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
    var invite by remember { mutableStateOf("") }
    var reply by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("加入会话") },
                navigationIcon = {
                    IconButton(onClick = {
                        SessionManager.abortPairing()
                        onBack()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
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
                    "粘贴对方发来的邀请码",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                OutlinedTextField(
                    value = invite,
                    onValueChange = { invite = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("邀请码") },
                    singleLine = true,
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    onClick = {
                        try {
                            reply = SessionManager.startJoin(invite)
                        } catch (e: IllegalStateException) {
                            error = when (e.message) {
                                "SWX_E_FORMAT" -> "这不是有效的邀请码(格式错误)"
                                "SWX_E_TYPE" -> "这不是邀请码——你贴的可能是回复码"
                                "SWX_E_STATE" -> "这是你自己的邀请码"
                                else -> "加入失败(${e.message})"
                            }
                        }
                    },
                    enabled = invite.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("生成回复码") }
            } else {
                Text(
                    "把回复码发回给对方",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                CodeCard(
                    title = "回复码",
                    code = reply ?: "",
                    action = {
                        TextButton(onClick = {
                            clipboard.setText(AnnotatedString(reply ?: ""))
                        }) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null)
                            Text("复制")
                        }
                    },
                )
                Button(onClick = onJoined, modifier = Modifier.fillMaxWidth()) {
                    Text("我已发送,去核对验证码")
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SasScreen(
    onConfirm: () -> Unit,
    onAbort: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val sas = remember { SessionManager.sas() }
    var confirmAbort by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(title = { Text("带外核对") })
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
            Text(
                "电话念码,或当面扫码。\n对不上 = 立即中止会话。",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.error,
                fontWeight = FontWeight.Bold,
            )
            SasDigits(sas)
            QrCode(content = sas)
            OutlinedButton(onClick = {
                clipboard.setText(AnnotatedString(sas))
            }) { Text("复制验证码") }
            Button(onClick = onConfirm, modifier = Modifier.fillMaxWidth()) {
                Text("对上了,开始聊天")
            }
            OutlinedButton(onClick = { confirmAbort = true }, modifier = Modifier.fillMaxWidth()) {
                Text("对不上,中止并清零")
            }
            Spacer(Modifier.height(32.dp))
        }
    }

    if (confirmAbort) {
        AlertDialog(
            onDismissRequest = { confirmAbort = false },
            title = { Text("中止会话") },
            text = { Text("全部清零,回到零状态。") },
            confirmButton = {
                TextButton(onClick = {
                    confirmAbort = false
                    SessionManager.abortPairing()
                    onAbort()
                }) { Text("中止") }
            },
            dismissButton = { TextButton(onClick = { confirmAbort = false }) { Text("取消") } },
        )
    }
}
