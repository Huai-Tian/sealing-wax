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
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import sealing.wax.SessionManager

/**
 * 配对两屏(§5,PAKE 化):发起方(暗号→邀请码→粘回复→直接进对话)、
 * 接收方(粘邀请→同一暗号→回复码→直接进对话)。SAS 不再有独立确认页:
 * 配对完成即进入对话屏,9 位数字常驻顶栏,随时核对(仪表盘,非关卡)。
 */

private const val SECRET_HINT =
    "输入一句只有你们俩知道的话(共同经历、地点、事件)。\n" +
        "两人必须一字不差;不要用在网上聊过的话题——服务器存档即失效。"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewSessionScreen(
    onBack: () -> Unit,
    onPaired: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    var secret by remember { mutableStateOf("") }
    var invite by remember { mutableStateOf<String?>(null) }
    var reply by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

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
            if (invite == null) {
                Text(
                    "第一步:和对方约好同一个暗号",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("暗号") },
                    supportingText = { Text(SECRET_HINT) },
                    singleLine = true,
                )
                Button(
                    onClick = {
                        try {
                            invite = SessionManager.startInvite(secret.toByteArray(Charsets.UTF_8))
                        } catch (e: IllegalStateException) {
                            error = "生成邀请码失败(${e.message})"
                        }
                    },
                    enabled = secret.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("生成邀请码") }
            } else {
                Text(
                    "第二步:把邀请码发给对方",
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
                    "第三步:粘贴对方的回复码",
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
                                "SWX_E_FORMAT" -> "这不是有效的回复码(长度不符)"
                                "SWX_E_CRYPTO" ->
                                    "暗号不一致或回复码被改动。和对方核对暗号后," +
                                        "请对方用同一个暗号重新生成回复码(邀请码不用重发)"
                                "SWX_E_STATE" -> "配对流程状态错误"
                                else -> "配对失败(${e.message})"
                            }
                        }
                    },
                    enabled = reply.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("完成配对") }
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
    var invite by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
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
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("暗号(和对方相同)") },
                    supportingText = { Text(SECRET_HINT) },
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
                            error = when (e.message) {
                                "SWX_E_FORMAT" -> "这不是有效的邀请码(长度不符)"
                                "SWX_E_CRYPTO" -> "邀请码无法解算"
                                "SWX_E_STATE" -> "加入流程状态错误"
                                else -> "加入失败(${e.message})"
                            }
                        }
                    },
                    enabled = invite.isNotBlank() && secret.isNotBlank(),
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
                Text(
                    "对方确认后你们就在同一会话里了。\n" +
                        "验证码 9 位数字会一直显示在对话页右上角,想核对随时念码。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(onClick = onJoined, modifier = Modifier.fillMaxWidth()) {
                    Text("我已发送,进入对话")
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
