/* SPDX-License-Identifier: AGPL-3.0-or-later
 * 火漆 · Sealing Wax — https://github.com/Huai-Tian/sealing-wax
 * Copyright (C) 2026 Huai-Tian and contributors
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version. See the GNU Affero General Public License
 * for more details. A copy of the license accompanies this program; if
 * not, see <https://www.gnu.org/licenses/>.
 */
package sealing.wax.ui

import android.util.Log
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
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
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.unit.dp
import sealing.wax.R
import sealing.wax.SessionManager

/** 运营屏 = 打开即武装(§5,所有者定稿 v2):静态邀请码卡 + 客户回复码
 *  粘贴框,仅此两样。粘贴即配对——暗号对则 armed ctx 毕业为普通客户
 *  会话并直接进对话(SAS 顶栏常驻),幕后再武装由下次打开完成;暗号错
 *  则如实报错,3ee0222 回滚令武装原地再战。退出(返回/系统返回)由
 *  MainActivity 焚毁武装——门禁运行时零驻留状态。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PublicSessionScreen(
    id: String,
    name: String,
    onBack: () -> Unit,
    onClientPaired: () -> Unit,
    onRename: (String) -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var code by remember(id) { mutableStateOf<String?>(null) }
    var loadError by remember(id) { mutableStateOf<String?>(null) }
    var reply by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    /* 点题改名(与对话屏同款手势,运营打磨批):对象永在,标题恒可改;
     * 本地即时更新,信封由 onRename 直写 */
    var title by remember(id) { mutableStateOf(name) }
    var renameOpen by remember { mutableStateOf(false) }

    LaunchedEffect(id) {
        runCatching { SessionManager.armPublicSession(context, id) }
            .onSuccess { code = it }
            .onFailure {
                Log.w("SealingWax", "armPublicSession failed", it)
                loadError = context.getString(R.string.home_load_failed)
            }
    }

    /* 粘贴即配对:与对话屏同一防抖节奏;长度即格式,裁决在 finish */
    LaunchedEffect(reply, code) {
        val t = reply.trim()
        if (code == null || t.isEmpty()) return@LaunchedEffect
        kotlinx.coroutines.delay(150)
        if (t.length != 88) {
            error = context.getString(R.string.pair_reply_bad_format)
            return@LaunchedEffect
        }
        runCatching { SessionManager.completeInvite(t) }
            .onSuccess { onClientPaired() }
            .onFailure { e ->
                Log.w("SealingWax", "completeInvite failed", e)
                error = when (e.message) {
                    "SWX_E_CRYPTO" -> context.getString(R.string.public_reply_crypto)
                    "SWX_E_STATE" -> context.getString(R.string.pair_state_error_new)
                    else -> SessionManager.stableError(
                        context.getString(R.string.pair_fail_new), e,
                    )
                }
            }
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    /* 点题改名:公共会话对象永在,标题恒可改 */
                    Text(title, modifier = Modifier.clickable { renameOpen = true })
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
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
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (code == null) {
                loadError?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            } else {
                CodeCard(
                    title = stringResource(R.string.public_static_code),
                    code = code ?: "",
                    action = {
                        TextButton(onClick = {
                            clipboard.setText(AnnotatedString(code ?: ""))
                        }) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null)
                            Text(stringResource(R.string.common_copy))
                        }
                    },
                )
                OutlinedTextField(
                    value = reply,
                    onValueChange = { reply = it },
                    modifier = Modifier.fillMaxWidth(),
                    /* 提示即「回复码」(文案修正):字段上下文自明,
                     * 与加入会话屏的码卡标题同串(pair_reply_code) */
                    label = { Text(stringResource(R.string.pair_reply_code)) },
                    singleLine = true,
                    trailingIcon = { ClearFieldIcon(reply) { reply = "" } },
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
            Spacer(Modifier.height(32.dp))
        }
    }

    if (renameOpen) {
        RenameSessionDialog(
            initialName = title,
            onDismiss = { renameOpen = false },
            onConfirm = {
                title = it
                onRename(it)
                renameOpen = false
            },
        )
    }
}
