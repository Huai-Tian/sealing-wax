/* SPDX-License-Identifier: AGPL-3.0-only
 * 火漆 · Sealing Wax — https://github.com/Huai-Tian/sealing-wax
 * Copyright (C) 2026 Huai-Tian and contributors
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License only. See the GNU
 * Affero General Public License for more details. You should have received
 * a copy of the license along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */
package sealing.wax.ui

import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import sealing.wax.R
import sealing.wax.store.PublicSession
import sealing.wax.store.SavedSession
import java.text.DateFormat
import java.util.Date

/** 会话列表三态:加载中/就绪/读不出来。空列表只在 Ready 里有语义
 *  ——"还在加载"与"解不开信封"绝不伪装成"没有会话"
 *  (真机反馈 2026-11:静默空表曾把加载失败当成了空数据)。 */
sealed interface SessionListState {
    data object Loading : SessionListState
    data class Ready(
        val sessions: List<SavedSession>,
        val publics: List<PublicSession>,
    ) : SessionListState
    data object Failed : SessionListState
}

/** 首页:会话列表(三态)+ 右下角 +(展开新建/加入,点空白收回)。 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun HomeScreen(
    state: SessionListState,
    onRetryLoad: () -> Unit,
    onNewSession: () -> Unit,
    onJoinSession: () -> Unit,
    onOpenSession: (String) -> Unit,
    onRenameSession: (SavedSession, String) -> Unit,
    onDeleteSession: (SavedSession) -> Unit,
    onOpenPublic: (PublicSession) -> Unit,
    onRenamePublic: (PublicSession, String) -> Unit,
    onDeletePublic: (PublicSession) -> Unit,
    onOpenSource: () -> Unit,
) {
    val context = LocalContext.current
    var fabExpanded by remember { mutableStateOf(false) }
    /* 两种卡片(普通会话/公共会话)共用改名与删除弹窗,目标按类型分发 */
    var renameTarget by remember { mutableStateOf<Any?>(null) }
    var deleteTarget by remember { mutableStateOf<Any?>(null) }
    var aboutOpen by remember { mutableStateOf(false) }

    Scaffold(
        floatingActionButton = {
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (fabExpanded) {
                    ExtendedFloatingActionButton(
                        text = { Text(stringResource(R.string.home_fab_join)) },
                        icon = { Icon(Icons.Default.Key, contentDescription = null) },
                        onClick = { fabExpanded = false; onJoinSession() },
                    )
                    ExtendedFloatingActionButton(
                        text = { Text(stringResource(R.string.home_fab_new)) },
                        icon = { Icon(Icons.Default.Add, contentDescription = null) },
                        onClick = { fabExpanded = false; onNewSession() },
                    )
                }
                FloatingActionButton(
                    onClick = { fabExpanded = !fabExpanded },
                ) {
                    Icon(Icons.Default.Add, contentDescription = stringResource(R.string.home_fab_cd))
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            Column(Modifier.fillMaxSize()) {
                /* Shizuku/KernelSU 式顶栏:应用名即标题 + 右上竖三点菜单 */
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        stringResource(R.string.app_name),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier
                            .weight(1f)
                            .padding(start = 16.dp, top = 24.dp, bottom = 12.dp),
                    )
                    /* Box 包住 IconButton + 溢出菜单:菜单锚定按钮本身;
                     * 曾直接放 Row 里锚到整行,真机上左展开(真机反馈 2026-11) */
                    Box {
                        var menuOpen by remember { mutableStateOf(false) }
                        IconButton(
                            onClick = { menuOpen = true },
                            modifier = Modifier.padding(top = 12.dp, end = 8.dp),
                        ) {
                            Icon(
                                Icons.Default.MoreVert,
                                contentDescription = stringResource(R.string.chat_menu_cd),
                            )
                        }
                        /* Shizuku 同款下拉:开放源代码在上,关于在下(§9);
                         * 长宽比 = appcompat 溢出菜单几何(196dp 最小宽 ×
                         * 48dp 行高,无竖向内边距),M3 DropdownMenu 偏方 */
                        OverflowMenu(
                            expanded = menuOpen,
                            onDismissRequest = { menuOpen = false },
                        ) {
                            OverflowMenuItem(
                                stringResource(R.string.menu_open_source),
                            ) {
                                menuOpen = false
                                onOpenSource()
                            }
                            OverflowMenuItem(
                                stringResource(R.string.menu_about),
                            ) {
                                menuOpen = false
                                aboutOpen = true
                            }
                        }
                    }
                }
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    when (state) {
                        SessionListState.Loading -> Column(
                            Modifier.align(Alignment.Center),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            CircularProgressIndicator()
                            Text(
                                stringResource(R.string.home_loading),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }

                        SessionListState.Failed -> Column(
                            Modifier.align(Alignment.Center),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Text(
                                stringResource(R.string.home_load_failed),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error,
                                textAlign = TextAlign.Center,
                            )
                            TextButton(onClick = onRetryLoad) { Text(stringResource(R.string.common_retry)) }
                        }

                        is SessionListState.Ready -> {
                            val sessions = state.sessions
                            val publics = state.publics
                            if (sessions.isEmpty() && publics.isEmpty()) {
                                /* 空态:原"已保存的会话"块的小字,移至居中(§9) */
                                Text(
                                    stringResource(R.string.home_empty),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier
                                        .align(Alignment.Center)
                                        .padding(horizontal = 32.dp),
                                )
                            } else {
                                LazyColumn(
                                    modifier = Modifier.fillMaxSize(),
                                    contentPadding = androidx.compose.foundation.layout.PaddingValues(start = 16.dp, end = 16.dp, bottom = 16.dp),
                                    verticalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    /* 公共会话置顶(所有者定稿):位置即身份,
                                     * 图标只当视觉节拍器——公共=书签,私聊=钥匙 */
                                    items(publics, key = { "p" + it.id }) { p ->
                                        Card(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .combinedClickable(
                                                    onClick = { onOpenPublic(p) },
                                                    onLongClick = { renameTarget = p },
                                                ),
                                            colors = CardDefaults.cardColors(
                                                containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                            ),
                                        ) {
                                            Row(
                                                Modifier.padding(16.dp),
                                                verticalAlignment = Alignment.CenterVertically,
                                            ) {
                                                Icon(
                                                    Icons.Default.Bookmark,
                                                    contentDescription = null,
                                                    tint = MaterialTheme.colorScheme.primary,
                                                )
                                                Spacer(Modifier.width(12.dp))
                                                Column(Modifier.weight(1f)) {
                                                    Text(p.name, style = MaterialTheme.typography.titleMedium)
                                                    Text(
                                                        stringResource(
                                                            R.string.home_last_used,
                                                            DateFormat.getDateTimeInstance().format(Date(p.lastUsedMs)),
                                                        ),
                                                        style = MaterialTheme.typography.bodySmall,
                                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    )
                                                }
                                                IconButton(onClick = { deleteTarget = p }) {
                                                    Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.common_delete))
                                                }
                                            }
                                        }
                                    }
                                    items(sessions, key = { it.id }) { s ->
                                        Card(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .combinedClickable(
                                                    onClick = { onOpenSession(s.id) },
                                                    onLongClick = { renameTarget = s },
                                                ),
                                            colors = CardDefaults.cardColors(
                                                containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                            ),
                                        ) {
                                            Row(
                                                Modifier.padding(16.dp),
                                                verticalAlignment = Alignment.CenterVertically,
                                            ) {
                                                Icon(
                                                    Icons.Default.Key,
                                                    contentDescription = null,
                                                    tint = MaterialTheme.colorScheme.primary,
                                                )
                                                Spacer(Modifier.width(12.dp))
                                                Column(Modifier.weight(1f)) {
                                                    Text(s.name, style = MaterialTheme.typography.titleMedium)
                                                    Text(
                                                        stringResource(
                                                            R.string.home_last_used,
                                                            DateFormat.getDateTimeInstance().format(Date(s.lastUsedMs)),
                                                        ),
                                                        style = MaterialTheme.typography.bodySmall,
                                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    )
                                                }
                                                IconButton(onClick = { deleteTarget = s }) {
                                                    Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.common_delete))
                                                }
                                            }
                                        }
                                    }
                                    item { Spacer(Modifier.height(88.dp)) }
                                }
                            }
                        }
                    }
                }
            }

            /* 点空白处收回展开的两个选项(FAB 在 content 之上,不受遮罩影响) */
            if (fabExpanded) {
                Box(
                    Modifier
                        .matchParentSize()
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                        ) { fabExpanded = false },
                )
            }
        }
    }

    renameTarget?.let { t ->
        val initial = when (t) {
            is SavedSession -> t.name
            is PublicSession -> t.name
            else -> ""
        }
        RenameSessionDialog(
            initialName = initial,
            onDismiss = { renameTarget = null },
            onConfirm = { name ->
                when (t) {
                    is SavedSession -> onRenameSession(t, name)
                    is PublicSession -> onRenamePublic(t, name)
                }
                renameTarget = null
            },
        )
    }

    deleteTarget?.let { t ->
        /* 删除语义随种类不同:普通会话=房塌(旧密文永远解不开);
         * 公共会话=门拆(已建会话不受影响,简介旧码永久失效) */
        val isPublic = t is PublicSession
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = {
                Text(
                    stringResource(
                        if (isPublic) R.string.public_delete_title
                        else R.string.home_delete_title,
                    ),
                )
            },
            text = {
                Text(
                    stringResource(
                        if (isPublic) R.string.public_delete_text
                        else R.string.home_delete_text,
                    ),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    when (t) {
                        is SavedSession -> onDeleteSession(t)
                        is PublicSession -> onDeletePublic(t)
                    }
                    deleteTarget = null
                    Toast.makeText(
                        context, context.getString(R.string.home_deleted_toast), Toast.LENGTH_SHORT,
                    ).show()
                }) { Text(stringResource(R.string.common_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(R.string.common_cancel))
                }
            },
        )
    }

    /* 关于 = Shizuku 式小弹窗(§9):无按钮,点空白关闭 */
    if (aboutOpen) {
        AboutDialog(onDismiss = { aboutOpen = false })
    }
}
