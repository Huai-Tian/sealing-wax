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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
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
import sealing.wax.store.SavedSession
import java.text.DateFormat
import java.util.Date

/** 会话列表三态:加载中/就绪/读不出来。空列表只在 Ready 里有语义
 *  ——"还在加载"与"解不开信封"绝不伪装成"没有会话"
 *  (真机反馈 2026-11:静默空表曾把加载失败当成了空数据)。 */
sealed interface SessionListState {
    data object Loading : SessionListState
    data class Ready(val sessions: List<SavedSession>) : SessionListState
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
    onOpenSource: () -> Unit,
    onAbout: () -> Unit,
) {
    val context = LocalContext.current
    var fabExpanded by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<SavedSession?>(null) }
    var deleteTarget by remember { mutableStateOf<SavedSession?>(null) }

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
                    /* Shizuku 同款下拉:开放源代码在上,关于在下(§9) */
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.menu_open_source)) },
                            onClick = { menuOpen = false; onOpenSource() },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.menu_about)) },
                            onClick = { menuOpen = false; onAbout() },
                        )
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
                            if (sessions.isEmpty()) {
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
                                                    Icons.Default.Lock,
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

    renameTarget?.let { s ->
        RenameSessionDialog(
            initialName = s.name,
            onDismiss = { renameTarget = null },
            onConfirm = { onRenameSession(s, it) },
        )
    }

    deleteTarget?.let { s ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.home_delete_title)) },
            text = { Text(stringResource(R.string.home_delete_text)) },
            confirmButton = {
                TextButton(onClick = {
                    onDeleteSession(s)
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
}
