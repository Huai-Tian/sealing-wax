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
package sealing.wax

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import sealing.wax.store.Persistence
import sealing.wax.store.SavedSession
import sealing.wax.ui.ChatScreen
import sealing.wax.ui.HomeScreen
import sealing.wax.ui.JoinSessionScreen
import sealing.wax.ui.NewSessionScreen
import sealing.wax.ui.theme.SealingWaxTheme

/** 导航:无导航库,一个密封类 + 返回处理足够。 */
private sealed interface Dest {
    data object Home : Dest
    data object NewSession : Dest
    data object JoinSession : Dest
    data object Chat : Dest
}

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        /* 截屏保护:禁截屏与最近任务缩略图 (§9) */
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        enableEdgeToEdge()

        SessionManager.appContext = applicationContext
        /* 上次遗留的分享暂存清掉;密文缓存不该比会话活得更久 */
        SessionManager.clearShareStaging()

        setContent {
            SealingWaxTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    App()
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        /* §4 同步时机:进入后台(切 IM 是常态,后台被杀是常态) */
        SessionManager.syncNow(applicationContext)
    }
}

@Composable
private fun App() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var dest by remember { mutableStateOf<Dest>(Dest.Home) }
    var sessions by remember { mutableStateOf(listOf<SavedSession>()) }
    var chatTitle by remember { mutableStateOf("会话") }
    var chatSaved by remember { mutableStateOf(false) }

    fun reload() {
        scope.launch {
            val list = withContext(Dispatchers.IO) { Persistence.listSessions(context) }
            sessions = list
        }
    }

    fun goHome() {
        dest = Dest.Home
        reload()
    }

    when (dest) {
        Dest.Home -> {
            /* 退出 App:直接清零,无弹窗 (§5) —— 未保存会话随进程消失 */
            BackHandler { (context as? Activity)?.finish() }
            HomeScreen(
                sessions = sessions,
                onNewSession = { dest = Dest.NewSession },
                onJoinSession = { dest = Dest.JoinSession },
                onOpenSession = { id ->
                    scope.launch {
                        runCatching { SessionManager.openSaved(context, id) }
                            .onSuccess {
                                chatTitle = SessionManager.saved?.name ?: "会话"
                                chatSaved = true
                                dest = Dest.Chat
                            }
                            .onFailure {
                                Toast.makeText(
                                    context, "打开失败:${it.message}", Toast.LENGTH_LONG,
                                ).show()
                            }
                    }
                },
                onRenameSession = { s, name ->
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            val loaded = Persistence.readSession(context, s.id)
                            if (loaded != null) {
                                loaded.name = name
                                Persistence.saveSession(context, loaded)
                            }
                        }
                        reload()
                    }
                },
                onDeleteSession = { s ->
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            Persistence.deleteSession(context, s.id)
                        }
                        reload()
                    }
                },
            )
        }

        Dest.NewSession -> {
            BackHandler {
                SessionManager.abortPairing()
                goHome()
            }
            NewSessionScreen(
                onBack = { goHome() },
                onPaired = {
                    /* PAKE finished and the confirm verified: straight to chat;
                     * SAS rides the top bar (§5: 无确认页) */
                    SessionManager.beginConversation()
                    chatTitle = "未命名会话"
                    chatSaved = false
                    dest = Dest.Chat
                },
            )
        }

        Dest.JoinSession -> {
            BackHandler {
                SessionManager.abortPairing()
                goHome()
            }
            JoinSessionScreen(
                onBack = { goHome() },
                onJoined = {
                    SessionManager.beginConversation()
                    chatTitle = "未命名会话"
                    chatSaved = false
                    dest = Dest.Chat
                },
            )
        }

        Dest.Chat -> {
            /* system back follows the same save-or-discard flow as the
             * top-bar back arrow (registered inside ChatScreen) */
            ChatScreen(
                title = chatTitle,
                isSaved = chatSaved,
                onExit = { goHome() },
            )
        }
    }
}
