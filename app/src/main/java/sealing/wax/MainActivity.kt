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
import android.util.Log
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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import sealing.wax.store.Persistence
import sealing.wax.ui.ChatScreen
import sealing.wax.ui.HomeScreen
import sealing.wax.ui.JoinSessionScreen
import sealing.wax.ui.NewSessionScreen
import sealing.wax.ui.OpenSourceScreen
import sealing.wax.ui.SessionListState
import sealing.wax.ui.theme.SealingWaxTheme

/** 导航:无导航库,一个密封类 + 返回处理足够。 */
private sealed interface Dest {
    data object Home : Dest
    data object NewSession : Dest
    data object JoinSession : Dest
    data object Chat : Dest
    data object OpenSource : Dest
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
    var chatTitle by remember { mutableStateOf(context.getString(R.string.chat_default_title)) }
    var chatSaved by remember { mutableStateOf(false) }
    var listState by remember { mutableStateOf<SessionListState>(SessionListState.Loading) }

    /* 读取是一个显式状态机,空列表只在 Ready 里有意义——"还在加载"与
     * "读不出来"不再伪装成"没有会话"(真机反馈 2026-11 的结构性修复)。
     * 加载在 Loading 态内保持耐心:目录在而列表空 = 瞬时失败(冷启动
     * 极早期 Tink/Keystore 首次初始化可能未热),退避重试后才判 Failed */
    fun reload() {
        scope.launch {
            listState = SessionListState.Loading
            var list = withContext(Dispatchers.IO) { Persistence.listSessions(context) }
            var failed = list.isEmpty() &&
                    withContext(Dispatchers.IO) { Persistence.sessionDirCount(context) } > 0
            var attempt = 0
            while (failed && attempt < 3) {
                attempt++
                delay(300L * attempt)    /* 300 / 600 / 900ms,加载动画之下 */
                list = withContext(Dispatchers.IO) { Persistence.listSessions(context) }
                failed = list.isEmpty() &&
                        withContext(Dispatchers.IO) {
                            Persistence.sessionDirCount(context)
                        } > 0
            }
            listState = if (failed) SessionListState.Failed
                       else SessionListState.Ready(list)
        }
    }

    fun goHome() {
        dest = Dest.Home
        reload()
    }

    /* 双触发:首次组合开读;此后每次 ON_RESUME 仅对 Failed 自动重试
     * (Ready 时不刷——切 IM 返回不该闪加载态;Loading 中不重复开读) */
    LaunchedEffect(Unit) { reload() }
    val owner = LocalContext.current as? ComponentActivity
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_RESUME &&
                listState is SessionListState.Failed
            ) {
                reload()
            }
        }
        owner?.lifecycle?.addObserver(obs)
        onDispose { owner?.lifecycle?.removeObserver(obs) }
    }

    when (dest) {
        Dest.Home -> {
            /* 退出 App:直接清零,无弹窗 (§5) —— 未保存会话随进程消失 */
            BackHandler { (context as? Activity)?.finish() }
            HomeScreen(
                state = listState,
                onRetryLoad = { reload() },
                onNewSession = { dest = Dest.NewSession },
                onJoinSession = { dest = Dest.JoinSession },
                onOpenSession = { id ->
                    scope.launch {
                        runCatching { SessionManager.openSaved(context, id) }
                            .onSuccess {
                                chatTitle = SessionManager.saved?.name
                                    ?: context.getString(R.string.chat_default_title)
                                chatSaved = true
                                dest = Dest.Chat
                            }
                            .onFailure {
                                Log.w("SealingWax", "openSaved failed", it)
                                Toast.makeText(
                                    context,
                                    SessionManager.stableError(
                                        context.getString(R.string.err_open_failed), it,
                                    ),
                                    Toast.LENGTH_LONG,
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
                onOpenSource = { dest = Dest.OpenSource },
            )
        }

        Dest.OpenSource -> {
            BackHandler { goHome() }
            OpenSourceScreen(onBack = { goHome() })
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
                    chatTitle = context.getString(R.string.unnamed_session)
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
                    chatTitle = context.getString(R.string.unnamed_session)
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
                onRenameTitle = { name ->
                    if (SessionManager.renameCurrent(name)) chatTitle = name
                },
                onExit = { goHome() },
            )
        }
    }
}
