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

import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Attachment
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import sealing.wax.FileMeta
import sealing.wax.OpenResult
import sealing.wax.SessionManager
import sealing.wax.SwxVerdict
import sealing.wax.UiMessage
import sealing.wax.store.DIR_SENT
import java.io.File
import java.text.DateFormat
import java.util.Date

/** 对话屏:五个动作全部一键化(§5),KPI = 平文 + 1 步。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    title: String,
    isSaved: Boolean,
    onExit: () -> Unit,
    onRenameTitle: ((String) -> Unit)? = null,
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    var renameOpen by remember { mutableStateOf(false) }
    var input by remember { mutableStateOf("") }
    var openNote by remember { mutableStateOf<String?>(null) }
    var panelOpen by remember { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }
    var sasOpen by remember { mutableStateOf(false) }
    var saveDialog by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf<String?>(null) }
    var pendingSwx by remember { mutableStateOf<Uri?>(null) }
    var swxVerdict by remember { mutableStateOf<String?>(null) }
    var swxHash by remember { mutableStateOf<ByteArray?>(null) }

    val sas = SessionManager.sas

    val listState = rememberLazyListState()
    LaunchedEffect(SessionManager.messages.size) {
        if (SessionManager.messages.isNotEmpty()) {
            listState.animateScrollToItem(SessionManager.messages.size - 1)
        }
    }

    /* 粘贴即解密(§5/§15):防抖后在活会话上直接试解——成功即收文,
     * [解密]按钮不存在;E_FORMAT = 普通输入,静默;其余如实提示 */
    val keyboard = LocalSoftwareKeyboardController.current
    LaunchedEffect(input) {
        if (input.isBlank()) return@LaunchedEffect
        delay(150)    /* 防抖:打字停顿后才试解;每次 input 变化重启本协程 */
        val r = try {
            SessionManager.openPasted(input)
        } catch (e: IllegalStateException) {
            return@LaunchedEffect    /* 无活跃会话等边缘,静默 */
        }
        when (r) {
            is OpenResult.Complete -> {
                input = ""
                openNote = null
            }
            is OpenResult.Partial -> {
                input = ""
                openNote = "已收 ${r.got}/${r.total} 片,继续粘贴其余分片…"
            }
            /* 提示是当前内容的纯函数:普通输入(E_FORMAT)清除旧提示,
             * 不残留上一次的报错;其余错误如实显示(真机反馈 2026-11) */
            is OpenResult.Failure ->
                openNote = if (r.code == "SWX_E_FORMAT") null else r.message
        }
    }

    /* 发文件:SAF 选源文件 → 加密成 .swx 暂存 → 分享到 IM */
    val pickSource = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) scope.launch {
            try {
                busy = "正在加密文件…"
                val resolver = context.contentResolver
                var name = "file"
                var size = -1L
                resolver.query(uri, null, null, null, null)?.use { c ->
                    val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val si = c.getColumnIndex(OpenableColumns.SIZE)
                    if (c.moveToFirst()) {
                        if (ni >= 0) c.getString(ni)?.let { name = it }
                        if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
                    }
                }
                if (size < 0) {
                    size = resolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
                }
                require(size >= 0) { "无法确定文件大小" }
                val outFile = File(SessionManager.shareDir(context), "$name.swx")
                withContext(Dispatchers.IO) {
                    resolver.openInputStream(uri)!!.use { i ->
                        outFile.outputStream().use { o ->
                            SessionManager.sealFile(i, FileMeta(name, size), o)
                        }
                    }
                }
                busy = null
                val shareUri = FileProvider.getUriForFile(
                    context, "${context.packageName}.fileprovider", outFile,
                )
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "application/octet-stream"
                    putExtra(Intent.EXTRA_STREAM, shareUri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                context.startActivity(Intent.createChooser(intent, "分享密文文件到 IM"))
            } catch (e: Exception) {
                busy = null
                Toast.makeText(context, "加密失败:${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    /* 收文件 pass 1:SAF 选 .swx → 整流 hash → 账本对账 */
    val pickSwx = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) scope.launch {
            try {
                busy = "正在对账…"
                val hash = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)!!.use {
                        SessionManager.inspectSwx(it)
                    }
                }
                swxHash = hash
                swxVerdict = when (val v = SessionManager.verdictFor(hash)) {
                    is SwxVerdict.Matched ->
                        "✓ 就是当时那条:${v.entry.name}(${v.entry.size} B,${dirLabel(v.entry.dir)})"
                    SwxVerdict.Mismatch ->
                        "✗ 不是当初的文件(账本中没有这个 hash)"
                    SwxVerdict.NoLedger ->
                        "本会话没有账本记录,跳过对账"
                }
                pendingSwx = uri
                busy = null
            } catch (e: Exception) {
                busy = null
                Toast.makeText(context, "读取失败:${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    /* 收文件 pass 2:SAF 选导出目标 → 解密导出(明文只经过流) */
    val pickTarget = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val src = pendingSwx
        val hash = swxHash
        if (uri != null && src != null && hash != null) scope.launch {
            try {
                busy = "正在解密…"
                withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(src)!!.use { i ->
                        context.contentResolver.openOutputStream(uri)!!.use { o ->
                            SessionManager.decryptSwx(i, o, hash)
                        }
                    }
                }
                pendingSwx = null
                swxVerdict = null
                busy = null
                Toast.makeText(context, "已解密导出", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                busy = null
                Toast.makeText(context, "解密失败:${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    fun doExit() {
        if (isSaved) {
            SessionManager.exitConversation(context)
            onExit()
        } else {
            saveDialog = true
        }
    }

    /* system back follows the same save-or-discard flow (§5) */
    androidx.activity.compose.BackHandler { doExit() }

    Scaffold(
        topBar = {
            /* 标题居左(2026-11):紧邻返回;已保存会话点标题改名(§5) */
            TopAppBar(
                title = {
                    Text(
                        title,
                        modifier = if (isSaved && onRenameTitle != null) {
                            Modifier.clickable { renameOpen = true }
                        } else {
                            Modifier
                        },
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { doExit() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "退出对话")
                    }
                },
                actions = {
                    /* SAS 常驻仪表盘(§9):一直在,不需要点出来;点击放大核对 */
                    if (sas != null && sas.length == 9) {
                        TextButton(onClick = { sasOpen = true }) {
                            Text(
                                "${sas.substring(0, 3)} ${sas.substring(3, 6)} ${sas.substring(6, 9)}",
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                style = MaterialTheme.typography.labelLarge,
                            )
                        }
                    }
                    /* 通用菜单(三横线):后期可承载更多设置项 */
                    IconButton(onClick = { menuOpen = true }) {
                        Icon(Icons.Default.Menu, contentDescription = "更多")
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = {
                                Column {
                                    Text(
                                        "长度混淆 · " +
                                            if (SessionManager.paddingEnabled) "开" else "关",
                                    )
                                    Text(
                                        "短消息等长;阈值 ${SessionManager.paddingThreshold} 字符",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                            },
                            onClick = {},
                            trailingIcon = {
                                Switch(
                                    checked = SessionManager.paddingEnabled,
                                    onCheckedChange = { on ->
                                        menuOpen = false
                                        SessionManager.setPadding(on, SessionManager.paddingThreshold)
                                    },
                                )
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("切换阈值 500 / 1000 / 2000 / 4000") },
                            onClick = {
                                val next = when (SessionManager.paddingThreshold) {
                                    500 -> 1000
                                    1000 -> 2000
                                    2000 -> 4000
                                    else -> 500
                                }
                                SessionManager.setPadding(true, next)
                                menuOpen = false
                            },
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
                .imePadding(),
        ) {
            /* transcript */
            LazyColumn(
                state = listState,
                modifier = Modifier.weight(1f).fillMaxWidth(),
                contentPadding = PaddingValues(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(SessionManager.messages) { m -> MessageBubble(m) }
                item { Spacer(Modifier.height(4.dp)) }
            }

            /* 统一输入栏(2026-11):收/发一体,粘贴即解密;解密按钮已删除 */
            Card(
                modifier = Modifier.fillMaxWidth().padding(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            ) {
                Column(
                    Modifier.padding(10.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.Bottom,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedTextField(
                            value = input,
                            onValueChange = { input = it },
                            modifier = Modifier.weight(0.8f),
                            label = { Text("明文,或粘贴 IM 密文") },
                            minLines = 1,
                            maxLines = 5,
                        )
                        /* 右槽 0.2:空框 = "+",有字 = [加密并复制](微信式) */
                        if (input.isEmpty()) {
                            Button(
                                onClick = {
                                    keyboard?.hide()
                                    panelOpen = !panelOpen
                                },
                                modifier = Modifier.weight(0.2f),
                                contentPadding = PaddingValues(0.dp),
                            ) {
                                Icon(Icons.Default.Add, contentDescription = "发文件等入口")
                            }
                        } else {
                            Button(
                                onClick = {
                                    val pieces = SessionManager.sealText(input)
                                    clipboard.setText(AnnotatedString(pieces.joinToString("\n")))
                                    input = ""
                                    panelOpen = false
                                    Toast.makeText(
                                        context,
                                        if (pieces.size == 1) "已加密并复制,去 IM 粘贴"
                                        else "已加密 ${pieces.size} 片并全部复制,一次粘贴即可",
                                        Toast.LENGTH_SHORT,
                                    ).show()
                                },
                                modifier = Modifier.weight(0.2f),
                                contentPadding = PaddingValues(0.dp),
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.Send,
                                    contentDescription = "加密并复制",
                                )
                            }
                        }
                    }
                    if (openNote != null) {
                        Text(
                            openNote!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.tertiary,
                        )
                    }
                    /* "+"面板:可扩展入口磁贴(未来特殊消息往这里加格) */
                    if (panelOpen) {
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            PanelTile(
                                icon = { Icon(Icons.Default.Attachment, contentDescription = null) },
                                label = "发文件",
                                onClick = {
                                    panelOpen = false
                                    pickSource.launch(arrayOf("*/*"))
                                },
                            )
                            PanelTile(
                                icon = { Icon(Icons.Default.Lock, contentDescription = null) },
                                label = "收文件",
                                onClick = {
                                    panelOpen = false
                                    pickSwx.launch(arrayOf("*/*"))
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    /* 会话内改名(§5:点顶栏名称;仅已保存会话,与首页长按共用弹窗) */
    if (renameOpen) {
        RenameSessionDialog(
            initialName = title,
            onDismiss = { renameOpen = false },
            onConfirm = { n -> onRenameTitle?.invoke(n) },
        )
    }

    /* SAS 放大核对(§9:大号数字点击即复制,二维码扫码;无按钮,
     * 点空白关闭——DismissRequest) */
    if (sasOpen && sas != null) {
        AlertDialog(
            onDismissRequest = { sasOpen = false },
            title = { Text("身份验证码") },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        "电话念码、当面扫码,或点击数字复制。\n对不上 = 立即中止会话。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    SasDigits(
                        sas,
                        Modifier.clickable {
                            clipboard.setText(AnnotatedString(sas))
                            Toast.makeText(context, "验证码已复制", Toast.LENGTH_SHORT).show()
                        },
                    )
                    QrCode(content = sas)
                }
            },
            /* M3 要求 confirmButton 必传;空槽 = 无按钮,点空白关闭 */
            confirmButton = {},
        )
    }

    /* exit: save-or-discard (unsaved only; §5/§6) */
    if (saveDialog) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { saveDialog = false },
            title = { Text("保存这个会话吗?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "不保存 = 全部清零,零状态。\n" +
                            "保存的代价:设备被掌控且解锁时,该会话历史可被解;换机即全丢。\n" +
                            "单方保存无效:对方没存,下次对方解不开。"
                    )
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text("会话名称(不是联系人)") },
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        SessionManager.saveLiveAs(name.ifBlank { "未命名会话" }, context)
                        SessionManager.exitConversation(context)
                        saveDialog = false
                        Toast.makeText(context, "已保存", Toast.LENGTH_SHORT).show()
                        onExit()
                    },
                ) { Text("保存") }
            },
            dismissButton = {
                TextButton(onClick = {
                    SessionManager.exitConversation(context)
                    saveDialog = false
                    onExit()
                }) { Text("不保存") }
            },
        )
    }

    /* inbound .swx: verdict → peek name → export target */
    if (pendingSwx != null) {
        AlertDialog(
            onDismissRequest = { pendingSwx = null; swxVerdict = null },
            title = { Text("对账结果") },
            text = { Text(swxVerdict ?: "…") },
            confirmButton = {
                TextButton(onClick = {
                    val src = pendingSwx
                    if (src != null) scope.launch {
                        try {
                            busy = "正在读取文件名…"
                            val meta = withContext(Dispatchers.IO) {
                                context.contentResolver.openInputStream(src)!!.use {
                                    SessionManager.peekSwxMeta(it)
                                }
                            }
                            busy = null
                            pickTarget.launch(meta.name)
                        } catch (e: Exception) {
                            busy = null
                            Toast.makeText(context, "读取失败:${e.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }) { Text("解密并导出") }
            },
            dismissButton = {
                TextButton(onClick = { pendingSwx = null; swxVerdict = null }) { Text("取消") }
            },
        )
    }

    busy?.let { b ->
        AlertDialog(
            onDismissRequest = {},
            title = { Text(b) },
            text = { Text("请稍候…") },
            confirmButton = {},
        )
    }
}

@Composable
private fun MessageBubble(m: UiMessage) {
    val mine = m.dir == DIR_SENT
    Box(
        Modifier.fillMaxWidth(),
        contentAlignment = if (mine) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Card(
            modifier = Modifier.widthIn(max = 320.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (mine) MaterialTheme.colorScheme.primaryContainer
                else MaterialTheme.colorScheme.surfaceVariant,
            ),
        ) {
            Column(Modifier.padding(10.dp)) {
                Text(m.text, style = MaterialTheme.typography.bodyMedium)
                Text(
                    DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(m.ts)) +
                        if (m.pieces.size > 1) " · ${m.pieces.size} 片" else "",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun dirLabel(dir: Int): String = if (dir == DIR_SENT) "我发出" else "我收到"

/** "+"面板入口磁贴(微信式):方形图标 + 标签;未来特殊消息加格即可。 */
@Composable
private fun PanelTile(
    icon: @Composable () -> Unit,
    label: String,
    onClick: () -> Unit,
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(4.dp),
    ) {
        Box(
            Modifier
                .size(52.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.45f)),
            contentAlignment = Alignment.Center,
        ) { icon() }
        Spacer(Modifier.height(4.dp))
        Text(label, style = MaterialTheme.typography.labelMedium)
    }
}
