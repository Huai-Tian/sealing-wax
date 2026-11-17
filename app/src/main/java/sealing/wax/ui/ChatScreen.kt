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

import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
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
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Attachment
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import sealing.wax.FileMeta
import sealing.wax.OpenResult
import sealing.wax.R
import sealing.wax.SessionManager
import sealing.wax.UiMessage
import sealing.wax.store.DIR_SENT
import java.io.File
import java.text.DateFormat
import java.util.Date

/** 长度混淆阈值档位(第六批,所有者定夺):等比数列,r = 20^(1/5) ≈ 1.82,
 *  精确命中核心区间端点 [200, 4000];单片容量 = T×3/4−66 字节,即
 *  28 / 69 / 144 / 280 / 528 / 978 字。无默认档——开启必从列表选档,
 *  关闭时分割 = 单片上限(非混淆,不受本表影响)。须为 4 的倍数。 */
private val PAD_THRESHOLDS = intArrayOf(200, 364, 664, 1208, 2200, 4000)

/** 对话屏:五个动作全部一键化(§5),KPI = 平文 + 1 步。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    title: String,
    isSaved: Boolean,
    onExit: () -> Unit,
    onRenameTitle: ((String) -> Unit)? = null,
    /** 未保存会话点顶栏标题 → 命名并立即保存后回调(第九批):
     *  宿主借此翻转 title/isSaved,此后点题走改名 */
    onLiveSaved: ((String) -> Unit)? = null,
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    var renameOpen by remember { mutableStateOf(false) }
    var input by remember { mutableStateOf("") }
    var openNote by remember { mutableStateOf<String?>(null) }
    var panelOpen by remember { mutableStateOf(false) }
    var sasOpen by remember { mutableStateOf(false) }
    var saveDialog by remember { mutableStateOf(false) }
    var saveNowOpen by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf<String?>(null) }
    var pendingSwx by remember { mutableStateOf<Uri?>(null) }
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
                openNote = context.getString(R.string.chat_partial_note, r.got, r.total)
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
                busy = context.getString(R.string.busy_encrypting)
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
                require(size >= 0) { "SWX_E_META" }
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
                context.startActivity(
                    Intent.createChooser(intent, context.getString(R.string.share_chooser))
                )
            } catch (e: Exception) {
                busy = null
                Log.w("SealingWax", "seal file failed", e)
                Toast.makeText(
                    context,
                    SessionManager.stableError(context.getString(R.string.err_seal_failed), e),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    /* 收文件 pass 2:SAF 选导出目标 → 解密导出(明文只经过流)。声明在
     * pass 1 之前——pass 1 完成后直接 launch 它 */
    val pickTarget = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val src = pendingSwx
        val hash = swxHash
        if (uri != null && src != null && hash != null) scope.launch {
            try {
                busy = context.getString(R.string.busy_decrypting)
                withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(src)!!.use { i ->
                        context.contentResolver.openOutputStream(uri)!!.use { o ->
                            SessionManager.decryptSwx(i, o, hash)
                        }
                    }
                }
                pendingSwx = null
                swxHash = null
                busy = null
                Toast.makeText(
                    context, context.getString(R.string.decrypted_exported), Toast.LENGTH_SHORT,
                ).show()
            } catch (e: Exception) {
                busy = null
                Log.w("SealingWax", "decrypt swx failed", e)
                Toast.makeText(
                    context,
                    SessionManager.stableError(context.getString(R.string.err_decrypt_failed), e),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    /* 收文件 pass 1:SAF 选 .swx → 整流 hash(记账依据) → 读文件名 → 直接
     * 进入导出目标选择。确认弹窗已移除(所有者指示):用户既然导入就是要
     * 解密,"账上没有"是首次收文件的常态,提示与二次确认都无意义 */
    val pickSwx = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) scope.launch {
            try {
                busy = context.getString(R.string.busy_reading_name)
                val hash = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)!!.use {
                        SessionManager.inspectSwx(it)
                    }
                }
                swxHash = hash
                pendingSwx = uri
                val meta = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)!!.use {
                        SessionManager.peekSwxMeta(it)
                    }
                }
                busy = null
                pickTarget.launch(meta.name)
            } catch (e: Exception) {
                busy = null
                pendingSwx = null
                swxHash = null
                Log.w("SealingWax", "inspect swx failed", e)
                Toast.makeText(
                    context,
                    SessionManager.stableError(context.getString(R.string.err_read_failed), e),
                    Toast.LENGTH_LONG,
                ).show()
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
                        modifier = when {
                            isSaved && onRenameTitle != null ->
                                Modifier.clickable { renameOpen = true }
                            /* 未保存会话:点题 = 命名并立即保存(第九批);
                             * 保存经 onLiveSaved 翻转 isSaved 后走改名 */
                            !isSaved && onLiveSaved != null ->
                                Modifier.clickable { saveNowOpen = true }
                            else -> Modifier
                        },
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { doExit() }) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.chat_exit_cd),
                        )
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
                    /* 通用菜单(三横线):Shizuku 溢出菜单同款几何(第六批同步);
                     * 长度混淆 = 单行,开关与阈值合并为右侧下拉(所有者指示) */
                    Box {
                        var menuOpen by remember { mutableStateOf(false) }
                        var padOpen by remember { mutableStateOf(false) }
                        IconButton(onClick = { menuOpen = true }) {
                            Icon(Icons.Default.Menu, contentDescription = stringResource(R.string.chat_menu_cd))
                        }
                        OverflowMenu(
                            expanded = menuOpen,
                            onDismissRequest = {
                                menuOpen = false
                                padOpen = false
                            },
                        ) {
                            Box {
                                /* 行必须带菜单最小宽:外层菜单仅此一行,宽度跟随
                                 * 行内蕴宽度,不带最小宽会把标签和当前值挤到
                                 * 一起(真机反馈,第六批收尾) */
                                Row(
                                    Modifier
                                        .fillMaxWidth()
                                        .widthIn(min = OverflowMenuRowMinWidth)
                                        .heightIn(min = 48.dp)
                                        .clickable { padOpen = !padOpen }
                                        .padding(horizontal = 16.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        stringResource(R.string.menu_length_padding),
                                        style = MaterialTheme.typography.bodyLarge,
                                        modifier = Modifier.weight(1f),
                                    )
                                    /* 当前值:12sp 蓝色小字,与标签拉开层次
                                     * (所有者指示,第六批收尾) */
                                    Text(
                                        if (SessionManager.paddingEnabled) {
                                            SessionManager.paddingThreshold.toString()
                                        } else {
                                            stringResource(R.string.padding_off)
                                        },
                                        style = MaterialTheme.typography.labelMedium,
                                        color = accentBlue(),
                                    )
                                    Icon(
                                        Icons.Default.ArrowDropDown,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                /* 嵌套下拉:关闭 + 阈值档位(等比 ×1.82);选档后
                                 * 仅关闭本层——外层菜单留着,让用户看到新当前值
                                 * (真机反馈,第六批收尾) */
                                OverflowMenu(
                                    expanded = padOpen,
                                    onDismissRequest = { padOpen = false },
                                ) {
                                    OverflowMenuItem(stringResource(R.string.padding_off)) {
                                        SessionManager.setPadding(false, SessionManager.paddingThreshold)
                                        padOpen = false
                                    }
                                    PAD_THRESHOLDS.forEach { t ->
                                        OverflowMenuItem(t.toString()) {
                                            SessionManager.setPadding(true, t)
                                            padOpen = false
                                        }
                                    }
                                }
                            }
                        }
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
                            label = { Text(stringResource(R.string.input_label)) },
                            minLines = 1,
                            maxLines = 5,
                            trailingIcon = { ClearFieldIcon(input) { input = "" } },
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
                                Icon(Icons.Default.Add, contentDescription = stringResource(R.string.plus_cd))
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
                                        if (pieces.size == 1) {
                                            context.getString(R.string.sealed_toast_one)
                                        } else {
                                            context.getString(R.string.sealed_toast_many, pieces.size)
                                        },
                                        Toast.LENGTH_SHORT,
                                    ).show()
                                },
                                modifier = Modifier.weight(0.2f),
                                contentPadding = PaddingValues(0.dp),
                            ) {
                                Icon(
                                    Icons.AutoMirrored.Filled.Send,
                                    contentDescription = stringResource(R.string.seal_cd),
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
                                label = stringResource(R.string.tile_send),
                                onClick = {
                                    panelOpen = false
                                    pickSource.launch(arrayOf("*/*"))
                                },
                            )
                            PanelTile(
                                icon = { Icon(Icons.Default.Lock, contentDescription = null) },
                                label = stringResource(R.string.tile_receive),
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
            title = { Text(stringResource(R.string.sas_dialog_title)) },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    SasDigits(
                        sas,
                        Modifier.clickable {
                            clipboard.setText(AnnotatedString(sas))
                            Toast.makeText(
                                context,
                                context.getString(R.string.sas_copied_toast),
                                Toast.LENGTH_SHORT,
                            ).show()
                        },
                    )
                    QrCode(content = sas)
                    /* 红字提示在二维码下方(第十批):标准+违约后果;
                     * 收尾:拆两行逐行居中(第一行较长,textAlign 保证
                     * 第二行不随块左对齐)、句号改叹号。核对方法与点击复制
                     * 说明撤除(点击行为保留,Toast 反馈) */
                    Text(
                        stringResource(R.string.sas_dialog_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center,
                    )
                }
            },
            /* M3 要求 confirmButton 必传;空槽 = 无按钮,点空白关闭 */
            confirmButton = {},
        )
    }

    /* 未保存会话点顶栏标题:命名并立即保存(第九批,§6 第二保存入口)。
     * 保存后不离开对话继续聊(活会话与信封同钥,后续消息经 saved 路径
     * 记账);isSaved 翻转后退出不再弹保存窗——"已保存过不再打扰" */
    if (saveNowOpen) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { saveNowOpen = false },
            title = { Text(stringResource(R.string.save_now_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.save_text))
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text(stringResource(R.string.save_name_label)) },
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val finalName =
                            name.ifBlank { context.getString(R.string.unnamed_session) }
                        SessionManager.saveLiveAs(finalName, context)
                        saveNowOpen = false
                        onLiveSaved?.invoke(finalName)
                        Toast.makeText(
                            context, context.getString(R.string.saved_toast), Toast.LENGTH_SHORT,
                        ).show()
                    },
                ) { Text(stringResource(R.string.save_btn)) }
            },
            dismissButton = {
                TextButton(onClick = { saveNowOpen = false }) {
                    Text(stringResource(R.string.common_cancel))
                }
            },
        )
    }

    /* exit: save-or-discard (unsaved only; §5/§6) */
    if (saveDialog) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { saveDialog = false },
            title = { Text(stringResource(R.string.save_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.save_text))
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text(stringResource(R.string.save_name_label)) },
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        SessionManager.saveLiveAs(
                            name.ifBlank { context.getString(R.string.unnamed_session) }, context,
                        )
                        SessionManager.exitConversation(context)
                        saveDialog = false
                        Toast.makeText(
                            context, context.getString(R.string.saved_toast), Toast.LENGTH_SHORT,
                        ).show()
                        onExit()
                    },
                ) { Text(stringResource(R.string.save_btn)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    SessionManager.exitConversation(context)
                    saveDialog = false
                    onExit()
                }) { Text(stringResource(R.string.discard_btn)) }
            },
        )
    }

    busy?.let { b ->
        AlertDialog(
            onDismissRequest = {},
            title = { Text(b) },
            text = { Text(stringResource(R.string.busy_please_wait)) },
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
                        if (m.pieces.size > 1) {
                            stringResource(R.string.chat_pieces_badge, m.pieces.size)
                        } else "",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

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
