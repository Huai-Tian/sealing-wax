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

import android.graphics.Bitmap
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.tween
import androidx.compose.animation.core.rememberTransition
import androidx.compose.foundation.Image
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntRect
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupPositionProvider
import androidx.compose.ui.window.PopupProperties
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import sealing.wax.R

/** Big grouped SAS display: 123-456-789. */
@Composable
fun SasDigits(sas: String, modifier: Modifier = Modifier) {
    val grouped = remember(sas) {
        if (sas.length == 9) "${sas.substring(0, 3)} ${sas.substring(3, 6)} ${sas.substring(6, 9)}" else sas
    }
    Text(
        text = grouped,
        modifier = modifier,
        fontSize = 44.sp,
        fontWeight = FontWeight.Bold,
        fontFamily = FontFamily.Monospace,
        letterSpacing = 2.sp,
    )
}

/** QR rendering without camera permissions (content = the 9 digits). */
@Composable
fun QrCode(content: String, size: Int = 220, modifier: Modifier = Modifier) {
    val bitmap = remember(content) {
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size)
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bmp.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
            }
        }
        bmp
    }
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        color = Color.White,
    ) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = stringResource(R.string.qr_sas_cd),
            modifier = Modifier.size(size.dp).padding(8.dp),
        )
    }
}

/** Wire-code card: monospace body + optional trailing copy button. */
@Composable
fun CodeCard(
    title: String,
    code: String,
    modifier: Modifier = Modifier,
    action: (@Composable () -> Unit)? = null,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                action?.invoke()
            }
            Text(
                code,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                lineHeight = 20.sp,
                modifier = Modifier.background(
                    MaterialTheme.colorScheme.surface,
                    RoundedCornerShape(8.dp),
                ).padding(10.dp).fillMaxWidth(),
            )
        }
    }
}

/** 重命名会话弹窗(§5):首页长按与对话屏点标题共用。命名的对象是
 *  会话(一把钥匙),不是联系人。空名不确认。 */
@Composable
fun RenameSessionDialog(
    initialName: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var name by remember(initialName) { mutableStateOf(initialName) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.rename_title)) },
        text = {
            Column {
                Text(stringResource(R.string.rename_hint))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (name.isNotBlank()) onConfirm(name.trim())
                onDismiss()
            }) { Text(stringResource(R.string.common_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) }
        },
    )
}

/* ---- Shizuku 式溢出菜单(所有者指示,UI 优化第五批) ---- */

/** appcompat 溢出菜单(Shizuku 首页 ⋮ 同款)的几何,来源逐项核对过:
 *  abc_popup_menu_item_layout 的 minWidth 196dip、
 *  dropdownListPreferredItemHeight = listPreferredItemHeightSmall = 48dp、
 *  文字内缩 16dp、列表无容器竖向内边距。M3 DropdownMenu 默认
 *  (112dp 最小宽 + 上下各 8dp 内边距)呈正方形,比例偏方——本组件
 *  复刻 Shizuku 的宽高比(两项 ≈ 196×96,≈2:1 横向矩形)。 */
private val OverflowMenuMinWidth = 196.dp
private val OverflowMenuItemHeight = 48.dp
private val OverflowMenuItemPadding = 16.dp

/**
 * Shizuku 溢出菜单同款比例的下拉菜单。放进包住锚点按钮的 Box 里使用
 * (锚点 = 父布局,与 DropdownMenu 相同);条目用 [OverflowMenuItem]。
 * 选项多时自动纵向滚动。
 */
@Composable
fun OverflowMenu(
    expanded: Boolean,
    onDismissRequest: () -> Unit,
    modifier: Modifier = Modifier,
    scrollState: ScrollState = rememberScrollState(),
    content: @Composable ColumnScope.() -> Unit,
) {
    val expandedState = remember { MutableTransitionState(false) }
    expandedState.targetState = expanded

    if (expandedState.currentState || expandedState.targetState) {
        Popup(
            onDismissRequest = onDismissRequest,
            popupPositionProvider = OverflowMenuPositionProvider,
            properties = PopupProperties(focusable = true),
        ) {
            /* 开合动画与 M3 DropdownMenu 同款:缩放 + 淡入,绕锚点角 */
            val transition = rememberTransition(expandedState, "OverflowMenu")
            val scale by transition.animateFloat(transitionSpec = { tween(150) }) {
                if (it) 1f else 0.8f
            }
            val alpha by transition.animateFloat(transitionSpec = { tween(150) }) {
                if (it) 1f else 0f
            }
            val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
            Surface(
                modifier = modifier.graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                    this.alpha = alpha
                    transformOrigin = TransformOrigin(if (rtl) 0f else 1f, 0f)
                },
                shape = MenuDefaults.shape,
                color = MenuDefaults.containerColor,
                shadowElevation = MenuDefaults.ShadowElevation,
            ) {
                /* 无竖向内边距:行高 48dp 连续堆叠,同 appcompat 溢出列表 */
                Column(
                    Modifier
                        .width(IntrinsicSize.Max)
                        .verticalScroll(scrollState),
                    content = content,
                )
            }
        }
    }
}

/** 溢出菜单条目:48dp 行高、16dp 文字内缩、整行最小宽 196dp。 */
@Composable
fun OverflowMenuItem(text: String, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .widthIn(min = OverflowMenuMinWidth)
            .heightIn(min = OverflowMenuItemHeight)
            .clickable(onClick = onClick)
            .padding(horizontal = OverflowMenuItemPadding),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

/** 菜单末端对齐锚点、顶边贴锚点底边,越界时收进窗口(同 DropdownMenu 语义)。 */
private object OverflowMenuPositionProvider : PopupPositionProvider {
    override fun calculatePosition(
        anchorBounds: IntRect,
        windowSize: IntSize,
        layoutDirection: LayoutDirection,
        popupContentSize: IntSize,
    ): IntOffset {
        val x = if (layoutDirection == LayoutDirection.Ltr) {
            (anchorBounds.right - popupContentSize.width).coerceAtLeast(0)
        } else {
            anchorBounds.left.coerceAtMost(windowSize.width - popupContentSize.width)
        }
        val y = anchorBounds.bottom.coerceAtMost(
            (windowSize.height - popupContentSize.height).coerceAtLeast(0),
        )
        return IntOffset(x, y)
    }
}
