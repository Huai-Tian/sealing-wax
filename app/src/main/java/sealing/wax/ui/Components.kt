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
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

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
            contentDescription = "SAS 二维码",
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
        title = { Text("重命名会话") },
        text = {
            Column {
                Text("命名的对象是会话(一把钥匙),不是联系人。")
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
            }) { Text("确定") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}
