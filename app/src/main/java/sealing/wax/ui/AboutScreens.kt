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

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import sealing.wax.R

/** 链接目标(非 UI 文案,常量即可;显示文字一律走资源)。 */
private const val REPO_URL = "https://github.com/Huai-Tian/sealing-wax"

/** AdaptiveIconDrawable 不能进 painterResource;画到画布取位图最通用。 */
private fun launcherIcon(context: Context, size: Int = 256): ImageBitmap {
    val drawable: android.graphics.drawable.Drawable =
        context.packageManager.getApplicationIcon(context.packageName)
    val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bmp)
    drawable.setBounds(0, 0, size, size)
    drawable.draw(canvas)
    return bmp.asImageBitmap()
}

private fun openRepo(context: Context) {
    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(REPO_URL)))
}

/** 关于 = Shizuku 同款极简弹窗(§9,其 about_dialog 布局照搬):40dp 图标 +
 *  应用名(18sp)/ 裸版本号 / 源码链接,横向排布;无标语、无许可证行;
 *  点空白关闭(SAS 弹窗同款)。第六批收紧:裸 Dialog + 自适应宽度——
 *  M3 AlertDialog 强制 280dp 最小宽 + 双层内边距(24 全包 + 24 底),
 *  这里复刻 MaterialAlertDialogBuilder 自定义视图的"刚刚好"。 */
@Composable
fun AboutDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val icon = remember { launcherIcon(context, 120) }
    val version = remember {
        @Suppress("DEPRECATION")    /* flags 变体需 API 28+;旧式调用全版本可用 */
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "?"
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            shape = AlertDialogDefaults.shape,
            color = AlertDialogDefaults.containerColor,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(24.dp),
            ) {
                Image(icon, contentDescription = null, modifier = Modifier.size(40.dp))
                Column(
                    modifier = Modifier.padding(start = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    Text(
                        stringResource(R.string.app_name),
                        fontSize = 18.sp,
                    )
                    Text(version, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        stringResource(R.string.about_source_code),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .padding(top = 8.dp)
                            .clickable { openRepo(context) },
                    )
                }
            }
        }
    }
}

/** 开放源代码页(§9,独立页):仅组件与许可证清单(所有者指示,UI 优化
 *  第五批——解释性文字全部移除,许可以组件条目为准)。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OpenSourceScreen(onBack: () -> Unit) {
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.menu_open_source)) },
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
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            @Composable
            fun Component(name: Int, license: Int) {
                Column {
                    Text(
                        stringResource(name),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        stringResource(license),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Component(R.string.oss_c1, R.string.oss_lic_agpl)
            Component(R.string.oss_c2, R.string.oss_lic_isc)
            Component(R.string.oss_c3, R.string.oss_lic_spake2)
            Component(R.string.oss_c4, R.string.oss_lic_apache)
            Component(R.string.oss_c5, R.string.oss_lic_apache)
            Component(R.string.oss_c6, R.string.oss_lic_apache)
        }
    }
}
