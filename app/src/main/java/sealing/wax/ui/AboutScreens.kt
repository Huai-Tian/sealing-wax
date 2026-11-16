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
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
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
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import sealing.wax.R

/** 链接目标(非 UI 文案,常量即可;显示文字一律走资源)。 */
private const val REPO_URL = "https://github.com/Huai-Tian/sealing-wax"

/** AdaptiveIconDrawable 不能进 painterResource;画到画布取位图最通用。
 *  显式设 density 使固有尺寸 ≡ 40dp(size px ÷ density 折算)——图标
 *  跨行对齐依赖固有高度,低密度屏上不设会把 120px 当 120dp 撑爆行高。 */
private fun launcherIcon(context: Context, size: Int = 256): ImageBitmap {
    val drawable: android.graphics.drawable.Drawable =
        context.packageManager.getApplicationIcon(context.packageName)
    val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    bmp.density = size * 4    /* size px ≡ 40dp(160 × size / 40) */
    val canvas = Canvas(bmp)
    drawable.setBounds(0, 0, size, size)
    drawable.draw(canvas)
    return bmp.asImageBitmap()
}

private fun openRepo(context: Context) {
    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(REPO_URL)))
}

/** 关于 = Shizuku 同款极简弹窗(§9):图标纵跨右侧两行文字——上界对齐
 *  第一行(应用名 + 裸版本号,同为 18sp 蓝字,两端对齐),下界对齐第二行
 *  (源码链接行,浏览器打开);点空白关闭(无按钮,SAS 弹窗同款)。
 *  第六批:裸 Dialog + 自适应宽度,复刻 MaterialAlertDialogBuilder 自定义
 *  视图的"刚刚好";第七批:两行布局 + 图标跨行对齐(所有者指示)。 */
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
            /* height(IntrinsicSize.Min):行高 = 两行文字的内蕴高度,
             * 图标 fillMaxHeight + 等比 → 上界恰贴第一行、下界恰贴第二行 */
            Row(
                modifier = Modifier
                    .padding(24.dp)
                    .height(IntrinsicSize.Min),
            ) {
                Image(
                    icon,
                    contentDescription = null,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier
                        .fillMaxHeight()
                        .aspectRatio(1f),
                )
                Column(
                    modifier = Modifier
                        .padding(start = 24.dp)
                        .width(IntrinsicSize.Max),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    /* 第一行:应用名(左)+ 版本号(右),正常色(第八批:
                     * 蓝字仅保留给菜单当前值) */
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            stringResource(R.string.app_name),
                            fontSize = 18.sp,
                        )
                        Text(version, fontSize = 18.sp)
                    }
                    /* 第二行:源码链接(维持原样) */
                    Text(
                        stringResource(R.string.about_source_code),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.clickable { openRepo(context) },
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
