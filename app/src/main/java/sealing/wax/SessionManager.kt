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
package sealing.wax

import android.content.Context
import sealing.wax.bridge.WaxNative
import sealing.wax.store.DIR_RECEIVED
import sealing.wax.store.DIR_SENT
import sealing.wax.store.GATE_SEED_LEN
import sealing.wax.store.HistoryEntry
import sealing.wax.store.LedgerEntry
import sealing.wax.store.Persistence
import sealing.wax.store.PublicSession
import sealing.wax.store.SavedSession
import sealing.wax.store.b64
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.UUID
import org.json.JSONObject

/** One decrypted view item (memory only). [fileHash] non-null = a file
 *  entry rendered from the ledger (§7): not a ciphertext message, never
 *  persisted into history — saveLiveAs routes it through the ledger. */
data class UiMessage(
    val dir: Int,
    val text: String,
    val ts: Long,
    val pieces: List<String>,
    val fileHash: ByteArray? = null,
)

sealed interface OpenResult {
    data class Complete(val text: String) : OpenResult
    data class Partial(val got: Int, val total: Int) : OpenResult
    /** code: the SWX error name (e.g. "SWX_E_FORMAT") so callers can tell
     *  "not ciphertext at all" (normal typing, silent) from honest errors. */
    data class Failure(val message: String, val code: String? = null) : OpenResult
}

data class FileMeta(val name: String, val size: Long)

/**
 * Runtime hub: one live conversation (saved or unsaved), the pairing state
 * machine, counter prepayment, history walking and file streaming. All
 * crypto goes through [WaxNative]; this class never touches key bytes.
 */
object SessionManager {

    private const val PREPAY = 128L
    private const val PREPAY_MARGIN = 16L

    /** Set once from MainActivity; application context (outlives rotation). */
    var appContext: Context? = null

    private fun ctx(): Context = appContext ?: error("SessionManager not attached")

    /** 双语铁律(§9):非组合层的用户可见文案统一从资源解析。 */
    private fun str(id: Int, vararg args: Any): String = ctx().getString(id, *args)

    /** 稳定错误码上屏(§9):SWX_E_* 代码随本地化前缀附出;其余异常
     *  只出前缀,细节进日志,绝不上屏。 */
    fun stableError(prefix: String, e: Throwable): String =
        e.message?.takeIf { it.startsWith("SWX_E_") }?.let { "$prefix($it)" } ?: prefix

    /** Live conversation handle; 0 = no conversation. */
    var handle: Long = 0
        private set

    /** Non-null when the live conversation belongs to a saved session. */
    var saved: SavedSession? = null
        private set

    /** End of the prepaid send-number segment (saved sessions, §4). */
    private var prepaidEnd: Long = 0

    /** Envelope needs a rewrite at the next sync point. */
    private var dirty: Boolean = false

    /** Pieces of a not-yet-complete inbound message (memory only). */
    private val pendingPieces = mutableListOf<String>()

    /** In-memory transcript of the live conversation (both directions). */
    val messages = androidx.compose.runtime.mutableStateListOf<UiMessage>()

    /** Ledger of an unsaved conversation (memory only, dies with the chat;
     *  §3-safe). Migrated into the envelope's ledger by saveLiveAs, so file
     *  history survives the save decision and drives re-import dedup. */
    private val liveLedger = mutableListOf<LedgerEntry>()

    /** True between createSession and SAS confirmation. */
    var pairing: Boolean = false
        private set

    /** Current conversation's SAS (9 digits) — live pairing value or the
     *  persisted value of a saved session; null when unknown (old saves). */
    var sas: String? = null
        private set

    /* ---- pairing (§5; PAKE 暗号认证) ---- */

    fun startInvite(secret: ByteArray): String {
        freeConversation()
        handle = WaxNative.createSession(true)
        pairing = true
        sas = null
        return WaxNative.invite(handle, secret)
    }

    fun startJoin(inviteB64: String, secret: ByteArray): String {
        freeConversation()
        handle = WaxNative.createSession(false)
        pairing = true
        sas = null
        return WaxNative.reply(handle, inviteB64.trim(), secret)
    }

    fun completeInvite(replyB64: String) {
        check(pairing && handle != 0L) { "配对流程状态错误" }
        WaxNative.finish(handle, replyB64.trim())
        sas = WaxNative.sas(handle)
    }

    fun sas(): String = WaxNative.sas(handle)

    /** After pairing: the live unsaved conversation starts here. The SAS is
     *  captured from the live session (responder side pairs at reply time
     *  and reaches this entry without completeInvite). */
    fun beginConversation() {
        pairing = false
        if (sas == null && handle != 0L) {
            sas = runCatching { WaxNative.sas(handle) }.getOrNull()
        }
        messages.clear()
    }

    fun abortPairing() {
        freeConversation()
    }

    /* ---- 公共会话 (§5/§15): 静态邀请码门禁 ---- */

    /** 创建即显式保存(§6 例外族:创建持久对象的动作本身就是保存)。
     *  种子 64B 一次性 CSPRNG,绝不从暗号派生(§8:暗号派生标量 =
     *  泄露即冒充本端)。此后 (种子, 暗号) 恒等复现同一静态邀请码。 */
    fun createPublicSession(name: String, secret: ByteArray) {
        val seed = ByteArray(GATE_SEED_LEN).also { SecureRandom().nextBytes(it) }
        val now = System.currentTimeMillis()
        Persistence.savePublicSession(
            ctx(),
            PublicSession(
                id = UUID.randomUUID().toString().replace("-", "").substring(0, 16),
                name = name.ifBlank { str(R.string.public_unnamed) },
                gateSeed = seed,
                gateSecret = secret.copyOf(),
                createdMs = now,
                lastUsedMs = now,
            ),
        )
    }

    /** 打开即武装:种子派生的标准 inviter 会话 + 恒等静态邀请码(44 字符,
     *  与核心层 swx_session_invite_seeded 对应)。已有 live(对话或配对)
     *  先释放——门禁屏与其他屏互斥,同既有配对入口的语义。
     *  粘贴客户回复码走 completeInvite(finish);成功后 armed ctx 直接
     *  毕业为普通客户会话(beginConversation 照常),再武装由下次打开
     *  完成——退出屏即焚毁,门禁运行时零驻留状态。错误的回复码被
     *  3ee0222 回滚,武装原地再战。 */
    fun armPublicSession(context: Context, id: String): String {
        val p = Persistence.readPublicSession(context, id) ?: error("会话不存在")
        freeConversation()
        handle = WaxNative.createSession(true)
        pairing = true
        sas = null
        val code = WaxNative.inviteSeeded(handle, p.gateSecret, b64(p.gateSeed))
        p.lastUsedMs = System.currentTimeMillis()
        Persistence.savePublicSession(context, p)
        return code
    }

    /* ---- conversation entry / exit ---- */

    fun openSaved(context: Context, id: String) {
        freeConversation()
        val s = Persistence.readSession(context, id) ?: error("会话不存在")
        val c = Persistence.readCounters(context, id)
        handle = WaxNative.importState(s.stateBlob, c[0], c[1])
        saved = s
        sas = s.sas.ifBlank { null }    /* §6: persisted identity fingerprint */
        WaxNative.setPadding(handle, s.padOn, s.padThreshold)
        /* prepay a send-number segment; skipping numbers is harmless (§4) */
        Persistence.writeCounters(context, id, c[0] + PREPAY, c[1])
        prepaidEnd = c[0] + PREPAY
        messages.clear()
        /* merged transcript: decrypted text history + file entries rendered
         * from the ledger (§7), chronological; stable sort keeps the stored
         * order for equal timestamps */
        (s.history.mapNotNull { decryptHistoryEntry(it) } + s.ledger.map { fileUi(it) })
            .sortedBy { it.ts }
            .forEach { messages.add(it) }
        resetHistoryScratch()    /* scratch pair only lives for the entry decrypt */
    }

    /** Saved conversation: extend the prepaid segment when it runs low. */
    private fun ensurePrepaid() {
        val s = saved ?: return
        val c = WaxNative.counters(handle)
        if (c[0] + PREPAY_MARGIN >= prepaidEnd) {
            prepaidEnd += PREPAY
            Persistence.writeCounters(ctx(), s.id, prepaidEnd, c[1])
        }
    }

    /** §4 sync moments: entering background / leaving the conversation. */
    fun syncNow(context: Context = ctx()) {
        if (handle == 0L) return
        val s = saved ?: return
        val c = WaxNative.counters(handle)
        Persistence.writeCounters(context, s.id, c[0], c[1])
        if (dirty) {
            Persistence.saveSession(context, s)
            dirty = false
        }
    }

    /** Exit flow (§5): wipes the live session; the saved copy stays on disk. */
    fun exitConversation(context: Context = ctx()) {
        syncNow(context)
        freeConversation()
    }

    /** Renames the live saved conversation (§5: 会话内点顶栏名称). Writes
     *  the envelope immediately through the §4 sync path so a crash after
     *  the rename keeps the new name. Returns false when nothing is saved. */
    fun renameCurrent(name: String, context: Context = ctx()): Boolean {
        val s = saved ?: return false
        s.name = name
        dirty = true
        syncNow(context)
        return true
    }

    /** Save-or-discard dialog outcome for an unsaved conversation. */
    fun saveLiveAs(name: String, context: Context = ctx()) {
        require(handle != 0L) { "没有活跃会话" }
        val blob = WaxNative.exportState(handle)
        val c = WaxNative.counters(handle)
        val s = SavedSession(
            id = UUID.randomUUID().toString().replace("-", "").substring(0, 16),
            name = name,
            role = WaxNative.sessionRole(handle),
            sas = sas ?: "",
            padOn = paddingEnabled,
            padThreshold = paddingThreshold,
            createdMs = System.currentTimeMillis(),
            lastUsedMs = System.currentTimeMillis(),
            stateBlob = blob,
        )
        messages.forEach { m ->
            /* file entries ride in the ledger, not in the ciphertext history */
            if (m.fileHash == null) {
                s.history.add(HistoryEntry(m.dir, m.ts, ByteArray(16), m.pieces))
            }
        }
        s.ledger.addAll(liveLedger)
        liveLedger.clear()
        Persistence.saveSession(context, s)
        /* 落盘预支号段而非当前值(对齐 openSaved 语义,第九批):中途保存
         * 后会话继续,若只写 c[0],首条消息的 counter 消耗与 ensurePrepaid
         * 落盘之间存在崩溃窗口——重开会从 c[0] 重来,重号违反 §4"绝不
         * 重号"。预支段把该窗口封死;退出流的 syncNow 随后会以实际值
         * 覆写(≥ next-unused,同样安全) */
        Persistence.writeCounters(context, s.id, c[0] + PREPAY, c[1])
        prepaidEnd = c[0] + PREPAY
        saved = s
        dirty = false
    }

    private fun freeConversation() {
        resetHistoryScratch()
        if (handle != 0L) {
            WaxNative.freeSession(handle)
        }
        handle = 0
        saved = null
        prepaidEnd = 0
        dirty = false
        pairing = false
        sas = null
        pendingPieces.clear()
        messages.clear()
        liveLedger.clear()
    }

    /* ---- padding (per-session, sender side only; §4) ---- */

    var paddingEnabled: Boolean = false
        private set
    var paddingThreshold: Int = 1000
        private set

    fun setPadding(enabled: Boolean, threshold: Int) {
        if (handle != 0L) {
            WaxNative.setPadding(handle, enabled, threshold)
        }
        paddingEnabled = enabled
        paddingThreshold = threshold
        saved?.let {
            it.padOn = enabled
            it.padThreshold = threshold
            dirty = true
        }
    }

    /* ---- text channel ---- */

    /** KPI path: one button, all pieces copied at once (newline-joined). */
    fun sealText(text: String): List<String> {
        require(handle != 0L) { "没有活跃会话" }
        val pieces = WaxNative.sealText(handle, text.toByteArray(Charsets.UTF_8)).toList()
        val fp = WaxNative.lastFp(handle)
        val ts = System.currentTimeMillis()
        messages.add(UiMessage(DIR_SENT, text, ts, pieces))
        saved?.let {
            it.history.add(HistoryEntry(DIR_SENT, ts, fp, pieces))
            it.lastUsedMs = ts
            dirty = true
        }
        ensurePrepaid()
        return pieces
    }

    /** Paste path: whitespace-split pieces fed in order (base64 never wraps). */
    fun openPasted(text: String): OpenResult {
        require(handle != 0L) { "没有活跃会话" }
        val tokens = text.split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return OpenResult.Failure(str(R.string.clipboard_empty))
        for (t in tokens) {
            val pt = try {
                WaxNative.openText(handle, t)
            } catch (e: IllegalStateException) {
                return OpenResult.Failure(friendlyError(e.message, saved != null), e.message)
            }
            pendingPieces.add(t)
            if (pt != null) {
                val msg = String(pt, Charsets.UTF_8)
                val ts = System.currentTimeMillis()
                val all = pendingPieces.toList()
                messages.add(UiMessage(DIR_RECEIVED, msg, ts, all))
                saved?.let {
                    it.history.add(HistoryEntry(DIR_RECEIVED, ts, WaxNative.lastFp(handle), all))
                    it.lastUsedMs = ts
                    dirty = true
                }
                pendingPieces.clear()
                return OpenResult.Complete(msg)
            }
        }
        /* 重组进度如实化(乱序感知):用重组器的已收片数而非 lastFrame
         * 片序(乱序粘贴时后者虚报——收 1,2,4 显示"4/4"实则缺第 3 片) */
        val rs = runCatching { WaxNative.reasmState(handle) }.getOrNull()
        return if (rs != null && rs[1] > 1 && rs[0] < rs[1]) {
            OpenResult.Partial(rs[0].toInt(), rs[1].toInt())
        } else {
            OpenResult.Failure(str(R.string.pieces_pending))
        }
    }

    /* ---- history (§7: decrypt on the spot, view then discard) ---- */

    private class HistoryScratch(val peer: Long, val own: Long)

    private var historyScratch: HistoryScratch? = null

    private fun createHistoryScratch(): HistoryScratch {
        val s = checkNotNull(saved)
        /* direction-bound keys: our own frames need the role-flipped mirror */
        val peer = WaxNative.importState(s.stateBlob, 1, 0)
        val own = WaxNative.importState(WaxNative.flipStateRole(s.stateBlob), 1, 0)
        return HistoryScratch(peer, own)
    }

    private fun resetHistoryScratch() {
        historyScratch?.let {
            WaxNative.freeSession(it.peer)
            WaxNative.freeSession(it.own)
        }
        historyScratch = null
    }

    private fun decryptHistoryEntry(e: HistoryEntry): UiMessage? {
        val scratch = historyScratch ?: createHistoryScratch().also { historyScratch = it }
        val target = if (e.dir == DIR_SENT) scratch.own else scratch.peer
        for (p in e.pieces) {
            val pt = try {
                WaxNative.openText(target, p)
            } catch (err: IllegalStateException) {
                return UiMessage(
                    e.dir,
                    str(R.string.history_undecryptable, friendlyError(err.message, true)),
                    e.ts, emptyList(),
                )
            }
            if (pt != null) {
                return UiMessage(e.dir, String(pt, Charsets.UTF_8), e.ts, e.pieces)
            }
        }
        return null    /* incomplete stored message */
    }

    /* ---- file channel (§7) ---- */

    /** Ledger sink for the live conversation: the envelope's ledger for a
     *  saved session (marks the envelope dirty), the in-memory ledger for
     *  an unsaved one (dies with the chat, §3-safe). */
    private fun recordLedger(entry: LedgerEntry) {
        val s = saved
        if (s != null) {
            s.ledger.add(entry)
            s.lastUsedMs = entry.ts
            dirty = true
        } else {
            liveLedger.add(entry)
        }
    }

    /** True when this exact .swx byte stream was already received (either
     *  ledger) — a re-import then decrypts and exports again but adds no
     *  second history entry. */
    private fun fileSeen(hash: ByteArray): Boolean =
        (saved?.ledger ?: liveLedger).any { e ->
            e.dir == DIR_RECEIVED && e.hash.contentEquals(hash)
        }

    /** "[文件] name (size)" bubble for a ledger entry (§7; 收发对称,
     *  双语铁律走资源)。 */
    fun fileUi(e: LedgerEntry): UiMessage = UiMessage(
        e.dir, str(R.string.file_bubble, e.name, formatSize(e.size)),
        e.ts, emptyList(), e.hash,
    )

    /** Human-readable byte size for the file bubble. */
    private fun formatSize(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024L * 1024 -> String.format(java.util.Locale.ROOT, "%.1f KB", n / 1024.0)
        n < 1024L * 1024 * 1024 -> String.format(java.util.Locale.ROOT, "%.1f MB", n / 1048576.0)
        else -> String.format(java.util.Locale.ROOT, "%.1f GB", n / 1073741824.0)
    }

    /** Staging dir for .swx shares; cleared on app start. */
    fun shareDir(context: Context = ctx()): File =
        File(context.cacheDir, "share").apply { mkdirs() }

    fun clearShareStaging(context: Context = ctx()) {
        shareDir(context).listFiles()?.forEach { it.delete() }
    }

    /**
     * Streams [input] into a sealed .swx at [out], hashing the container as
     * it is written. Returns the ledger entry to record.
     */
    fun sealFile(
        input: InputStream,
        meta: FileMeta,
        out: OutputStream,
        onProgress: (Long) -> Unit = {},
    ): LedgerEntry {
        require(handle != 0L) { "没有活跃会话" }
        val metaJson = JSONObject()
            .put("name", meta.name)
            .put("size", meta.size)
            .toString().toByteArray(Charsets.UTF_8)
        val se = WaxNative.fileSealBegin(handle, metaJson, meta.size)
        val hh = WaxNative.hashCreate()
        val prefix = ByteArray(4)
        try {
            var done = 0L
            while (!WaxNative.fileSealDone(se)) {
                val room = WaxNative.fileChunkRoom(se)
                val buf = ByteArray(room)
                readFully(input, buf, room)
                val frame = WaxNative.fileSealChunk(se, buf)
                val len = frame.size
                prefix[0] = (len ushr 24).toByte()
                prefix[1] = (len ushr 16).toByte()
                prefix[2] = (len ushr 8).toByte()
                prefix[3] = len.toByte()
                out.write(prefix)
                out.write(frame)
                WaxNative.hashUpdate(hh, prefix, 0, 4)
                WaxNative.hashUpdate(hh, frame, 0, len)
                done += room
                onProgress(done)
            }
            out.flush()
        } finally {
            WaxNative.fileSealFree(se)
        }
        val hash = WaxNative.hashFinal(hh)
        WaxNative.hashFree(hh)
        val fp = WaxNative.lastFp(handle)
        val counter = WaxNative.lastFrame(handle)[0]
        val entry = LedgerEntry(meta.name, hash, fp, meta.size, DIR_SENT, counter,
                                System.currentTimeMillis())
        recordLedger(entry)
        ensurePrepaid()
        return entry
    }

    /** Pass 1 (§7): BLAKE2b over the whole .swx — no key needed. */
    fun inspectSwx(input: InputStream): ByteArray {
        val hh = WaxNative.hashCreate()
        try {
            val buf = ByteArray(1 shl 16)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (n > 0) WaxNative.hashUpdate(hh, buf, 0, n)
            }
        } finally {
            /* digest below; free after final */
        }
        val digest = WaxNative.hashFinal(hh)
        WaxNative.hashFree(hh)
        return digest
    }

    /**
     * Reads the encrypted metadata of the first chunk WITHOUT touching the
     * live session's high-water: a throwaway import does the decrypt and is
     * freed immediately (the state blob exists in memory only).
     */
    fun peekSwxMeta(input: InputStream): FileMeta {
        require(handle != 0L) { "没有活跃会话" }
        val frame = SwxReader(input).nextFrame() ?: error("SWX_E_EMPTY")
        val blob = WaxNative.exportState(handle)
        val scratch = WaxNative.importState(blob, 1, 0)
        val meta = try {
            val pt = WaxNative.openFileFrame(scratch, frame)
            val metaLen = ((pt[0].toInt() and 0xff) shl 24) or
                ((pt[1].toInt() and 0xff) shl 16) or
                ((pt[2].toInt() and 0xff) shl 8) or
                (pt[3].toInt() and 0xff)
            require(metaLen in 1..pt.size - 4) { "SWX_E_META" }
            runCatching {
                val mo = JSONObject(String(pt, 4, metaLen, Charsets.UTF_8))
                FileMeta(mo.getString("name"), mo.getLong("size"))
            }.getOrElse { error("SWX_E_META") }
        } finally {
            WaxNative.freeSession(scratch)
        }
        return meta
    }

    /**
     * Pass 2: decrypt the .swx stream, trim by the encrypted size metadata,
     * write plaintext to [out], and record the inbound ledger entry using
     * the pass-1 [hash]. Decrypts on a throwaway mirror of the session state
     * (counters pinned at 1/0 — the peek/history pattern): the live session's
     * high-water is never touched by file imports, so re-importing the same
     * .swx any number of times succeeds (the old live-handle path replayed
     * consumed counters and failed with SWX_E_REPLAY). The ledger entry is
     * deduped by hash — re-exports of the same byte stream are not new
     * events. Returns the "[文件] name (size)" bubble on first import,
     * null on a re-import (history already has it). Plaintext exists only
     * in the stream.
     */
    fun decryptSwx(
        input: InputStream,
        out: OutputStream,
        hash: ByteArray,
        onProgress: (Long) -> Unit = {},
    ): UiMessage? {
        require(handle != 0L) { "没有活跃会话" }
        val blob = WaxNative.exportState(handle)
        val scratch = WaxNative.importState(blob, 1, 0)
        val reader = SwxReader(input)
        var meta: FileMeta? = null
        var remaining = 0L
        var written = 0L
        var expectedIdx = 0L
        var total = -1L
        var counter = 0L
        var fp = ByteArray(16)
        try {
            while (true) {
                val frame = reader.nextFrame() ?: break
                val pt = WaxNative.openFileFrame(scratch, frame)
                val info = WaxNative.lastFrame(scratch)
                if (total < 0) {
                    total = info[2]
                    require(total >= 1) { "SWX_E_ORDER" }
                } else if (info[2] != total) {
                    error("SWX_E_ORDER")
                }
                if (info[1] != expectedIdx) error("SWX_E_ORDER")
                if (meta == null) {
                    val metaLen = ((pt[0].toInt() and 0xff) shl 24) or
                        ((pt[1].toInt() and 0xff) shl 16) or
                        ((pt[2].toInt() and 0xff) shl 8) or
                        (pt[3].toInt() and 0xff)
                    require(metaLen in 1..pt.size - 4) { "SWX_E_META" }
                    val m = runCatching {
                        val mo = JSONObject(String(pt, 4, metaLen, Charsets.UTF_8))
                        FileMeta(mo.getString("name"), mo.getLong("size"))
                    }.getOrElse { error("SWX_E_META") }
                    val start = 4 + metaLen
                    remaining = m.size
                    val take = minOf((pt.size - start).toLong(), remaining)
                    /* write(buf, off, LEN):len 是长度,不是结束偏移 */
                    out.write(pt, start, take.toInt())
                    remaining -= take
                    written += take
                    meta = m
                    counter = info[0]
                    fp = WaxNative.lastFp(scratch)
                } else {
                    val take = minOf(pt.size.toLong(), remaining)
                    if (take > 0) out.write(pt, 0, take.toInt())
                    remaining -= take
                    written += take
                }
                expectedIdx++
                onProgress(written)
            }
            out.flush()
        } finally {
            WaxNative.freeSession(scratch)
        }
        val m = meta ?: error("SWX_E_EMPTY")
        require(expectedIdx == total) { "SWX_E_TRUNCATED" }
        require(remaining == 0L) { "SWX_E_TRUNCATED" }
        if (fileSeen(hash)) return null    /* re-import: export again, no new entry */
        val entry = LedgerEntry(m.name, hash, fp, m.size, DIR_RECEIVED, counter,
                                System.currentTimeMillis())
        recordLedger(entry)
        return fileUi(entry)
    }

    /* ---- helpers ---- */

    private fun readFully(input: InputStream, buf: ByteArray, want: Int) {
        var got = 0
        while (got < want) {
            val n = input.read(buf, got, want - got)
            if (n < 0) error("SWX_E_SRC_SHORT")
            got += n
        }
    }

    private fun friendlyError(code: String?, isSaved: Boolean): String = when (code) {
        "SWX_E_FORMAT" -> str(R.string.swx_e_format)
        "SWX_E_TYPE" -> str(R.string.swx_e_type)
        "SWX_E_UNSUPPORTED" -> str(R.string.swx_e_unsupported)
        "SWX_E_REPLAY" -> str(R.string.swx_e_replay)
        "SWX_E_CRYPTO" -> if (isSaved) str(R.string.swx_e_crypto_saved)
        else str(R.string.swx_e_crypto_live)
        else -> str(R.string.swx_decrypt_failed_code, code ?: "unknown")
    }
}

/**
 * .swx container reader: a sequence of [4B BE length][frame] records.
 * Truncation and corrupted lengths are rejected.
 */
private class SwxReader(private val input: InputStream) {

    fun nextFrame(): ByteArray? {
        val p = ByteArray(4)
        if (!readFully(p, 4)) return null
        val len = ((p[0].toInt() and 0xff) shl 24) or
            ((p[1].toInt() and 0xff) shl 16) or
            ((p[2].toInt() and 0xff) shl 8) or
            (p[3].toInt() and 0xff)
        if (len < 66 || len > 8 * 1024 * 1024 + 82) error("SWX_E_TRUNCATED")
        val frame = ByteArray(len)
        if (!readFully(frame, len)) error("SWX_E_TRUNCATED")
        return frame
    }

    private fun readFully(buf: ByteArray, want: Int): Boolean {
        var got = 0
        while (got < want) {
            val n = input.read(buf, got, want - got)
            if (n < 0) return false
            got += n
        }
        return true
    }
}
