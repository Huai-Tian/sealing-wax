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

import android.content.Context
import sealing.wax.bridge.WaxNative
import sealing.wax.store.DIR_RECEIVED
import sealing.wax.store.DIR_SENT
import sealing.wax.store.HistoryEntry
import sealing.wax.store.LedgerEntry
import sealing.wax.store.Persistence
import sealing.wax.store.SavedSession
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import org.json.JSONObject

/** One decrypted view item (memory only). */
data class UiMessage(
    val dir: Int,
    val text: String,
    val ts: Long,
    val pieces: List<String>,
)

sealed interface OpenResult {
    data class Complete(val text: String) : OpenResult
    data class Partial(val got: Int, val total: Int) : OpenResult
    /** code: the SWX error name (e.g. "SWX_E_FORMAT") so callers can tell
     *  "not ciphertext at all" (normal typing, silent) from honest errors. */
    data class Failure(val message: String, val code: String? = null) : OpenResult
}

data class FileMeta(val name: String, val size: Long)

data class SwxDecryption(val meta: FileMeta, val bytesWritten: Long)

sealed interface SwxVerdict {
    /** Ledger entry matched: “就是当时那条”. */
    data class Matched(val entry: LedgerEntry) : SwxVerdict
    /** This session has ledger entries but none matches: “不是当初的文件”. */
    data object Mismatch : SwxVerdict
    /** Nothing to reconcile against (unsaved conversation / empty ledger). */
    data object NoLedger : SwxVerdict
}

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
        s.history.forEach { e ->
            decryptHistoryEntry(e)?.let { messages.add(it) }
        }
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
            s.history.add(HistoryEntry(m.dir, m.ts, ByteArray(16), m.pieces))
        }
        Persistence.saveSession(context, s)
        Persistence.writeCounters(context, s.id, c[0], c[1])
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
        if (tokens.isEmpty()) return OpenResult.Failure("剪贴板里没有内容")
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
        val lf = runCatching { WaxNative.lastFrame(handle) }.getOrNull()
        return if (lf != null && lf[2] > 1) {
            OpenResult.Partial((lf[1] + 1).toInt(), lf[2].toInt())
        } else {
            OpenResult.Failure("已收分片,但消息尚未完整")
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
                return UiMessage(e.dir, "〔该条无法解密:${err.message}〕", e.ts, emptyList())
            }
            if (pt != null) {
                return UiMessage(e.dir, String(pt, Charsets.UTF_8), e.ts, e.pieces)
            }
        }
        return null    /* incomplete stored message */
    }

    /* ---- file channel (§7) ---- */

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
        val ts = System.currentTimeMillis()
        val entry = LedgerEntry(meta.name, hash, fp, meta.size, DIR_SENT, counter, ts)
        saved?.let {
            it.ledger.add(entry)
            it.lastUsedMs = ts
            dirty = true
        }
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

    /** Verdict against this conversation's ledger (§7 对账). */
    fun verdictFor(hash: ByteArray): SwxVerdict {
        val s = saved ?: return SwxVerdict.NoLedger
        if (s.ledger.isEmpty()) return SwxVerdict.NoLedger
        val hit = s.ledger.lastOrNull { it.hash.contentEquals(hash) }
        return if (hit != null) SwxVerdict.Matched(hit) else SwxVerdict.Mismatch
    }

    /**
     * Reads the encrypted metadata of the first chunk WITHOUT touching the
     * live session's high-water: a throwaway import does the decrypt and is
     * freed immediately (the state blob exists in memory only).
     */
    fun peekSwxMeta(input: InputStream): FileMeta {
        require(handle != 0L) { "没有活跃会话" }
        val frame = SwxReader(input).nextFrame() ?: error("空的 .swx 文件")
        val blob = WaxNative.exportState(handle)
        val scratch = WaxNative.importState(blob, 1, 0)
        val meta = try {
            val pt = WaxNative.openFileFrame(scratch, frame)
            val metaLen = ((pt[0].toInt() and 0xff) shl 24) or
                ((pt[1].toInt() and 0xff) shl 16) or
                ((pt[2].toInt() and 0xff) shl 8) or
                (pt[3].toInt() and 0xff)
            require(metaLen in 1..pt.size - 4) { "元数据损坏" }
            val mo = JSONObject(String(pt, 4, metaLen, Charsets.UTF_8))
            FileMeta(mo.getString("name"), mo.getLong("size"))
        } finally {
            WaxNative.freeSession(scratch)
        }
        return meta
    }

    /**
     * Pass 2: decrypt the .swx stream, trim by the encrypted size metadata,
     * write plaintext to [out], and record the inbound ledger entry using
     * the pass-1 [hash]. Plaintext exists only in the stream.
     */
    fun decryptSwx(
        input: InputStream,
        out: OutputStream,
        hash: ByteArray,
        onProgress: (Long) -> Unit = {},
    ): SwxDecryption {
        require(handle != 0L) { "没有活跃会话" }
        val reader = SwxReader(input)
        var meta: FileMeta? = null
        var remaining = 0L
        var written = 0L
        var expectedIdx = 0L
        var total = -1L
        var counter = 0L
        var fp = ByteArray(16)
        while (true) {
            val frame = reader.nextFrame() ?: break
            val pt = WaxNative.openFileFrame(handle, frame)
            val info = WaxNative.lastFrame(handle)
            if (total < 0) {
                total = info[2]
                require(total >= 1) { "分片数非法" }
            } else if (info[2] != total) {
                error("总分片数不一致")
            }
            if (info[1] != expectedIdx) error("分片乱序或缺失")
            if (meta == null) {
                val metaLen = ((pt[0].toInt() and 0xff) shl 24) or
                    ((pt[1].toInt() and 0xff) shl 16) or
                    ((pt[2].toInt() and 0xff) shl 8) or
                    (pt[3].toInt() and 0xff)
                require(metaLen in 1..pt.size - 4) { "元数据损坏" }
                val mo = JSONObject(String(pt, 4, metaLen, Charsets.UTF_8))
                val m = FileMeta(mo.getString("name"), mo.getLong("size"))
                val start = 4 + metaLen
                remaining = m.size
                val take = minOf((pt.size - start).toLong(), remaining)
                out.write(pt, start, (start + take).toInt())
                remaining -= take
                written += take
                meta = m
                counter = info[0]
                fp = WaxNative.lastFp(handle)
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
        val m = meta ?: error("空的 .swx 文件")
        require(expectedIdx == total) { "文件不完整(缺分片)" }
        require(remaining == 0L) { "文件不完整(数据不足)" }
        saved?.let {
            it.ledger.add(
                LedgerEntry(m.name, hash, fp, m.size, DIR_RECEIVED, counter, System.currentTimeMillis())
            )
            it.lastUsedMs = System.currentTimeMillis()
            dirty = true
        }
        return SwxDecryption(m, written)
    }

    /* ---- helpers ---- */

    private fun readFully(input: InputStream, buf: ByteArray, want: Int) {
        var got = 0
        while (got < want) {
            val n = input.read(buf, got, want - got)
            if (n < 0) error("源文件比预期短")
            got += n
        }
    }

    private fun friendlyError(code: String?, isSaved: Boolean): String = when (code) {
        "SWX_E_FORMAT" -> "解不开:不是火漆密文,或粘错会话(需双端同版本)"
        "SWX_E_TYPE" -> "消息类型不符"
        "SWX_E_UNSUPPORTED" -> "不支持的套件,请升级 App"
        "SWX_E_REPLAY" -> "这条密文之前已经收过了"
        "SWX_E_CRYPTO" -> if (isSaved) {
            "解不开:粘错会话,或对方未保存此会话(单方保存无效,请重新配对)"
        } else {
            "解不开:这不是发到本会话的密文"
        }
        else -> "解密失败($code)"
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
        if (len < 66 || len > 8 * 1024 * 1024 + 82) error("记录长度损坏")
        val frame = ByteArray(len)
        if (!readFully(frame, len)) error("文件被截断")
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
