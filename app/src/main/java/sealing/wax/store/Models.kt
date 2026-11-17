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
package sealing.wax.store

import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/** Direction tags persisted inside the envelope (wire-independent). */
const val DIR_SENT = 0
const val DIR_RECEIVED = 1

/** One stored text message: ciphertext pieces only — 明文永不落盘. */
data class HistoryEntry(
    val dir: Int,
    val ts: Long,
    val fp: ByteArray,
    val pieces: List<String>,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("d", dir)
        put("t", ts)
        put("f", b64(fp))
        put("p", JSONArray(pieces))
    }

    companion object {
        fun fromJson(o: JSONObject): HistoryEntry = HistoryEntry(
            dir = o.getInt("d"),
            ts = o.getLong("t"),
            fp = unb64(o.getString("f")),
            pieces = List(o.getJSONArray("p").length()) { o.getJSONArray("p").getString(it) },
        )
    }
}

/** File ledger entry (§7): name encrypted at rest inside the envelope. */
data class LedgerEntry(
    val name: String,
    val hash: ByteArray,
    val fp: ByteArray,
    val size: Long,
    val dir: Int,
    val counter: Long,
    val ts: Long,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("n", name)
        put("h", b64(hash))
        put("f", b64(fp))
        put("s", size)
        put("d", dir)
        put("c", counter)
        put("t", ts)
    }

    companion object {
        fun fromJson(o: JSONObject): LedgerEntry = LedgerEntry(
            name = o.getString("n"),
            hash = unb64(o.getString("h")),
            fp = unb64(o.getString("f")),
            size = o.getLong("s"),
            dir = o.getInt("d"),
            counter = o.getLong("c"),
            ts = o.getLong("t"),
        )
    }
}

/** Everything a saved session keeps, minus counters (16B plaintext file).
 *  sas: the 9-digit identity fingerprint from the pairing — non-secret,
 *  shown in the chat top bar for lifelong re-verification (§6/§9). */
data class SavedSession(
    val id: String,
    var name: String,
    val role: Int,
    val sas: String,
    var padOn: Boolean,
    var padThreshold: Int,
    val createdMs: Long,
    var lastUsedMs: Long,
    val stateBlob: ByteArray,
    val history: MutableList<HistoryEntry> = mutableListOf(),
    val ledger: MutableList<LedgerEntry> = mutableListOf(),
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("v", 1)
        put("kind", "chat")
        put("name", name)
        put("role", role)
        put("sas", sas)
        put("padOn", padOn)
        put("padThresh", padThreshold)
        put("created", createdMs)
        put("lastUsed", lastUsedMs)
        put("state", b64(stateBlob))
        put("history", JSONArray().also { h -> history.forEach { h.put(it.toJson()) } })
        put("ledger", JSONArray().also { l -> ledger.forEach { l.put(it.toJson()) } })
    }

    companion object {
        fun fromJson(id: String, o: JSONObject): SavedSession = SavedSession(
            id = id,
            name = o.getString("name"),
            role = o.getInt("role"),
            sas = o.optString("sas", ""),
            padOn = o.optBoolean("padOn", false),
            padThreshold = o.optInt("padThresh", 1000),
            createdMs = o.getLong("created"),
            lastUsedMs = o.optLong("lastUsed", o.getLong("created")),
            stateBlob = unb64(o.getString("state")),
            history = MutableList(o.getJSONArray("history").length()) {
                HistoryEntry.fromJson(o.getJSONArray("history").getJSONObject(it))
            },
            ledger = MutableList(o.getJSONArray("ledger").length()) {
                LedgerEntry.fromJson(o.getJSONArray("ledger").getJSONObject(it))
            },
        )
    }
}

internal fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
internal fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)

/** 公共会话种子长度,与核心层 SWX_GATE_SEED_LEN 一致(swx_session.h)。 */
const val GATE_SEED_LEN = 64

/** 公共会话 (§5/§15): a session frozen in pairing state — a standing door
 *  with a 静态邀请码. Holds the gate seed (64B CSPRNG output captured once
 *  at creation, NEVER derived from the 暗号 — §8: a 暗号-derived scalar
 *  would turn leakage into impersonation) and the 暗号 itself, both sealed
 *  in the Tink envelope (§6: creation is the explicit save act). No state
 *  blob, history, ledger or counters: at runtime the armed ctx is a
 *  standard inviter session that graduates into an ordinary client chat
 *  on finish — the door never chats, only the rooms it births do. */
data class PublicSession(
    val id: String,
    var name: String,
    val gateSeed: ByteArray,
    val gateSecret: ByteArray,
    val createdMs: Long,
    var lastUsedMs: Long,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("v", 1)
        put("kind", "public")
        put("name", name)
        put("seed", b64(gateSeed))
        put("secret", b64(gateSecret))
        put("created", createdMs)
        put("lastUsed", lastUsedMs)
    }

    companion object {
        fun fromJson(id: String, o: JSONObject): PublicSession = PublicSession(
            id = id,
            name = o.getString("name"),
            gateSeed = unb64(o.getString("seed")),
            gateSecret = unb64(o.getString("secret")),
            createdMs = o.getLong("created"),
            lastUsedMs = o.optLong("lastUsed", o.getLong("created")),
        )
    }
}
