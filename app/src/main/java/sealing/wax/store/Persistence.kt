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

import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer

/**
 * Disk layout (§6): everything under filesDir/sessions/<id>/.
 *  - envelope: Tink AEAD (Android Keystore master key) over the session JSON.
 *    Associated data = session id, binding each envelope to its directory.
 *  - counters: 16B plaintext (sendNext BE64 + recvHwm BE64), atomically
 *    written (tmp + rename) at the §4 sync moments.
 *
 * The Tink keyset is created lazily on first save, so a user who never saves
 * a session leaves no new bytes on disk.
 */
object Persistence {

    private const val KEYSET_NAME = "swx_keyset"
    private const val PREF_FILE = "swx_keyset_prefs"
    private const val MASTER_KEY_URI = "android-keystore://sealing_wax_master_key"

    @Volatile
    private var aead: Aead? = null

    private fun aead(context: Context): Aead = aead ?: synchronized(this) {
        aead ?: run {
            AeadConfig.register()
            val handle = AndroidKeysetManager.Builder()
                .withSharedPref(context.applicationContext, KEYSET_NAME, PREF_FILE)
                .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .keysetHandle
            handle.getPrimitive(Aead::class.java)
        }.also { aead = it }
    }

    private fun sessionsRoot(context: Context): File =
        File(context.filesDir, "sessions").apply { mkdirs() }

    private fun sessionDir(context: Context, id: String): File =
        File(sessionsRoot(context), id)

    /** Stable ordered listing; unreadable directories are skipped. */
    fun listSessions(context: Context): List<SavedSession> =
        sessionsRoot(context).listFiles { f -> f.isDirectory }
            ?.sortedBy { it.name }
            ?.mapNotNull { dir ->
                runCatching {
                    SavedSession.fromJson(dir.name, readEnvelope(context, dir.name))
                }.getOrNull()
            }
            .orEmpty()

    /** Saved-session directory count: lets callers tell "empty because the
     *  load failed" from "empty because fresh install" (listSessions swallows
     *  per-session errors, including a transient first Tink/Keystore init at
     *  ultra-early cold start, as an empty list). */
    fun sessionDirCount(context: Context): Int =
        sessionsRoot(context).listFiles { f -> f.isDirectory }?.size ?: 0

    fun readSession(context: Context, id: String): SavedSession? =
        runCatching { SavedSession.fromJson(id, readEnvelope(context, id)) }.getOrNull()

    fun saveSession(context: Context, s: SavedSession) {
        val dir = sessionDir(context, s.id).apply { mkdirs() }
        val plaintext = s.toJson().toString().toByteArray(Charsets.UTF_8)
        val sealed = aead(context).encrypt(plaintext, s.id.toByteArray(Charsets.UTF_8))
        val tmp = File(dir, "envelope.tmp")
        tmp.writeBytes(sealed)
        if (!tmp.renameTo(File(dir, "envelope"))) {
            tmp.delete()
            error("envelope rename failed")
        }
    }

    fun deleteSession(context: Context, id: String) {
        sessionDir(context, id).deleteRecursively()
    }

    private fun readEnvelope(context: Context, id: String): JSONObject {
        val sealed = File(sessionDir(context, id), "envelope").readBytes()
        val plain = aead(context).decrypt(sealed, id.toByteArray(Charsets.UTF_8))
        return JSONObject(String(plain, Charsets.UTF_8))
    }

    /** [sendNext, recvHwm]; defaults for a fresh session. */
    fun readCounters(context: Context, id: String): LongArray {
        val f = File(sessionDir(context, id), "counters")
        if (!f.exists()) return longArrayOf(1L, 0L)
        val b = f.readBytes()
        if (b.size != 16) return longArrayOf(1L, 0L)
        val buf = ByteBuffer.wrap(b)
        return longArrayOf(buf.long, buf.long)
    }

    /** Atomic 16B write: sendNext BE64 || recvHwm BE64. */
    fun writeCounters(context: Context, id: String, sendNext: Long, recvHwm: Long) {
        val dir = sessionDir(context, id).apply { mkdirs() }
        val b = ByteBuffer.allocate(16).putLong(sendNext).putLong(recvHwm).array()
        val tmp = File(dir, "counters.tmp")
        tmp.writeBytes(b)
        if (!tmp.renameTo(File(dir, "counters"))) {
            tmp.delete()
            error("counters rename failed")
        }
    }
}
