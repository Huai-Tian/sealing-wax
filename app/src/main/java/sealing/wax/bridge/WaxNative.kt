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
package sealing.wax.bridge

/**
 * Thin facade over the native protocol core (libwax.so). Handles are opaque
 * longs; all payload arguments are wire bytes (base64 strings, frame bytes)
 * or opaque state blobs — never interpreted key material.
 *
 * Failures throw [IllegalStateException] whose message is the SWX error
 * name (e.g. "SWX_E_CRYPTO", "SWX_E_REPLAY"); map them to user-facing
 * strings at the UI layer. [openText] returns null when a piece was
 * accepted but the logical message is still incomplete.
 */
object WaxNative {
    init {
        System.loadLibrary("wax")
    }

    /** Creates a session with a fresh keypair + salt. */
    external fun createSession(asInviter: Boolean): Long

    /** Wipes all key material in place and releases the guarded allocation. */
    external fun freeSession(h: Long)

    /** SWX_ROLE_INVITER = 1, SWX_ROLE_RESPONDER = 2, 0 when dead. */
    external fun sessionRole(h: Long): Int

    /** Invite code (base64, 72 chars) for the peer to paste. */
    external fun invite(h: Long): String

    /** Consumes the invite, returns the reply code (base64, 72 chars). */
    external fun reply(h: Long, inviteB64: String): String

    /** Consumes the reply; the session is established afterwards. */
    external fun finish(h: Long, replyB64: String)

    /** 9 decimal digits (3-3-3 grouping is a UI concern). */
    external fun sas(h: Long): String

    /** Sender-side length confusion; thresholdB64 ∈ {500, 1000, 2000, 4000}. */
    external fun setPadding(h: Long, enabled: Boolean, thresholdB64: Int)

    /** [sendNext, recvHwm]. */
    external fun counters(h: Long): LongArray

    /** Encrypts to base64 pieces (each ≤ 4000 chars), in order. */
    external fun sealText(h: Long, pt: ByteArray): Array<String>

    /** Decrypts one pasted piece; null = accepted, message incomplete. */
    external fun openText(h: Long, pieceB64: String): ByteArray?

    /** Opaque established-state blob (goes into the Tink envelope). */
    external fun exportState(h: Long): ByteArray

    /** Restores a session; counters come from the 16B platform file. */
    external fun importState(blob: ByteArray, sendNext: Long, recvHwm: Long): Long

    /** Begins streaming file sealing; meta is encrypted in the first chunk. */
    external fun fileSealBegin(h: Long, meta: ByteArray, fileSize: Long): Long

    /** File-byte capacity of the next chunk. */
    external fun fileChunkRoom(se: Long): Int

    /** Seals the next chunk (feed exactly fileChunkRoom bytes). */
    external fun fileSealChunk(se: Long, data: ByteArray): ByteArray

    external fun fileSealDone(se: Long): Boolean

    external fun fileSealFree(se: Long)

    /** Decrypts one FILE frame; final-chunk padding is trimmed upstream. */
    external fun openFileFrame(h: Long, wire: ByteArray): ByteArray

    /** 16B fingerprint of the last sealed/opened logical message. */
    external fun lastFp(h: Long): ByteArray

    /** [counter, chunkIndex, totalChunks] of the last frame. */
    external fun lastFrame(h: Long): LongArray

    /** Streaming BLAKE2b-256 over the whole .swx (ledger hash, §7). */
    external fun hashCreate(): Long

    external fun hashUpdate(h: Long, data: ByteArray)

    external fun hashFinal(h: Long): ByteArray

    external fun hashFree(h: Long)
}
