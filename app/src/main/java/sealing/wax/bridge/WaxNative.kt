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

    /** Invite code (base64, 44 chars): 32B headerless SPAKE2 share, blinded
     *  by the 暗号. The 暗号 never crosses the wire. */
    external fun invite(h: Long, secret: ByteArray): String

    /** 公共会话 (§5): invite with the private scalar derived deterministically
     *  from seedB64 (64B) instead of a fresh CSPRNG draw — the same
     *  (seed, 暗号) reproduces a byte-identical static invite code every
     *  arming. Identical upstream pipeline (spake2 integration change #5);
     *  the seed is 64B CSPRNG output captured once at gate creation and
     *  never derived from the 暗号 (§8). */
    external fun inviteSeeded(h: Long, secret: ByteArray, seedB64: String): String

    /** Consumes the invite with the SAME 暗号, returns the reply code
     *  (base64, 88 chars): 32B share || 32B HKDF confirm. */
    external fun reply(h: Long, inviteB64: String, secret: ByteArray): String

    /** Consumes the reply; verifies the confirm — a mismatched 暗号
     *  throws SWX_E_CRYPTO here. Established afterwards. */
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

    /** Role-flipped copy of a state blob (checksum fixed): import it as a
     * mirror session to decrypt this side's own history frames. */
    external fun flipStateRole(blob: ByteArray): ByteArray

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

    external fun hashUpdate(h: Long, data: ByteArray, offset: Int, len: Int)

    external fun hashFinal(h: Long): ByteArray

    external fun hashFree(h: Long)
}
