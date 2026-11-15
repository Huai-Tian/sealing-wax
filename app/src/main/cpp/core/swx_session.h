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
#ifndef SWX_SESSION_H
#define SWX_SESSION_H

#include "swx_common.h"
#include "swx_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Session layer: PAKE pairing (暗号-authenticated, headerless SPAKE2
 * shares on the wire), per-message key derivation (no ratchet), lifetime-
 * monotonic counters with a receive high-water mark, text piece reassembly,
 * streaming file sealing, optional length-confusion padding, and an
 * export/import byte interface.
 *
 * Zero I/O: persistence decisions live entirely in the platform layer.
 * Key material lives on the sodium guarded heap; free/wipe zeroes it.
 * The vendored SPAKE2 context lives outside that heap, so wipe()/free()
 * explicitly zero it before releasing (it holds the ephemeral scalar and
 * the password scalar while a pairing is in flight).
 */
typedef struct swx_session swx_session;

/* ---- lifecycle ---- */

/* Creates a session in the NEW state with a fresh SPAKE2 context bound to
 * the role (inviter = alice blinding, responder = bob). as_inviter:
 * SWX_ROLE_* */
int swx_session_create(swx_session **out, int as_inviter);

/* Wipes all key material in place and frees the guarded allocation. */
void swx_session_free(swx_session *s);

/* Zeroes key material in place without freeing; session becomes DEAD.
 * Every later call returns SWX_E_STATE. */
void swx_session_wipe(swx_session *s);

/* ---- pairing (wire bytes only; 暗号 never crosses the wire) ---- */

/* Inviter side: emits the 32B invite share (type 0x01 retired — headerless).
 * The 暗号 (secret) is hashed into the SPAKE2 blinding; it must match the
 * responder's byte for byte. NEW state only. */
int swx_session_invite(swx_session *s,
                       const uint8_t *secret, size_t secret_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* Responder side: consumes the 32B invite share, derives the session and
 * emits the 64B reply share (32B SPAKE2 share || 32B HKDF confirm).
 * Pairing material is wiped and freed here; the session is ESTABLISHED
 * on success. A wrong 暗号 is NOT detectable on this side until the
 * inviter's first decryptable message (§4). */
int swx_session_reply(swx_session *s,
                      const uint8_t *secret, size_t secret_len,
                      const uint8_t *invite, size_t invite_len,
                      uint8_t *out, size_t out_cap, size_t *out_len);

/* Inviter side: consumes the 64B reply share and verifies the confirm
 * value — a mismatched 暗号 yields SWX_E_CRYPTO here. ESTABLISHED on
 * success; pairing material wiped and freed. */
int swx_session_finish(swx_session *s,
                       const uint8_t *reply, size_t reply_len);

/* 9 decimal digits + NUL (grouping 3-3-3 is a UI concern). Only while the
 * session is alive and was paired on this device; imported sessions carry
 * no SAS (the platform layer persists it, §6). */
int swx_session_sas(const swx_session *s, char out[SWX_SAS_DIGITS + 1]);

/* Role under which the session was created / imported (SWX_ROLE_* or 0). */
int swx_session_role(const swx_session *s);

/* ---- length-confusion padding (sender-side, per-session; §4) ---- */

/* enabled != 0 pads every piece; threshold_b64 is the target piece size in
 * base64 chars, a multiple of 4 within [500, 4000]. Default: off. */
int swx_session_set_padding(swx_session *s, int enabled, uint32_t threshold_b64);

/* ---- counters (§4: prepaid send numbers + receive high-water) ---- */

void swx_session_counters(const swx_session *s,
                          uint64_t *send_next, uint64_t *recv_hwm);

/* ---- text channel ---- */

/* Encrypts pt as one logical message; pieces are NUL-terminated base64
 * strings written to pieces[i * piece_stride] (stride >= 4001).
 * fp_out (nullable) receives the 16B logical-message fingerprint. */
int swx_session_seal_text(swx_session *s,
                          const uint8_t *pt, size_t pt_len,
                          uint8_t fp_out[SWX_FINGERPRINT_LEN],
                          char *pieces, size_t piece_stride,
                          uint32_t pieces_cap, uint32_t *n_pieces);

/* Decrypts one wire frame. Single-piece messages return SWX_OK with the
 * full plaintext; accepted pieces of an incomplete message return
 * SWX_E_PARTIAL (pt untouched). fp_out (nullable) receives the piece's
 * fingerprint. Padding is stripped by marker: [pt][0x80][0x00*]. */
int swx_session_open_text(swx_session *s,
                          const uint8_t *wire, size_t wire_len,
                          uint8_t fp_out[SWX_FINGERPRINT_LEN],
                          uint8_t *pt_out, size_t pt_cap, size_t *pt_len);

/* ---- file channel (streaming; .swx container logic stays in platform) ---- */

typedef struct swx_file_sealer swx_file_sealer;

/* meta (<= SWX_FILE_META_MAX) is encrypted inside the first chunk's
 * plaintext as [4B BE meta_len][meta][file bytes...]. chunk_size 0 selects
 * SWX_FILE_PIECE_DEFAULT. fp_out (nullable) receives the fingerprint. */
int swx_file_seal_begin(swx_file_sealer **se, swx_session *s,
                        const uint8_t *meta, size_t meta_len,
                        uint64_t file_size, uint32_t chunk_size,
                        uint8_t fp_out[SWX_FINGERPRINT_LEN]);

/* File-byte capacity of the next chunk (first chunk is smaller by the
 * metadata prefix). */
size_t swx_file_chunk_room(const swx_file_sealer *se);

uint32_t swx_file_total_chunks(const swx_file_sealer *se);

/* Seals the next data chunk: data_len must equal swx_file_chunk_room()
 * (the final call carries the remainder; an empty file emits one
 * metadata-only chunk). The chunk completing the file is padded to the
 * full chunk size when padding is on. */
int swx_file_seal_chunk(swx_file_sealer *se,
                        const uint8_t *data, size_t data_len,
                        uint8_t *wire_out, size_t wire_cap, size_t *wire_len);

/* 1 once exactly file_size bytes have been sealed. */
int swx_file_seal_done(const swx_file_sealer *se);

void swx_file_seal_free(swx_file_sealer *se);

/* Decrypts one FILE frame. Plaintext of the final chunk may carry padding;
 * the platform layer trims by the size carried in the encrypted metadata.
 * Chunk index / total / counter of the frame are exposed via
 * swx_session_last_frame(). */
int swx_session_open_file_frame(swx_session *s,
                                const uint8_t *wire, size_t wire_len,
                                uint8_t fp_out[SWX_FINGERPRINT_LEN],
                                uint8_t *pt_out, size_t pt_cap, size_t *pt_len);

/* ---- last-frame introspection (non-secret; for platform bookkeeping) ---- */

int swx_session_last_frame(const swx_session *s,
                           uint8_t fp_out[SWX_FINGERPRINT_LEN],
                           uint64_t *counter, uint32_t *chunk_index,
                           uint32_t *total_chunks);

/* ---- state export/import (§6: what a saved session keeps) ---- */

/* Serialized established state: role, suite, session key, padding config.
 * Counters are deliberately excluded (they live in the platform's 16B
 * counter file). Blob layout is versioned and checksummed. */
#define SWX_STATE_BLOB_MAX  64

int swx_session_export(const swx_session *s,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* Restores an established session; counters come from the caller (send_next
 * may legitimately jump forward — skipping numbers is harmless, reusing
 * them is not). Corrupted blobs yield SWX_E_IO, never a live session. */
int swx_session_import(swx_session **out,
                       const uint8_t *in, size_t in_len,
                       uint64_t send_next, uint64_t recv_hwm);

/* Flips the role inside an exported state blob (checksum recomputed).
 * The platform layer imports the flipped blob as a mirror session to
 * decrypt this side's OWN stored history frames: message keys bind to
 * direction, and direction is derived from role. */
int swx_state_flip_role(uint8_t *blob, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SWX_SESSION_H */
