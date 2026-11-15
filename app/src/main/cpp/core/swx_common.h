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
#ifndef SWX_COMMON_H
#define SWX_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- error codes (all functions return SWX_OK or negative) ---- */
#define SWX_OK              0
#define SWX_E_ARG          (-1)   /* invalid argument */
#define SWX_E_FORMAT       (-2)   /* malformed frame: magic/type/length */
#define SWX_E_TYPE         (-3)   /* unknown or unexpected message type */
#define SWX_E_LEN          (-4)   /* buffer too small / length mismatch */
#define SWX_E_CRYPTO       (-5)   /* AEAD authentication failed */
#define SWX_E_STATE        (-6)   /* operation not valid in current state */
#define SWX_E_REPLAY       (-7)   /* counter at/below receive high-water */
#define SWX_E_UNSUPPORTED  (-8)   /* e.g. unknown suite (future migration) */
#define SWX_E_IO           (-9)   /* state import corruption */
#define SWX_E_PARTIAL      (-10)  /* piece accepted; logical message incomplete */

/* ---- wire format (README_AGENT.md §4) ---- */
#define SWX_MAGIC            "SWX1"
#define SWX_MAGIC_LEN        4
#define SWX_HEADER_LEN       6     /* magic(4) + type(1) + suite(1) */

#define SWX_TYPE_TEXT        0x03
#define SWX_TYPE_FILE        0x04
/* 0x01/0x02 (invite/reply) retired with the bare X25519 handshake: pairing
 * frames are headerless SPAKE2 messages (README_AGENT.md §4, 2026-11 PAKE
 * 化) and carry no type byte. The values stay reserved, never reused. */

#define SWX_SUITE_CHACHA     0x01  /* v1: only suite (X25519+HKDF+ChaCha20-Poly1305) */

#define SWX_NONCE_LEN        12    /* pure random per message (CSPRNG) */
#define SWX_FINGERPRINT_LEN  16    /* logical-message id (groups chunks) */
#define SWX_COUNTER_LEN      8     /* per-direction lifetime monotonic */
#define SWX_CHUNK_LEN        4     /* chunk index / total chunks */
#define SWX_TAG_LEN          16    /* Poly1305 tag */

/* pairing frames: headerless SPAKE2 shares — nothing recognizable on the
 * wire. invite = A's 32B share; reply = B's 32B share || 32B HKDF confirm */
#define SWX_PAIR_MSG_LEN     32
#define SWX_PAIR_CONFIRM_LEN 32
#define SWX_PAIR_REPLY_LEN   (SWX_PAIR_MSG_LEN + SWX_PAIR_CONFIRM_LEN)        /* 64 */
#define SWX_PAIR_SECRET_MAX  256   /* 暗号 byte cap (pathological-input guard) */

/* data frame = header + counter + nonce + fingerprint + idx + total + ct||tag */
#define SWX_DATA_FIXED_LEN   (SWX_HEADER_LEN + SWX_COUNTER_LEN + SWX_NONCE_LEN + \
                              SWX_FINGERPRINT_LEN + 2 * SWX_CHUNK_LEN)        /* 50 */

/* AAD = frame bytes [0..14) || [26..50): header+counter and fp+idx+total */
#define SWX_AAD_LEN          (SWX_HEADER_LEN + SWX_COUNTER_LEN + \
                              SWX_FINGERPRINT_LEN + 2 * SWX_CHUNK_LEN)        /* 38 */

/* Transmission mask (README_AGENT.md §4): data-frame header bytes
 * [0..14) and [26..50) are XOR-masked on the wire with
 * HKDF-SHA256-Expand(session_key, "mask" || nonce, SWX_MASK_LEN).
 * Same byte regions as the AAD; the nonce stays in the clear. */
#define SWX_MASK_LEN          (SWX_AAD_LEN)                                    /* 38 */

/* text channel: base64 single-piece cap and derived binary/plain limits */
#define SWX_MAX_PIECE_B64    4000
#define SWX_MAX_FRAME_BIN    ((SWX_MAX_PIECE_B64 / 4) * 3)          /* 3000 */
#define SWX_MAX_CT_PIECE     (SWX_MAX_FRAME_BIN - SWX_DATA_FIXED_LEN) /* 2950 */
#define SWX_MAX_PT_PIECE     (SWX_MAX_CT_PIECE - SWX_TAG_LEN)        /* 2934 */

/* ---- session layer (README_AGENT.md §4/§6) ---- */

/* roles / direction bytes for message-key derivation */
#define SWX_ROLE_INVITER     1
#define SWX_ROLE_RESPONDER   2
#define SWX_DIR_INVITER      0x01   /* inviter -> responder */
#define SWX_DIR_RESPONDER    0x02   /* responder -> inviter */

/* session states */
#define SWX_ST_NEW           1
#define SWX_ST_ESTABLISHED   2
#define SWX_ST_DEAD          3

/* SAS: 9 uniform decimal digits via rejection sampling (3-3-3 grouping is UI) */
#define SWX_SAS_DIGITS       9

/* text channel logical-message budget (pieces are reassembled in core) */
#define SWX_TEXT_MAX_PIECES  256
#define SWX_TEXT_MAX_PT      ((size_t) SWX_TEXT_MAX_PIECES * SWX_MAX_PT_PIECE)

/* file channel: in-memory chunking granularity, independent of IM limits */
#define SWX_FILE_PIECE_DEFAULT  ((uint32_t) (8u * 1024u * 1024u))
#define SWX_FILE_META_MAX    4096   /* filename etc., encrypted in first chunk */

/* length-confusion padding thresholds, measured in base64 chars of a piece.
 * A threshold T maps to a plaintext target of T*3/4 - 66 bytes, so a padded
 * piece encodes to exactly T base64 characters (4000 -> 2934 = piece cap).
 * Presets offered by the UI (2026-11 第六批): 200/300/500/1000/3000;
 * older saves may still carry 500..4000 (MAX unchanged) and stay valid. */
#define SWX_PAD_THRESHOLD_MIN  200
#define SWX_PAD_THRESHOLD_MAX  4000

#ifdef __cplusplus
}
#endif

#endif /* SWX_COMMON_H */
