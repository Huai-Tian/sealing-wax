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

/* ---- wire format (README_AGENT.md §4) ---- */
#define SWX_MAGIC            "SWX1"
#define SWX_MAGIC_LEN        4
#define SWX_HEADER_LEN       6     /* magic(4) + type(1) + suite(1) */

#define SWX_TYPE_INVITE      0x01
#define SWX_TYPE_REPLY       0x02
#define SWX_TYPE_TEXT        0x03
#define SWX_TYPE_FILE        0x04

#define SWX_SUITE_CHACHA     0x01  /* v1: only suite (X25519+HKDF+ChaCha20-Poly1305) */

#define SWX_PUBKEY_LEN       32    /* X25519 */
#define SWX_SALT_LEN         16    /* HKDF extract salt contribution per side */
#define SWX_NONCE_LEN        12    /* pure random per message (CSPRNG) */
#define SWX_FINGERPRINT_LEN  16    /* logical-message id (groups chunks) */
#define SWX_COUNTER_LEN      8     /* per-direction lifetime monotonic */
#define SWX_CHUNK_LEN        4     /* chunk index / total chunks */
#define SWX_TAG_LEN          16    /* Poly1305 tag */

/* invite/reply frame = header + pubkey + salt */
#define SWX_INVITE_FRAME_LEN (SWX_HEADER_LEN + SWX_PUBKEY_LEN + SWX_SALT_LEN) /* 54 */

/* data frame = header + counter + nonce + fingerprint + idx + total + ct||tag */
#define SWX_DATA_FIXED_LEN   (SWX_HEADER_LEN + SWX_COUNTER_LEN + SWX_NONCE_LEN + \
                              SWX_FINGERPRINT_LEN + 2 * SWX_CHUNK_LEN)        /* 50 */

/* AAD = frame bytes [0..14) || [26..50): header+counter and fp+idx+total */
#define SWX_AAD_LEN          (SWX_HEADER_LEN + SWX_COUNTER_LEN + \
                              SWX_FINGERPRINT_LEN + 2 * SWX_CHUNK_LEN)        /* 38 */

/* text channel: base64 single-piece cap and derived binary/plain limits */
#define SWX_MAX_PIECE_B64    4000
#define SWX_MAX_FRAME_BIN    ((SWX_MAX_PIECE_B64 / 4) * 3)          /* 3000 */
#define SWX_MAX_CT_PIECE     (SWX_MAX_FRAME_BIN - SWX_DATA_FIXED_LEN) /* 2950 */
#define SWX_MAX_PT_PIECE     (SWX_MAX_CT_PIECE - SWX_TAG_LEN)        /* 2934 */

#ifdef __cplusplus
}
#endif

#endif /* SWX_COMMON_H */
