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
#ifndef SWX_SESSION_INTERNAL_H
#define SWX_SESSION_INTERNAL_H

/* White-box view for host tests only. Not part of the public core API and
 * never used by the JNI bridge: tests verify memory discipline (wipe zeroes
 * key bytes) and key-derivation separation directly. */

#include "swx_session.h"

#include <stdint.h>

#define SWX_REASM_MAX_PIECES SWX_TEXT_MAX_PIECES

typedef struct {
    uint8_t  fp[SWX_FINGERPRINT_LEN];
    uint32_t total;
    uint32_t got;                          /* count of stored pieces */
    uint8_t  have[SWX_REASM_MAX_PIECES];   /* per-index presence */
    size_t   len[SWX_REASM_MAX_PIECES];    /* stored (unpadded) lengths */
    uint8_t  buf[SWX_TEXT_MAX_PT];         /* fixed slots: idx * SWX_MAX_PT_PIECE */
    size_t   used;                         /* sum of stored lengths */
} swx_reasm;

struct swx_session {
    uint8_t  state;        /* SWX_ST_* */
    uint8_t  role;         /* SWX_ROLE_* */
    uint8_t  suite;        /* SWX_SUITE_* */
    uint8_t  pad_on;
    uint16_t pad_threshold;                /* base64 chars per piece */
    void    *spake;                         /* vendored SPAKE2 ctx; alive only
                                             * during pairing (NEW state), wiped
                                             * and freed at establishment */
    uint8_t  session_key[32];
    char     sas[SWX_SAS_DIGITS + 1];
    uint64_t send_next;
    uint64_t recv_hwm;
    /* last frame bookkeeping (non-secret) */
    uint8_t  last_fp[SWX_FINGERPRINT_LEN];
    uint64_t last_counter;
    uint32_t last_idx;
    uint32_t last_total;
    swx_reasm *reasm;                      /* lazy, guarded heap */
};

struct swx_file_sealer {
    swx_session *s;
    uint8_t  fp[SWX_FINGERPRINT_LEN];
    uint32_t chunk_size;                   /* plaintext bytes per chunk */
    uint64_t file_size;                    /* file bytes to be fed */
    uint64_t total_plain;                  /* 4 + meta_len + file_size */
    uint64_t fed;                          /* file bytes fed so far */
    uint32_t emitted;                      /* frames emitted so far */
    uint32_t meta_len;
    uint8_t  meta[SWX_FILE_META_MAX];
};

/* Message key: HKDF-Expand(session_key, "msg" || dir || counter_be64).
 * Exposed for test assertions on key separation only. */
int swx_msg_key(uint8_t out[32], const uint8_t session_key[32],
                uint8_t dir, uint64_t counter);

#endif /* SWX_SESSION_INTERNAL_H */
