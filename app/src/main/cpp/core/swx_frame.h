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
#ifndef SWX_FRAME_H
#define SWX_FRAME_H

#include "swx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Non-owning frame view. Pointers reference caller-owned memory and remain
 * valid only as long as that memory does.
 */
typedef struct {
    uint8_t  type;                 /* SWX_TYPE_* */
    uint8_t  suite;                /* SWX_SUITE_* */
    /* invite / reply */
    const uint8_t *pubkey;         /* SWX_PUBKEY_LEN */
    const uint8_t *salt;           /* SWX_SALT_LEN */
    /* data */
    uint64_t counter;              /* per-direction lifetime monotonic */
    const uint8_t *nonce;          /* SWX_NONCE_LEN */
    const uint8_t *fingerprint;    /* SWX_FINGERPRINT_LEN */
    uint32_t chunk_index;
    uint32_t total_chunks;
    const uint8_t *ct;             /* ciphertext || tag */
    size_t   ct_len;               /* includes SWX_TAG_LEN */
} swx_frame;

/* Wire size of a data frame carrying ct_len bytes of ciphertext||tag. */
size_t swx_frame_size(size_t ct_len);

/* Serialize a frame. Returns SWX_OK, SWX_E_ARG/FORMAT/TYPE/LEN. */
int swx_frame_encode(uint8_t *out, size_t out_cap, size_t *out_len,
                     const swx_frame *f);

/* Parse a non-owning view. Validates magic, type, suite and exact lengths.
 * Unknown suites yield SWX_E_UNSUPPORTED (never wrong plaintext). */
int swx_frame_decode(swx_frame *out, const uint8_t *in, size_t in_len);

/* AAD for a data frame = wire[0..14) || wire[26..50). aad_out: SWX_AAD_LEN. */
int swx_frame_aad(uint8_t *aad_out, const uint8_t *wire, size_t wire_len);

/* ---- base64: standard alphabet, with padding, never wrapped ---- */

/* Encoded length excluding the NUL terminator. */
size_t swx_b64_encoded_len(size_t bin_len);

/* out_cap must be swx_b64_encoded_len(in_len) + 1 (NUL). */
int swx_b64_encode(char *out, size_t out_cap,
                   const uint8_t *in, size_t in_len);

/* Strict decode: rejects wrong length, '=', whitespace, invalid chars. */
int swx_b64_decode(uint8_t *out, size_t out_cap, size_t *out_len,
                   const char *in, size_t in_len);

#ifdef __cplusplus
}
#endif

#endif /* SWX_FRAME_H */
