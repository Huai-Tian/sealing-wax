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
#include "swx_frame.h"

#include <string.h>

static void swx_store64be(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t) (v & 0xff);
        v >>= 8;
    }
}

static uint64_t swx_load64be(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void swx_store32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static uint32_t swx_load32be(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

size_t swx_frame_size(size_t ct_len)
{
    return SWX_DATA_FIXED_LEN + ct_len;
}

int swx_frame_encode(uint8_t *out, size_t out_cap, size_t *out_len,
                     const swx_frame *f)
{
    if (out == NULL || out_len == NULL || f == NULL) {
        return SWX_E_ARG;
    }
    if (f->suite != SWX_SUITE_CHACHA) {
        return SWX_E_FORMAT;
    }

    if (f->type == SWX_TYPE_INVITE || f->type == SWX_TYPE_REPLY) {
        if (f->pubkey == NULL || f->salt == NULL) {
            return SWX_E_ARG;
        }
        if (out_cap < SWX_INVITE_FRAME_LEN) {
            return SWX_E_LEN;
        }
        memcpy(out, SWX_MAGIC, SWX_MAGIC_LEN);
        out[4] = f->type;
        out[5] = f->suite;
        memcpy(out + SWX_HEADER_LEN, f->pubkey, SWX_PUBKEY_LEN);
        memcpy(out + SWX_HEADER_LEN + SWX_PUBKEY_LEN, f->salt, SWX_SALT_LEN);
        *out_len = SWX_INVITE_FRAME_LEN;
        return SWX_OK;
    }

    if (f->type == SWX_TYPE_TEXT || f->type == SWX_TYPE_FILE) {
        if (f->nonce == NULL || f->fingerprint == NULL ||
            (f->ct == NULL && f->ct_len > 0)) {
            return SWX_E_ARG;
        }
        size_t need = swx_frame_size(f->ct_len);
        if (out_cap < need) {
            return SWX_E_LEN;
        }
        memcpy(out, SWX_MAGIC, SWX_MAGIC_LEN);
        out[4] = f->type;
        out[5] = f->suite;
        swx_store64be(out + SWX_HEADER_LEN, f->counter);
        memcpy(out + SWX_HEADER_LEN + SWX_COUNTER_LEN, f->nonce, SWX_NONCE_LEN);
        memcpy(out + 26, f->fingerprint, SWX_FINGERPRINT_LEN);
        swx_store32be(out + 42, f->chunk_index);
        swx_store32be(out + 46, f->total_chunks);
        if (f->ct_len > 0) {
            memcpy(out + SWX_DATA_FIXED_LEN, f->ct, f->ct_len);
        }
        *out_len = need;
        return SWX_OK;
    }

    return SWX_E_TYPE;
}

int swx_frame_decode(swx_frame *out, const uint8_t *in, size_t in_len)
{
    if (out == NULL || in == NULL) {
        return SWX_E_ARG;
    }
    if (in_len < SWX_HEADER_LEN) {
        return SWX_E_FORMAT;
    }
    if (memcmp(in, SWX_MAGIC, SWX_MAGIC_LEN) != 0) {
        return SWX_E_FORMAT;
    }

    memset(out, 0, sizeof(*out));
    out->type = in[4];
    out->suite = in[5];

    if (out->suite != SWX_SUITE_CHACHA) {
        return SWX_E_UNSUPPORTED;
    }

    if (out->type == SWX_TYPE_INVITE || out->type == SWX_TYPE_REPLY) {
        if (in_len != SWX_INVITE_FRAME_LEN) {
            return SWX_E_FORMAT;
        }
        out->pubkey = in + SWX_HEADER_LEN;
        out->salt = out->pubkey + SWX_PUBKEY_LEN;
        return SWX_OK;
    }

    if (out->type == SWX_TYPE_TEXT || out->type == SWX_TYPE_FILE) {
        if (in_len < SWX_DATA_FIXED_LEN + SWX_TAG_LEN) {
            return SWX_E_FORMAT;
        }
        out->counter = swx_load64be(in + SWX_HEADER_LEN);
        out->nonce = in + SWX_HEADER_LEN + SWX_COUNTER_LEN;
        out->fingerprint = in + 26;
        out->chunk_index = swx_load32be(in + 42);
        out->total_chunks = swx_load32be(in + 46);
        out->ct = in + SWX_DATA_FIXED_LEN;
        out->ct_len = in_len - SWX_DATA_FIXED_LEN;
        return SWX_OK;
    }

    return SWX_E_TYPE;
}

int swx_frame_apply_mask(uint8_t *buf, size_t len, const uint8_t ks[SWX_MASK_LEN])
{
    if (buf == NULL || ks == NULL) {
        return SWX_E_ARG;
    }
    if (len < SWX_DATA_FIXED_LEN) {
        return SWX_E_LEN;
    }
    for (size_t i = 0; i < SWX_HEADER_LEN + SWX_COUNTER_LEN; i++) {
        buf[i] ^= ks[i];
    }
    for (size_t i = 26; i < SWX_DATA_FIXED_LEN; i++) {
        buf[i] ^= ks[SWX_HEADER_LEN + SWX_COUNTER_LEN + (i - 26)];
    }
    return SWX_OK;
}

int swx_frame_parse_data(swx_frame *out, const uint8_t hdr[SWX_DATA_FIXED_LEN],
                         const uint8_t *wire, size_t wire_len)
{
    if (out == NULL || hdr == NULL || wire == NULL) {
        return SWX_E_ARG;
    }
    if (wire_len < SWX_DATA_FIXED_LEN + SWX_TAG_LEN) {
        return SWX_E_FORMAT;
    }
    if (memcmp(hdr, SWX_MAGIC, SWX_MAGIC_LEN) != 0) {
        return SWX_E_FORMAT;
    }

    memset(out, 0, sizeof(*out));
    out->type = hdr[4];
    out->suite = hdr[5];

    if (out->suite != SWX_SUITE_CHACHA) {
        return SWX_E_UNSUPPORTED;
    }
    if (out->type != SWX_TYPE_TEXT && out->type != SWX_TYPE_FILE) {
        return SWX_E_TYPE;
    }

    out->counter = swx_load64be(hdr + SWX_HEADER_LEN);
    out->nonce = wire + SWX_HEADER_LEN + SWX_COUNTER_LEN; /* never masked */
    out->fingerprint = hdr + 26;
    out->chunk_index = swx_load32be(hdr + 42);
    out->total_chunks = swx_load32be(hdr + 46);
    out->ct = wire + SWX_DATA_FIXED_LEN;
    out->ct_len = wire_len - SWX_DATA_FIXED_LEN;
    return SWX_OK;
}

int swx_frame_aad(uint8_t *aad_out, const uint8_t *wire, size_t wire_len)
{
    if (aad_out == NULL || wire == NULL) {
        return SWX_E_ARG;
    }
    if (wire_len < SWX_DATA_FIXED_LEN) {
        return SWX_E_FORMAT;
    }
    /* header + counter */
    memcpy(aad_out, wire, SWX_HEADER_LEN + SWX_COUNTER_LEN);
    /* fingerprint + chunk index + total chunks (skipping the nonce) */
    memcpy(aad_out + SWX_HEADER_LEN + SWX_COUNTER_LEN, wire + 26, 24);
    return SWX_OK;
}

/* ---- base64 ---- */

static const char SWX_B64_TAB[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t swx_b64_encoded_len(size_t bin_len)
{
    return ((bin_len + 2) / 3) * 4;
}

int swx_b64_encode(char *out, size_t out_cap,
                   const uint8_t *in, size_t in_len)
{
    if (out == NULL || in == NULL) {
        return SWX_E_ARG;
    }
    size_t need = swx_b64_encoded_len(in_len);
    if (out_cap < need + 1) {
        return SWX_E_LEN;
    }

    size_t o = 0, i = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i + 1] << 8) |
                     in[i + 2];
        out[o++] = SWX_B64_TAB[(v >> 18) & 63];
        out[o++] = SWX_B64_TAB[(v >> 12) & 63];
        out[o++] = SWX_B64_TAB[(v >> 6) & 63];
        out[o++] = SWX_B64_TAB[v & 63];
        i += 3;
    }

    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t) in[i] << 16;
        out[o++] = SWX_B64_TAB[(v >> 18) & 63];
        out[o++] = SWX_B64_TAB[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i + 1] << 8);
        out[o++] = SWX_B64_TAB[(v >> 18) & 63];
        out[o++] = SWX_B64_TAB[(v >> 12) & 63];
        out[o++] = SWX_B64_TAB[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
    return SWX_OK;
}

static int swx_b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int swx_b64_decode(uint8_t *out, size_t out_cap, size_t *out_len,
                   const char *in, size_t in_len)
{
    if (out == NULL || out_len == NULL || in == NULL) {
        return SWX_E_ARG;
    }
    if (in_len == 0) {
        *out_len = 0; /* empty roundtrips to empty */
        return SWX_OK;
    }
    if ((in_len & 3) != 0) {
        return SWX_E_FORMAT;
    }

    size_t pad = 0;
    if (in[in_len - 1] == '=') pad++;
    if (in[in_len - 2] == '=') pad++;
    size_t data_len = in_len - pad;
    for (size_t i = 0; i < data_len; i++) {
        if (in[i] == '=') {
            return SWX_E_FORMAT; /* '=' is legal only at the very end */
        }
    }

    size_t groups = in_len / 4;
    size_t need = groups * 3 - pad;
    if (out_cap < need) {
        return SWX_E_LEN;
    }

    size_t o = 0;
    for (size_t g = 0; g < groups; g++) {
        const char *p = in + g * 4;
        int v0 = swx_b64_val(p[0]);
        int v1 = swx_b64_val(p[1]);
        int v2 = (g * 4 + 2 < data_len) ? swx_b64_val(p[2]) : 0;
        int v3 = (g * 4 + 3 < data_len) ? swx_b64_val(p[3]) : 0;
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            return SWX_E_FORMAT;
        }
        uint32_t v = ((uint32_t) v0 << 18) | ((uint32_t) v1 << 12) |
                     ((uint32_t) v2 << 6) | (uint32_t) v3;
        out[o++] = (uint8_t) (v >> 16);
        if (g * 4 + 2 < data_len) out[o++] = (uint8_t) (v >> 8);
        if (g * 4 + 3 < data_len) out[o++] = (uint8_t) v;
    }
    *out_len = o;
    return SWX_OK;
}
