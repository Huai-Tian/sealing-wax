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

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                                     \
    if (!(cond)) {                                                           \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        failures++;                                                          \
        return 1;                                                            \
    }                                                                        \
} while (0)

static int test_data_roundtrip(void)
{
    uint8_t nonce[SWX_NONCE_LEN], fp[SWX_FINGERPRINT_LEN];
    uint8_t ct[SWX_TAG_LEN + 100];
    uint8_t wire[512];
    size_t n = 0;

    for (int i = 0; i < SWX_NONCE_LEN; i++) nonce[i] = (uint8_t) (i * 7);
    for (int i = 0; i < SWX_FINGERPRINT_LEN; i++) fp[i] = (uint8_t) (0x5A ^ i);
    for (int i = 0; i < sizeof ct; i++) ct[i] = (uint8_t) (i * 3);

    swx_frame f;
    memset(&f, 0, sizeof f);
    f.type = SWX_TYPE_TEXT;
    f.suite = SWX_SUITE_CHACHA;
    f.counter = 0x0102030405060708ULL;
    f.nonce = nonce;
    f.fingerprint = fp;
    f.chunk_index = 2;
    f.total_chunks = 9;
    f.ct = ct;
    f.ct_len = sizeof ct;

    CHECK(swx_frame_encode(wire, sizeof wire, &n, &f) == SWX_OK);
    CHECK(n == SWX_DATA_FIXED_LEN + sizeof ct);

    swx_frame g;
    CHECK(swx_frame_decode(&g, wire, n) == SWX_OK);
    CHECK(g.type == SWX_TYPE_TEXT);
    CHECK(g.counter == 0x0102030405060708ULL);
    CHECK(memcmp(g.nonce, nonce, SWX_NONCE_LEN) == 0);
    CHECK(memcmp(g.fingerprint, fp, SWX_FINGERPRINT_LEN) == 0);
    CHECK(g.chunk_index == 2);
    CHECK(g.total_chunks == 9);
    CHECK(g.ct_len == sizeof ct);
    CHECK(memcmp(g.ct, ct, sizeof ct) == 0);

    /* file type roundtrip */
    f.type = SWX_TYPE_FILE;
    CHECK(swx_frame_encode(wire, sizeof wire, &n, &f) == SWX_OK);
    CHECK(swx_frame_decode(&g, wire, n) == SWX_OK);
    CHECK(g.type == SWX_TYPE_FILE);

    /* truncation below minimum (fixed + tag) must be rejected */
    CHECK(swx_frame_decode(&g, wire, SWX_DATA_FIXED_LEN + SWX_TAG_LEN - 1)
          == SWX_E_FORMAT);

    /* tampered magic must be rejected */
    wire[0] = 'X';
    CHECK(swx_frame_decode(&g, wire, n) == SWX_E_FORMAT);
    wire[0] = 'S';

    /* retired pairing types (0x01/0x02) and unknown types must be rejected
     * on the data channel — never parsed */
    CHECK(swx_frame_encode(wire, sizeof wire, &n, &f) == SWX_OK);
    wire[4] = 0x01;
    CHECK(swx_frame_decode(&g, wire, n) == SWX_E_TYPE);
    wire[4] = 0x02;
    CHECK(swx_frame_decode(&g, wire, n) == SWX_E_TYPE);
    wire[4] = 0x77;
    CHECK(swx_frame_decode(&g, wire, n) == SWX_E_TYPE);

    /* unknown suite must be rejected with UNSUPPORTED, never parsed */
    CHECK(swx_frame_encode(wire, sizeof wire, &n, &f) == SWX_OK);
    wire[5] = 0x02;
    CHECK(swx_frame_decode(&g, wire, n) == SWX_E_UNSUPPORTED);

    return failures ? 1 : 0;
}

static int test_aad(void)
{
    uint8_t wire[SWX_DATA_FIXED_LEN + 32];
    uint8_t aad[SWX_AAD_LEN], expect[SWX_AAD_LEN];

    for (int i = 0; i < (int) sizeof wire; i++) wire[i] = (uint8_t) i;

    CHECK(swx_frame_aad(aad, wire, sizeof wire) == SWX_OK);

    /* AAD = wire[0..14) || wire[26..50) */
    memcpy(expect, wire, 14);
    memcpy(expect + 14, wire + 26, 24);
    CHECK(memcmp(aad, expect, SWX_AAD_LEN) == 0);

    /* short wire must be rejected */
    CHECK(swx_frame_aad(aad, wire, SWX_DATA_FIXED_LEN - 1) == SWX_E_FORMAT);

    return failures ? 1 : 0;
}

static int test_b64(void)
{
    const uint8_t bin[] = { 0x00, 0x01, 0x02, 0xFE, 0xFF };
    char enc[64];
    uint8_t dec[64];
    size_t dn = 0;

    /* known vectors */
    CHECK(swx_b64_encode(enc, sizeof enc, bin, 3) == SWX_OK);
    CHECK(strcmp(enc, "AAEC") == 0);
    CHECK(swx_b64_encode(enc, sizeof enc, bin, 1) == SWX_OK);
    CHECK(strcmp(enc, "AA==") == 0);
    CHECK(swx_b64_encode(enc, sizeof enc, bin, 2) == SWX_OK);
    CHECK(strcmp(enc, "AAE=") == 0);
    CHECK(swx_b64_encode(enc, sizeof enc, bin, 5) == SWX_OK);
    CHECK(strcmp(enc, "AAEC/v8=") == 0); /* cross-checked against system base64 */

    /* roundtrip of all sizes 0..64 */
    uint8_t buf[64], back[64];
    char rtenv[128];
    for (int len = 0; len <= 64; len++) {
        for (int i = 0; i < len; i++) buf[i] = (uint8_t) (i * 31 + len);
        CHECK(swx_b64_encode(rtenv, sizeof rtenv, buf, (size_t) len) == SWX_OK);
        CHECK(strlen(rtenv) == swx_b64_encoded_len((size_t) len));
        CHECK(swx_b64_decode(back, sizeof back, &dn, rtenv, strlen(rtenv))
              == SWX_OK);
        CHECK(dn == (size_t) len);
        CHECK(memcmp(back, buf, (size_t) len) == 0);
    }

    /* rejections: bad length, bad char, newline, '=' in middle */
    CHECK(swx_b64_decode(back, sizeof back, &dn, "AAEC", 4) == SWX_OK);
    CHECK(swx_b64_decode(back, sizeof back, &dn, "AAEC", 3) == SWX_E_FORMAT);
    CHECK(swx_b64_decode(back, sizeof back, &dn, "AA=C", 4) == SWX_E_FORMAT);
    CHECK(swx_b64_decode(back, sizeof back, &dn, "AA\nC", 4) == SWX_E_FORMAT);
    CHECK(swx_b64_decode(back, sizeof back, &dn, "AA C", 4) == SWX_E_FORMAT);
    CHECK(swx_b64_decode(back, sizeof back, &dn, "A-EC", 4) == SWX_E_FORMAT);

    /* output cap too small */
    CHECK(swx_b64_decode(back, 2, &dn, "AAEC/v//", 8) == SWX_E_LEN);

    return failures ? 1 : 0;
}

int main(void)
{
    int r = 0;
    r |= test_data_roundtrip();
    r |= test_aad();
    r |= test_b64();
    if (failures == 0) {
        printf("test_frame: all passed\n");
    } else {
        printf("test_frame: %d failure(s)\n", failures);
    }
    return r;
}
