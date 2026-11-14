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
/*
 * Deterministic wire-spec vectors (docs/wire-spec.md §5/§10).
 *
 * Everything random in the real protocol is pinned here: X25519 keys, salts,
 * nonce, fingerprint, counter. The key schedule and frames are built directly
 * from the spec with libsodium primitives, then CROSS-CHECKED against the
 * production core: the generated frames must open through swx_session_import
 * + swx_session_open_text, and the SAS must match HKDF("sas").
 *
 * Output: JSON on stdout. Self-verification failure = non-zero exit.
 */
#include "swx_session.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static const uint8_t A_SK[32] = {
    0x77, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x3f,
};
static const uint8_t B_SK[32] = {
    0x88, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x1f,
};
static const uint8_t A_SALT[16] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
};
static const uint8_t B_SALT[16] = {
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
};
static const uint8_t NONCE[12] = {
    0x0c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
};
static const uint8_t FP[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const uint8_t COUNTER = 1;
static const char *PT = "火漆 wire-spec vector";

static int failures = 0;

#define CHECK(cond) do {                                                     \
    if (!(cond)) {                                                           \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        failures++;                                                          \
        return 1;                                                            \
    }                                                                        \
} while (0)

static void print_hex(const char *name, const uint8_t *p, size_t n)
{
    printf("\"%s\": \"", name);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    printf("\"");
}

static void print_b64(const char *name, const uint8_t *p, size_t n)
{
    char b64[8192];
    if (swx_b64_encode(b64, sizeof b64, p, n) != SWX_OK) {
        failures++;
        return;
    }
    printf("\"%s\": \"%s\"", name, b64);
}

static void aad_spec(uint8_t aad[SWX_AAD_LEN], uint8_t type, uint8_t suite,
                     uint64_t counter, const uint8_t fp[16],
                     uint32_t idx, uint32_t total)
{
    uint8_t *p = aad;
    memcpy(p, "SWX1", 4); p += 4;
    *p++ = type;
    *p++ = suite;
    for (int i = 7; i >= 0; i--) {
        *p++ = (uint8_t) ((counter >> (8 * i)) & 0xff);
    }
    memcpy(p, fp, 16); p += 16;
    *p++ = (uint8_t) (idx >> 24);
    *p++ = (uint8_t) (idx >> 16);
    *p++ = (uint8_t) (idx >> 8);
    *p++ = (uint8_t) idx;
    *p++ = (uint8_t) (total >> 24);
    *p++ = (uint8_t) (total >> 16);
    *p++ = (uint8_t) (total >> 8);
    *p++ = (uint8_t) total;
}

/* Spec key schedule with pinned inputs. */
static int derive_spec(uint8_t session_key[32], char sas[10],
                       const uint8_t a_salt[16], const uint8_t b_salt[16])
{
    uint8_t a_pk[32], b_pk[32], shared[32], salt[32];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    uint8_t sas_raw[64];
    uint8_t info[8];

    CHECK(crypto_scalarmult_base(a_pk, A_SK) == 0);
    CHECK(crypto_scalarmult_base(b_pk, B_SK) == 0);
    CHECK(crypto_scalarmult(shared, A_SK, b_pk) == 0);
    CHECK(crypto_scalarmult(salt, B_SK, a_pk) == 0);        /* same shared */
    CHECK(memcmp(shared, salt, 32) == 0);
    CHECK(!sodium_is_zero(shared, 32));

    memcpy(salt, a_salt, 16);
    memcpy(salt + 16, b_salt, 16);
    CHECK(crypto_kdf_hkdf_sha256_extract(prk, salt, 32, shared, 32) == 0);

    memcpy(info, "session", 7);
    info[7] = SWX_SUITE_CHACHA;
    CHECK(crypto_kdf_hkdf_sha256_expand(session_key, 32,
                                        (const char *) info, 8, prk) == 0);

    CHECK(crypto_kdf_hkdf_sha256_expand(sas_raw, 64, "sas", 3, prk) == 0);
    for (size_t off = 0; off + 4 <= 64; off += 4) {
        uint32_t v = ((uint32_t) sas_raw[off] << 24) |
                     ((uint32_t) sas_raw[off + 1] << 16) |
                     ((uint32_t) sas_raw[off + 2] << 8) |
                     (uint32_t) sas_raw[off + 3];
        if (v < 4000000000u) {
            uint32_t n = v % 1000000000u;
            for (int i = 8; i >= 0; i--) {
                sas[i] = (char) ('0' + (n % 10));
                n /= 10;
            }
            sas[9] = '\0';
            sodium_memzero(shared, sizeof shared);
            sodium_memzero(prk, sizeof prk);
            sodium_memzero(sas_raw, sizeof sas_raw);
            return 0;
        }
    }
    return 1;
}

static int msg_key_spec(uint8_t out[32], const uint8_t session_key[32],
                        uint8_t dir, uint64_t counter)
{
    uint8_t info[12];
    memcpy(info, "msg", 3);
    info[3] = dir;
    for (int i = 0; i < 8; i++) {
        info[4 + i] = (uint8_t) ((counter >> (8 * (7 - i))) & 0xff);
    }
    CHECK(crypto_kdf_hkdf_sha256_expand(out, 32, (const char *) info, 12,
                                        session_key) == 0);
    return 0;
}

/* Build one data frame from the spec, including the transmission mask. */
static int data_frame_spec(uint8_t *wire, size_t cap, size_t *wire_len,
                           uint8_t type, uint8_t dir,
                           const uint8_t session_key[32],
                           const uint8_t mask_ks[SWX_MASK_LEN])
{
    uint8_t key[32], aad[SWX_AAD_LEN], ct[128];
    unsigned long long ct_len = 0;
    swx_frame f;

    CHECK(msg_key_spec(key, session_key, dir, COUNTER) == 0);
    aad_spec(aad, type, SWX_SUITE_CHACHA, COUNTER, FP, 0, 1);
    CHECK(crypto_aead_chacha20poly1305_ietf_encrypt(
              ct, &ct_len, (const uint8_t *) PT, strlen(PT),
              aad, SWX_AAD_LEN, NULL, NONCE, key) == 0);
    sodium_memzero(key, sizeof key);

    memset(&f, 0, sizeof f);
    f.type = type;
    f.suite = SWX_SUITE_CHACHA;
    f.counter = COUNTER;
    f.nonce = NONCE;
    f.fingerprint = FP;
    f.chunk_index = 0;
    f.total_chunks = 1;
    f.ct = ct;
    f.ct_len = (size_t) ct_len;
    CHECK(swx_frame_encode(wire, cap, wire_len, &f) == SWX_OK);
    /* transmission mask: header regions XOR the keystream (wire-spec §3);
     * the nonce region [14,26) stays in the clear */
    CHECK(swx_frame_apply_mask(wire, *wire_len, mask_ks) == SWX_OK);
    return SWX_OK;
}

/* State blob per wire-spec §10 (role byte 5). */
static void state_blob_spec(uint8_t blob[60], uint8_t role,
                            const uint8_t session_key[32])
{
    memcpy(blob, "SWXS", 4);
    blob[4] = 1;
    blob[5] = role;
    blob[6] = SWX_SUITE_CHACHA;
    blob[7] = 0;
    blob[8] = 0x03;
    blob[9] = 0xe8;    /* threshold 1000, inert while flags bit0 = 0 */
    blob[10] = 0;
    blob[11] = 0;
    memcpy(blob + 12, session_key, 32);
    crypto_generichash(blob + 44, 16, blob, 44, NULL, 0);
}

/* Cross-check: the generated frame opens through the production core. */
static int cross_check(uint8_t type, uint8_t sealing_dir, uint8_t opener_role,
                       const uint8_t session_key[32], const uint8_t *wire,
                       size_t wire_len)
{
    uint8_t blob[60];
    uint8_t pt[512];
    size_t pt_len = 0;
    swx_session *s = NULL;

    state_blob_spec(blob, opener_role, session_key);
    CHECK(swx_session_import(&s, blob, sizeof blob, 1, 0) == SWX_OK);
    CHECK(swx_session_open_text(s, wire, wire_len, NULL,
                                pt, sizeof pt, &pt_len) == SWX_OK);
    CHECK(pt_len == strlen(PT) && memcmp(pt, PT, pt_len) == 0);
    swx_session_free(s);
    (void) type;
    (void) sealing_dir;
    return 0;
}

int main(void)
{
    uint8_t a_pk[32], b_pk[32], session_key[32];
    uint8_t invite[SWX_INVITE_FRAME_LEN], reply[SWX_INVITE_FRAME_LEN];
    uint8_t wire_a2b[256], wire_b2a[256];
    uint8_t blob_responder[60], blob_inviter[60];
    uint8_t mask_ks[SWX_MASK_LEN];
    size_t invite_len = 0, reply_len = 0, a2b_len = 0, b2a_len = 0;
    char sas[10];
    uint8_t msg_key_a2b[32], msg_key_b2a[32], aad[SWX_AAD_LEN];
    swx_frame f;

    CHECK(sodium_init() >= 0);
    CHECK(crypto_scalarmult_base(a_pk, A_SK) == 0);
    CHECK(crypto_scalarmult_base(b_pk, B_SK) == 0);

    /* handshake frames via the production encoder */
    memset(&f, 0, sizeof f);
    f.type = SWX_TYPE_INVITE;
    f.suite = SWX_SUITE_CHACHA;
    f.pubkey = a_pk;
    f.salt = A_SALT;
    CHECK(swx_frame_encode(invite, sizeof invite, &invite_len, &f) == SWX_OK);
    f.type = SWX_TYPE_REPLY;
    f.pubkey = b_pk;
    f.salt = B_SALT;
    CHECK(swx_frame_encode(reply, sizeof reply, &reply_len, &f) == SWX_OK);

    CHECK(derive_spec(session_key, sas, A_SALT, B_SALT) == 0);
    /* mask keystream: HKDF-Expand(session_key, "mask" || nonce, 38) —
     * direction-independent (derived from session_key and nonce only) */
    {
        uint8_t info[4 + SWX_NONCE_LEN];
        memcpy(info, "mask", 4);
        memcpy(info + 4, NONCE, SWX_NONCE_LEN);
        CHECK(crypto_kdf_hkdf_sha256_expand(mask_ks, SWX_MASK_LEN,
                                            (const char *) info, sizeof info,
                                            session_key) == 0);
    }
    CHECK(data_frame_spec(wire_a2b, sizeof wire_a2b, &a2b_len,
                          SWX_TYPE_TEXT, SWX_DIR_INVITER, session_key,
                          mask_ks) == 0);
    CHECK(data_frame_spec(wire_b2a, sizeof wire_b2a, &b2a_len,
                          SWX_TYPE_TEXT, SWX_DIR_RESPONDER, session_key,
                          mask_ks) == 0);
    CHECK(msg_key_spec(msg_key_a2b, session_key, SWX_DIR_INVITER, COUNTER) == 0);
    CHECK(msg_key_spec(msg_key_b2a, session_key, SWX_DIR_RESPONDER, COUNTER) == 0);
    aad_spec(aad, SWX_TYPE_TEXT, SWX_SUITE_CHACHA, COUNTER, FP, 0, 1);

    /* production core must agree with the spec implementation */
    CHECK(cross_check(SWX_TYPE_TEXT, SWX_DIR_INVITER, SWX_ROLE_RESPONDER,
                      session_key, wire_a2b, a2b_len) == 0);
    CHECK(cross_check(SWX_TYPE_TEXT, SWX_DIR_RESPONDER, SWX_ROLE_INVITER,
                      session_key, wire_b2a, b2a_len) == 0);

    state_blob_spec(blob_responder, SWX_ROLE_RESPONDER, session_key);
    state_blob_spec(blob_inviter, SWX_ROLE_INVITER, session_key);

    if (failures != 0) {
        fprintf(stderr, "vector_gen: %d failure(s); vectors NOT emitted\n",
                failures);
        return 1;
    }

    printf("{\n");
    printf("  \"spec\": \"SWX1\",\n");
    printf("  \"suite\": 1,\n");
    printf("  \"note\": \"fixed inputs; cross-checked against the production core\",\n");
    printf("  \"fixed_inputs\": {\n");
    printf("    ");
    print_hex("a_sk", A_SK, sizeof A_SK); printf(",\n    ");
    print_hex("b_sk", B_SK, sizeof B_SK); printf(",\n    ");
    print_hex("a_salt", A_SALT, sizeof A_SALT); printf(",\n    ");
    print_hex("b_salt", B_SALT, sizeof B_SALT); printf(",\n    ");
    print_hex("nonce", NONCE, sizeof NONCE); printf(",\n    ");
    print_hex("fingerprint", FP, sizeof FP); printf(",\n    ");
    printf("\"counter\": %d,\n    ", COUNTER);
    printf("\"plaintext\": \"%s\",\n    ", PT);
    print_hex("plaintext_hex", (const uint8_t *) PT, strlen(PT));
    printf("\n  },\n  ");
    print_b64("invite_frame_b64", invite, invite_len); printf(",\n  ");
    print_b64("reply_frame_b64", reply, reply_len); printf(",\n  ");
    printf("\"sas\": \"%s\",\n  ", sas);
    print_hex("session_key_hex", session_key, 32); printf(",\n  ");
    print_hex("aad_hex", aad, SWX_AAD_LEN); printf(",\n  ");
    print_hex("mask_keystream_hex", mask_ks, SWX_MASK_LEN); printf(",\n");
    printf("  \"a2b\": {\n    ");
    print_hex("msg_key_hex", msg_key_a2b, 32); printf(",\n    ");
    print_hex("frame_hex", wire_a2b, a2b_len); printf(",\n    ");
    print_b64("frame_b64", wire_a2b, a2b_len); printf("\n  },\n");
    printf("  \"b2a\": {\n    ");
    print_hex("msg_key_hex", msg_key_b2a, 32); printf(",\n    ");
    print_hex("frame_hex", wire_b2a, b2a_len); printf(",\n    ");
    print_b64("frame_b64", wire_b2a, b2a_len); printf("\n  },\n  ");
    print_hex("state_blob_responder_hex", blob_responder, 60); printf(",\n  ");
    print_hex("state_blob_inviter_hex", blob_inviter, 60);
    printf("\n}\n");
    return 0;
}
