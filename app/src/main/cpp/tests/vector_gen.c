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
 * Deterministic wire-spec vectors (docs/wire-spec.md, spec version 2).
 *
 * Everything random in the real protocol is pinned here by installing a
 * BLAKE2b-based deterministic PRNG as the libsodium randombytes backend
 * BEFORE sodium_init(): the two 64B chunks the vendored SPAKE2 draws for
 * its ephemeral scalars are then fixed (A's invite first, B's reply
 * second), and the whole pairing becomes reproducible byte for byte.
 *
 * The PAKE computation itself is the vendored third-party library
 * (BoringSSL spake25519 port) — the reference implementation IS the
 * library, so vectors pin its inputs and capture its outputs. The data
 * frames are then built directly from the spec (pinned nonce, fingerprint
 * and counter; session_key captured from the PAKE pairing) and
 * CROSS-CHECKED against the production core: the generated frames must
 * open through swx_session_import + swx_session_open_text, and the SAS
 * must match the core's own derivation.
 *
 * Output: JSON on stdout. Self-verification failure = non-zero exit.
 */
#include "swx_session.h"

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- deterministic randombytes backend (pairing entropy pin) ---- */

static const uint8_t PRNG_SEED[32] = {
    0x73, 0x77, 0x78, 0x2d, 0x70, 0x61, 0x6b, 0x65, 0x2d, 0x76, 0x32, 0x2d,
    0x73, 0x65, 0x65, 0x64, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
};
static uint8_t  prng_block[64];
static size_t   prng_off = sizeof prng_block;
static uint64_t prng_ctr = 0;
/* journal of everything emitted: A's 64B, then B's 64B */
static uint8_t  prng_log[256];
static size_t   prng_log_used = 0;

static void prng_refill(void)
{
    uint8_t in[40];
    memcpy(in, PRNG_SEED, sizeof PRNG_SEED);
    for (int i = 0; i < 8; i++) {
        in[32 + i] = (uint8_t) (prng_ctr >> (8 * i));
    }
    prng_ctr++;
    if (crypto_generichash(prng_block, sizeof prng_block, in, sizeof in,
                           NULL, 0) != 0) {
        abort();
    }
    prng_off = 0;
}

static void prng_buf(void *out, size_t len)
{
    uint8_t *p = (uint8_t *) out;
    size_t orig = len;

    while (len-- > 0) {
        if (prng_off >= sizeof prng_block) {
            prng_refill();
        }
        *p++ = prng_block[prng_off++];
    }
    /* journal AFTER filling: the log must hold the emitted bytes */
    if (orig <= sizeof prng_log - prng_log_used) {
        memcpy(prng_log + prng_log_used, out, orig);
        prng_log_used += orig;
    }
}

static const char *prng_name(void)
{
    return "swx_vector_prng";
}

static uint32_t prng_random(void)
{
    uint32_t v = 0;
    prng_buf(&v, sizeof v);
    return v;
}

static uint32_t prng_uniform(const uint32_t upper_bound)
{
    uint32_t vmin, v;
    if (upper_bound < 2) {
        return 0;
    }
    vmin = (1u + ~upper_bound) % upper_bound;    /* ceil(2^32 / ub) * ub - 2^32 */
    do {
        v = prng_random();
    } while (v < vmin);
    return v % upper_bound;
}

static void prng_stir(void)
{
}

static int prng_close(void)
{
    return 0;
}

static randombytes_implementation swx_prng = {
    prng_name,
    prng_random,
    prng_stir,
    prng_uniform,
    prng_buf,
    prng_close,
};

/* ---- fixed protocol inputs ---- */

static const uint8_t PAIR_SECRET[] = "火漆配对暗号";
#define PAIR_SECRET_LEN (sizeof PAIR_SECRET - 1)

static const uint8_t NONCE[12] = {
    0x0c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
};
static const uint8_t FP[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const uint64_t COUNTER = 1;
static const char *PT = "火漆 wire-spec vector";

/* 公共会话 (public session / 静态邀请码): deterministic pairing seed —
 * fixed constants, NOT a PRNG-log draw; the seeded invite consumes zero
 * entropy by construction (self-checked below). Production seeds are 64B
 * CSPRNG output captured once at gate creation (§6), never derived from
 * the 暗号 (§8). */
static const uint8_t GATE_SEED[64] = {
    0x37, 0x0a, 0x5e, 0xc2, 0x91, 0x4d, 0xb8, 0x66,
    0xf3, 0x1d, 0x7a, 0x09, 0xd4, 0x8b, 0x2c, 0x50,
    0xe6, 0x19, 0xaf, 0x73, 0x02, 0x9c, 0x48, 0xbe,
    0x65, 0xf1, 0x30, 0x8a, 0xd7, 0x4b, 0x2e, 0x96,
    0x71, 0x0d, 0xca, 0x58, 0x23, 0xb9, 0x04, 0x6e,
    0xe2, 0x97, 0x3a, 0x51, 0xc8, 0x06, 0x74, 0x1b,
    0x9d, 0x42, 0xa5, 0x30, 0x86, 0xf9, 0x63, 0x2b,
    0x14, 0xdc, 0x79, 0x05, 0xba, 0x38, 0x91, 0x60,
};

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

/* State blob per wire-spec (role byte 5). */
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
    swx_session *a = NULL, *b = NULL;
    uint8_t invite[SWX_PAIR_MSG_LEN], reply[SWX_PAIR_REPLY_LEN];
    uint8_t wire_a2b[256], wire_b2a[256];
    uint8_t blob_responder[60], blob_inviter[60], blob_a[60];
    uint8_t mask_ks[SWX_MASK_LEN];
    uint8_t session_key[32];
    size_t invite_len = 0, reply_len = 0, a2b_len = 0, b2a_len = 0, blen = 0;
    char sas[10], sas_a[10], sas_b[10];
    uint8_t msg_key_a2b[32], msg_key_b2a[32], aad[SWX_AAD_LEN];
    /* 公共会话向量 (public gate vector) */
    uint8_t gate_blob[60], gate_session_key[32];
    uint8_t ginv[SWX_PAIR_MSG_LEN], ginv2[SWX_PAIR_MSG_LEN];
    uint8_t grep[SWX_PAIR_REPLY_LEN];
    size_t ginv_len = 0, grep_len = 0, gblen = 0;
    char gsas[SWX_SAS_DIGITS + 1], gsas_b[SWX_SAS_DIGITS + 1];

    /* pin every random byte BEFORE the library draws any */
    randombytes_set_implementation(&swx_prng);
    CHECK(sodium_init() >= 0);

    /* production pairing with pinned entropy: A's invite (draw 1),
     * B's reply (draw 2), A's finish (no draw) */
    CHECK(swx_session_create(&a, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_create(&b, SWX_ROLE_RESPONDER) == SWX_OK);
    CHECK(swx_session_invite(a, PAIR_SECRET, PAIR_SECRET_LEN,
                             invite, sizeof invite, &invite_len) == SWX_OK);
    CHECK(invite_len == SWX_PAIR_MSG_LEN);
    CHECK(swx_session_reply(b, PAIR_SECRET, PAIR_SECRET_LEN,
                            invite, invite_len,
                            reply, sizeof reply, &reply_len) == SWX_OK);
    CHECK(reply_len == SWX_PAIR_REPLY_LEN);
    CHECK(swx_session_finish(a, reply, reply_len) == SWX_OK);

    /* the core's own SAS derivation must agree with itself across roles */
    CHECK(swx_session_sas(a, sas_a) == SWX_OK);
    CHECK(swx_session_sas(b, sas_b) == SWX_OK);
    CHECK(strcmp(sas_a, sas_b) == 0);
    memcpy(sas, sas_a, sizeof sas);

    /* capture the PAKE-derived session key via the export blob (§10) */
    CHECK(swx_session_export(a, blob_a, sizeof blob_a, &blen) == SWX_OK);
    CHECK(blen == 60);
    memcpy(session_key, blob_a + 12, 32);

    /* mask keystream: HKDF-Expand(session_key, "mask" || nonce, 38) */
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

    /* deterministic consumption: sodium_init draws 16B (internal
     * seeding), then each SPAKE2 share generation draws 64B (A, then B) */
    CHECK(prng_log_used == 16 + 64 + 64);

    /* ---- 公共会话 (public session / 静态邀请码) ----
     * Two independent armed sessions must reproduce a byte-identical
     * static invite while the PRNG log stays FROZEN (the seeded path draws
     * zero entropy); a client then pairs against the static code with an
     * ordinary responder draw. */
    {
        swx_session *g1 = NULL, *g2 = NULL, *gc = NULL;
        size_t frozen;

        CHECK(swx_session_create(&g1, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_invite_seeded(g1, PAIR_SECRET, PAIR_SECRET_LEN,
                                        GATE_SEED, ginv, sizeof ginv,
                                        &ginv_len) == SWX_OK);
        frozen = prng_log_used;
        CHECK(swx_session_create(&g2, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_invite_seeded(g2, PAIR_SECRET, PAIR_SECRET_LEN,
                                        GATE_SEED, ginv2, sizeof ginv2,
                                        &ginv_len) == SWX_OK);
        CHECK(memcmp(ginv, ginv2, sizeof ginv) == 0);   /* 静态码恒等复现 */
        CHECK(prng_log_used == frozen);                 /* 零熵消耗 */
        swx_session_free(g2);

        CHECK(swx_session_create(&gc, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_reply(gc, PAIR_SECRET, PAIR_SECRET_LEN,
                                ginv, sizeof ginv,
                                grep, sizeof grep, &grep_len) == SWX_OK);
        CHECK(swx_session_finish(g1, grep, grep_len) == SWX_OK);
        CHECK(swx_session_sas(g1, gsas) == SWX_OK);
        CHECK(swx_session_sas(gc, gsas_b) == SWX_OK);
        CHECK(strcmp(gsas, gsas_b) == 0);
        CHECK(swx_session_export(g1, gate_blob, sizeof gate_blob,
                                 &gblen) == SWX_OK);
        CHECK(gblen == 60);
        memcpy(gate_session_key, gate_blob + 12, 32);
        swx_session_free(g1);
        swx_session_free(gc);
        CHECK(prng_log_used == frozen + 64);            /* 仅客户端抽 64B */
    }

    swx_session_free(a);
    swx_session_free(b);

    if (failures != 0) {
        fprintf(stderr, "vector_gen: %d failure(s); vectors NOT emitted\n",
                failures);
        return 1;
    }

    printf("{\n");
    printf("  \"spec\": \"SWX1\",\n");
    printf("  \"wire_spec\": 2,\n");
    printf("  \"suite\": 1,\n");
    printf("  \"pairing\": \"spake2 (BoringSSL spake25519 port, vendored)\",\n");
    printf("  \"note\": \"pairing entropy pinned via the PRNG log; data frames cross-checked against the production core\",\n");
    printf("  \"fixed_inputs\": {\n    ");
    printf("\"password\": \"%s\",\n    ", PAIR_SECRET);
    print_hex("prng_init_hex", prng_log, 16); printf(",\n    ");
    print_hex("spake_entropy_a_hex", prng_log + 16, 64); printf(",\n    ");
    print_hex("spake_entropy_b_hex", prng_log + 16 + 64, 64); printf(",\n    ");
    print_hex("nonce", NONCE, sizeof NONCE); printf(",\n    ");
    print_hex("fingerprint", FP, sizeof FP); printf(",\n    ");
    printf("\"counter\": %llu,\n    ", (unsigned long long) COUNTER);
    printf("\"plaintext\": \"%s\",\n    ", PT);
    print_hex("plaintext_hex", (const uint8_t *) PT, strlen(PT));
    printf("\n  },\n  ");
    print_b64("invite_share_b64", invite, invite_len); printf(",\n  ");
    print_b64("reply_share_b64", reply, reply_len); printf(",\n  ");
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
    printf("\"public_gate\": {\n    ");
    printf("\"note\": \"seeded invite draws zero entropy (PRNG log frozen across both armed sessions); the client pairing consumes the third 64B draw\",\n    ");
    print_hex("seed_hex", GATE_SEED, 64); printf(",\n    ");
    print_b64("static_invite_b64", ginv, sizeof ginv); printf(",\n    ");
    print_b64("client_reply_b64", grep, grep_len); printf(",\n    ");
    printf("\"sas\": \"%s\",\n    ", gsas);
    print_hex("session_key_hex", gate_session_key, 32); printf("\n  },\n  ");
    print_hex("state_blob_responder_hex", blob_responder, 60); printf(",\n  ");
    print_hex("state_blob_inviter_hex", blob_inviter, 60);
    printf("\n}\n");
    return 0;
}
