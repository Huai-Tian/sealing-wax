/* SPDX-License-Identifier: AGPL-3.0-only
 * 火漆 · Sealing Wax — https://github.com/Huai-Tian/sealing-wax
 * Copyright (C) 2026 Huai-Tian and contributors
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License only. See the GNU
 * Affero General Public License for more details. You should have received
 * a copy of the license along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */
/*
 * Vendored SPAKE2 self-test: replicates the upstream BoringSSL test matrix
 * (crypto/curve25519/spake25519_test.cc) against the vendored port:
 *
 *   - same password  -> both ends derive the same 64B key
 *   - wrong password -> keys differ (offline verification impossible by
 *     construction, but the derived keys must never match)
 *   - wrong names    -> transcript binding: keys differ
 *   - corrupted bits -> process fails or the keys diverge
 */
#include "spake2.h"

#include <sodium.h>
#include <stdint.h>
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

static const uint8_t NAME_A[] = "swx-inviter";
static const uint8_t NAME_B[] = "swx-responder";

/* One full pairing against the vendored library. Returns 0 and fills
 * a_key/b_key only if both process calls succeed. */
static int run(const uint8_t *pw_a, size_t pw_a_len,
               const uint8_t *pw_b, size_t pw_b_len,
               const uint8_t *my_a, size_t my_a_len,
               const uint8_t *their_a, size_t their_a_len,
               const uint8_t *my_b, size_t my_b_len,
               const uint8_t *their_b, size_t their_b_len,
               uint8_t a_msg[SPAKE2_MAX_MSG_SIZE],
               uint8_t b_msg[SPAKE2_MAX_MSG_SIZE],
               uint8_t a_key[64], uint8_t b_key[64])
{
    struct spake2_ctx_st *a = SPAKE2_CTX_new(spake2_role_alice,
                                            my_a, my_a_len, their_a, their_a_len);
    struct spake2_ctx_st *b = SPAKE2_CTX_new(spake2_role_bob,
                                            my_b, my_b_len, their_b, their_b_len);
    size_t n = 0, ka = 0, kb = 0;

    CHECK(a != NULL && b != NULL);
    CHECK(SPAKE2_generate_msg(a, a_msg, &n, SPAKE2_MAX_MSG_SIZE,
                              pw_a, pw_a_len) == 1);
    CHECK(SPAKE2_generate_msg(b, b_msg, &n, SPAKE2_MAX_MSG_SIZE,
                              pw_b, pw_b_len) == 1);
    if (SPAKE2_process_msg(a, a_key, &ka, 64, b_msg, 32) != 1 ||
        SPAKE2_process_msg(b, b_key, &kb, 64, a_msg, 32) != 1) {
        SPAKE2_CTX_free(a);
        SPAKE2_CTX_free(b);
        return 1;    /* rejected (caller decides if that was expected) */
    }
    CHECK(ka == 64 && kb == 64);
    SPAKE2_CTX_free(a);
    SPAKE2_CTX_free(b);
    return 0;
}

static int test_same_password(void)
{
    for (int i = 0; i < 20; i++) {
        uint8_t am[32], bm[32], ak[64], bk[64];
        CHECK(run((const uint8_t *) "password", 8,
                  (const uint8_t *) "password", 8,
                  NAME_A, sizeof NAME_A - 1, NAME_B, sizeof NAME_B - 1,
                  NAME_B, sizeof NAME_B - 1, NAME_A, sizeof NAME_A - 1,
                  am, bm, ak, bk) == 0);
        CHECK(memcmp(ak, bk, 64) == 0);
    }
    return 0;
}

static int test_wrong_password(void)
{
    uint8_t am[32], bm[32], ak[64], bk[64];
    /* both sides succeed locally — but the keys must never match */
    CHECK(run((const uint8_t *) "password", 8,
              (const uint8_t *) "wrong password", 14,
              NAME_A, sizeof NAME_A - 1, NAME_B, sizeof NAME_B - 1,
              NAME_B, sizeof NAME_B - 1, NAME_A, sizeof NAME_A - 1,
              am, bm, ak, bk) == 0);
    CHECK(memcmp(ak, bk, 64) != 0);
    return 0;
}

static int test_wrong_names(void)
{
    uint8_t am[32], bm[32], ak[64], bk[64];
    static const uint8_t CHARLIE[] = "charlie";
    /* mirror of the upstream BoringSSL test: BOTH sides believe the peer
     * is "charlie" while keeping their own names — the ordered transcripts
     * then differ and the keys must diverge */
    CHECK(run((const uint8_t *) "password", 8,
              (const uint8_t *) "password", 8,
              NAME_A, sizeof NAME_A - 1, CHARLIE, sizeof CHARLIE - 1,
              NAME_B, sizeof NAME_B - 1, CHARLIE, sizeof CHARLIE - 1,
              am, bm, ak, bk) == 0);
    CHECK(memcmp(ak, bk, 64) != 0);    /* transcript binding */
    return 0;
}

static int test_corrupt_bits(void)
{
    for (int bit = 0; bit < 8 * SPAKE2_MAX_MSG_SIZE; bit++) {
        uint8_t am[32], bm[32], ak[64], bk[64];
        size_t n = 0, ka = 0, kb = 0;
        struct spake2_ctx_st *a = SPAKE2_CTX_new(spake2_role_alice,
                                                NAME_A, sizeof NAME_A - 1,
                                                NAME_B, sizeof NAME_B - 1);
        struct spake2_ctx_st *b = SPAKE2_CTX_new(spake2_role_bob,
                                                NAME_B, sizeof NAME_B - 1,
                                                NAME_A, sizeof NAME_A - 1);
        CHECK(a != NULL && b != NULL);
        CHECK(SPAKE2_generate_msg(a, am, &n, SPAKE2_MAX_MSG_SIZE,
                                  (const uint8_t *) "password", 8) == 1);
        CHECK(SPAKE2_generate_msg(b, bm, &n, SPAKE2_MAX_MSG_SIZE,
                                  (const uint8_t *) "password", 8) == 1);
        am[bit / 8] ^= (uint8_t) (1 << (bit & 7));    /* corrupt A's share */
        int pa = SPAKE2_process_msg(a, ak, &ka, 64, bm, 32);
        int pb = SPAKE2_process_msg(b, bk, &kb, 64, am, 32);
        if (pa == 1 && pb == 1) {
            CHECK(memcmp(ak, bk, 64) != 0);    /* keys must diverge */
        }
        SPAKE2_CTX_free(a);
        SPAKE2_CTX_free(b);
    }
    return 0;
}

/* 火漆 integration change #5 (公共会话/静态邀请码): the seeded variant must
 * be byte-deterministic per (seed, password) and must pair normally with a
 * standard responder — a seeded run is equivalent to a CSPRNG run that
 * happened to draw |seed|. */
static int test_seeded_determinism(void)
{
    static const uint8_t SEED[64] = {
        0x37, 0x0a, 0x5e, 0xc2, 0x91, 0x4d, 0xb8, 0x66,
        0xf3, 0x1d, 0x7a, 0x09, 0xd4, 0x8b, 0x2c, 0x50,
        0xe6, 0x19, 0xaf, 0x73, 0x02, 0x9c, 0x48, 0xbe,
        0x65, 0xf1, 0x30, 0x8a, 0xd7, 0x4b, 0x2e, 0x96,
        0x71, 0x0d, 0xca, 0x58, 0x23, 0xb9, 0x04, 0x6e,
        0xe2, 0x97, 0x3a, 0x51, 0xc8, 0x06, 0x74, 0x1b,
        0x9d, 0x42, 0xa5, 0x30, 0x86, 0xf9, 0x63, 0x2b,
        0x14, 0xdc, 0x79, 0x05, 0xba, 0x38, 0x91, 0x60,
    };
    uint8_t m1[32], m2[32], mr[32], bm[32], ak[64], bk[64];
    size_t n = 0, ka = 0, kb = 0;
    struct spake2_ctx_st *a1 = SPAKE2_CTX_new(spake2_role_alice,
                                             NAME_A, sizeof NAME_A - 1,
                                             NAME_B, sizeof NAME_B - 1);
    struct spake2_ctx_st *a2 = SPAKE2_CTX_new(spake2_role_alice,
                                             NAME_A, sizeof NAME_A - 1,
                                             NAME_B, sizeof NAME_B - 1);
    struct spake2_ctx_st *ar = NULL, *b = NULL;

    CHECK(a1 != NULL && a2 != NULL);
    CHECK(SPAKE2_generate_msg_seeded(a1, m1, &n, SPAKE2_MAX_MSG_SIZE,
                                     (const uint8_t *) "password", 8,
                                     SEED) == 1);
    CHECK(SPAKE2_generate_msg_seeded(a2, m2, &n, SPAKE2_MAX_MSG_SIZE,
                                     (const uint8_t *) "password", 8,
                                     SEED) == 1);
    CHECK(memcmp(m1, m2, 32) == 0);          /* deterministic share */
    SPAKE2_CTX_free(a1);
    SPAKE2_CTX_free(a2);

    /* a different seed must yield a different share */
    ar = SPAKE2_CTX_new(spake2_role_alice,
                        NAME_A, sizeof NAME_A - 1, NAME_B, sizeof NAME_B - 1);
    CHECK(ar != NULL);
    CHECK(SPAKE2_generate_msg_seeded(ar, mr, &n, SPAKE2_MAX_MSG_SIZE,
                                     (const uint8_t *) "password", 8,
                                     SEED) == 1);
    /* vary one seed byte via a local copy */
    {
        uint8_t alt[64];
        struct spake2_ctx_st *ax = NULL;
        memcpy(alt, SEED, sizeof alt);
        alt[0] ^= 0x01;
        ax = SPAKE2_CTX_new(spake2_role_alice,
                            NAME_A, sizeof NAME_A - 1,
                            NAME_B, sizeof NAME_B - 1);
        CHECK(ax != NULL);
        CHECK(SPAKE2_generate_msg_seeded(ax, m2, &n, SPAKE2_MAX_MSG_SIZE,
                                         (const uint8_t *) "password", 8,
                                         alt) == 1);
        CHECK(memcmp(mr, m2, 32) != 0);
        SPAKE2_CTX_free(ax);
    }

    /* the seeded share pairs normally with a standard responder */
    b = SPAKE2_CTX_new(spake2_role_bob,
                       NAME_B, sizeof NAME_B - 1, NAME_A, sizeof NAME_A - 1);
    CHECK(b != NULL);
    CHECK(SPAKE2_generate_msg(b, bm, &n, SPAKE2_MAX_MSG_SIZE,
                              (const uint8_t *) "password", 8) == 1);
    CHECK(SPAKE2_process_msg(ar, ak, &ka, 64, bm, 32) == 1);
    CHECK(SPAKE2_process_msg(b, bk, &kb, 64, mr, 32) == 1);
    CHECK(memcmp(ak, bk, 64) == 0);          /* keys agree */
    SPAKE2_CTX_free(ar);
    SPAKE2_CTX_free(b);

    /* discipline: NULL seed is an explicit error, never a CSPRNG fallback */
    a1 = SPAKE2_CTX_new(spake2_role_alice,
                        NAME_A, sizeof NAME_A - 1, NAME_B, sizeof NAME_B - 1);
    CHECK(a1 != NULL);
    CHECK(SPAKE2_generate_msg_seeded(a1, m1, &n, SPAKE2_MAX_MSG_SIZE,
                                     (const uint8_t *) "password", 8,
                                     NULL) == 0);
    SPAKE2_CTX_free(a1);
    return 0;
}

int main(void)
{
    CHECK(sodium_init() >= 0);
    CHECK(test_same_password() == 0);
    CHECK(test_wrong_password() == 0);
    CHECK(test_wrong_names() == 0);
    CHECK(test_corrupt_bits() == 0);
    CHECK(test_seeded_determinism() == 0);
    if (failures == 0) {
        printf("test_spake2: all passed\n");
        return 0;
    }
    printf("test_spake2: %d failure(s)\n", failures);
    return 1;
}
