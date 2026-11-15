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

int main(void)
{
    CHECK(sodium_init() >= 0);
    CHECK(test_same_password() == 0);
    CHECK(test_wrong_password() == 0);
    CHECK(test_wrong_names() == 0);
    CHECK(test_corrupt_bits() == 0);
    if (failures == 0) {
        printf("test_spake2: all passed\n");
        return 0;
    }
    printf("test_spake2: %d failure(s)\n", failures);
    return 1;
}
