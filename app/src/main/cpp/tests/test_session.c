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
#include "swx_session_internal.h"
#include "swx_hash.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                                     \
    if (!(cond)) {                                                           \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        failures++;                                                          \
        return 1;                                                            \
    }                                                                        \
} while (0)

#define PIECE_STRIDE (SWX_MAX_PIECE_B64 + 1)
#define MAX_PIECES 8

/* ---- helpers ---- */

static const uint8_t PAIR_SECRET[] = "火漆配对暗号";
#define PAIR_SECRET_LEN (sizeof PAIR_SECRET - 1)

/* full pairing with two explicit 暗号 (differ them for wrong-secret tests) */
static int pair_as(swx_session **a, swx_session **b,
                   const uint8_t *sec_a, size_t len_a,
                   const uint8_t *sec_b, size_t len_b)
{
    uint8_t inv[SWX_PAIR_MSG_LEN], rep[SWX_PAIR_REPLY_LEN];
    size_t n = 0;

    CHECK(swx_session_create(a, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_create(b, SWX_ROLE_RESPONDER) == SWX_OK);
    CHECK(swx_session_invite(*a, sec_a, len_a, inv, sizeof inv, &n) == SWX_OK);
    CHECK(n == SWX_PAIR_MSG_LEN);
    CHECK(swx_session_reply(*b, sec_b, len_b, inv, n,
                            rep, sizeof rep, &n) == SWX_OK);
    CHECK(n == SWX_PAIR_REPLY_LEN);
    CHECK(swx_session_finish(*a, rep, n) == SWX_OK);
    return 0;
}

static int pair(swx_session **a, swx_session **b)
{
    return pair_as(a, b, PAIR_SECRET, PAIR_SECRET_LEN,
                  PAIR_SECRET, PAIR_SECRET_LEN);
}

/* paste one base64 piece into a session */
static int open_b64(swx_session *s, const char *b64,
                    uint8_t *pt_out, size_t cap, size_t *pt_len)
{
    uint8_t wire[SWX_MAX_FRAME_BIN];
    size_t wire_len = 0;
    CHECK(swx_b64_decode(wire, sizeof wire, &wire_len, b64, strlen(b64))
          == SWX_OK);
    return swx_session_open_text(s, wire, wire_len, NULL, pt_out, cap, pt_len);
}

/* white-box: spec-side transmission-mask keystream for a wire frame
 * (mirrors mask_keystream in swx_session.c) */
static int mask_ks_spec(uint8_t ks[SWX_MASK_LEN], const swx_session *s,
                        const uint8_t *wire)
{
    uint8_t info[4 + SWX_NONCE_LEN];
    memcpy(info, "mask", 4);
    memcpy(info + 4, wire + SWX_HEADER_LEN + SWX_COUNTER_LEN, SWX_NONCE_LEN);
    if (crypto_kdf_hkdf_sha256_expand(ks, SWX_MASK_LEN, (const char *) info,
                                      sizeof info, s->session_key) != 0) {
        return SWX_E_CRYPTO;
    }
    return SWX_OK;
}

/* ---- pairing + SAS ---- */

static int test_pairing_sas(void)
{
    swx_session *a = NULL, *b = NULL;
    char sa[SWX_SAS_DIGITS + 1], sb[SWX_SAS_DIGITS + 1];
    uint8_t inv[SWX_PAIR_MSG_LEN], rep[SWX_PAIR_REPLY_LEN];
    size_t n = 0;

    CHECK(pair(&a, &b) == 0);
    CHECK(swx_session_sas(a, sa) == SWX_OK);
    CHECK(swx_session_sas(b, sb) == SWX_OK);
    CHECK(strcmp(sa, sb) == 0);                 /* §11-1: identical SAS */
    CHECK(strlen(sa) == SWX_SAS_DIGITS);
    for (int i = 0; i < SWX_SAS_DIGITS; i++) {
        CHECK(sa[i] >= '0' && sa[i] <= '9');
    }

    /* roles are sticky */
    CHECK(swx_session_role(a) == SWX_ROLE_INVITER);
    CHECK(swx_session_role(b) == SWX_ROLE_RESPONDER);

    /* responder cannot emit an invite */
    CHECK(swx_session_invite(b, PAIR_SECRET, PAIR_SECRET_LEN,
                             inv, sizeof inv, &n) == SWX_E_STATE);
    /* finished session cannot pair again */
    CHECK(swx_session_invite(a, PAIR_SECRET, PAIR_SECRET_LEN,
                             inv, sizeof inv, &n) == SWX_E_STATE);
    CHECK(swx_session_finish(a, rep, 0) == SWX_E_STATE);

    /* pairing-shape confusion is rejected: lengths ARE the format */
    {
        swx_session *c = NULL, *d = NULL, *e = NULL, *f = NULL;
        CHECK(pair(&c, &d) == 0);
        /* an established session can no longer emit invites */
        CHECK(swx_session_invite(c, PAIR_SECRET, PAIR_SECRET_LEN,
                                 inv, sizeof inv, &n) == SWX_E_STATE);
        swx_session_free(c);
        swx_session_free(d);

        CHECK(swx_session_create(&e, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_create(&f, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_invite(f, PAIR_SECRET, PAIR_SECRET_LEN,
                                 inv, sizeof inv, &n) == SWX_OK);
        /* self-paste: A finishing with its own 32B invite (64B expected) */
        CHECK(swx_session_finish(f, inv, n) == SWX_E_FORMAT);
        /* truncated / padded shares are rejected */
        CHECK(swx_session_reply(e, PAIR_SECRET, PAIR_SECRET_LEN,
                                inv, n - 1, rep, sizeof rep, &n)
              == SWX_E_FORMAT);
        CHECK(swx_session_reply(e, PAIR_SECRET, PAIR_SECRET_LEN,
                                inv, n + 1, rep, sizeof rep, &n)
              == SWX_E_FORMAT);
        /* role confusion: a fresh inviter cannot take the responder path */
        CHECK(swx_session_reply(f, PAIR_SECRET, PAIR_SECRET_LEN,
                                inv, n, rep, sizeof rep, &n)
              == SWX_E_STATE);
        /* a fresh responder cannot run finish */
        CHECK(swx_session_finish(e, rep, 0) == SWX_E_STATE);
        /* empty / oversized 暗号 rejected */
        CHECK(swx_session_invite(f, PAIR_SECRET, 0,
                                 inv, sizeof inv, &n) == SWX_E_ARG);
        CHECK(swx_session_invite(f, PAIR_SECRET, SWX_PAIR_SECRET_MAX + 1,
                                 inv, sizeof inv, &n) == SWX_E_ARG);
        swx_session_free(e);
        swx_session_free(f);
    }

    swx_session_free(a);
    swx_session_free(b);
    return failures ? 1 : 0;
}

/* ---- pairing: wrong 暗号 + corruption never produce a live session ---- */

static int test_pairing_wrong_secret(void)
{
    static const uint8_t WRONG[] = "完全不同的暗号";
    swx_session *a = NULL, *b1 = NULL, *b2 = NULL;
    uint8_t inv[SWX_PAIR_MSG_LEN], rep[SWX_PAIR_REPLY_LEN];
    uint8_t blob1[64], blob2[64];
    size_t n = 0, rn = 0, blen = 0;

    /* one invite, two responders with different 暗号: both reply locally,
     * but only the matching 暗号 yields the session A will accept — and
     * the two responders' session keys must differ (暗号 binds the key) */
    CHECK(swx_session_create(&a, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite(a, PAIR_SECRET, PAIR_SECRET_LEN,
                             inv, sizeof inv, &n) == SWX_OK);

    CHECK(swx_session_create(&b1, SWX_ROLE_RESPONDER) == SWX_OK);
    CHECK(swx_session_reply(b1, PAIR_SECRET, PAIR_SECRET_LEN, inv, n,
                            rep, sizeof rep, &rn) == SWX_OK);
    CHECK(swx_session_export(b1, blob1, sizeof blob1, &blen) == SWX_OK);
    CHECK(swx_session_finish(a, rep, rn) == SWX_OK);        /* correct path */
    CHECK(swx_session_sas(a, (char[10]){ 0 }) == SWX_OK);

    /* a SECOND pair: fresh invite bytes consumed with the WRONG 暗号 —
     * the reply is produced locally (undetectable on B by design, §4)
     * but A2 must reject it at finish() */
    {
        swx_session *a2 = NULL;
        CHECK(swx_session_create(&a2, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_create(&b2, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_invite(a2, PAIR_SECRET, PAIR_SECRET_LEN,
                                 inv, sizeof inv, &n) == SWX_OK);
        CHECK(swx_session_reply(b2, WRONG, sizeof WRONG - 1, inv, n,
                                rep, sizeof rep, &rn) == SWX_OK);
        CHECK(swx_session_export(b2, blob2, sizeof blob2, &blen) == SWX_OK);
        CHECK(swx_session_finish(a2, rep, rn) == SWX_E_CRYPTO);
        CHECK(swx_session_sas(a2, (char[10]){ 0 }) == SWX_E_STATE);
        swx_session_free(a2);
    }

    /* 真机 BUG(2026-11,第八批后):B 先用错暗号回复,A finish 失败;
     * B 复用同一邀请码 + 正确暗号重发,A 必须能凭原会话重试成功——
     * SPAKE2_process_msg 单次消费,失败路径需回滚 ctx(swx_session_finish) */
    {
        swx_session *x = NULL, *y = NULL;
        char sx[SWX_SAS_DIGITS + 1], sy[SWX_SAS_DIGITS + 1];
        char pieces[1][PIECE_STRIDE];
        uint32_t np = 0;
        uint8_t out[64];
        size_t out_len = 0;

        CHECK(swx_session_create(&x, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_invite(x, PAIR_SECRET, PAIR_SECRET_LEN,
                                 inv, sizeof inv, &n) == SWX_OK);
        /* B 用错暗号回复:A 报暗号不一致,但会话必须保持可重试 */
        CHECK(swx_session_create(&y, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_reply(y, WRONG, sizeof WRONG - 1, inv, n,
                                rep, sizeof rep, &rn) == SWX_OK);
        CHECK(swx_session_finish(x, rep, rn) == SWX_E_CRYPTO);
        CHECK(swx_session_role(x) == SWX_ROLE_INVITER);   /* 仍 NEW */
        swx_session_free(y);
        /* B 复用同一邀请码 + 正确暗号;A 原会话重试 */
        CHECK(swx_session_create(&y, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_reply(y, PAIR_SECRET, PAIR_SECRET_LEN, inv, n,
                                rep, sizeof rep, &rn) == SWX_OK);
        CHECK(swx_session_finish(x, rep, rn) == SWX_OK);
        CHECK(swx_session_sas(x, sx) == SWX_OK);
        CHECK(swx_session_sas(y, sy) == SWX_OK);
        CHECK(strcmp(sx, sy) == 0);
        /* 重试建立的会话可正常收发 */
        CHECK(swx_session_seal_text(x, (const uint8_t *) "retry ok", 8, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(open_b64(y, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == 8 && memcmp(out, "retry ok", 8) == 0);
        swx_session_free(x);
        swx_session_free(y);
    }

    /* the two responder key schedules must differ (blob layout: key at 12) */
    CHECK(memcmp(blob1 + 12, blob2 + 12, 32) != 0);
    sodium_memzero(blob1, sizeof blob1);
    sodium_memzero(blob2, sizeof blob2);
    swx_session_free(a);
    swx_session_free(b1);
    swx_session_free(b2);

    /* every corrupted bit of the pairing bytes kills the pairing: the
     * reply rejects the share or A's finish rejects the confirm — a
     * corrupted exchange can never complete with live keys */
    for (int bit = 0; bit < 8 * SWX_PAIR_MSG_LEN; bit++) {
        swx_session *x = NULL, *y = NULL;
        CHECK(swx_session_create(&x, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_create(&y, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_invite(x, PAIR_SECRET, PAIR_SECRET_LEN,
                                 inv, sizeof inv, &n) == SWX_OK);
        inv[bit / 8] ^= (uint8_t) (1 << (bit & 7));
        int rb = swx_session_reply(y, PAIR_SECRET, PAIR_SECRET_LEN,
                                   inv, n, rep, sizeof rep, &rn);
        int fa = (rb == SWX_OK) ? swx_session_finish(x, rep, rn)
                                : SWX_E_CRYPTO;
        CHECK(!(rb == SWX_OK && fa == SWX_OK));
        swx_session_free(x);
        swx_session_free(y);
    }
    for (int bit = 0; bit < 8 * SWX_PAIR_REPLY_LEN; bit++) {
        swx_session *x = NULL, *y = NULL;
        CHECK(swx_session_create(&x, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_create(&y, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_invite(x, PAIR_SECRET, PAIR_SECRET_LEN,
                                 inv, sizeof inv, &n) == SWX_OK);
        CHECK(swx_session_reply(y, PAIR_SECRET, PAIR_SECRET_LEN,
                                inv, n, rep, sizeof rep, &rn) == SWX_OK);
        rep[bit / 8] ^= (uint8_t) (1 << (bit & 7));
        CHECK(swx_session_finish(x, rep, rn) == SWX_E_CRYPTO);
        swx_session_free(x);
        swx_session_free(y);
    }

    return failures ? 1 : 0;
}

/* ---- text channel ---- */

static int test_text_roundtrip(void)
{
    swx_session *a = NULL, *b = NULL;
    const uint8_t msg[] = { 'h', 'e', 'l', 'l', 'o', ' ',
                            0xe7, 0x81, 0xab, 0xe6, 0xbc, 0x86 }; /* "hello 火漆" */
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t out[SWX_TEXT_MAX_PT];
    size_t out_len = 0;
    uint64_t sn = 0, hwm = 0;

    CHECK(pair(&a, &b) == 0);
    swx_session_counters(a, &sn, &hwm);
    CHECK(sn == 1 && hwm == 0);

    /* a -> b */
    CHECK(swx_session_seal_text(a, msg, sizeof msg, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(np == 1);
    CHECK(strlen(pieces[0]) <= SWX_MAX_PIECE_B64);
    CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == sizeof msg);
    CHECK(memcmp(out, msg, sizeof msg) == 0);

    swx_session_counters(a, &sn, &hwm);
    CHECK(sn == 2 && hwm == 0);              /* one counter consumed */
    swx_session_counters(b, &sn, &hwm);
    CHECK(sn == 1 && hwm == 1);

    /* b -> a (opposite direction key) */
    CHECK(swx_session_seal_text(b, msg, sizeof msg, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(open_b64(a, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == sizeof msg && memcmp(out, msg, sizeof msg) == 0);

    /* empty message roundtrips to empty */
    CHECK(swx_session_seal_text(a, (const uint8_t *) "", 0, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(np == 1);
    CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == 0);

    swx_session_free(a);
    swx_session_free(b);
    return failures ? 1 : 0;
}

static int test_text_multipiece(void)
{
    swx_session *a = NULL, *b = NULL;
    uint8_t pt[2 * SWX_MAX_PT_PIECE + 100];
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t out[SWX_TEXT_MAX_PT];
    size_t out_len = 0;
    uint64_t sn = 0, hwm = 0;

    for (size_t i = 0; i < sizeof pt; i++) {
        pt[i] = (uint8_t) (i * 7 + 3);
    }

    CHECK(pair(&a, &b) == 0);
    CHECK(swx_session_seal_text(a, pt, sizeof pt, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(np == 3);                          /* 2934 + 2934 + 100 */

    /* in-order paste: partial, partial, complete */
    CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_E_PARTIAL);
    CHECK(open_b64(b, pieces[1], out, sizeof out, &out_len) == SWX_E_PARTIAL);
    CHECK(open_b64(b, pieces[2], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == sizeof pt);
    CHECK(memcmp(out, pt, sizeof pt) == 0);

    swx_session_counters(a, &sn, &hwm);
    CHECK(sn == 4 && hwm == 0);              /* three counters consumed */
    swx_session_counters(b, &sn, &hwm);
    CHECK(hwm == 3);

    /* strict high-water: pasting an earlier piece after a later one is
     * rejected (§4 "旧号拒收"); reassembly never yields wrong plaintext */
    {
        swx_session *c = NULL, *d = NULL;
        CHECK(pair(&c, &d) == 0);
        CHECK(swx_session_seal_text(c, pt, sizeof pt, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(open_b64(d, pieces[1], out, sizeof out, &out_len)
              == SWX_E_PARTIAL);
        CHECK(open_b64(d, pieces[0], out, sizeof out, &out_len)
              == SWX_E_REPLAY);               /* counter 1 <= hwm 2 */
        CHECK(open_b64(d, pieces[2], out, sizeof out, &out_len)
              == SWX_E_PARTIAL);              /* piece 1 lost: incomplete */
        swx_session_free(c);
        swx_session_free(d);
    }

    /* boundary: pt == piece cap is one piece; +1 byte is two */
    {
        swx_session *c = NULL, *d = NULL;
        uint8_t big[SWX_MAX_PT_PIECE + 1];
        memset(big, 0x41, sizeof big);
        CHECK(pair(&c, &d) == 0);
        CHECK(swx_session_seal_text(c, big, SWX_MAX_PT_PIECE, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(np == 1);
        CHECK(swx_session_seal_text(c, big, SWX_MAX_PT_PIECE + 1, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(np == 2);
        CHECK(open_b64(d, pieces[0], out, sizeof out, &out_len)
              == SWX_E_PARTIAL);
        CHECK(open_b64(d, pieces[1], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == SWX_MAX_PT_PIECE + 1);
        CHECK(memcmp(out, big, sizeof big) == 0);
        swx_session_free(c);
        swx_session_free(d);
    }

    swx_session_free(a);
    swx_session_free(b);
    return failures ? 1 : 0;
}

static int test_replay_tamper(void)
{
    swx_session *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    const uint8_t msg[] = "attack at dawn";
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t wire[SWX_MAX_FRAME_BIN], out[SWX_TEXT_MAX_PT];
    size_t wire_len = 0, out_len = 0;

    CHECK(pair(&a, &b) == 0);
    CHECK(pair(&c, &d) == 0);                 /* unrelated session pair */
    CHECK(swx_session_seal_text(a, msg, sizeof msg, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(swx_b64_decode(wire, sizeof wire, &wire_len, pieces[0],
                         strlen(pieces[0])) == SWX_OK);

    /* replay: same wire twice */
    CHECK(swx_session_open_text(b, wire, wire_len, NULL,
                                out, sizeof out, &out_len) == SWX_OK);
    CHECK(swx_session_open_text(b, wire, wire_len, NULL,
                                out, sizeof out, &out_len) == SWX_E_REPLAY);

    /* tampering needs a not-yet-received counter: the replay gate would
     * otherwise fire first (indistinguishable from a replay) */
    CHECK(swx_session_seal_text(a, (const uint8_t *) "tamper me", 9, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(swx_b64_decode(wire, sizeof wire, &wire_len, pieces[0],
                         strlen(pieces[0])) == SWX_OK);

    /* tampered ciphertext -> authentication failure, never wrong plaintext */
    {
        uint8_t bad[SWX_MAX_FRAME_BIN];
        memcpy(bad, wire, wire_len);
        bad[wire_len - 1] ^= 0x01;
        CHECK(swx_session_open_text(b, bad, wire_len, NULL,
                                    out, sizeof out, &out_len)
              == SWX_E_CRYPTO);
    }
    /* tampered counter via white-box re-mask (raised past the high-water
     * gate): the unmask stays valid, AEAD must catch the AAD mismatch */
    {
        uint8_t bad[SWX_MAX_FRAME_BIN];
        uint8_t ks[SWX_MASK_LEN];
        memcpy(bad, wire, wire_len);
        CHECK(mask_ks_spec(ks, a, bad) == SWX_OK);
        CHECK(swx_frame_apply_mask(bad, wire_len, ks) == SWX_OK);
        bad[13] = 0x7f;                       /* counter LSB */
        CHECK(swx_frame_apply_mask(bad, wire_len, ks) == SWX_OK);
        CHECK(swx_session_open_text(b, bad, wire_len, NULL,
                                    out, sizeof out, &out_len)
              == SWX_E_CRYPTO);
    }
    /* tampered fingerprint via white-box re-mask: AEAD catches it */
    {
        uint8_t bad[SWX_MAX_FRAME_BIN];
        uint8_t ks[SWX_MASK_LEN];
        memcpy(bad, wire, wire_len);
        CHECK(mask_ks_spec(ks, a, bad) == SWX_OK);
        CHECK(swx_frame_apply_mask(bad, wire_len, ks) == SWX_OK);
        bad[26] ^= 0xff;
        CHECK(swx_frame_apply_mask(bad, wire_len, ks) == SWX_OK);
        CHECK(swx_session_open_text(b, bad, wire_len, NULL,
                                    out, sizeof out, &out_len)
              == SWX_E_CRYPTO);
    }
    /* truncated frame: mid-ciphertext truncation fails authentication;
     * truncation below the frame minimum is a format error */
    CHECK(swx_session_open_text(b, wire, wire_len - 1, NULL,
                                out, sizeof out, &out_len) == SWX_E_CRYPTO);
    CHECK(swx_session_open_text(b, wire, SWX_DATA_FIXED_LEN + SWX_TAG_LEN - 1,
                                NULL, out, sizeof out, &out_len)
          == SWX_E_FORMAT);
    /* wrong session: the mask derives from a different key, the magic
     * unmasks to garbage -> format error (never wrong plaintext) */
    CHECK(swx_session_open_text(d, wire, wire_len, NULL,
                                out, sizeof out, &out_len) == SWX_E_FORMAT);
    /* the untampered frame is still fine afterwards */
    CHECK(swx_session_open_text(b, wire, wire_len, NULL,
                                out, sizeof out, &out_len) == SWX_OK);

    /* type confusion: a FILE frame must not open as text */
    {
        swx_file_sealer *se = NULL;
        static uint8_t fwire[SWX_FILE_PIECE_DEFAULT + 128];
        size_t flen = 0;
        const uint8_t meta[] = "x.bin";
        CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, 4, 0, NULL)
              == SWX_OK);
        CHECK(swx_file_seal_chunk(se, (const uint8_t *) "abcd", 4,
                                  fwire, sizeof fwire, &flen) == SWX_OK);
        CHECK(swx_session_open_text(b, fwire, flen, NULL,
                                    out, sizeof out, &out_len) == SWX_E_TYPE);
        swx_file_seal_free(se);
    }

    swx_session_free(a);
    swx_session_free(b);
    swx_session_free(c);
    swx_session_free(d);
    return failures ? 1 : 0;
}

/* ---- transmission mask (§4: daily traffic must be unrecognizable) ---- */

static int test_transport_mask(void)
{
    swx_session *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    const uint8_t msg[] = "mask me";
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t wire[SWX_MAX_FRAME_BIN], out[SWX_TEXT_MAX_PT];
    size_t wire_len = 0, out_len = 0;

    /* 8 frames: the first 14 wire bytes carry no magic and differ pairwise
     * (fresh keystream per nonce), and every frame still opens */
    {
        uint8_t heads[8][SWX_HEADER_LEN + SWX_COUNTER_LEN];
        CHECK(pair(&a, &b) == 0);
        for (int i = 0; i < 8; i++) {
            CHECK(swx_session_seal_text(a, msg, sizeof msg, NULL,
                                        (char *) pieces, PIECE_STRIDE,
                                        MAX_PIECES, &np) == SWX_OK);
            CHECK(swx_b64_decode(wire, sizeof wire, &wire_len, pieces[0],
                                 strlen(pieces[0])) == SWX_OK);
            CHECK(wire_len >= SWX_DATA_FIXED_LEN + SWX_TAG_LEN);
            memcpy(heads[i], wire, sizeof heads[i]);
            CHECK(memcmp(heads[i], "SWX1", 4) != 0);  /* magic is masked */
            CHECK(swx_session_open_text(b, wire, wire_len, NULL,
                                        out, sizeof out, &out_len) == SWX_OK);
            CHECK(out_len == sizeof msg && memcmp(out, msg, sizeof msg) == 0);
        }
        for (int i = 0; i < 8; i++) {
            for (int j = i + 1; j < 8; j++) {
                CHECK(memcmp(heads[i], heads[j], sizeof heads[i]) != 0);
            }
        }
        swx_session_free(a);
        swx_session_free(b);
    }

    /* raw tampering: magic region or the clear nonce breaks the unmask
     * (magic unmasks to garbage -> format error); the fingerprint region
     * keeps a valid magic, so AEAD is what catches it */
    CHECK(pair(&a, &b) == 0);
    CHECK(pair(&c, &d) == 0);                     /* unrelated session pair */
    CHECK(swx_session_seal_text(a, msg, sizeof msg, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(swx_b64_decode(wire, sizeof wire, &wire_len, pieces[0],
                         strlen(pieces[0])) == SWX_OK);
    {
        uint8_t bad[SWX_MAX_FRAME_BIN];
        memcpy(bad, wire, wire_len);
        bad[0] ^= 0x01;                           /* masked magic region */
        CHECK(swx_session_open_text(b, bad, wire_len, NULL,
                                    out, sizeof out, &out_len)
              == SWX_E_FORMAT);
        memcpy(bad, wire, wire_len);
        bad[14] ^= 0x01;                          /* clear nonce -> wrong ks */
        CHECK(swx_session_open_text(b, bad, wire_len, NULL,
                                    out, sizeof out, &out_len)
              == SWX_E_FORMAT);
        memcpy(bad, wire, wire_len);
        bad[26] ^= 0x01;                          /* masked fingerprint region */
        CHECK(swx_session_open_text(b, bad, wire_len, NULL,
                                    out, sizeof out, &out_len)
              == SWX_E_CRYPTO);
    }
    /* wrong session: keystream from a different session_key */
    CHECK(swx_session_open_text(d, wire, wire_len, NULL,
                                out, sizeof out, &out_len) == SWX_E_FORMAT);
    /* the untampered frame still opens */
    CHECK(swx_session_open_text(b, wire, wire_len, NULL,
                                out, sizeof out, &out_len) == SWX_OK);

    swx_session_free(a);
    swx_session_free(b);
    swx_session_free(c);
    swx_session_free(d);
    return failures ? 1 : 0;
}

/* ---- padding (§4 length confusion) ---- */

static int test_padding(void)
{
    swx_session *a = NULL, *b = NULL;
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t out[SWX_TEXT_MAX_PT];
    size_t out_len = 0;

    CHECK(pair(&a, &b) == 0);
    CHECK(swx_session_set_padding(a, 1, 1000) == SWX_OK);   /* sender only */

    /* short message: padded to exactly 1000 base64 chars */
    CHECK(swx_session_seal_text(a, (const uint8_t *) "hi", 2, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(np == 1);
    CHECK(strlen(pieces[0]) == 1000);
    CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == 2 && memcmp(out, "hi", 2) == 0);

    /* long message: every piece padded to the threshold */
    {
        uint8_t pt[1500];
        for (size_t i = 0; i < sizeof pt; i++) {
            pt[i] = (uint8_t) (i * 13 + 1);
        }
        CHECK(swx_session_seal_text(a, pt, sizeof pt, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(np == 3);                       /* ceil(1500 / 684) */
        for (uint32_t i = 0; i < np; i++) {
            CHECK(strlen(pieces[i]) == 1000);
        }
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len)
              == SWX_E_PARTIAL);
        CHECK(open_b64(b, pieces[1], out, sizeof out, &out_len)
              == SWX_E_PARTIAL);
        CHECK(open_b64(b, pieces[2], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == sizeof pt && memcmp(out, pt, sizeof pt) == 0);
    }

    /* threshold 4000 maps to the full piece cap */
    CHECK(swx_session_set_padding(a, 1, 4000) == SWX_OK);
    {
        uint8_t pt[SWX_MAX_PT_PIECE];
        memset(pt, 0x42, sizeof pt);
        CHECK(swx_session_seal_text(a, pt, sizeof pt, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(np == 1);
        CHECK(strlen(pieces[0]) == 4000);
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == sizeof pt);
    }

    /* invalid thresholds are rejected (MIN = 200 since 2026-11 第六批) */
    CHECK(swx_session_set_padding(a, 1, 999) == SWX_E_ARG);
    CHECK(swx_session_set_padding(a, 1, 196) == SWX_E_ARG);
    CHECK(swx_session_set_padding(a, 1, 4004) == SWX_E_ARG);

    /* lowest preset: threshold 200 pads short messages to exactly 200 chars */
    CHECK(swx_session_set_padding(a, 1, 200) == SWX_OK);
    CHECK(swx_session_seal_text(a, (const uint8_t *) "hi", 2, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(np == 1 && strlen(pieces[0]) == 200);
    CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == 2 && memcmp(out, "hi", 2) == 0);

    /* a lone trailing 0x80 (no 0x00 after it) is plaintext, not a
     * marker: the receiver must keep it (v2 marker rule) */
    CHECK(swx_session_set_padding(a, 0, 0) == SWX_OK);
    {
        const uint8_t tricky[] = { 'a', 'b', 0x80 };
        CHECK(swx_session_seal_text(a, tricky, sizeof tricky, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == 3 && memcmp(out, tricky, 3) == 0);
    }

    /* v2 marker rule: "呀" = E5 91 80 ends in 0x80 and must survive,
     * padding on or off, single- or multi-piece (owner-reported bug:
     * it used to lose its last byte and render as U+FFFD) */
    {
        const uint8_t ya[] = { 0xe5, 0xa5, 0xbd, 0xe5, 0x91, 0x80 }; /* 好呀 */

        /* padding off: the exact user report */
        CHECK(swx_session_seal_text(a, ya, sizeof ya, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == sizeof ya && memcmp(out, ya, sizeof ya) == 0);

        /* padding on: the marker carries a 0x00, the strip removes
         * only the marker */
        CHECK(swx_session_set_padding(a, 1, 1000) == SWX_OK);
        CHECK(swx_session_seal_text(a, ya, sizeof ya, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(np == 1 && strlen(pieces[0]) == 1000);
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == sizeof ya && memcmp(out, ya, sizeof ya) == 0);

        /* multi-piece, padding on: the full first piece deliberately
         * ends in a raw 0x80 (full pieces carry no marker); the last
         * piece ends in 呀 and carries the [0x80][0x00+] marker */
        {
            uint8_t pt[684 + 6];
            for (size_t i = 0; i < sizeof pt; i++) {
                pt[i] = (uint8_t) ('A' + (i % 26));
            }
            pt[683] = 0x80;                    /* full piece, raw tail */
            memcpy(pt + 684, ya, sizeof ya);   /* last piece ends in 呀 */
            CHECK(swx_session_seal_text(a, pt, sizeof pt, NULL,
                                        (char *) pieces, PIECE_STRIDE,
                                        MAX_PIECES, &np) == SWX_OK);
            CHECK(np == 2);
            CHECK(strlen(pieces[0]) == 1000 && strlen(pieces[1]) == 1000);
            CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len)
                  == SWX_E_PARTIAL);
            CHECK(open_b64(b, pieces[1], out, sizeof out, &out_len) == SWX_OK);
            CHECK(out_len == sizeof pt && memcmp(out, pt, sizeof pt) == 0);
        }

        /* room == 1 (seg = target-1): the piece goes out unpadded and
         * its base64 still encodes to exactly the threshold */
        {
            uint8_t pt[683];
            for (size_t i = 0; i < sizeof pt; i++) {
                pt[i] = (uint8_t) (i * 11 + 1);
            }
            pt[682] = 0x80;
            CHECK(swx_session_seal_text(a, pt, sizeof pt, NULL,
                                        (char *) pieces, PIECE_STRIDE,
                                        MAX_PIECES, &np) == SWX_OK);
            CHECK(np == 1);
            CHECK(strlen(pieces[0]) == 1000);
            CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
            CHECK(out_len == sizeof pt && memcmp(out, pt, sizeof pt) == 0);
        }
    }

    swx_session_free(a);
    swx_session_free(b);
    return failures ? 1 : 0;
}

/* ---- tail-byte stress: the padding marker must never eat plaintext ---- */

/* Every possible final byte value, padding off and on. This is the
 * machine-checked closure of the "呀" bug class: any character whose
 * UTF-8 encoding ends in 0x80 (一 E4B880, 呀 E59180, 😀 F09F9880,
 * 🐀 F09F9080, ... 327 common hanzi + a pile of emoji) must survive. */
static int test_tail_bytes(void)
{
    swx_session *a = NULL, *b = NULL;
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t out[SWX_TEXT_MAX_PT];
    size_t out_len = 0;

    CHECK(pair(&a, &b) == 0);

    /* padding off: every final byte 0x00..0xFF roundtrips byte-exact */
    for (int t = 0; t < 256; t++) {
        const uint8_t pt[4] = { 'x', 'y', 'z', (uint8_t) t };
        CHECK(swx_session_seal_text(a, pt, sizeof pt, NULL,
                                    (char *) pieces, PIECE_STRIDE,
                                    MAX_PIECES, &np) == SWX_OK);
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == 4 && memcmp(out, pt, 4) == 0);
    }

    /* padding on: the marker always carries a 0x00, so the strip can
     * never touch a genuine plaintext tail byte */
    CHECK(swx_session_set_padding(a, 1, 1000) == SWX_OK);
    for (int t = 0; t < 256; t++) {
        const uint8_t pt[4] = { 'x', 'y', 'z', (uint8_t) t };
        CHECK(swx_session_seal_text(a, pt, sizeof pt, NULL,
                                    (char *) pieces, PIECE_STRIDE,
                                    MAX_PIECES, &np) == SWX_OK);
        CHECK(strlen(pieces[0]) == 1000);
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == 4 && memcmp(out, pt, 4) == 0);
    }
    CHECK(swx_session_set_padding(a, 0, 0) == SWX_OK);

    /* boundary contract: an input genuinely ending in [0x80][0x00+] IS
     * the marker and is stripped — unreachable from UTF-8 text (0x00
     * never appears in UTF-8), documented residual (wire-spec §9) */
    {
        const uint8_t markerish[] = { 'a', 0x80, 0x00 };
        CHECK(swx_session_seal_text(a, markerish, sizeof markerish, NULL,
                                    (char *) pieces, PIECE_STRIDE,
                                    MAX_PIECES, &np) == SWX_OK);
        CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == 1 && out[0] == 'a');
    }

    swx_session_free(a);
    swx_session_free(b);
    return failures ? 1 : 0;
}

/* ---- state export/import (§6) ---- */

static int test_state_roundtrip(void)
{
    swx_session *a = NULL, *b = NULL, *a2 = NULL;
    const uint8_t msg1[] = "before export";
    const uint8_t msg2[] = "after import";
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t out[SWX_TEXT_MAX_PT];
    size_t out_len = 0, blob_len = 0;
    uint8_t blob[SWX_STATE_BLOB_MAX];
    uint64_t sn = 0, hwm = 0;

    CHECK(pair(&a, &b) == 0);
    CHECK(swx_session_seal_text(a, msg1, sizeof msg1, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(swx_session_seal_text(b, msg1, sizeof msg1, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(open_b64(a, pieces[0], out, sizeof out, &out_len) == SWX_OK);

    swx_session_counters(a, &sn, &hwm);
    CHECK(sn == 2 && hwm == 1);
    CHECK(swx_session_export(a, blob, sizeof blob, &blob_len) == SWX_OK);
    CHECK(blob_len == 60);
    swx_session_free(a);

    /* import with the persisted counters; conversation continues */
    CHECK(swx_session_import(&a2, blob, blob_len, sn, hwm) == SWX_OK);
    CHECK(swx_session_role(a2) == SWX_ROLE_INVITER);
    CHECK(swx_session_sas(a2, (char[10]){ 0 }) == SWX_E_STATE); /* no SAS */

    CHECK(swx_session_seal_text(a2, msg2, sizeof msg2, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(open_b64(b, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == sizeof msg2 && memcmp(out, msg2, sizeof msg2) == 0);

    CHECK(swx_session_seal_text(b, msg2, sizeof msg2, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(open_b64(a2, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == sizeof msg2 && memcmp(out, msg2, sizeof msg2) == 0);

    /* replay across import is still rejected (hwm carried over) */
    {
        uint8_t wire[SWX_MAX_FRAME_BIN];
        size_t wire_len = 0;
        CHECK(swx_session_seal_text(b, msg1, sizeof msg1, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(swx_b64_decode(wire, sizeof wire, &wire_len, pieces[0],
                             strlen(pieces[0])) == SWX_OK);
        CHECK(swx_session_open_text(a2, wire, wire_len, NULL,
                                    out, sizeof out, &out_len) == SWX_OK);
        CHECK(swx_session_open_text(a2, wire, wire_len, NULL,
                                    out, sizeof out, &out_len)
              == SWX_E_REPLAY);
    }

    /* corrupted blob -> SWX_E_IO, never a live session */
    {
        swx_session *bad = NULL;
        uint8_t copy[SWX_STATE_BLOB_MAX];
        memcpy(copy, blob, blob_len);
        copy[20] ^= 0x40;
        CHECK(swx_session_import(&bad, copy, blob_len, 1, 0) == SWX_E_IO);
        CHECK(bad == NULL);
        CHECK(swx_session_import(&bad, blob, blob_len - 1, 1, 0) == SWX_E_IO);
        CHECK(swx_session_import(&bad, blob, blob_len + 1, 1, 0) == SWX_E_IO);
    }
    /* unknown suite -> explicit rejection, never wrong plaintext */
    {
        swx_session *bad = NULL;
        uint8_t copy[SWX_STATE_BLOB_MAX];
        memcpy(copy, blob, blob_len);
        copy[6] = 0x02;                       /* suite byte */
        crypto_generichash(copy + 44, 16, copy, 44, NULL, 0);
        CHECK(swx_session_import(&bad, copy, blob_len, 1, 0)
              == SWX_E_UNSUPPORTED);
        CHECK(bad == NULL);
    }
    /* padding config survives the roundtrip */
    {
        swx_session *p1 = NULL, *p2 = NULL;
        CHECK(pair(&p1, &p2) == 0);
        CHECK(swx_session_set_padding(p1, 1, 2000) == SWX_OK);
        CHECK(swx_session_export(p1, blob, sizeof blob, &blob_len) == SWX_OK);
        swx_session_free(p1);
        CHECK(swx_session_import(&p1, blob, blob_len, 1, 0) == SWX_OK);
        CHECK(swx_session_seal_text(p1, (const uint8_t *) "x", 1, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(strlen(pieces[0]) == 2000);
        swx_session_free(p1);
        swx_session_free(p2);
    }

    /* role flip: mirror session decrypts our own sent frames (history walk) */
    {
        uint8_t mirror[SWX_STATE_BLOB_MAX];
        swx_session *m = NULL;
        uint8_t own[SWX_MAX_FRAME_BIN];
        size_t own_len = 0;
        char sa2[SWX_SAS_DIGITS + 1];
        uint64_t sn2 = 0, hwm2 = 0;

        /* a was freed above; the imported a2 carries the same inviter role */
        CHECK(swx_session_seal_text(a2, msg2, sizeof msg2, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(swx_b64_decode(own, sizeof own, &own_len, pieces[0],
                             strlen(pieces[0])) == SWX_OK);
        /* the peer can open it; we cannot (direction keys — the second
         * seal keeps the counter above our receive high-water so the
         * direction mismatch, not the replay gate, is what fires) */
        CHECK(swx_session_open_text(b, own, own_len, NULL,
                                    out, sizeof out, &out_len) == SWX_OK);
        CHECK(swx_session_seal_text(a2, msg1, sizeof msg1, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_OK);
        CHECK(swx_b64_decode(own, sizeof own, &own_len, pieces[0],
                             strlen(pieces[0])) == SWX_OK);
        CHECK(swx_session_open_text(a2, own, own_len, NULL,
                                    out, sizeof out, &out_len) == SWX_E_CRYPTO);

        /* re-export: the padding sub-test above reused the blob variable */
        CHECK(swx_session_export(a2, blob, sizeof blob, &blob_len) == SWX_OK);
        memcpy(mirror, blob, blob_len);
        CHECK(swx_state_flip_role(mirror, blob_len) == SWX_OK);
        CHECK(mirror[5] != blob[5]);
        CHECK(swx_session_import(&m, mirror, blob_len, 1, 0) == SWX_OK);
        CHECK(swx_session_role(m) == SWX_ROLE_RESPONDER);   /* a was inviter */
        CHECK(swx_session_sas(m, sa2) == SWX_E_STATE);      /* no SAS on import */
        CHECK(swx_session_open_text(m, own, own_len, NULL,
                                    out, sizeof out, &out_len) == SWX_OK);
        CHECK(out_len == sizeof msg1 && memcmp(out, msg1, sizeof msg1) == 0);
        swx_session_free(m);

        /* corrupted blob is refused */
        mirror[9] ^= 0x11;
        CHECK(swx_state_flip_role(mirror, blob_len) == SWX_E_IO);
    }

    swx_session_free(a2);
    swx_session_free(b);
    return failures ? 1 : 0;
}

/* ---- file channel ---- */

static int test_file_roundtrip(void)
{
    swx_session *a = NULL, *b = NULL;
    const uint8_t meta[] = "hello.bin";
    uint8_t file[2500];
    uint8_t fp[SWX_FINGERPRINT_LEN];
    static uint8_t wire[SWX_FILE_PIECE_DEFAULT + SWX_TAG_LEN + SWX_DATA_FIXED_LEN];
    static uint8_t out[SWX_FILE_PIECE_DEFAULT];
    uint8_t reassembled[4096];
    size_t wire_len = 0, out_len = 0, got = 0;
    uint32_t n_frames = 0;
    uint64_t sn = 0, hwm = 0;
    swx_file_sealer *se = NULL;

    for (size_t i = 0; i < sizeof file; i++) {
        file[i] = (uint8_t) (i * 31 + 7);
    }

    const size_t head = 4 + sizeof meta;       /* meta includes its NUL */
    const size_t room0 = 1000 - head;          /* file bytes fitting chunk 0 */
    CHECK(pair(&a, &b) == 0);
    CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, sizeof file,
                              1000, fp) == SWX_OK);
    CHECK(swx_file_total_chunks(se) == 3);    /* ceil((4+10+2500)/1000) */
    CHECK(swx_file_chunk_room(se) == room0);

    /* wrong feed size (would span a boundary or underfill) is rejected */
    CHECK(swx_file_seal_chunk(se, file, 500, wire, sizeof wire, &wire_len)
          == SWX_E_ARG);

    /* chunk 0: [4B meta_len][meta][room0 file bytes] */
    CHECK(swx_file_seal_chunk(se, file, room0, wire, sizeof wire, &wire_len)
          == SWX_OK);
    CHECK(wire_len == SWX_DATA_FIXED_LEN + 1000 + SWX_TAG_LEN);
    CHECK(swx_session_open_file_frame(b, wire, wire_len, NULL,
                                      out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == 1000);
    CHECK(out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == sizeof meta);
    CHECK(memcmp(out + 4, meta, sizeof meta) == 0);
    CHECK(memcmp(out + head, file, room0) == 0);
    memcpy(reassembled, out + head, room0);
    got = room0;
    n_frames = 1;

    /* chunk 1: exactly 1000 */
    CHECK(swx_file_seal_chunk(se, file + room0, 1000, wire, sizeof wire,
                              &wire_len) == SWX_OK);
    CHECK(swx_session_open_file_frame(b, wire, wire_len, NULL,
                                      out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == 1000 && memcmp(out, file + room0, 1000) == 0);
    memcpy(reassembled + got, out, 1000);
    got += 1000;
    n_frames++;

    /* chunk 2: remainder (final; unpadded because padding is off) */
    {
        const size_t rem = sizeof file - room0 - 1000;    /* 514 */
        CHECK(swx_file_seal_chunk(se, file + room0 + 1000, rem, wire,
                                  sizeof wire, &wire_len) == SWX_OK);
        CHECK(wire_len == SWX_DATA_FIXED_LEN + rem + SWX_TAG_LEN);
        CHECK(swx_file_seal_done(se));
        CHECK(swx_session_open_file_frame(b, wire, wire_len, NULL,
                                          out, sizeof out, &out_len)
              == SWX_OK);
        CHECK(out_len == rem && memcmp(out, file + room0 + 1000, rem) == 0);
        memcpy(reassembled + got, out, rem);
        got += rem;
        n_frames++;
    }

    CHECK(got == sizeof file);
    CHECK(memcmp(reassembled, file, sizeof file) == 0);   /* §11-2 */
    CHECK(n_frames == 3);

    /* one counter consumed per chunk */
    swx_session_counters(a, &sn, &hwm);
    CHECK(sn == 4 && hwm == 0);
    swx_session_counters(b, &sn, &hwm);
    CHECK(hwm == 3);

    /* over-feeding after completion */
    CHECK(swx_file_seal_chunk(se, file, 1, wire, sizeof wire, &wire_len)
          == SWX_E_STATE);
    swx_file_seal_free(se);

    /* tamper + replay need a not-yet-received file frame */
    CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, 4, 1000, fp)
          == SWX_OK);
    CHECK(swx_file_seal_chunk(se, (const uint8_t *) "abcd", 4,
                              wire, sizeof wire, &wire_len) == SWX_OK);
    swx_file_seal_free(se);
    {
        static uint8_t bad[SWX_FILE_PIECE_DEFAULT + 64];
        memcpy(bad, wire, wire_len);
        bad[wire_len - 1] ^= 0x80;
        CHECK(swx_session_open_file_frame(b, bad, wire_len, NULL,
                                          out, sizeof out, &out_len)
              == SWX_E_CRYPTO);
        CHECK(swx_session_open_file_frame(b, wire, wire_len, NULL,
                                          out, sizeof out, &out_len)
              == SWX_OK);
        CHECK(swx_session_open_file_frame(b, wire, wire_len, NULL,
                                          out, sizeof out, &out_len)
              == SWX_E_REPLAY);
    }

    swx_session_free(a);
    swx_session_free(b);
    (void) fp;
    return failures ? 1 : 0;
}

static int test_file_padding_and_edges(void)
{
    swx_session *a = NULL, *b = NULL;
    const uint8_t meta[] = "pad.bin";
    uint8_t file[2000];
    uint8_t fp[SWX_FINGERPRINT_LEN];
    static uint8_t wire[SWX_FILE_PIECE_DEFAULT + SWX_TAG_LEN + SWX_DATA_FIXED_LEN];
    static uint8_t out[SWX_FILE_PIECE_DEFAULT];
    uint8_t cat[4096];
    size_t wire_len = 0, out_len = 0, got = 0, trim_total = 0;
    swx_file_sealer *se = NULL;

    for (size_t i = 0; i < sizeof file; i++) {
        file[i] = (uint8_t) (i * 17 + 11);
    }

    CHECK(pair(&a, &b) == 0);
    CHECK(swx_session_set_padding(a, 1, 1000) == SWX_OK);

    /* padded file: every chunk plaintext is the full bucket size, so the
     * .swx only reveals the bucket count (§4) */
    CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, sizeof file,
                              1000, fp) == SWX_OK);
    CHECK(swx_file_total_chunks(se) == 3);    /* (4+7+2000+999)/1000 */
    for (int i = 0; !swx_file_seal_done(se); i++) {
        size_t room = swx_file_chunk_room(se);
        const uint8_t *src = file + got;
        CHECK(swx_file_seal_chunk(se, src, room, wire, sizeof wire,
                                  &wire_len) == SWX_OK);
        CHECK(swx_session_open_file_frame(b, wire, wire_len, NULL,
                                          out, sizeof out, &out_len)
              == SWX_OK);
        CHECK(out_len == 1000);               /* uniform bucket */
        size_t take = room;
        if (got + take > sizeof file) {
            take = sizeof file - got;         /* trim by known size */
        }
        if (i == 0) {
            /* first chunk carries [4B meta_len][meta] then file bytes */
            CHECK(out[3] == sizeof meta);
            CHECK(memcmp(out + 4, meta, sizeof meta) == 0);
            memcpy(cat + got, out + 4 + sizeof meta, take);
            trim_total = 4 + sizeof meta;
        } else {
            memcpy(cat + got, out, take);
        }
        got += room;
    }
    CHECK(got == sizeof file);
    CHECK(memcmp(cat, file, sizeof file) == 0);
    (void) trim_total;
    swx_file_seal_free(se);

    /* empty file: exactly one metadata-only chunk */
    CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, 0, 1000, fp)
          == SWX_OK);
    CHECK(swx_file_total_chunks(se) == 1);
    CHECK(swx_file_chunk_room(se) == 0);
    CHECK(swx_file_seal_chunk(se, NULL, 0, wire, sizeof wire, &wire_len)
          == SWX_OK);
    CHECK(swx_file_seal_done(se));
    CHECK(swx_session_open_file_frame(b, wire, wire_len, NULL,
                                      out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == 1000);                   /* padded to the bucket */
    CHECK(out[3] == sizeof meta && memcmp(out + 4, meta, sizeof meta) == 0);
    swx_file_seal_free(se);

    /* oversized meta is rejected up front */
    {
        uint8_t bigmeta[SWX_FILE_META_MAX + 1];
        CHECK(swx_file_seal_begin(&se, a, bigmeta, sizeof bigmeta, 10, 0, fp)
              == SWX_E_ARG);
    }
    /* chunk size bounds */
    CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, 10, 100, fp)
          == SWX_E_ARG);
    CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, 10,
                              SWX_FILE_PIECE_DEFAULT + 1, fp) == SWX_E_ARG);

    /* fingerprint is stable across chunks and visible via last_frame */
    {
        uint8_t fp2[SWX_FINGERPRINT_LEN];
        uint64_t counter = 0;
        uint32_t idx = 0, total = 0;
        CHECK(swx_file_seal_begin(&se, a, meta, sizeof meta, 10, 1000, fp2)
              == SWX_OK);
        CHECK(memcmp(fp2, fp, sizeof fp) != 0);  /* fresh per message */
        CHECK(swx_file_seal_chunk(se, file, 10, wire, sizeof wire,
                                  &wire_len) == SWX_OK);
        CHECK(swx_session_last_frame(a, NULL, &counter, &idx, &total)
              == SWX_OK);
        CHECK(counter == a->send_next - 1 && idx == 0 && total == 1);
        swx_file_seal_free(se);
    }

    swx_session_free(a);
    swx_session_free(b);
    return failures ? 1 : 0;
}

/* ---- ledger hash (§7) ---- */

static int test_hash(void)
{
    uint8_t data[10000], digest[SWX_HASH_LEN], digest2[SWX_HASH_LEN];
    swx_hash *h = NULL;

    for (size_t i = 0; i < sizeof data; i++) {
        data[i] = (uint8_t) (i * 37 + 5);
    }

    CHECK(swx_hash_create(&h) == SWX_OK);
    CHECK(swx_hash_update(h, data, sizeof data) == SWX_OK);
    CHECK(swx_hash_final(h, digest) == SWX_OK);
    crypto_generichash(digest2, SWX_HASH_LEN, data, sizeof data, NULL, 0);
    CHECK(memcmp(digest, digest2, SWX_HASH_LEN) == 0);
    swx_hash_free(h);

    /* arbitrary splits agree with the one-shot digest */
    {
        size_t offs[] = { 1, 3, 4096, 4096, 1804, 0 };
        size_t pos = 0;
        CHECK(swx_hash_create(&h) == SWX_OK);
        for (size_t i = 0; i < sizeof offs / sizeof offs[0]; i++) {
            CHECK(swx_hash_update(h, data + pos, offs[i]) == SWX_OK);
            pos += offs[i];
        }
        CHECK(pos == sizeof data);
        CHECK(swx_hash_final(h, digest2) == SWX_OK);
        CHECK(memcmp(digest, digest2, SWX_HASH_LEN) == 0);
        /* final() consumes the state */
        CHECK(swx_hash_final(h, digest2) == SWX_E_STATE);
        CHECK(swx_hash_update(h, data, 1) == SWX_E_STATE);
        swx_hash_free(h);
    }

    /* different input, different digest */
    {
        data[0] ^= 1;
        CHECK(swx_hash_create(&h) == SWX_OK);
        CHECK(swx_hash_update(h, data, sizeof data) == SWX_OK);
        CHECK(swx_hash_final(h, digest2) == SWX_OK);
        CHECK(memcmp(digest, digest2, SWX_HASH_LEN) != 0);
        swx_hash_free(h);
    }
    return failures ? 1 : 0;
}

/* ---- memory discipline (§10, §11-3) ---- */

static int test_memory_discipline(void)
{
    swx_session *a = NULL, *b = NULL;
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t out[64];
    size_t out_len = 0;

    CHECK(pair(&a, &b) == 0);
    CHECK(swx_session_seal_text(a, (const uint8_t *) "wipe me", 7, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);

    /* white-box: wipe zeroes key bytes in place and kills the session */
    {
        uint8_t before[32];
        memcpy(before, a->session_key, 32);
        swx_session_wipe(a);
        for (size_t i = 0; i < 32; i++) {
            CHECK(a->session_key[i] == 0);
        }
        CHECK(a->spake == NULL);    /* pairing ctx burned, never dangling */
        CHECK(a->state == SWX_ST_DEAD);
        CHECK(swx_session_sas(a, (char[10]){ 0 }) == SWX_E_STATE);
        CHECK(swx_session_seal_text(a, (const uint8_t *) "x", 1, NULL,
                                    (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                    &np) == SWX_E_STATE);
        CHECK(before[0] != 0 || before[1] != 0 || before[2] != 0);
    }
    swx_session_free(a);    /* free after wipe must be safe */

    /* white-box: an in-flight pairing carries a live ctx; wipe burns it */
    {
        swx_session *p = NULL;
        uint8_t inv[SWX_PAIR_MSG_LEN];
        size_t n = 0;
        CHECK(swx_session_create(&p, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(p->spake != NULL);
        CHECK(swx_session_invite(p, PAIR_SECRET, PAIR_SECRET_LEN,
                                 inv, sizeof inv, &n) == SWX_OK);
        swx_session_wipe(p);
        CHECK(p->spake == NULL);
        CHECK(p->state == SWX_ST_DEAD);
        swx_session_free(p);
    }

    /* message keys separate by direction and counter */
    {
        uint8_t k1[32], k2[32], k3[32];
        uint8_t key[32];
        memset(key, 0x77, sizeof key);
        CHECK(swx_msg_key(k1, key, SWX_DIR_INVITER, 1) == SWX_OK);
        CHECK(swx_msg_key(k2, key, SWX_DIR_RESPONDER, 1) == SWX_OK);
        CHECK(swx_msg_key(k3, key, SWX_DIR_INVITER, 2) == SWX_OK);
        CHECK(memcmp(k1, k2, 32) != 0);
        CHECK(memcmp(k1, k3, 32) != 0);
        CHECK(memcmp(k2, k3, 32) != 0);
        /* deterministic */
        CHECK(swx_msg_key(k2, key, SWX_DIR_INVITER, 1) == SWX_OK);
        CHECK(memcmp(k1, k2, 32) == 0);
    }

    /* nonce uniqueness across many messages (12B CSPRNG per message) */
    {
        swx_session *c = NULL, *d = NULL;
        uint8_t nonces[32][SWX_NONCE_LEN];
        CHECK(pair(&c, &d) == 0);
        for (int i = 0; i < 32; i++) {
            uint8_t wire[SWX_MAX_FRAME_BIN];
            size_t wire_len = 0;
            CHECK(swx_session_seal_text(c, (const uint8_t *) "n", 1, NULL,
                                        (char *) pieces, PIECE_STRIDE,
                                        MAX_PIECES, &np) == SWX_OK);
            CHECK(swx_b64_decode(wire, sizeof wire, &wire_len, pieces[0],
                                 strlen(pieces[0])) == SWX_OK);
            /* nonce region is never masked: read it straight off the wire */
            memcpy(nonces[i], wire + SWX_HEADER_LEN + SWX_COUNTER_LEN,
                   SWX_NONCE_LEN);
            CHECK(swx_session_open_text(d, wire, wire_len, NULL,
                                        out, sizeof out, &out_len)
                  == SWX_OK);
        }
        for (int i = 0; i < 32; i++) {
            for (int j = i + 1; j < 32; j++) {
                CHECK(memcmp(nonces[i], nonces[j], SWX_NONCE_LEN) != 0);
            }
        }
        swx_session_free(c);
        swx_session_free(d);
    }

    swx_session_free(b);
    return failures ? 1 : 0;
}

/* ---- 公共会话 (public session / 静态邀请码, §5) ---- */

/* 固定测试种子:非零、非重复图案;生产种子是门禁创建时的一次性 CSPRNG
 * 输出(平台层持久化,§6),绝不从暗号派生(§8)。 */
static const uint8_t GATE_SEED[SWX_GATE_SEED_LEN] = {
    0x37, 0x0a, 0x5e, 0xc2, 0x91, 0x4d, 0xb8, 0x66,
    0xf3, 0x1d, 0x7a, 0x09, 0xd4, 0x8b, 0x2c, 0x50,
    0xe6, 0x19, 0xaf, 0x73, 0x02, 0x9c, 0x48, 0xbe,
    0x65, 0xf1, 0x30, 0x8a, 0xd7, 0x4b, 0x2e, 0x96,
    0x71, 0x0d, 0xca, 0x58, 0x23, 0xb9, 0x04, 0x6e,
    0xe2, 0x97, 0x3a, 0x51, 0xc8, 0x06, 0x74, 0x1b,
    0x9d, 0x42, 0xa5, 0x30, 0x86, 0xf9, 0x63, 0x2b,
    0x14, 0xdc, 0x79, 0x05, 0xba, 0x38, 0x91, 0x60,
};

static int test_public_invite_deterministic(void)
{
    swx_session *a = NULL, *b = NULL;
    uint8_t x1[SWX_PAIR_MSG_LEN], x2[SWX_PAIR_MSG_LEN], xr[SWX_PAIR_MSG_LEN];
    size_t n = 0;

    /* 同种子 + 同暗号 → 恒等复现同一静态邀请码 */
    CHECK(swx_session_create(&a, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite_seeded(a, PAIR_SECRET, PAIR_SECRET_LEN,
                                     GATE_SEED, x1, sizeof x1, &n)
          == SWX_OK);
    CHECK(n == SWX_PAIR_MSG_LEN);
    CHECK(swx_session_create(&b, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite_seeded(b, PAIR_SECRET, PAIR_SECRET_LEN,
                                    GATE_SEED, x2, sizeof x2, &n) == SWX_OK);
    CHECK(memcmp(x1, x2, sizeof x1) == 0);
    swx_session_free(a);
    swx_session_free(b);

    /* 暗号变 → 静态码随 blinding 携带的 H(暗号) 同变(换锁 = 换码) */
    CHECK(swx_session_create(&a, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite_seeded(a, (const uint8_t *) "另一个暗号", 15,
                                    GATE_SEED, xr, sizeof xr, &n) == SWX_OK);
    CHECK(memcmp(x1, xr, sizeof x1) != 0);
    swx_session_free(a);

    /* 无种子的普通配对用临时标量,与静态码必然不同 */
    CHECK(swx_session_create(&a, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite(a, PAIR_SECRET, PAIR_SECRET_LEN,
                             xr, sizeof xr, &n) == SWX_OK);
    CHECK(memcmp(x1, xr, sizeof x1) != 0);
    swx_session_free(a);

    /* 入参纪律:应答方无邀请路径;NULL 种子显式拒绝 */
    CHECK(swx_session_create(&b, SWX_ROLE_RESPONDER) == SWX_OK);
    CHECK(swx_session_invite_seeded(b, PAIR_SECRET, PAIR_SECRET_LEN,
                                    GATE_SEED, xr, sizeof xr, &n)
          == SWX_E_STATE);
    swx_session_free(b);
    CHECK(swx_session_create(&a, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite_seeded(a, PAIR_SECRET, PAIR_SECRET_LEN,
                                    NULL, xr, sizeof xr, &n) == SWX_E_ARG);
    swx_session_free(a);
    return 0;
}

/* 两位客户先后用同一静态码配对:码恒等、会话钥匙互相独立(交叉解密必败)、
 * SAS 各自新鲜——公共会话的核心安全性质(§5/§14) */
static int test_public_pair_independence(void)
{
    swx_session *a1 = NULL, *b1 = NULL, *a2 = NULL, *b2 = NULL;
    uint8_t inv1[SWX_PAIR_MSG_LEN], inv2[SWX_PAIR_MSG_LEN];
    uint8_t rep[SWX_PAIR_REPLY_LEN];
    char sas1[SWX_SAS_DIGITS + 1], sas2[SWX_SAS_DIGITS + 1];
    const uint8_t msg[] = "给客户的私信";
    char pieces[MAX_PIECES][PIECE_STRIDE];
    uint32_t np = 0;
    uint8_t out[SWX_TEXT_MAX_PT];
    size_t out_len = 0, n = 0;

    /* 客户 1 全流程 */
    CHECK(swx_session_create(&a1, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite_seeded(a1, PAIR_SECRET, PAIR_SECRET_LEN,
                                    GATE_SEED, inv1, sizeof inv1, &n)
          == SWX_OK);
    CHECK(swx_session_create(&b1, SWX_ROLE_RESPONDER) == SWX_OK);
    CHECK(swx_session_reply(b1, PAIR_SECRET, PAIR_SECRET_LEN,
                            inv1, n, rep, sizeof rep, &n) == SWX_OK);
    CHECK(swx_session_finish(a1, rep, n) == SWX_OK);
    CHECK(swx_session_sas(a1, sas1) == SWX_OK);
    CHECK(swx_session_sas(b1, sas2) == SWX_OK);
    CHECK(strcmp(sas1, sas2) == 0);          /* 同一次配对双端一致 */

    /* 再武装:同种子恒等复现同一静态码;客户 2 照常配对 */
    CHECK(swx_session_create(&a2, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite_seeded(a2, PAIR_SECRET, PAIR_SECRET_LEN,
                                    GATE_SEED, inv2, sizeof inv2, &n)
          == SWX_OK);
    CHECK(memcmp(inv1, inv2, sizeof inv1) == 0);
    CHECK(swx_session_create(&b2, SWX_ROLE_RESPONDER) == SWX_OK);
    CHECK(swx_session_reply(b2, PAIR_SECRET, PAIR_SECRET_LEN,
                            inv2, n, rep, sizeof rep, &n) == SWX_OK);
    CHECK(swx_session_finish(a2, rep, n) == SWX_OK);
    CHECK(swx_session_sas(a2, sas2) == SWX_OK);
    CHECK(strcmp(sas1, sas2) != 0);          /* 每位客户 SAS 各自新鲜 */

    /* 钥匙独立:a1→客户1 的密文,客户2 打不开;客户1 自己能开。
     * 错会话的帧在传输掩码层即死——头被错钥匙解掩码出垃圾 magic,
     * 连 AEAD 都到不了(E_FORMAT 早于 E_CRYPTO,§4 掩码设计) */
    CHECK(swx_session_seal_text(a1, msg, sizeof msg, NULL,
                                (char *) pieces, PIECE_STRIDE, MAX_PIECES,
                                &np) == SWX_OK);
    CHECK(np == 1);
    CHECK(open_b64(b2, pieces[0], out, sizeof out, &out_len) == SWX_E_FORMAT);
    CHECK(open_b64(b1, pieces[0], out, sizeof out, &out_len) == SWX_OK);
    CHECK(out_len == sizeof msg && memcmp(out, msg, sizeof msg) == 0);

    swx_session_free(a1);
    swx_session_free(b1);
    swx_session_free(a2);
    swx_session_free(b2);
    return 0;
}

/* 错误暗号的回复不消耗武装(3ee0222 回滚对静态码同样成立);拿着
 * 别的门的静态码来配也自然拒绝(旧码/错码在 finish 裁决) */
static int test_public_reject_and_rearm(void)
{
    swx_session *gate = NULL, *client = NULL;
    uint8_t inv[SWX_PAIR_MSG_LEN], inv_other[SWX_PAIR_MSG_LEN];
    uint8_t rep[SWX_PAIR_REPLY_LEN];
    size_t n = 0;

    CHECK(swx_session_create(&gate, SWX_ROLE_INVITER) == SWX_OK);
    CHECK(swx_session_invite_seeded(gate, PAIR_SECRET, PAIR_SECRET_LEN,
                                    GATE_SEED, inv, sizeof inv, &n) == SWX_OK);

    /* 错误暗号:B 侧照常出回复码(两帧下限,裁决在 A 端),finish 拒绝 */
    CHECK(swx_session_create(&client, SWX_ROLE_RESPONDER) == SWX_OK);
    CHECK(swx_session_reply(client, (const uint8_t *) "猜错的暗号", 15,
                            inv, n, rep, sizeof rep, &n) == SWX_OK);
    CHECK(swx_session_finish(gate, rep, n) == SWX_E_CRYPTO);
    swx_session_free(client);

    /* 下一客户(正确暗号)在同一武装上直接成功——拒绝未消耗静态码 */
    CHECK(swx_session_create(&client, SWX_ROLE_RESPONDER) == SWX_OK);
    n = SWX_PAIR_MSG_LEN;    /* reply() 把 n 写成 64,这里要用邀请码长度 */
    CHECK(swx_session_reply(client, PAIR_SECRET, PAIR_SECRET_LEN,
                            inv, n, rep, sizeof rep, &n) == SWX_OK);
    CHECK(swx_session_finish(gate, rep, n) == SWX_OK);
    swx_session_free(client);
    swx_session_free(gate);

    /* 拿别的门的静态码来配:码不同 → confirm 必然不匹配 */
    {
        swx_session *other_gate = NULL;
        uint8_t other_seed[SWX_GATE_SEED_LEN];
        for (size_t i = 0; i < sizeof other_seed; i++) {
            other_seed[i] = (uint8_t) (0x5b ^ i);
        }
        CHECK(swx_session_create(&other_gate, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_invite_seeded(other_gate, PAIR_SECRET,
                                        PAIR_SECRET_LEN, other_seed,
                                        inv_other, sizeof inv_other, &n)
              == SWX_OK);
        CHECK(memcmp(inv, inv_other, sizeof inv) != 0);
        CHECK(swx_session_create(&client, SWX_ROLE_RESPONDER) == SWX_OK);
        CHECK(swx_session_reply(client, PAIR_SECRET, PAIR_SECRET_LEN,
                                inv_other, n, rep, sizeof rep, &n) == SWX_OK);
        CHECK(swx_session_create(&gate, SWX_ROLE_INVITER) == SWX_OK);
        CHECK(swx_session_invite_seeded(gate, PAIR_SECRET, PAIR_SECRET_LEN,
                                        GATE_SEED, inv, sizeof inv, &n)
              == SWX_OK);
        CHECK(swx_session_finish(gate, rep, SWX_PAIR_REPLY_LEN) == SWX_E_CRYPTO);
        swx_session_free(client);
        swx_session_free(gate);
        swx_session_free(other_gate);
    }
    return 0;
}

int main(void)
{
    int r = 0;
    r |= test_pairing_sas();
    r |= test_pairing_wrong_secret();
    r |= test_public_invite_deterministic();
    r |= test_public_pair_independence();
    r |= test_public_reject_and_rearm();
    r |= test_text_roundtrip();
    r |= test_text_multipiece();
    r |= test_replay_tamper();
    r |= test_transport_mask();
    r |= test_padding();
    r |= test_tail_bytes();
    r |= test_state_roundtrip();
    r |= test_file_roundtrip();
    r |= test_file_padding_and_edges();
    r |= test_hash();
    r |= test_memory_discipline();
    if (failures == 0) {
        printf("test_session: all passed\n");
    } else {
        printf("test_session: %d failure(s)\n", failures);
    }
    return r;
}
