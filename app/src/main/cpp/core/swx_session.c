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

#include <sodium.h>
#include <string.h>

/* ---- byte helpers ---- */

static void put32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static void put64be(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t) (v & 0xff);
        v >>= 8;
    }
}

/* AAD = magic || type || suite || counter || fp || idx || total
 * (equals wire[0..14) || wire[26..50); the nonce is excluded by design) */
static void aad_build(uint8_t aad[SWX_AAD_LEN], uint8_t type, uint8_t suite,
                      uint64_t counter, const uint8_t fp[SWX_FINGERPRINT_LEN],
                      uint32_t idx, uint32_t total)
{
    memcpy(aad, SWX_MAGIC, SWX_MAGIC_LEN);
    aad[4] = type;
    aad[5] = suite;
    put64be(aad + 6, counter);
    memcpy(aad + 14, fp, SWX_FINGERPRINT_LEN);
    put32be(aad + 30, idx);
    put32be(aad + 34, total);
}

/* Plaintext target for a base64 padding threshold (swx_common.h note). */
static size_t pad_target(uint16_t threshold_b64)
{
    size_t t = (size_t) (threshold_b64 / 4) * 3;
    t -= SWX_DATA_FIXED_LEN + SWX_TAG_LEN;
    if (t < 1) {
        t = 1;
    }
    if (t > SWX_MAX_PT_PIECE) {
        t = SWX_MAX_PT_PIECE;
    }
    return t;
}

/* Strip [pt][0x80][0x00*] marker padding; returns len when no marker. */
static size_t pad_strip(const uint8_t *pt, size_t len)
{
    size_t i = len;
    while (i > 0 && pt[i - 1] == 0x00) {
        i--;
    }
    if (i > 0 && pt[i - 1] == 0x80) {
        return i - 1;
    }
    return len;
}

/* ---- key derivation (§4) ---- */

int swx_msg_key(uint8_t out[32], const uint8_t session_key[32],
                uint8_t dir, uint64_t counter)
{
    uint8_t info[3 + 1 + 8];
    memcpy(info, "msg", 3);
    info[3] = dir;
    put64be(info + 4, counter);
    if (crypto_kdf_hkdf_sha256_expand(out, 32, (const char *) info,
                                      sizeof info, session_key) != 0) {
        return SWX_E_CRYPTO;
    }
    return SWX_OK;
}

static int derive(swx_session *s, const uint8_t peer_pk[SWX_PUBKEY_LEN],
                  const uint8_t peer_salt[SWX_SALT_LEN])
{
    uint8_t shared[32];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    uint8_t salt[2 * SWX_SALT_LEN];
    uint8_t sas_raw[64];
    uint8_t info[8];
    int ret = SWX_E_CRYPTO;
    int ok = 0;

    /* shared = X25519(sk, peer_pk); reject degenerate results */
    if (crypto_scalarmult(shared, s->sk, peer_pk) != 0 ||
        sodium_is_zero(shared, sizeof shared)) {
        goto out;
    }

    /* salt = inviter_salt || responder_salt: role-ordered, both ends agree */
    if (s->role == SWX_ROLE_INVITER) {
        memcpy(salt, s->salt_own, SWX_SALT_LEN);
        memcpy(salt + SWX_SALT_LEN, peer_salt, SWX_SALT_LEN);
    } else {
        memcpy(salt, peer_salt, SWX_SALT_LEN);
        memcpy(salt + SWX_SALT_LEN, s->salt_own, SWX_SALT_LEN);
    }
    if (crypto_kdf_hkdf_sha256_extract(prk, salt, sizeof salt,
                                       shared, sizeof shared) != 0) {
        goto out;
    }

    /* session_key = HKDF-Expand(prk, "session" || suite, 32) */
    memcpy(info, "session", 7);
    info[7] = s->suite;
    if (crypto_kdf_hkdf_sha256_expand(s->session_key, 32,
                                      (const char *) info, sizeof info,
                                      prk) != 0) {
        goto out;
    }

    /* sas = HKDF-Expand(prk, "sas") -> rejection sampling -> 9 digits */
    if (crypto_kdf_hkdf_sha256_expand(sas_raw, sizeof sas_raw, "sas", 3,
                                      prk) != 0) {
        goto out;
    }
    for (size_t off = 0; off + 4 <= sizeof sas_raw; off += 4) {
        uint32_t v = ((uint32_t) sas_raw[off] << 24) |
                     ((uint32_t) sas_raw[off + 1] << 16) |
                     ((uint32_t) sas_raw[off + 2] << 8) |
                     (uint32_t) sas_raw[off + 3];
        if (v < 4000000000u) {                    /* 4 * 10^9: uniform mod 1e9 */
            uint32_t n = v % 1000000000u;
            for (int i = 8; i >= 0; i--) {
                s->sas[i] = (char) ('0' + (n % 10));
                n /= 10;
            }
            s->sas[9] = '\0';
            ok = 1;
            break;
        }
    }
    if (!ok) {
        goto out;    /* probability ~5e-19; fail closed */
    }

    s->state = SWX_ST_ESTABLISHED;
    ret = SWX_OK;

out:
    sodium_memzero(shared, sizeof shared);
    sodium_memzero(prk, sizeof prk);
    sodium_memzero(sas_raw, sizeof sas_raw);
    if (ok) {
        /* pairing material is dead: only the session key survives */
        sodium_memzero(s->sk, sizeof s->sk);
        sodium_memzero(s->salt_own, sizeof s->salt_own);
        sodium_memzero(s->salt_peer, sizeof s->salt_peer);
    }
    return ret;
}

/* ---- lifecycle ---- */

static int session_alloc(swx_session **out)
{
    if (out == NULL) {
        return SWX_E_ARG;
    }
    if (sodium_init() < 0) {
        return SWX_E_CRYPTO;
    }
    *out = (swx_session *) sodium_malloc(sizeof(swx_session));
    if (*out == NULL) {
        return SWX_E_LEN;
    }
    sodium_memzero(*out, sizeof **out);
    return SWX_OK;
}

int swx_session_create(swx_session **out, int as_inviter)
{
    swx_session *s = NULL;
    int ret = session_alloc(&s);
    if (ret != SWX_OK) {
        return ret;
    }
    s->state = SWX_ST_NEW;
    s->role = (uint8_t) as_inviter;
    s->suite = SWX_SUITE_CHACHA;
    s->pad_threshold = 1000;
    s->send_next = 1;    /* counter 0 is never used (hwm starts at 0) */
    randombytes_buf(s->sk, sizeof s->sk);
    if (crypto_scalarmult_base(s->pk, s->sk) != 0) {
        sodium_free(s);
        return SWX_E_CRYPTO;
    }
    randombytes_buf(s->salt_own, sizeof s->salt_own);
    *out = s;
    return SWX_OK;
}

static void reasm_reset(swx_reasm *r)
{
    sodium_memzero(r, sizeof *r);
}

void swx_session_wipe(swx_session *s)
{
    if (s == NULL) {
        return;
    }
    if (s->reasm != NULL) {
        sodium_memzero(s->reasm, sizeof *s->reasm);
        sodium_free(s->reasm);
        s->reasm = NULL;
    }
    sodium_memzero(s, sizeof *s);
    s->state = SWX_ST_DEAD;
}

void swx_session_free(swx_session *s)
{
    if (s == NULL) {
        return;
    }
    swx_session_wipe(s);
    sodium_free(s);
}

/* ---- pairing ---- */

int swx_session_invite(const swx_session *s,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    swx_frame f;
    if (s == NULL || out == NULL || out_len == NULL) {
        return SWX_E_ARG;
    }
    if (s->state != SWX_ST_NEW || s->role != SWX_ROLE_INVITER) {
        return SWX_E_STATE;
    }
    memset(&f, 0, sizeof f);
    f.type = SWX_TYPE_INVITE;
    f.suite = s->suite;
    f.pubkey = s->pk;
    f.salt = s->salt_own;
    return swx_frame_encode(out, out_cap, out_len, &f);
}

static int consume_handshake(swx_session *s, uint8_t expect_type,
                             const uint8_t *wire, size_t wire_len,
                             swx_frame *view)
{
    int ret;
    if (s == NULL || wire == NULL) {
        return SWX_E_ARG;
    }
    if (s->state != SWX_ST_NEW) {
        return SWX_E_STATE;
    }
    if ((ret = swx_frame_decode(view, wire, wire_len)) != SWX_OK) {
        return ret;
    }
    if (view->type != expect_type) {
        return SWX_E_TYPE;
    }
    if (memcmp(view->pubkey, s->pk, SWX_PUBKEY_LEN) == 0) {
        return SWX_E_STATE;    /* our own frame pasted back */
    }
    return SWX_OK;
}

int swx_session_reply(swx_session *s,
                      const uint8_t *invite, size_t invite_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    swx_frame view, f;
    int ret = consume_handshake(s, SWX_TYPE_INVITE, invite, invite_len, &view);
    if (ret != SWX_OK) {
        return ret;
    }
    /* encode first: derive() wipes the salt this frame must still carry */
    memset(&f, 0, sizeof f);
    f.type = SWX_TYPE_REPLY;
    f.suite = s->suite;
    f.pubkey = s->pk;
    f.salt = s->salt_own;
    ret = swx_frame_encode(out, out_cap, out_len, &f);
    if (ret != SWX_OK) {
        return ret;
    }
    return derive(s, view.pubkey, view.salt);
}

int swx_session_finish(swx_session *s, const uint8_t *reply, size_t reply_len)
{
    swx_frame view;
    int ret = consume_handshake(s, SWX_TYPE_REPLY, reply, reply_len, &view);
    if (ret != SWX_OK) {
        return ret;
    }
    return derive(s, view.pubkey, view.salt);
}

int swx_session_sas(const swx_session *s, char out[SWX_SAS_DIGITS + 1])
{
    if (s == NULL || out == NULL) {
        return SWX_E_ARG;
    }
    /* established but imported sessions have no SAS (prk is gone) */
    if (s->state != SWX_ST_ESTABLISHED || s->sas[0] == '\0') {
        return SWX_E_STATE;
    }
    memcpy(out, s->sas, SWX_SAS_DIGITS + 1);
    return SWX_OK;
}

int swx_session_role(const swx_session *s)
{
    if (s == NULL || s->state == SWX_ST_DEAD) {
        return 0;
    }
    return s->role;
}

/* ---- padding ---- */

int swx_session_set_padding(swx_session *s, int enabled, uint32_t threshold_b64)
{
    if (s == NULL) {
        return SWX_E_ARG;
    }
    if (s->state == SWX_ST_DEAD) {
        return SWX_E_STATE;
    }
    if (enabled) {
        if (threshold_b64 < SWX_PAD_THRESHOLD_MIN ||
            threshold_b64 > SWX_PAD_THRESHOLD_MAX ||
            (threshold_b64 & 3u) != 0) {
            return SWX_E_ARG;
        }
        s->pad_threshold = (uint16_t) threshold_b64;
    }
    s->pad_on = (uint8_t) (enabled ? 1 : 0);
    return SWX_OK;
}

/* ---- counters ---- */

void swx_session_counters(const swx_session *s,
                          uint64_t *send_next, uint64_t *recv_hwm)
{
    if (s == NULL) {
        return;
    }
    if (send_next != NULL) {
        *send_next = s->send_next;
    }
    if (recv_hwm != NULL) {
        *recv_hwm = s->recv_hwm;
    }
}

/* ---- sealing core (one frame) ---- */

static int seal_frame(swx_session *s, uint8_t type,
                      const uint8_t *pt, size_t pt_len,
                      const uint8_t fp[SWX_FINGERPRINT_LEN],
                      uint32_t idx, uint32_t total,
                      uint8_t *wire_out, size_t wire_cap, size_t *wire_len)
{
    uint8_t key[32];
    uint8_t nonce[SWX_NONCE_LEN];
    uint8_t aad[SWX_AAD_LEN];
    uint8_t *ct;
    unsigned long long ct_len = 0;
    swx_frame f;
    uint8_t dir = (s->role == SWX_ROLE_INVITER) ? SWX_DIR_INVITER
                                                : SWX_DIR_RESPONDER;
    uint64_t counter = s->send_next;
    int ret;

    if (pt_len > SWX_FILE_PIECE_DEFAULT) {
        return SWX_E_LEN;
    }
    if (wire_cap < swx_frame_size(pt_len + SWX_TAG_LEN)) {
        return SWX_E_LEN;
    }
    ct = (uint8_t *) sodium_malloc(pt_len + SWX_TAG_LEN);
    if (ct == NULL) {
        return SWX_E_LEN;
    }

    if ((ret = swx_msg_key(key, s->session_key, dir, counter)) != SWX_OK) {
        goto out;
    }
    randombytes_buf(nonce, sizeof nonce);
    aad_build(aad, type, s->suite, counter, fp, idx, total);
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ct, &ct_len, pt, (unsigned long long) pt_len,
            aad, SWX_AAD_LEN, NULL, nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        ret = SWX_E_CRYPTO;
        goto out;
    }
    sodium_memzero(key, sizeof key);

    memset(&f, 0, sizeof f);
    f.type = type;
    f.suite = s->suite;
    f.counter = counter;
    f.nonce = nonce;
    f.fingerprint = fp;
    f.chunk_index = idx;
    f.total_chunks = total;
    f.ct = ct;
    f.ct_len = (size_t) ct_len;
    if ((ret = swx_frame_encode(wire_out, wire_cap, wire_len, &f)) == SWX_OK) {
        s->send_next++;    /* counter consumed only on success */
        memcpy(s->last_fp, fp, SWX_FINGERPRINT_LEN);
        s->last_counter = counter;
        s->last_idx = idx;
        s->last_total = total;
    }

out:
    sodium_free(ct);
    return ret;
}

/* ---- text channel ---- */

int swx_session_seal_text(swx_session *s,
                          const uint8_t *pt, size_t pt_len,
                          uint8_t fp_out[SWX_FINGERPRINT_LEN],
                          char *pieces, size_t piece_stride,
                          uint32_t pieces_cap, uint32_t *n_pieces)
{
    uint8_t fp[SWX_FINGERPRINT_LEN];
    uint8_t *piece;
    size_t target;           /* plaintext size of a full piece */
    uint32_t total;
    int ret;

    if (s == NULL || pt == NULL || pieces == NULL || n_pieces == NULL) {
        return SWX_E_ARG;
    }
    if (s->state != SWX_ST_ESTABLISHED) {
        return SWX_E_STATE;
    }
    if (piece_stride < SWX_MAX_PIECE_B64 + 1) {
        return SWX_E_ARG;
    }
    if (pt_len > SWX_TEXT_MAX_PT) {
        return SWX_E_LEN;
    }

    target = s->pad_on ? pad_target(s->pad_threshold) : SWX_MAX_PT_PIECE;
    total = (uint32_t) ((pt_len + target - 1) / target);
    if (total == 0) {
        total = 1;    /* empty message occupies one piece */
    }
    if (total > pieces_cap || total > SWX_TEXT_MAX_PIECES) {
        return SWX_E_LEN;
    }

    randombytes_buf(fp, sizeof fp);
    piece = (uint8_t *) sodium_malloc(SWX_MAX_PT_PIECE);
    if (piece == NULL) {
        return SWX_E_LEN;
    }

    *n_pieces = 0;
    for (uint32_t i = 0; i < total; i++) {
        size_t off = (size_t) i * target;
        size_t seg = pt_len - off;
        size_t piece_pt;
        if (seg > target) {
            seg = target;
        }
        uint8_t wire[SWX_MAX_FRAME_BIN];
        size_t wire_len = 0;

        if (s->pad_on) {
            /* [pt][0x80][0x00*] up to the exact piece size; a piece that
             * is exactly full carries no marker (nothing to hide) */
            piece_pt = target;
            sodium_memzero(piece, piece_pt);
            memcpy(piece, pt + off, seg);
            if (seg < piece_pt) {
                piece[seg] = 0x80;
            }
        } else {
            piece_pt = seg;
            memcpy(piece, pt + off, seg);
        }

        ret = seal_frame(s, SWX_TYPE_TEXT, piece, piece_pt, fp, i, total,
                         wire, sizeof wire, &wire_len);
        if (ret != SWX_OK) {
            goto out;
        }
        ret = swx_b64_encode(pieces + (size_t) i * piece_stride,
                             piece_stride, wire, wire_len);
        if (ret != SWX_OK) {
            goto out;
        }
        (*n_pieces)++;
    }

    memcpy(s->last_fp, fp, sizeof fp);
    if (fp_out != NULL) {
        memcpy(fp_out, fp, sizeof fp);
    }
    ret = SWX_OK;

out:
    sodium_free(piece);
    return ret;
}

static int reasm_stash(swx_session *s, const swx_frame *v,
                       const uint8_t *pt, size_t pt_len)
{
    swx_reasm *r = s->reasm;

    if (v->total_chunks == 0 || v->total_chunks > SWX_REASM_MAX_PIECES ||
        v->chunk_index >= v->total_chunks) {
        return SWX_E_FORMAT;
    }
    if (r == NULL || r->total != v->total_chunks ||
        memcmp(r->fp, v->fingerprint, SWX_FINGERPRINT_LEN) != 0) {
        /* new logical message: abandon any incomplete predecessor */
        if (r == NULL) {
            r = (swx_reasm *) sodium_malloc(sizeof *r);
            if (r == NULL) {
                return SWX_E_LEN;
            }
            s->reasm = r;
        }
        reasm_reset(r);
        memcpy(r->fp, v->fingerprint, SWX_FINGERPRINT_LEN);
        r->total = v->total_chunks;
    }
    if (r->have[v->chunk_index]) {
        return SWX_E_FORMAT;    /* duplicate index */
    }
    memcpy(r->buf + (size_t) v->chunk_index * SWX_MAX_PT_PIECE, pt, pt_len);
    r->len[v->chunk_index] = pt_len;
    r->have[v->chunk_index] = 1;
    r->got++;
    r->used += pt_len;
    return SWX_OK;
}

/* Shared open path for data frames. view_out (nullable) receives a copy of
 * the decoded view; its pointers reference the caller's wire buffer. */
static int open_data(swx_session *s, uint8_t want_type,
                     const uint8_t *wire, size_t wire_len,
                     uint8_t fp_out[SWX_FINGERPRINT_LEN], swx_frame *view_out,
                     uint8_t *pt_out, size_t pt_cap, size_t *pt_len)
{
    swx_frame v;
    uint8_t key[32];
    uint8_t aad[SWX_AAD_LEN];
    unsigned long long m_len = 0;
    uint8_t dir = (s->role == SWX_ROLE_INVITER) ? SWX_DIR_RESPONDER
                                                : SWX_DIR_INVITER;
    int ret;

    if (s == NULL || wire == NULL || pt_len == NULL) {
        return SWX_E_ARG;
    }
    if (s->state != SWX_ST_ESTABLISHED) {
        return SWX_E_STATE;
    }
    if ((ret = swx_frame_decode(&v, wire, wire_len)) != SWX_OK) {
        return ret;
    }
    if (v.type != want_type) {
        return SWX_E_TYPE;
    }
    if (v.counter <= s->recv_hwm) {
        return SWX_E_REPLAY;
    }
    if (v.ct_len > SWX_FILE_PIECE_DEFAULT + SWX_TAG_LEN ||
        v.ct_len < SWX_TAG_LEN || pt_cap < v.ct_len - SWX_TAG_LEN) {
        return SWX_E_LEN;
    }
    if ((ret = swx_msg_key(key, s->session_key, dir, v.counter)) != SWX_OK) {
        return ret;
    }
    aad_build(aad, v.type, v.suite, v.counter, v.fingerprint,
              v.chunk_index, v.total_chunks);
    ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        pt_out, &m_len, NULL, v.ct, (unsigned long long) v.ct_len,
        aad, SWX_AAD_LEN, v.nonce, key);
    sodium_memzero(key, sizeof key);
    if (ret != 0) {
        return SWX_E_CRYPTO;
    }

    /* authentic frame: advance high-water and record bookkeeping */
    s->recv_hwm = v.counter;
    memcpy(s->last_fp, v.fingerprint, SWX_FINGERPRINT_LEN);
    s->last_counter = v.counter;
    s->last_idx = v.chunk_index;
    s->last_total = v.total_chunks;
    if (fp_out != NULL) {
        memcpy(fp_out, v.fingerprint, SWX_FINGERPRINT_LEN);
    }
    if (view_out != NULL) {
        *view_out = v;
    }
    *pt_len = (size_t) m_len;
    return SWX_OK;
}

int swx_session_open_text(swx_session *s,
                          const uint8_t *wire, size_t wire_len,
                          uint8_t fp_out[SWX_FINGERPRINT_LEN],
                          uint8_t *pt_out, size_t pt_cap, size_t *pt_len)
{
    swx_frame v;
    uint8_t scratch[SWX_MAX_PT_PIECE];
    size_t raw_len = 0, len;
    int ret;

    if (wire_len > SWX_MAX_FRAME_BIN) {
        return SWX_E_FORMAT;    /* text channel pieces are base64-bounded */
    }
    ret = open_data(s, SWX_TYPE_TEXT, wire, wire_len, fp_out, &v,
                    scratch, sizeof scratch, &raw_len);
    if (ret != SWX_OK) {
        return ret;
    }

    len = pad_strip(scratch, raw_len);

    if (v.total_chunks == 1) {
        if (pt_cap < len) {
            return SWX_E_LEN;
        }
        memcpy(pt_out, scratch, len);
        *pt_len = len;
        return SWX_OK;
    }

    /* multi-piece: stash, assemble when the last piece arrives */
    if ((ret = reasm_stash(s, &v, scratch, len)) != SWX_OK) {
        return ret;
    }
    {
        swx_reasm *r = s->reasm;
        if (r->got < r->total) {
            return SWX_E_PARTIAL;
        }
        if (r->used > pt_cap) {
            return SWX_E_LEN;
        }
        size_t off = 0;
        for (uint32_t i = 0; i < r->total; i++) {
            memcpy(pt_out + off,
                   r->buf + (size_t) i * SWX_MAX_PT_PIECE, r->len[i]);
            off += r->len[i];
        }
        *pt_len = off;
        reasm_reset(r);    /* ready for the next logical message */
    }
    return SWX_OK;
}

int swx_session_open_file_frame(swx_session *s,
                                const uint8_t *wire, size_t wire_len,
                                uint8_t fp_out[SWX_FINGERPRINT_LEN],
                                uint8_t *pt_out, size_t pt_cap, size_t *pt_len)
{
    return open_data(s, SWX_TYPE_FILE, wire, wire_len, fp_out, NULL,
                     pt_out, pt_cap, pt_len);
}

int swx_session_last_frame(const swx_session *s,
                           uint8_t fp_out[SWX_FINGERPRINT_LEN],
                           uint64_t *counter, uint32_t *chunk_index,
                           uint32_t *total_chunks)
{
    if (s == NULL) {
        return SWX_E_ARG;
    }
    if (s->state != SWX_ST_ESTABLISHED) {
        return SWX_E_STATE;
    }
    if (fp_out != NULL) {
        memcpy(fp_out, s->last_fp, SWX_FINGERPRINT_LEN);
    }
    if (counter != NULL) {
        *counter = s->last_counter;
    }
    if (chunk_index != NULL) {
        *chunk_index = s->last_idx;
    }
    if (total_chunks != NULL) {
        *total_chunks = s->last_total;
    }
    return SWX_OK;
}

/* ---- file channel ---- */

/* Plain-stream position of the next unfed byte (meta prefix included). */
static uint64_t file_plain_pos(const swx_file_sealer *se)
{
    return 4 + se->meta_len + se->fed;
}

/* Bytes the next seal_chunk call may accept: never spans a chunk boundary.
 * Zero-room happens exactly when the file is fully fed (possibly empty). */
static size_t file_room(const swx_file_sealer *se)
{
    uint64_t pos = file_plain_pos(se);
    uint64_t left = se->file_size - se->fed;
    uint64_t room = se->chunk_size - (pos % se->chunk_size);
    return (size_t) (left < room ? left : room);
}

int swx_file_seal_begin(swx_file_sealer **se, swx_session *s,
                        const uint8_t *meta, size_t meta_len,
                        uint64_t file_size, uint32_t chunk_size,
                        uint8_t fp_out[SWX_FINGERPRINT_LEN])
{
    swx_file_sealer *e;

    if (se == NULL || s == NULL || (meta == NULL && meta_len > 0)) {
        return SWX_E_ARG;
    }
    if (s->state != SWX_ST_ESTABLISHED) {
        return SWX_E_STATE;
    }
    if (meta_len > SWX_FILE_META_MAX) {
        return SWX_E_ARG;
    }
    if (chunk_size == 0) {
        chunk_size = SWX_FILE_PIECE_DEFAULT;
    }
    if (chunk_size < 256 || chunk_size > SWX_FILE_PIECE_DEFAULT ||
        (uint64_t) meta_len + 4 + SWX_TAG_LEN >= chunk_size) {
        return SWX_E_ARG;
    }

    e = (swx_file_sealer *) sodium_malloc(sizeof *e);
    if (e == NULL) {
        return SWX_E_LEN;
    }
    sodium_memzero(e, sizeof *e);
    e->s = s;
    e->chunk_size = chunk_size;
    e->meta_len = (uint32_t) meta_len;
    e->file_size = file_size;
    e->total_plain = 4 + (uint64_t) meta_len + file_size;
    if (meta_len > 0) {
        memcpy(e->meta, meta, meta_len);
    }
    randombytes_buf(e->fp, sizeof e->fp);

    memcpy(s->last_fp, e->fp, sizeof e->fp);
    if (fp_out != NULL) {
        memcpy(fp_out, e->fp, sizeof e->fp);
    }
    *se = e;
    return SWX_OK;
}

size_t swx_file_chunk_room(const swx_file_sealer *se)
{
    if (se == NULL || se->fed >= se->file_size) {
        return 0;
    }
    return file_room(se);
}

uint32_t swx_file_total_chunks(const swx_file_sealer *se)
{
    if (se == NULL) {
        return 0;
    }
    return (uint32_t) ((se->total_plain + se->chunk_size - 1) / se->chunk_size);
}

int swx_file_seal_done(const swx_file_sealer *se)
{
    return se != NULL && se->emitted >= swx_file_total_chunks(se);
}

void swx_file_seal_free(swx_file_sealer *se)
{
    if (se == NULL) {
        return;
    }
    sodium_memzero(se, sizeof *se);
    sodium_free(se);
}

/* Feeding contract: every call passes exactly swx_file_chunk_room() bytes
 * (the final call passes the remainder; an empty file passes zero bytes
 * once to emit the metadata-only chunk). Chunks therefore never span a
 * chunk boundary and indices stay unique. */
int swx_file_seal_chunk(swx_file_sealer *se,
                        const uint8_t *data, size_t data_len,
                        uint8_t *wire_out, size_t wire_cap, size_t *wire_len)
{
    uint8_t *pt;
    size_t pt_len, head = 0, room;
    uint32_t idx, total;
    int ret;

    if (se == NULL || (data == NULL && data_len > 0) || wire_out == NULL ||
        wire_len == NULL) {
        return SWX_E_ARG;
    }
    total = swx_file_total_chunks(se);
    if (se->emitted >= total) {
        return SWX_E_STATE;
    }
    room = file_room(se);
    if (data_len != room) {
        return SWX_E_ARG;
    }

    idx = se->emitted;
    pt = (uint8_t *) sodium_malloc(se->chunk_size);
    if (pt == NULL) {
        return SWX_E_LEN;
    }
    sodium_memzero(pt, se->chunk_size);

    if (se->fed == 0) {
        put32be(pt, se->meta_len);
        memcpy(pt + 4, se->meta, se->meta_len);
        head = 4 + se->meta_len;
    }
    memcpy(pt + head, data, data_len);
    pt_len = head + data_len;

    if (se->s->pad_on && se->fed + data_len == se->file_size &&
        pt_len < se->chunk_size) {
        /* pad the final chunk to the full bucket: [pt][0x80][0x00*] */
        pt[pt_len] = 0x80;
        pt_len = se->chunk_size;
    }

    ret = seal_frame(se->s, SWX_TYPE_FILE, pt, pt_len, se->fp, idx, total,
                     wire_out, wire_cap, wire_len);
    if (ret == SWX_OK) {
        se->fed += data_len;
        se->emitted++;
    }
    sodium_free(pt);
    return ret;
}

/* ---- state export/import (§6) ---- */

#define SWX_STATE_MAGIC "SWXS"
#define SWX_STATE_VER   1
#define SWX_STATE_LEN   60    /* magic4 ver1 role1 suite1 flags1 thresh2 rsv2
                              * key32 blake2b-128(16) */

int swx_session_export(const swx_session *s,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t blob[SWX_STATE_LEN];

    if (s == NULL || out == NULL || out_len == NULL) {
        return SWX_E_ARG;
    }
    if (s->state != SWX_ST_ESTABLISHED) {
        return SWX_E_STATE;
    }
    if (out_cap < sizeof blob) {
        return SWX_E_LEN;
    }

    memcpy(blob, SWX_STATE_MAGIC, 4);
    blob[4] = SWX_STATE_VER;
    blob[5] = s->role;
    blob[6] = s->suite;
    blob[7] = (uint8_t) (s->pad_on ? 1 : 0);
    blob[8] = (uint8_t) (s->pad_threshold >> 8);
    blob[9] = (uint8_t) s->pad_threshold;
    blob[10] = 0;
    blob[11] = 0;
    memcpy(blob + 12, s->session_key, 32);
    crypto_generichash(blob + 44, 16, blob, 44, NULL, 0);

    memcpy(out, blob, sizeof blob);
    *out_len = sizeof blob;
    sodium_memzero(blob, sizeof blob);
    return SWX_OK;
}

int swx_session_import(swx_session **out,
                       const uint8_t *in, size_t in_len,
                       uint64_t send_next, uint64_t recv_hwm)
{
    uint8_t mac[16];
    uint16_t thresh;
    swx_session *s = NULL;
    int ret;

    if (out == NULL || in == NULL) {
        return SWX_E_ARG;
    }
    if (in_len != SWX_STATE_LEN || memcmp(in, SWX_STATE_MAGIC, 4) != 0 ||
        in[4] != SWX_STATE_VER) {
        return SWX_E_IO;
    }
    crypto_generichash(mac, 16, in, 44, NULL, 0);
    if (memcmp(mac, in + 44, 16) != 0) {
        return SWX_E_IO;
    }
    if (in[5] != SWX_ROLE_INVITER && in[5] != SWX_ROLE_RESPONDER) {
        return SWX_E_IO;
    }
    if (in[6] != SWX_SUITE_CHACHA) {
        return SWX_E_UNSUPPORTED;
    }
    thresh = (uint16_t) ((in[8] << 8) | in[9]);
    if ((in[7] & 1) &&
        (thresh < SWX_PAD_THRESHOLD_MIN || thresh > SWX_PAD_THRESHOLD_MAX ||
         (thresh & 3u) != 0)) {
        return SWX_E_IO;
    }

    if ((ret = session_alloc(&s)) != SWX_OK) {
        return ret;
    }
    s->state = SWX_ST_ESTABLISHED;
    s->role = in[5];
    s->suite = in[6];
    s->pad_on = in[7] & 1;
    s->pad_threshold = thresh;
    memcpy(s->session_key, in + 12, 32);
    s->sas[0] = '\0';    /* prk is gone; SAS exists only at pairing time */
    s->send_next = send_next == 0 ? 1 : send_next;    /* 0 is never used */
    s->recv_hwm = recv_hwm;
    *out = s;
    return SWX_OK;
}
