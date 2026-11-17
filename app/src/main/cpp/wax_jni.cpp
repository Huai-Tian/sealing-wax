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
 * Thin JNI bridge (README_AGENT.md §10): wires the pure-C core to
 * sealing.wax.bridge.WaxNative. Only wire bytes (base64 strings / frame
 * bytes / opaque state blobs) cross this boundary; no key material is
 * interpreted here. Failures throw IllegalStateException carrying the
 * SWX error name; openText returns null for an accepted-but-incomplete
 * logical message.
 */
#include <jni.h>

#include <cstdlib>
#include <cstring>

#include <sodium.h>

#include "swx_hash.h"
#include "swx_session.h"

#define JNI_CLASS_PATH "sealing/wax/bridge/WaxNative"

static void throw_swx(JNIEnv *env, int code)
{
    const char *name = "SWX_E_UNKNOWN";
    switch (code) {
    case SWX_E_ARG:         name = "SWX_E_ARG"; break;
    case SWX_E_FORMAT:      name = "SWX_E_FORMAT"; break;
    case SWX_E_TYPE:        name = "SWX_E_TYPE"; break;
    case SWX_E_LEN:         name = "SWX_E_LEN"; break;
    case SWX_E_CRYPTO:      name = "SWX_E_CRYPTO"; break;
    case SWX_E_STATE:       name = "SWX_E_STATE"; break;
    case SWX_E_REPLAY:      name = "SWX_E_REPLAY"; break;
    case SWX_E_UNSUPPORTED: name = "SWX_E_UNSUPPORTED"; break;
    case SWX_E_IO:          name = "SWX_E_IO"; break;
    case SWX_E_PARTIAL:     name = "SWX_E_PARTIAL"; break;
    default: break;
    }
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != NULL) {
        env->ThrowNew(cls, name);
    }
}

static jbyteArray to_bytes(JNIEnv *env, const uint8_t *buf, size_t len)
{
    jbyteArray arr = env->NewByteArray((jsize) len);
    if (arr == NULL) {
        return NULL;
    }
    env->SetByteArrayRegion(arr, 0, (jsize) len, (const jbyte *) buf);
    return arr;
}

/* ---- lifecycle ---- */

extern "C" JNIEXPORT jlong JNICALL
Java_sealing_wax_bridge_WaxNative_createSession(JNIEnv *env, jclass,
                                                jboolean as_inviter)
{
    swx_session *s = NULL;
    int ret = swx_session_create(&s, as_inviter ? SWX_ROLE_INVITER
                                                : SWX_ROLE_RESPONDER);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return 0;
    }
    return (jlong) (intptr_t) s;
}

extern "C" JNIEXPORT void JNICALL
Java_sealing_wax_bridge_WaxNative_freeSession(JNIEnv *, jclass, jlong h)
{
    if (h != 0) {
        swx_session_free((swx_session *) (intptr_t) h);
    }
}

extern "C" JNIEXPORT jint JNICALL
Java_sealing_wax_bridge_WaxNative_sessionRole(JNIEnv *, jclass, jlong h)
{
    return swx_session_role((const swx_session *) (intptr_t) h);
}

/* ---- pairing ---- */

/* base64 capacity for pairing codes, including the NUL: invite = 32B
 * share (44 chars), reply = 64B share||confirm (88 chars) */
#define B64_PAIR_CAP (SWX_PAIR_REPLY_LEN * 4 / 3 + 8)

/* copies a jbyteArray into a bounded stack buffer; -1 on bad args */
static int secret_to_buf(JNIEnv *env, jbyteArray secret,
                         uint8_t *buf, size_t cap, size_t *out_len)
{
    jsize n = env->GetArrayLength(secret);
    if (n < 1 || (size_t) n > cap) {
        return SWX_E_ARG;
    }
    env->GetByteArrayRegion(secret, 0, n, (jbyte *) buf);
    *out_len = (size_t) n;
    return SWX_OK;
}

extern "C" JNIEXPORT jstring JNICALL
Java_sealing_wax_bridge_WaxNative_invite(JNIEnv *env, jclass, jlong h,
                                         jbyteArray secret)
{
    uint8_t sec[SWX_PAIR_SECRET_MAX];
    uint8_t wire[SWX_PAIR_MSG_LEN];
    char b64[B64_PAIR_CAP];
    size_t sec_len = 0, n = 0;
    int ret;

    if (secret == NULL) {
        throw_swx(env, SWX_E_ARG);
        return NULL;
    }
    ret = secret_to_buf(env, secret, sec, sizeof sec, &sec_len);
    if (ret == SWX_OK) {
        ret = swx_session_invite((swx_session *) (intptr_t) h,
                                 sec, sec_len, wire, sizeof wire, &n);
    }
    if (ret == SWX_OK) {
        ret = swx_b64_encode(b64, sizeof b64, wire, n);
    }
    sodium_memzero(sec, sizeof sec);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return NULL;
    }
    return env->NewStringUTF(b64);
}

/* 公共会话 (§5): deterministic inviter share from a persisted gate seed —
 * the same (seed, 暗号) reproduces a byte-identical static invite code
 * every arming. Key material is zeroed after use. */
extern "C" JNIEXPORT jstring JNICALL
Java_sealing_wax_bridge_WaxNative_inviteSeeded(JNIEnv *env, jclass, jlong h,
                                               jbyteArray secret, jstring seed_b64)
{
    const char *sb = env->GetStringUTFChars(seed_b64, NULL);
    if (sb == NULL) {
        return NULL;
    }
    size_t sb_len = strlen(sb);
    uint8_t seed[SWX_GATE_SEED_LEN];
    uint8_t sec[SWX_PAIR_SECRET_MAX];
    uint8_t wire[SWX_PAIR_MSG_LEN];
    char b64[B64_PAIR_CAP];
    size_t seed_len = 0, sec_len = 0, n = 0;
    jstring out = NULL;
    int ret;

    ret = swx_b64_decode(seed, sizeof seed, &seed_len, sb, sb_len);
    if (ret == SWX_OK && seed_len != SWX_GATE_SEED_LEN) {
        ret = SWX_E_FORMAT;
    }
    if (ret == SWX_OK && secret != NULL) {
        ret = secret_to_buf(env, secret, sec, sizeof sec, &sec_len);
    } else if (ret == SWX_OK) {
        ret = SWX_E_ARG;
    }
    if (ret == SWX_OK) {
        ret = swx_session_invite_seeded((swx_session *) (intptr_t) h,
                                        sec, sec_len, seed,
                                        wire, sizeof wire, &n);
    }
    if (ret == SWX_OK) {
        ret = swx_b64_encode(b64, sizeof b64, wire, n);
    }
    if (ret == SWX_OK) {
        out = env->NewStringUTF(b64);
    } else {
        throw_swx(env, ret);
    }
    sodium_memzero(sec, sizeof sec);
    sodium_memzero(seed, sizeof seed);
    env->ReleaseStringUTFChars(seed_b64, sb);
    return out;
}

extern "C" JNIEXPORT jstring JNICALL
Java_sealing_wax_bridge_WaxNative_reply(JNIEnv *env, jclass, jlong h,
                                        jstring invite_b64, jbyteArray secret)
{
    const char *inv = env->GetStringUTFChars(invite_b64, NULL);
    if (inv == NULL) {
        return NULL;
    }
    size_t inv_len = strlen(inv);
    uint8_t *wire = (uint8_t *) malloc(inv_len ? inv_len : 1);
    uint8_t sec[SWX_PAIR_SECRET_MAX];
    uint8_t rwire[SWX_PAIR_REPLY_LEN];
    char rb64[B64_PAIR_CAP];
    size_t wire_len = 0, sec_len = 0, rlen = 0;
    jstring out = NULL;
    int ret;

    if (wire == NULL) {
        env->ReleaseStringUTFChars(invite_b64, inv);
        throw_swx(env, SWX_E_LEN);
        return NULL;
    }
    ret = swx_b64_decode(wire, inv_len, &wire_len, inv, inv_len);
    if (ret == SWX_OK && secret != NULL) {
        ret = secret_to_buf(env, secret, sec, sizeof sec, &sec_len);
    } else if (ret == SWX_OK) {
        ret = SWX_E_ARG;
    }
    if (ret == SWX_OK) {
        ret = swx_session_reply((swx_session *) (intptr_t) h,
                                sec, sec_len, wire, wire_len,
                                rwire, sizeof rwire, &rlen);
    }
    if (ret == SWX_OK) {
        ret = swx_b64_encode(rb64, sizeof rb64, rwire, rlen);
    }
    if (ret == SWX_OK) {
        out = env->NewStringUTF(rb64);
    } else {
        throw_swx(env, ret);
    }
    sodium_memzero(sec, sizeof sec);
    free(wire);
    env->ReleaseStringUTFChars(invite_b64, inv);
    return out;
}

extern "C" JNIEXPORT void JNICALL
Java_sealing_wax_bridge_WaxNative_finish(JNIEnv *env, jclass, jlong h,
                                         jstring reply_b64)
{
    const char *rep = env->GetStringUTFChars(reply_b64, NULL);
    if (rep == NULL) {
        return;
    }
    size_t rep_len = strlen(rep);
    uint8_t *wire = (uint8_t *) malloc(rep_len ? rep_len : 1);
    size_t wire_len = 0;
    int ret = SWX_E_LEN;

    if (wire != NULL) {
        ret = swx_b64_decode(wire, rep_len, &wire_len, rep, rep_len);
        if (ret == SWX_OK) {
            ret = swx_session_finish((swx_session *) (intptr_t) h,
                                     wire, wire_len);
        }
        free(wire);
    }
    env->ReleaseStringUTFChars(reply_b64, rep);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_sealing_wax_bridge_WaxNative_sas(JNIEnv *env, jclass, jlong h)
{
    char sas[SWX_SAS_DIGITS + 1];
    int ret = swx_session_sas((const swx_session *) (intptr_t) h, sas);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return NULL;
    }
    return env->NewStringUTF(sas);
}

/* ---- padding / counters ---- */

extern "C" JNIEXPORT void JNICALL
Java_sealing_wax_bridge_WaxNative_setPadding(JNIEnv *env, jclass, jlong h,
                                             jboolean enabled, jint threshold)
{
    int ret = swx_session_set_padding((swx_session *) (intptr_t) h,
                                      enabled != JNI_FALSE, (uint32_t) threshold);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
    }
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_sealing_wax_bridge_WaxNative_counters(JNIEnv *env, jclass, jlong h)
{
    uint64_t sn = 0, hwm = 0;
    jlong out[2];
    swx_session_counters((const swx_session *) (intptr_t) h, &sn, &hwm);
    out[0] = (jlong) sn;
    out[1] = (jlong) hwm;
    jlongArray arr = env->NewLongArray(2);
    if (arr != NULL) {
        env->SetLongArrayRegion(arr, 0, 2, out);
    }
    return arr;
}

/* ---- text ---- */

extern "C" JNIEXPORT jobjectArray JNICALL
Java_sealing_wax_bridge_WaxNative_sealText(JNIEnv *env, jclass, jlong h,
                                           jbyteArray pt)
{
    const size_t stride = SWX_MAX_PIECE_B64 + 1;
    jsize pt_len = env->GetArrayLength(pt);
    jbyte *pt_buf = env->GetByteArrayElements(pt, NULL);
    char *pieces = NULL;
    jobjectArray out = NULL;
    uint32_t np = 0;
    int ret;

    if (pt_buf == NULL) {
        return NULL;
    }
    pieces = (char *) malloc(SWX_TEXT_MAX_PIECES * stride);
    if (pieces == NULL) {
        env->ReleaseByteArrayElements(pt, pt_buf, JNI_ABORT);
        throw_swx(env, SWX_E_LEN);
        return NULL;
    }
    ret = swx_session_seal_text((swx_session *) (intptr_t) h,
                                (const uint8_t *) pt_buf, (size_t) pt_len,
                                NULL, pieces, stride, SWX_TEXT_MAX_PIECES, &np);
    env->ReleaseByteArrayElements(pt, pt_buf, JNI_ABORT);
    if (ret != SWX_OK) {
        free(pieces);
        throw_swx(env, ret);
        return NULL;
    }

    jclass str_cls = env->FindClass("java/lang/String");
    if (str_cls == NULL) {
        free(pieces);
        return NULL;
    }
    out = env->NewObjectArray((jsize) np, str_cls, NULL);
    if (out != NULL) {
        for (uint32_t i = 0; i < np; i++) {
            jstring s = env->NewStringUTF(pieces + (size_t) i * stride);
            if (s == NULL) {
                out = NULL;
                break;
            }
            env->SetObjectArrayElement(out, (jsize) i, s);
            env->DeleteLocalRef(s);
        }
    }
    free(pieces);
    return out;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_sealing_wax_bridge_WaxNative_openText(JNIEnv *env, jclass, jlong h,
                                           jstring piece_b64)
{
    const char *b64 = env->GetStringUTFChars(piece_b64, NULL);
    if (b64 == NULL) {
        return NULL;
    }
    size_t b64_len = strlen(b64);
    size_t cap = b64_len / 4 * 3 + 4;
    uint8_t *wire = (uint8_t *) malloc(cap);
    uint8_t *pt = NULL;
    size_t wire_len = 0, pt_len = 0;
    jbyteArray out = NULL;
    int ret;

    if (wire == NULL) {
        env->ReleaseStringUTFChars(piece_b64, b64);
        throw_swx(env, SWX_E_LEN);
        return NULL;
    }
    ret = swx_b64_decode(wire, cap, &wire_len, b64, b64_len);
    if (ret == SWX_OK) {
        pt = (uint8_t *) malloc(SWX_TEXT_MAX_PT);
        if (pt == NULL) {
            ret = SWX_E_LEN;
        }
    }
    if (ret == SWX_OK) {
        ret = swx_session_open_text((swx_session *) (intptr_t) h,
                                    wire, wire_len, NULL,
                                    pt, SWX_TEXT_MAX_PT, &pt_len);
        if (ret == SWX_OK) {
            out = to_bytes(env, pt, pt_len);
        } else if (ret == SWX_E_PARTIAL) {
            out = NULL;    /* accepted piece, message incomplete */
        }
    }
    if (ret != SWX_OK && ret != SWX_E_PARTIAL) {
        throw_swx(env, ret);
    }
    free(pt);
    free(wire);
    env->ReleaseStringUTFChars(piece_b64, b64);
    return out;
}

/* ---- state ---- */

extern "C" JNIEXPORT jbyteArray JNICALL
Java_sealing_wax_bridge_WaxNative_exportState(JNIEnv *env, jclass, jlong h)
{
    uint8_t blob[SWX_STATE_BLOB_MAX];
    size_t len = 0;
    int ret = swx_session_export((const swx_session *) (intptr_t) h,
                                 blob, sizeof blob, &len);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return NULL;
    }
    return to_bytes(env, blob, len);
}

extern "C" JNIEXPORT jlong JNICALL
Java_sealing_wax_bridge_WaxNative_importState(JNIEnv *env, jclass,
                                              jbyteArray blob,
                                              jlong send_next, jlong recv_hwm)
{
    jsize len = env->GetArrayLength(blob);
    jbyte *buf = env->GetByteArrayElements(blob, NULL);
    swx_session *s = NULL;
    int ret;

    if (buf == NULL) {
        return 0;
    }
    ret = swx_session_import(&s, (const uint8_t *) buf, (size_t) len,
                             (uint64_t) send_next, (uint64_t) recv_hwm);
    env->ReleaseByteArrayElements(blob, buf, JNI_ABORT);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return 0;
    }
    return (jlong) (intptr_t) s;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_sealing_wax_bridge_WaxNative_flipStateRole(JNIEnv *env, jclass,
                                                jbyteArray blob)
{
    jsize len = env->GetArrayLength(blob);
    uint8_t *copy = (uint8_t *) malloc((size_t) (len > 0 ? len : 1));
    jbyte *buf = NULL;
    jbyteArray out = NULL;
    int ret = SWX_E_LEN;

    if (copy == NULL) {
        throw_swx(env, SWX_E_LEN);
        return NULL;
    }
    buf = env->GetByteArrayElements(blob, NULL);
    if (buf != NULL) {
        memcpy(copy, buf, (size_t) len);
        ret = swx_state_flip_role(copy, (size_t) len);
        env->ReleaseByteArrayElements(blob, buf, JNI_ABORT);
    }
    if (ret != SWX_OK) {
        throw_swx(env, ret);
    } else {
        out = to_bytes(env, copy, (size_t) len);
    }
    free(copy);
    return out;
}

/* ---- file channel ---- */

extern "C" JNIEXPORT jlong JNICALL
Java_sealing_wax_bridge_WaxNative_fileSealBegin(JNIEnv *env, jclass, jlong h,
                                                jbyteArray meta,
                                                jlong file_size)
{
    jsize meta_len = env->GetArrayLength(meta);
    jbyte *meta_buf = env->GetByteArrayElements(meta, NULL);
    swx_file_sealer *se = NULL;
    int ret;

    if (meta_buf == NULL) {
        return 0;
    }
    ret = swx_file_seal_begin(&se, (swx_session *) (intptr_t) h,
                              (const uint8_t *) meta_buf, (size_t) meta_len,
                              (uint64_t) file_size, 0, NULL);
    env->ReleaseByteArrayElements(meta, meta_buf, JNI_ABORT);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return 0;
    }
    return (jlong) (intptr_t) se;
}

extern "C" JNIEXPORT jint JNICALL
Java_sealing_wax_bridge_WaxNative_fileChunkRoom(JNIEnv *, jclass, jlong se)
{
    return (jint) swx_file_chunk_room((const swx_file_sealer *) (intptr_t) se);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_sealing_wax_bridge_WaxNative_fileSealChunk(JNIEnv *env, jclass, jlong se,
                                                jbyteArray data)
{
    const size_t cap = (size_t) SWX_FILE_PIECE_DEFAULT +
                       SWX_DATA_FIXED_LEN + SWX_TAG_LEN;
    jsize data_len = env->GetArrayLength(data);
    jbyte *data_buf = env->GetByteArrayElements(data, NULL);
    uint8_t *wire = NULL;
    jbyteArray out = NULL;
    size_t wire_len = 0;
    int ret;

    if (data_buf == NULL) {
        return NULL;
    }
    wire = (uint8_t *) malloc(cap);
    if (wire == NULL) {
        env->ReleaseByteArrayElements(data, data_buf, JNI_ABORT);
        throw_swx(env, SWX_E_LEN);
        return NULL;
    }
    ret = swx_file_seal_chunk((swx_file_sealer *) (intptr_t) se,
                              (const uint8_t *) data_buf, (size_t) data_len,
                              wire, cap, &wire_len);
    env->ReleaseByteArrayElements(data, data_buf, JNI_ABORT);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
    } else {
        out = to_bytes(env, wire, wire_len);
    }
    free(wire);
    return out;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_sealing_wax_bridge_WaxNative_fileSealDone(JNIEnv *, jclass, jlong se)
{
    return swx_file_seal_done((const swx_file_sealer *) (intptr_t) se)
               ? JNI_TRUE
               : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_sealing_wax_bridge_WaxNative_fileSealFree(JNIEnv *, jclass, jlong se)
{
    if (se != 0) {
        swx_file_seal_free((swx_file_sealer *) (intptr_t) se);
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_sealing_wax_bridge_WaxNative_openFileFrame(JNIEnv *env, jclass, jlong h,
                                                jbyteArray wire_arr)
{
    jsize wire_len = env->GetArrayLength(wire_arr);
    jbyte *wire = env->GetByteArrayElements(wire_arr, NULL);
    uint8_t *pt = NULL;
    jbyteArray out = NULL;
    size_t pt_len = 0;
    int ret;

    if (wire == NULL) {
        return NULL;
    }
    /* plaintext never exceeds ciphertext, so wire_len is a safe cap */
    pt = (uint8_t *) malloc(wire_len ? (size_t) wire_len : 1);
    if (pt == NULL) {
        env->ReleaseByteArrayElements(wire_arr, wire, JNI_ABORT);
        throw_swx(env, SWX_E_LEN);
        return NULL;
    }
    ret = swx_session_open_file_frame((swx_session *) (intptr_t) h,
                                      (const uint8_t *) wire,
                                      (size_t) wire_len, NULL,
                                      pt, (size_t) wire_len, &pt_len);
    env->ReleaseByteArrayElements(wire_arr, wire, JNI_ABORT);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
    } else {
        out = to_bytes(env, pt, pt_len);
    }
    free(pt);
    return out;
}

/* ---- last-frame introspection ---- */

extern "C" JNIEXPORT jbyteArray JNICALL
Java_sealing_wax_bridge_WaxNative_lastFp(JNIEnv *env, jclass, jlong h)
{
    uint8_t fp[SWX_FINGERPRINT_LEN];
    int ret = swx_session_last_frame((const swx_session *) (intptr_t) h,
                                     fp, NULL, NULL, NULL);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return NULL;
    }
    return to_bytes(env, fp, sizeof fp);
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_sealing_wax_bridge_WaxNative_lastFrame(JNIEnv *env, jclass, jlong h)
{
    uint64_t counter = 0;
    uint32_t idx = 0, total = 0;
    jlong out[3];
    int ret = swx_session_last_frame((const swx_session *) (intptr_t) h,
                                     NULL, &counter, &idx, &total);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return NULL;
    }
    out[0] = (jlong) counter;
    out[1] = (jlong) idx;
    out[2] = (jlong) total;
    jlongArray arr = env->NewLongArray(3);
    if (arr != NULL) {
        env->SetLongArrayRegion(arr, 0, 3, out);
    }
    return arr;
}

/* ---- ledger hash ---- */

extern "C" JNIEXPORT jlong JNICALL
Java_sealing_wax_bridge_WaxNative_hashCreate(JNIEnv *env, jclass)
{
    swx_hash *h = NULL;
    int ret = swx_hash_create(&h);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return 0;
    }
    return (jlong) (intptr_t) h;
}

extern "C" JNIEXPORT void JNICALL
Java_sealing_wax_bridge_WaxNative_hashUpdate(JNIEnv *env, jclass, jlong h,
                                             jbyteArray data, jint offset,
                                             jint len)
{
    if (len <= 0 || offset < 0) {
        return;
    }
    jbyte *buf = env->GetByteArrayElements(data, NULL);
    if (buf == NULL) {
        return;
    }
    int ret = swx_hash_update((swx_hash *) (intptr_t) h,
                              (const uint8_t *) buf + offset, (size_t) len);
    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_sealing_wax_bridge_WaxNative_hashFinal(JNIEnv *env, jclass, jlong h)
{
    uint8_t digest[SWX_HASH_LEN];
    int ret = swx_hash_final((swx_hash *) (intptr_t) h, digest);
    if (ret != SWX_OK) {
        throw_swx(env, ret);
        return NULL;
    }
    return to_bytes(env, digest, sizeof digest);
}

extern "C" JNIEXPORT void JNICALL
Java_sealing_wax_bridge_WaxNative_hashFree(JNIEnv *, jclass, jlong h)
{
    if (h != 0) {
        swx_hash_free((swx_hash *) (intptr_t) h);
    }
}
