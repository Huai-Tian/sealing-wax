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
 * SHA-512 streaming shim for the vendored SPAKE2 (upstream spake2-c ships a
 * glibc-derived LGPL copy; we back the same 3-call interface with libsodium's
 * crypto_hash_sha512 so the vendored set stays permissively licensed and the
 * crypto stack stays single-source. Digest output is bit-identical.)
 */
#ifndef SWX_SPAKE2_SHA512_H
#define SWX_SPAKE2_SHA512_H

#include <sodium.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sha512_ctx {
    crypto_hash_sha512_state st;
};

extern void __sha512_init_ctx(struct sha512_ctx *ctx);

extern void __sha512_process_bytes(const void *buffer, size_t len,
                                   struct sha512_ctx *ctx);

extern void *__sha512_finish_ctx(struct sha512_ctx *ctx, void *resbuf);

#ifdef __cplusplus
}
#endif

#endif /* SWX_SPAKE2_SHA512_H */
