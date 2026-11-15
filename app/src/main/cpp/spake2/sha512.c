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
#include "sha512.h"

void __sha512_init_ctx(struct sha512_ctx *ctx)
{
    (void) crypto_hash_sha512_init(&ctx->st);
}

void __sha512_process_bytes(const void *buffer, size_t len,
                            struct sha512_ctx *ctx)
{
    (void) crypto_hash_sha512_update(&ctx->st, (const unsigned char *) buffer,
                                     (unsigned long long) len);
}

void *__sha512_finish_ctx(struct sha512_ctx *ctx, void *resbuf)
{
    (void) crypto_hash_sha512_final(&ctx->st, (unsigned char *) resbuf);
    return resbuf;
}
