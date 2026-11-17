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
#ifndef SWX_HASH_H
#define SWX_HASH_H

#include "swx_common.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Streaming BLAKE2b-256 over arbitrary byte streams — the file-ledger
 * ciphertext hash (§7). Used to reconcile a re-imported .swx against the
 * local ledger *without* needing the key.
 */
typedef struct swx_hash swx_hash;

#define SWX_HASH_LEN 32

int swx_hash_create(swx_hash **out);
int swx_hash_update(swx_hash *h, const uint8_t *in, size_t in_len);
int swx_hash_final(swx_hash *h, uint8_t out[SWX_HASH_LEN]);
void swx_hash_free(swx_hash *h);

#ifdef __cplusplus
}
#endif

#endif /* SWX_HASH_H */
