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
#include "swx_hash.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

struct swx_hash {
    crypto_generichash_state st;
    int live;
};

int swx_hash_create(swx_hash **out)
{
    if (out == NULL) {
        return SWX_E_ARG;
    }
    if (sodium_init() < 0) {
        return SWX_E_CRYPTO;
    }
    *out = (swx_hash *) sodium_malloc(sizeof(swx_hash));
    if (*out == NULL) {
        return SWX_E_LEN;
    }
    if (crypto_generichash_init(&(*out)->st, NULL, 0, SWX_HASH_LEN) != 0) {
        sodium_free(*out);
        *out = NULL;
        return SWX_E_CRYPTO;
    }
    (*out)->live = 1;
    return SWX_OK;
}

int swx_hash_update(swx_hash *h, const uint8_t *in, size_t in_len)
{
    if (h == NULL || (in == NULL && in_len > 0)) {
        return SWX_E_ARG;
    }
    if (!h->live) {
        return SWX_E_STATE;
    }
    if (crypto_generichash_update(&h->st, in, in_len) != 0) {
        return SWX_E_CRYPTO;
    }
    return SWX_OK;
}

int swx_hash_final(swx_hash *h, uint8_t out[SWX_HASH_LEN])
{
    int ret;
    if (h == NULL || out == NULL) {
        return SWX_E_ARG;
    }
    if (!h->live) {
        return SWX_E_STATE;
    }
    ret = crypto_generichash_final(&h->st, out, SWX_HASH_LEN) == 0
              ? SWX_OK
              : SWX_E_CRYPTO;
    h->live = 0;    /* final() consumes the state; update() is over */
    return ret;
}

void swx_hash_free(swx_hash *h)
{
    if (h == NULL) {
        return;
    }
    sodium_memzero(h, sizeof *h);
    sodium_free(h);
}
