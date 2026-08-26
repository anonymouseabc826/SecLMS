#include "lms_internal.h"

#include "sha256.h"

#include <limits.h>
#ifndef LMS_SHA256_ONLY
#include <stdlib.h>
#endif
#include <string.h>

static void sha256_update_size(SHA256_CTX *ctx, const uint8_t *data, size_t length)
{
    while (length > 0u) {
        unsigned int chunk = length > (size_t)UINT_MAX ? UINT_MAX : (unsigned int)length;
        SHA256_Update(ctx, data, chunk);
        data += chunk;
        length -= chunk;
    }
}

void lms_store_u16(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

void lms_store_u32(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

uint32_t lms_load_u32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

/* F4 (Phase 3): parameter-table entry cache -- consecutive queries of the same
 * type skip the switch chain (saves ~100-200 cycles per op; PC/firmware are
 * both single-threaded, no concurrency risk). */
static uint32_t s_lms_cache_type;
static uint8_t s_lms_cache_valid;
static lms_param_t s_lms_cache_param;
static uint32_t s_lmots_cache_type;
static uint8_t s_lmots_cache_valid;
static lmots_param_t s_lmots_cache_param;

int lms_get_lms_param(uint32_t type, lms_param_t *param)
{
    lms_hash_alg_t hash_alg;
    uint32_t height;
    lms_param_t result;

    if (s_lms_cache_valid != 0u && s_lms_cache_type == type) {
        if (param) {
            *param = s_lms_cache_param;
        }
        return LMS_OK;
    }

    switch (type) {
    case LMS_SHAKE256_N32_H5:
        hash_alg = LMS_HASH_SHAKE256;
        height = 5;
        break;
    case LMS_SHAKE256_N32_H10:
        hash_alg = LMS_HASH_SHAKE256;
        height = 10;
        break;
    case LMS_SHAKE256_N32_H15:
        hash_alg = LMS_HASH_SHAKE256;
        height = 15;
        break;
    case LMS_SHAKE256_N32_H20:
        hash_alg = LMS_HASH_SHAKE256;
        height = 20;
        break;
    case LMS_SHAKE256_N32_H25:
        hash_alg = LMS_HASH_SHAKE256;
        height = 25;
        break;
    case LMS_SHA256_N32_H5:
        hash_alg = LMS_HASH_SHA256;
        height = 5;
        break;
    case LMS_SHA256_N32_H10:
        hash_alg = LMS_HASH_SHA256;
        height = 10;
        break;
    case LMS_SHA256_N32_H15:
        hash_alg = LMS_HASH_SHA256;
        height = 15;
        break;
    case LMS_SHA256_N32_H20:
        hash_alg = LMS_HASH_SHA256;
        height = 20;
        break;
    case LMS_SHA256_N32_H25:
        hash_alg = LMS_HASH_SHA256;
        height = 25;
        break;
    case LMS_HARAKA_N32_H5:
        hash_alg = LMS_HASH_HARAKA;
        height = 5;
        break;
    case LMS_HARAKA_N32_H10:
        hash_alg = LMS_HASH_HARAKA;
        height = 10;
        break;
    case LMS_HARAKA_N32_H15:
        hash_alg = LMS_HASH_HARAKA;
        height = 15;
        break;
    case LMS_HARAKA_N32_H20:
        hash_alg = LMS_HASH_HARAKA;
        height = 20;
        break;
    case LMS_HARAKA_N32_H25:
        hash_alg = LMS_HASH_HARAKA;
        height = 25;
        break;
    default:
        return LMS_ERR_INVALID;
    }

    result.type = type;
    result.hash_alg = hash_alg;
    result.height = height;
    result.n = LMS_N;
    if (param) {
        *param = result;
    }
    s_lms_cache_type = type;
    s_lms_cache_param = result;
    s_lms_cache_valid = 1u;

    return LMS_OK;
}

int lms_get_lmots_param(uint32_t type, lmots_param_t *param)
{
    lms_hash_alg_t hash_alg;
    uint32_t w;
    uint32_t p;
    uint32_t ls;
    lmots_param_t result;

    if (s_lmots_cache_valid != 0u && s_lmots_cache_type == type) {
        if (param) {
            *param = s_lmots_cache_param;
        }
        return LMS_OK;
    }

    switch (type) {
    case LMOTS_SHA256_N32_W1:
        hash_alg = LMS_HASH_SHA256;
        w = 1;
        p = 265;
        ls = 7;
        break;
    case LMOTS_SHA256_N32_W2:
        hash_alg = LMS_HASH_SHA256;
        w = 2;
        p = 133;
        ls = 6;
        break;
    case LMOTS_SHA256_N32_W4:
        hash_alg = LMS_HASH_SHA256;
        w = 4;
        p = 67;
        ls = 4;
        break;
    case LMOTS_SHA256_N32_W8:
        hash_alg = LMS_HASH_SHA256;
        w = 8;
        p = 34;
        ls = 0;
        break;
    case LMOTS_SHAKE256_N32_W1:
        hash_alg = LMS_HASH_SHAKE256;
        w = 1;
        p = 265;
        ls = 7;
        break;
    case LMOTS_SHAKE256_N32_W2:
        hash_alg = LMS_HASH_SHAKE256;
        w = 2;
        p = 133;
        ls = 6;
        break;
    case LMOTS_SHAKE256_N32_W4:
        hash_alg = LMS_HASH_SHAKE256;
        w = 4;
        p = 67;
        ls = 4;
        break;
    case LMOTS_SHAKE256_N32_W8:
        hash_alg = LMS_HASH_SHAKE256;
        w = 8;
        p = 34;
        ls = 0;
        break;
    case LMOTS_HARAKA_N32_W1:
        hash_alg = LMS_HASH_HARAKA;
        w = 1;
        p = 265;
        ls = 7;
        break;
    case LMOTS_HARAKA_N32_W2:
        hash_alg = LMS_HASH_HARAKA;
        w = 2;
        p = 133;
        ls = 6;
        break;
    case LMOTS_HARAKA_N32_W4:
        hash_alg = LMS_HASH_HARAKA;
        w = 4;
        p = 67;
        ls = 4;
        break;
    case LMOTS_HARAKA_N32_W8:
        hash_alg = LMS_HASH_HARAKA;
        w = 8;
        p = 34;
        ls = 0;
        break;
    default:
        return LMS_ERR_INVALID;
    }

    result.type = type;
    result.hash_alg = hash_alg;
    result.n = LMS_N;
    result.w = w;
    result.p = p;
    result.ls = ls;
    if (param) {
        *param = result;
    }
    s_lmots_cache_type = type;
    s_lmots_cache_param = result;
    s_lmots_cache_valid = 1u;

    return LMS_OK;
}

int lms_get_private_hash_alg(const lms_private_key_t *priv, lms_hash_alg_t *hash_alg)
{
    lms_param_t lms_param;
    lmots_param_t ots_param;

    if (lms_get_lms_param(priv->lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(priv->lmots_type, &ots_param) != LMS_OK ||
        lms_param.hash_alg != ots_param.hash_alg) {
        return LMS_ERR_INVALID;
    }
    *hash_alg = lms_param.hash_alg;
    return LMS_OK;
}

int lms_get_public_hash_alg(const lms_public_key_t *pub, lms_hash_alg_t *hash_alg)
{
    lms_param_t lms_param;
    lmots_param_t ots_param;

    if (lms_get_lms_param(pub->lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(pub->lmots_type, &ots_param) != LMS_OK ||
        lms_param.hash_alg != ots_param.hash_alg) {
        return LMS_ERR_INVALID;
    }
    *hash_alg = lms_param.hash_alg;
    return LMS_OK;
}

size_t lms_signature_len(uint32_t lms_type, uint32_t lmots_type)
{
    lms_param_t lms_param;
    lmots_param_t ots_param;

    if (lms_get_lms_param(lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(lmots_type, &ots_param) != LMS_OK ||
        lms_param.hash_alg != ots_param.hash_alg) {
        return 0;
    }

    return 4u + 4u + ots_param.n + ots_param.p * ots_param.n + 4u + lms_param.height * lms_param.n;
}

uint32_t lms_lmots_coef(const uint8_t *data, uint32_t i, uint32_t w)
{
    uint32_t index = (i * w) / 8;
    uint32_t digits_per_byte = 8 / w;
    uint32_t shift = w * (~i & (digits_per_byte - 1));
    uint32_t mask = (1u << w) - 1u;

    return (data[index] >> shift) & mask;
}

uint32_t lms_lmots_checksum(const uint8_t *Q, uint32_t Q_len, uint32_t w, uint32_t ls)
{
    uint32_t sum = 0;
    uint32_t u = 8u * Q_len / w;
    uint32_t max_digit = (1u << w) - 1u;
    uint32_t i;

    for (i = 0; i < u; i++) {
        sum += max_digit - lms_lmots_coef(Q, i, w);
    }

    return sum << ls;
}

int lms_hash_parts(const uint8_t *a, size_t a_len,
                   const uint8_t *b, size_t b_len,
                   const uint8_t *c, size_t c_len,
                   const uint8_t *d, size_t d_len,
                   lms_hash_alg_t hash_alg,
                   uint8_t out[LMS_N])
{
#ifndef LMS_SHA256_ONLY
    /* REVIEW B03-R2: 8.5KB stack buffer (upper bound for concatenating full W1
     * D_PBLC/D_LEAF/D_INTR). Fine on PC; on RV32 firmware only the pure-software
     * baseline (LMS_FW_NO_HW_ACCEL) path hits it, peaking at ~17-19KB with
     * lmots_public_from_signature's ~8.8KB frame, still within the 32K stack
     * budget (lms_soc.ld __stack_size=32K), verified by on-board software
     * baseline; if parameter sets grow or call chains deepen, switch to
     * static/injected allocation. */
    uint8_t stack_buf[4 + LMS_I_LEN + LMS_N * 2 + LMS_MAX_OTS_P * LMS_N];
    uint8_t *buf = stack_buf;
#endif
    size_t total_len;
#ifndef LMS_SHA256_ONLY
    size_t off = 0;
    int status;
#endif

    if (a_len > SIZE_MAX - b_len ||
        a_len + b_len > SIZE_MAX - c_len ||
        a_len + b_len + c_len > SIZE_MAX - d_len) {
        return LMS_ERR_INVALID;
    }
    total_len = a_len + b_len + c_len + d_len;

    if (hash_alg == LMS_HASH_SHA256) {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        sha256_update_size(&ctx, a, a_len);
        sha256_update_size(&ctx, b, b_len);
        sha256_update_size(&ctx, c, c_len);
        sha256_update_size(&ctx, d, d_len);
        SHA256_Final(out, &ctx);
        return LMS_OK;
    }

#ifdef LMS_SHA256_ONLY
    (void)total_len;
    return LMS_ERR_INVALID;
#else
    if (total_len > sizeof(stack_buf)) {
        buf = (uint8_t *)malloc(total_len);
        if (!buf) {
            return LMS_ERR_INVALID;
        }
    }
    if (a_len) {
        memcpy(buf + off, a, a_len);
        off += a_len;
    }
    if (b_len) {
        memcpy(buf + off, b, b_len);
        off += b_len;
    }
    if (c_len) {
        memcpy(buf + off, c, c_len);
        off += c_len;
    }
    if (d_len) {
        memcpy(buf + off, d, d_len);
        off += d_len;
    }

    status = lms_hash(hash_alg, buf, off, out, LMS_N) == 0 ? LMS_OK : LMS_ERR_INVALID;
    if (buf != stack_buf) {
        free(buf);
    }
    return status;
#endif
}
