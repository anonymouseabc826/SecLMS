#include "hash_api.h"

#ifndef LMS_SHA256_ONLY
#include "fips202.h"
#ifndef LMS_NO_HARAKA
#include "haraka.h"
#endif
#ifdef LMS_HASH_XKCP_32BI
#include "xkcp/xkcp_shake.h"
#endif
#endif
#include "sha256.h"

#include <limits.h>
#include <string.h>

#ifndef LMS_SHA256_ONLY
#if !defined(LMS_NO_HARAKA)
static void ensure_haraka_initialized(void)
{
    static const uint8_t zero_seed[32] = {0};
    static int initialized = 0;

    if (!initialized) {
        tweak_constants(zero_seed, zero_seed, sizeof(zero_seed));
        initialized = 1;
    }
}
#endif /* !LMS_NO_HARAKA */

static int hash_shake256(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
#ifdef LMS_HASH_XKCP_32BI
    /* 32-bit-lane Keccak (XKCP inplace32BI): SHAKE256 acceleration alternative for RV32 without 64-bit instructions */
    xkcp_shake256(output, output_len, input, input_len);
#else
    shake256(output, output_len, input, input_len);
#endif
    return 0;
}
#endif

static int hash_sha256(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
    SHA256_CTX ctx;
    uint8_t digest[SHA256_LEN];

    if (output_len > sizeof(digest)) {
        return -1;
    }

    SHA256_Init(&ctx);
    while (input_len > 0u) {
        unsigned int chunk_len = input_len > (size_t)UINT_MAX ? UINT_MAX : (unsigned int)input_len;
        SHA256_Update(&ctx, input, chunk_len);
        input += chunk_len;
        input_len -= chunk_len;
    }
    SHA256_Final(digest, &ctx);
    memcpy(output, digest, output_len);
    return 0;
}

#ifndef LMS_SHA256_ONLY
#if !defined(LMS_NO_HARAKA)
static int hash_haraka(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
    if (output_len != 32u) {
        return -1;
    }
    ensure_haraka_initialized();
    haraka_S(output, (unsigned long long)output_len, input, (unsigned long long)input_len);
    return 0;
}
#endif /* !LMS_NO_HARAKA */
#endif

int lms_hash(lms_hash_alg_t alg,
             const uint8_t *input,
             size_t input_len,
             uint8_t *output,
             size_t output_len)
{
    if (!output || (!input && input_len != 0)) {
        return -1;
    }

    switch (alg) {
#ifndef LMS_SHA256_ONLY
    case LMS_HASH_SHAKE256:
        return hash_shake256(input, input_len, output, output_len);
#endif
    case LMS_HASH_SHA256:
        return hash_sha256(input, input_len, output, output_len);
#ifndef LMS_SHA256_ONLY
#if !defined(LMS_NO_HARAKA)
    case LMS_HASH_HARAKA:
        return hash_haraka(input, input_len, output, output_len);
#endif
#endif
    default:
        return -1;
    }
}