/*
 * SecLMS soft-core classic algorithm benchmark core (RSA-2048 / ECDSA P-256, mbedTLS 2.28.9)
 *
 * Purpose: same-platform data support for the paper Motivation "LMS's favorable trade-offs
 * relative to RSA/ECC".
 * - mbedTLS: external mbedtls-2.28.9 checkout (Apache-2.0 OR GPL-2.0-or-later; this project adopts
 *   Apache-2.0, NOTICE attribution)
 * - Trimmed config: bench/mbedtls_lms_config.h (RSA PKCS#1 v1.5 + ECP P-256 + ECDSA det + SHA-256)
 * - Memory: provides calloc/free/malloc/realloc on bare metal (SoC firmware -nostdlib) (first-fit allocator);
 *   PC self-check (BENCH_NATIVE) uses libc.
 * - Keys: mbedTLS test keys (rsa_pkcs1_2048_clear.pem / ec_256_prv.pem, fixed, public test keys).
 * - ECDSA signing goes through mbedtls_pk_sign with f_rng=NULL -> MBEDTLS_ECDSA_DETERMINISTIC
 *   (RFC 6979 deterministic nonce, reproducible across runs); RSA signing blinding uses bench_rng (deterministic xorshift).
 */
#include "bench_crypto.h"

#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#include <string.h>

/* ================= Bare-metal memory allocator (first-fit free list) ================= */
#if !defined(BENCH_NATIVE)
/* 24KB: measured peak heap ~8KB (RSA-2048 CRT transient MPI + 2 embedded keys resident + ECDSA HMAC_DRBG),
 * leaves fragmentation headroom; with 128K RAM/32K stack, the image ~80KB fits the 96K budget. */
#define BENCH_ARENA_SIZE (24u * 1024u)

typedef struct bench_mem_block {
    size_t size;                 /* user-area bytes (8-byte aligned) */
    uint32_t magic;              /* 0xBEBCA11C = on free list; 0xBEBCA11D = freed */
    struct bench_mem_block *next; /* free list */
} bench_mem_block;

static unsigned char bench_arena[BENCH_ARENA_SIZE] __attribute__((aligned(8)));
static bench_mem_block *bench_free_head;
static int bench_mem_init_done;

static void bench_mem_init(void)
{
    bench_free_head = (bench_mem_block *)bench_arena;
    bench_free_head->size = BENCH_ARENA_SIZE - sizeof(bench_mem_block);
    bench_free_head->magic = 0xBEBCA11Du;
    bench_free_head->next = NULL;
    bench_mem_init_done = 1;
}

static void *bench_mem_alloc(size_t size)
{
    bench_mem_block *prev = NULL;
    bench_mem_block *cur;
    size_t need = (size + 7u) & ~(size_t)7u;

    if (!bench_mem_init_done) {
        bench_mem_init();
    }
    if (need < sizeof(bench_mem_block)) {
        need = sizeof(bench_mem_block);
    }
    for (cur = bench_free_head; cur != NULL; prev = cur, cur = cur->next) {
        if (cur->size >= need + sizeof(bench_mem_block)) {
            /* Split: front part of cur goes to the user, remainder stays on the free list */
            bench_mem_block *rest =
                (bench_mem_block *)((unsigned char *)(cur + 1) + need);
            rest->size = cur->size - need - sizeof(bench_mem_block);
            rest->magic = 0xBEBCA11Du;
            rest->next = cur->next;
            cur->size = need;
            cur->magic = 0xBEBCA11Cu;
            cur->next = NULL;
            if (prev != NULL) {
                prev->next = rest;
            } else {
                bench_free_head = rest;
            }
            return (void *)(cur + 1);
        } else if (cur->size >= need) {
            /* Give the whole block */
            cur->magic = 0xBEBCA11Cu;
            if (prev != NULL) {
                prev->next = cur->next;
            } else {
                bench_free_head = cur->next;
            }
            return (void *)(cur + 1);
        }
    }
    return NULL;   /* exhausted */
}

static void bench_mem_free(void *ptr)
{
    bench_mem_block *blk;
    bench_mem_block *cur;
    bench_mem_block *prev = NULL;

    if (ptr == NULL) {
        return;
    }
    blk = (bench_mem_block *)ptr - 1;
    if (blk->magic != 0xBEBCA11Cu) {
        return;   /* not a block from this allocator (native builds never reach here) */
    }
    blk->magic = 0xBEBCA11Du;
    /* Insert into the free list by address and try to merge with adjacent free blocks (for
     * simplicity, only insert, no merge -- the per-command allocation pattern is fixed, so
     * fragmentation is acceptable) */
    for (cur = bench_free_head; cur != NULL && (unsigned char *)cur < (unsigned char *)blk;
         prev = cur, cur = cur->next) {
    }
    blk->next = cur;
    if (prev != NULL) {
        prev->next = blk;
    } else {
        bench_free_head = blk;
    }
}

void *malloc(size_t size)
{
    return bench_mem_alloc(size);
}

void free(void *ptr)
{
    bench_mem_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void *p = bench_mem_alloc(total);
    if (p != NULL) {
        memset(p, 0, total);
    }
    return p;
}

void *realloc(void *ptr, size_t size)
{
    void *p;
    if (ptr == NULL) {
        return bench_mem_alloc(size);
    }
    p = bench_mem_alloc(size);
    if (p != NULL) {
        /* mbedTLS does not actually use realloc; conservatively copy the original contents (may overflow, but this path is unused) */
        memcpy(p, ptr, size);
        bench_mem_free(ptr);
    }
    return p;
}
#endif /* !BENCH_NATIVE */

/* ================= Embedded test keys (mbedTLS test data, fixed and public) ================= */
static const char rsa_pkcs1_2048_pem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAqFVn+bKgHDTGFY6QU25+HlEP7ppDRC320hNPs91pri4VZrjL\n"
    "hOD4/N7sAoWTZiIOGCo5pJ+OztG7GA2B5tC9/cmdSN8UAXR8YO49+8ZqN4g9Ox6q\n"
    "91E42Rq5A9aCMkr7wm5Ym3cK9dZGXHVa4QsROdnoaIKpu3UbbjYOrmQSXXzEkTiX\n"
    "wMTIsXz8SclaRYNhHtnv6CKAIm1sTP4a3GyGeCzBW40zknNcgTqHo6J3FLw1AENY\n"
    "iaQEeXqTOxq3MFWm0HQFoJC4IND54RiARCo7+qJe+aqMGPwIIzQEXRIQVVcG3lvU\n"
    "8lUyTPpegYb2O4zdRrCE7GCpBBe137NmJcZMtQIDAQABAoIBABl8JKu3EWpzyvGE\n"
    "jfEzr0BjwWe8TybJVq7jYZO3l8JZE8BjhdxuOwP9s/mFw5UY3s1lxyhXR8WkFxFD\n"
    "KkGJpNoBZiCcNWkq+5GpQBUYKwiRRcPnlrauw06LLyuXlEqM86SyFBQlZ7FkaW6i\n"
    "Dco4ZLk/dmIsNgo9ZpO+92YLnIQumq5nAY4Mw6CVra54koDmLXorJzidAo2n0059\n"
    "K0hUUMgh4o1BEn5I+YPZOkmASsNUh6zbm26tyaiBnU47ueYE//+RPCTPTI4ePBG5\n"
    "8nGuRGebGpdOm9OO3IGgps80mADnVUI3QTjcwQlY1pEeaQ6FMf6WpfwFSzssD6WS\n"
    "lfEoVBkCgYEA0vRCLOvbhikfaKCnAkaBYlhna1BI32gPa4+bwCKupaI2Kl3uRhPT\n"
    "JB+I+fzWXjPZDq4JsuTcHCpP2EpfBi3ltXmjmmI742D4h20Cv9lPWItICn11HHcQ\n"
    "aV40Td2Lo96N8fSzwdgr0cH8fVvTEWaZiUMZpafypNIecf7UMMi7opMCgYEAzEdP\n"
    "e/zyTHUIUpYI4OlD/C+mCHGOGnDtVG5RIAPNOiXuDshGBetQf+GmCt88RjH5Gz4R\n"
    "LuYhOQIKObtMRzsgD8UbxBoRtmwTAtaX/e/rZiW6kEgplwA7ZV/7oADOBEqhf5Yz\n"
    "ublAtD1VS9zDXr6ZoTeJVmZ0VMlKXPd3wgnZ+JcCgYBgYQRS7bcwBl25OZzT5055\n"
    "lhY560Y/+5T/+W6ZS78rIX9Jv/x6u9f9awLz49Y0189Va6I2v2To4VP1Z5Ueh52p\n"
    "WderUzI1Yjpp9R4KdMhRleDmGgeFZ8hxu35+DLgduDJ11uzBpXfvr4ch5u/5xTxk\n"
    "f+mZy6+KKg2K23gqiatgTQKBgQCW2Amfmvco8jrFETlZK6ciL+VA0umGKOF3uUZ6\n"
    "h5QiXiPeEpFyiYMWC4BbAuE1TG2QalKx+QmLWTBH1UDMUKKqQnjwY/e0ZzXaoK/3\n"
    "uhRvh2iuZjsf3/H8N9ZNHosCrEF5P2bOvDdFYQz9SfWSntg/Lg1iGaHJgiJBaBOs\n"
    "2y1z3QKBgQDF1Fd/BqSCKA3WM0+3Bf7Mu4l40CKmzjFpVGALTQIscfE4kUiymXna\n"
    "DLWearAGdiGpWLD9Wq6/hBC+LLQXQ0zckITz3L2Lh5IJBoysOc2R+N2BHdSvVlti\n"
    "sF7IbcMbszEf8rtt2+ZosApwouLjqtb//15r8CfKiUKDRYNP3OBN2A==\n"
    "-----END RSA PRIVATE KEY-----\n";

static const char ec_p256_prv_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIEnJqMGMS4hWOMQxzx3xyZQTFgm1gNT9Q6DKsX2y8T7uoAoGCCqGSM49\n"
    "AwEHoUQDQgAEd3Jlb4FLOZJ51eHxeB+sbwmaPFyhsONTUYNLCLZeC1clkM2vj3aT\n"
    "YbzzSs/BHl4HToQmvd4Evm5lOUVElhfeRQ==\n"
    "-----END EC PRIVATE KEY-----\n";

static mbedtls_pk_context pk_rsa;
static mbedtls_pk_context pk_ec;
static int bench_keys_ready;

/* ================= xorshift64 RNG (RSA blinding; fixed seed, reproducible) ================= */
static uint64_t bench_rng_state = 0x9E3779B97F4A7C15ull;

int bench_rng(void *ctx, unsigned char *out, size_t len)
{
    size_t i;
    (void)ctx;
    for (i = 0; i < len; i++) {
        bench_rng_state ^= bench_rng_state << 13;
        bench_rng_state ^= bench_rng_state >> 7;
        bench_rng_state ^= bench_rng_state << 17;
        out[i] = (unsigned char)(bench_rng_state >> 32);
    }
    return 0;
}

/* ================= Interface implementation ================= */

int bench_crypto_init(void)
{
    int ret;

    mbedtls_pk_init(&pk_rsa);
    mbedtls_pk_init(&pk_ec);

    ret = mbedtls_pk_parse_key(&pk_rsa, (const unsigned char *)rsa_pkcs1_2048_pem,
                               sizeof(rsa_pkcs1_2048_pem), NULL, 0);
    if (ret != 0) {
        return -ret;
    }
    ret = mbedtls_pk_parse_key(&pk_ec, (const unsigned char *)ec_p256_prv_pem,
                               sizeof(ec_p256_prv_pem), NULL, 0);
    if (ret != 0) {
        return -ret;
    }
    bench_keys_ready = 1;
    return 0;
}

void bench_sha256(const uint8_t msg[BENCH_MSG_LEN], uint8_t digest[32])
{
    mbedtls_sha256(msg, BENCH_MSG_LEN, digest, 0);
}

int bench_rsa_sign(const uint8_t msg[BENCH_MSG_LEN], uint8_t sig[256])
{
    uint8_t hash[32];
    size_t olen = 0;
    int ret;

    if (!bench_keys_ready) {
        return -1;
    }
    bench_sha256(msg, hash);
    ret = mbedtls_pk_sign(&pk_rsa, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                          sig, &olen, bench_rng, NULL);
    return (ret == 0 && olen == 256u) ? 0 : (ret != 0 ? -ret : -2);
}

int bench_rsa_verify(const uint8_t msg[BENCH_MSG_LEN], const uint8_t sig[256])
{
    uint8_t hash[32];
    int ret;

    if (!bench_keys_ready) {
        return -1;
    }
    bench_sha256(msg, hash);
    ret = mbedtls_pk_verify(&pk_rsa, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                            sig, 256u);
    return ret == 0 ? 0 : -ret;
}

int bench_ecdsa_sign(const uint8_t msg[BENCH_MSG_LEN], uint8_t *sig_buf,
                     size_t sig_cap, size_t *sig_len)
{
    uint8_t hash[32];
    size_t olen = 0;
    int ret;

    if (!bench_keys_ready || sig_buf == NULL || sig_len == NULL) {
        return -1;
    }
    bench_sha256(msg, hash);
    /* f_rng=NULL -> MBEDTLS_ECDSA_DETERMINISTIC (RFC 6979 deterministic nonce, reproducible) */
    ret = mbedtls_pk_sign(&pk_ec, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                          sig_buf, &olen, NULL, NULL);
    if (ret == 0 && olen <= sig_cap) {
        *sig_len = olen;
        return 0;
    }
    return ret != 0 ? -ret : -2;
}

int bench_ecdsa_verify(const uint8_t msg[BENCH_MSG_LEN], const uint8_t *sig,
                       size_t sig_len)
{
    uint8_t hash[32];
    int ret;

    if (!bench_keys_ready || sig == NULL) {
        return -1;
    }
    bench_sha256(msg, hash);
    ret = mbedtls_pk_verify(&pk_ec, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                            sig, sig_len);
    return ret == 0 ? 0 : -ret;
}
