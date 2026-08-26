#include "hash_api.h"

#include <stdio.h>
#include <string.h>

static int check_digest(lms_hash_alg_t alg,
                        const char *name,
                        const uint8_t *message,
                        size_t message_len,
                        const uint8_t expected[32])
{
    uint8_t digest[32];

    if (lms_hash(alg, message, message_len, digest, sizeof(digest)) != 0) {
        printf("FAIL: %s hash returned error\n", name);
        return 1;
    }
    if (memcmp(digest, expected, sizeof(digest)) != 0) {
        printf("FAIL: %s digest mismatch\n", name);
        return 1;
    }
    return 0;
}

int main(void)
{
    static const uint8_t abc[] = "abc";
    static const uint8_t sha256_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    /* SHAKE256("abc") truncated to 32B (FIPS 202 standard vector, KAT added by REVIEW B04-R3;
     * consistent across Python hashlib and the on-board SHAKE256 hardware) */
    static const uint8_t shake256_abc[32] = {
        0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77,
        0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
        0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee,
        0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39
    };
    uint8_t haraka_abc[32];
    uint8_t oversized_out[33];
    uint8_t shake_empty[32];
    uint8_t shake_136[32];
    uint8_t zero_136[136];
    int failures = 0;

    memset(zero_136, 0, sizeof(zero_136));
    failures += check_digest(LMS_HASH_SHA256, "SHA256 abc", abc, 3, sha256_abc);
    failures += check_digest(LMS_HASH_SHAKE256, "SHAKE256 abc", abc, 3, shake256_abc);
    /* SHAKE256 boundary smoke test (return-code level, 0 length / full 136B=rate block;
     * digest values not hardcoded to avoid self-referential vectors. The XKCP adapter
     * cross-validation (second half of B04-R3) is pending once the Makefile frees up. */
    if (lms_hash(LMS_HASH_SHAKE256, NULL, 0u, shake_empty, sizeof(shake_empty)) != 0) {
        puts("FAIL: SHAKE256 empty input returned error");
        failures++;
    }
    if (lms_hash(LMS_HASH_SHAKE256, zero_136, sizeof(zero_136), shake_136,
                 sizeof(shake_136)) != 0) {
        puts("FAIL: SHAKE256 136B input returned error");
        failures++;
    }
    if (lms_hash(LMS_HASH_HARAKA, abc, 3, haraka_abc, sizeof(haraka_abc)) != 0) {
        puts("FAIL: Haraka abc returned error");
        failures++;
    }
    if (lms_hash(LMS_HASH_HARAKA, abc, 3, oversized_out, sizeof(oversized_out)) == 0) {
        puts("FAIL: Haraka accepted non-LMS output length");
        failures++;
    }
    if (lms_hash(LMS_HASH_SHA256, abc, 3, oversized_out, sizeof(oversized_out)) == 0) {
        puts("FAIL: SHA256 accepted oversized output");
        failures++;
    }

    if (failures) {
        printf("hash tests failed: %d\n", failures);
        return 1;
    }

    puts("hash tests passed");
    return 0;
}