/*
 * SecLMS classic algorithm benchmark -- PC self-check (verifies the mbedTLS trimmed config + RSA/ECDSA correctness)
 *
 * Usage (native gcc; the BENCH_NATIVE macro uses libc memory):
 *   gcc -std=c99 -Wall -Wextra -O2 -Ibench -I$(MBEDTLS_DIR)/include \
 *       -DMBEDTLS_CONFIG_FILE='"bench/mbedtls_lms_config.h"' -DBENCH_NATIVE \
 *       -o build/bench_native_check bench/bench_native_check.c bench/bench_crypto.c \
 *       <mbedtls library sources>
 *
 * Output: PASS/FAIL per operation + signature hex (for cross-checking against Python cryptography).
 */
#include "bench_crypto.h"

#include <stdio.h>
#include <string.h>

static uint8_t g_msg[BENCH_MSG_LEN];

static void print_hex(const char *label, const uint8_t *p, size_t len)
{
    size_t i;
    printf("%s (%zuB): ", label, len);
    for (i = 0; i < len && i < 64; i++) {
        printf("%02x", p[i]);
    }
    printf("%s\n", len > 64 ? "..." : "");
}

int main(void)
{
    uint8_t sig_rsa[256];
    uint8_t sig_ec[80];
    size_t sig_ec_len = 0;
    int rc;

    for (size_t i = 0; i < BENCH_MSG_LEN; i++) {
        g_msg[i] = (uint8_t)i;
    }

    rc = bench_crypto_init();
    if (rc != 0) {
        printf("FAIL: bench_crypto_init rc=%d\n", rc);
        return 1;
    }
    printf("PASS: bench_crypto_init (RSA-2048 + EC P-256 keys parsed)\n");

    rc = bench_rsa_sign(g_msg, sig_rsa);
    if (rc != 0) {
        printf("FAIL: rsa_sign rc=%d\n", rc);
        return 1;
    }
    print_hex("rsa sig", sig_rsa, sizeof(sig_rsa));

    rc = bench_rsa_verify(g_msg, sig_rsa);
    if (rc != 0) {
        printf("FAIL: rsa_verify rc=%d\n", rc);
        return 1;
    }
    printf("PASS: rsa sign->verify self-consistent\n");

    rc = bench_ecdsa_sign(g_msg, sig_ec, sizeof(sig_ec), &sig_ec_len);
    if (rc != 0) {
        printf("FAIL: ecdsa_sign rc=%d\n", rc);
        return 1;
    }
    print_hex("ecdsa sig", sig_ec, sig_ec_len);

    rc = bench_ecdsa_verify(g_msg, sig_ec, sig_ec_len);
    if (rc != 0) {
        printf("FAIL: ecdsa_verify rc=%d\n", rc);
        return 1;
    }
    printf("PASS: ecdsa sign->verify self-consistent\n");

    /* Corrupted signatures must be rejected (negative self-check) */
    sig_rsa[0] ^= 0x01;
    rc = bench_rsa_verify(g_msg, sig_rsa);
    if (rc == 0) {
        printf("FAIL: rsa_verify accepted corrupted sig\n");
        return 1;
    }
    sig_ec[0] ^= 0x01;
    rc = bench_ecdsa_verify(g_msg, sig_ec, sig_ec_len);
    if (rc == 0) {
        printf("FAIL: ecdsa_verify accepted corrupted sig\n");
        return 1;
    }
    printf("PASS: corrupted signatures rejected\n");
    printf("ALL BENCH NATIVE CHECKS PASSED\n");
    return 0;
}
