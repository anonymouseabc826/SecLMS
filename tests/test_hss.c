#include "hss.h"
#include "../src/lms_internal.h"

#include <stdio.h>
#include <string.h>

static int expect_ok(int status, const char *label)
{
    if (status != LMS_OK) {
        printf("FAIL: %s returned %d\n", label, status);
        return 1;
    }
    return 0;
}

static int expect_fail(int status, const char *label)
{
    if (status == LMS_OK) {
        printf("FAIL: %s unexpectedly succeeded\n", label);
        return 1;
    }
    return 0;
}

int main(void)
{
    static const uint8_t master_seed[HSS_MASTER_SEED_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    static const uint32_t lms_types[2] = {
        LMS_SHA256_N32_H5,
        LMS_SHA256_N32_H5
    };
    static const uint32_t lmots_types[2] = {
        LMOTS_SHA256_N32_W4,
        LMOTS_SHA256_N32_W4
    };
    static const uint8_t msg0[] = "hss message";
    hss_private_key_t priv;
    hss_private_key_t single_priv;
    hss_public_key_t pub;
    hss_public_key_t single_pub;
    hss_public_key_t parsed_pub;
    lmots_chain_stats_t keygen_chain_stats;
    lmots_chain_stats_t sign_chain_stats;
    lmots_chain_stats_t verify_chain_stats;
    uint8_t sig[HSS_MAX_SIGNATURE_LEN];
    uint8_t pub_bytes[HSS_PUBLIC_KEY_LEN];
    uint8_t msg[64];
    size_t sig_len = 0;
    int failures = 0;
    uint32_t i;

    failures += expect_ok(hss_private_key_init(&priv, 2, lms_types, lmots_types, master_seed), "hss init");
    failures += expect_ok(hss_public_key_generate(&priv, &pub), "hss pub generate");
    failures += expect_ok(hss_sign(&priv, msg0, sizeof(msg0) - 1u, sig, sizeof(sig), &sig_len), "hss sign");
    failures += expect_ok(hss_verify(&pub, msg0, sizeof(msg0) - 1u, sig, sig_len), "hss verify");
    sig[10] ^= 0x01;
    failures += expect_fail(hss_verify(&pub, msg0, sizeof(msg0) - 1u, sig, sig_len), "hss tampered sig");
    sig[10] ^= 0x01;

    failures += expect_fail(hss_verify(&pub, (const uint8_t *)"hss messagf", sizeof(msg0) - 1u, sig, sig_len), "hss tampered msg");

    {
        hss_private_key_t before = priv;
        failures += expect_fail(hss_sign(&priv, msg0, sizeof(msg0) - 1u, sig, 1u, &sig_len), "hss short buffer");
        if (memcmp(&priv, &before, sizeof(priv)) != 0) {
            puts("FAIL: hss short buffer changed private state");
            failures++;
        }
    }
 
    /* Run enough signatures to force lower-level LMS rollover and chain refresh. */
    for (i = 0; i < 40u; i++) {
        size_t mlen;
        msg[0] = (uint8_t)i;
        msg[1] = (uint8_t)(i >> 8);
        msg[2] = (uint8_t)0xA5;
        msg[3] = (uint8_t)0x5A;
        mlen = 4u;

        failures += expect_ok(hss_sign(&priv, msg, mlen, sig, sizeof(sig), &sig_len), "hss rollover sign");
        failures += expect_ok(hss_verify(&pub, msg, mlen, sig, sig_len), "hss rollover verify");
    }

    lmots_chain_stats_reset();
    failures += expect_ok(hss_private_key_init(&single_priv, 1u, lms_types, lmots_types, master_seed), "hss L1 init");
    failures += expect_ok(hss_public_key_generate(&single_priv, &single_pub), "hss L1 pub generate");
    lmots_chain_stats_get(&keygen_chain_stats);
    lmots_chain_stats_reset();
    failures += expect_ok(hss_sign(&single_priv, msg0, sizeof(msg0) - 1u, sig, sizeof(sig), &sig_len), "hss L1 sign");
    lmots_chain_stats_get(&sign_chain_stats);
    if (sig_len < 4u || sig[0] != 0u || sig[1] != 0u || sig[2] != 0u || sig[3] != 0u) {
        puts("FAIL: hss L1 signature prefix is not u32str(0)");
        failures++;
    }
    lmots_chain_stats_reset();
    failures += expect_ok(hss_verify(&single_pub, msg0, sizeof(msg0) - 1u, sig, sig_len), "hss L1 verify");
    lmots_chain_stats_get(&verify_chain_stats);

    if (keygen_chain_stats.calls != 2144u || keygen_chain_stats.steps != 32160u) {
        printf("FAIL: HSS L1 keygen chain baseline expected 2144/32160, got %llu/%llu\n",
               (unsigned long long)keygen_chain_stats.calls,
               (unsigned long long)keygen_chain_stats.steps);
        failures++;
    }
    if (sign_chain_stats.calls != 2144u || sign_chain_stats.steps != 31560u ||
        verify_chain_stats.calls != 67u || verify_chain_stats.steps != 600u) {
        printf("FAIL: HSS L1 sign/verify chain baseline got %llu/%llu and %llu/%llu\n",
               (unsigned long long)sign_chain_stats.calls,
               (unsigned long long)sign_chain_stats.steps,
               (unsigned long long)verify_chain_stats.calls,
               (unsigned long long)verify_chain_stats.steps);
        failures++;
    }
    printf("HSS L1 chain baseline: keygen=%llu/%llu sign=%llu/%llu verify=%llu/%llu\n",
           (unsigned long long)keygen_chain_stats.calls,
           (unsigned long long)keygen_chain_stats.steps,
           (unsigned long long)sign_chain_stats.calls,
           (unsigned long long)sign_chain_stats.steps,
           (unsigned long long)verify_chain_stats.calls,
           (unsigned long long)verify_chain_stats.steps);

    failures += expect_ok(hss_public_key_serialize(&single_pub, pub_bytes, sizeof(pub_bytes)), "hss pub serialize");
    pub_bytes[3] = HSS_MAX_LEVELS;
    failures += expect_ok(hss_public_key_parse(&parsed_pub, pub_bytes, sizeof(pub_bytes)), "hss L8 pub parse");
    pub_bytes[3] = HSS_MAX_LEVELS + 1u;
    failures += expect_fail(hss_public_key_parse(&parsed_pub, pub_bytes, sizeof(pub_bytes)), "hss reject L9 pub");

    {
        hss_private_key_t before;
        memset(priv.generation[1], 0xff, HSS_GENERATION_LEN);
        priv.keys[1].q = 1u << 5;
        before = priv;
        failures += expect_fail(hss_sign(&priv, msg0, sizeof(msg0) - 1u, sig, sizeof(sig), &sig_len), "hss generation exhausted");
        if (memcmp(&priv, &before, sizeof(priv)) != 0) {
            puts("FAIL: hss generation exhaustion changed private state");
            failures++;
        }
    }

    if (failures) {
        printf("HSS tests failed: %d\n", failures);
        return 1;
    }

    puts("HSS tests passed");
    return 0;
}
