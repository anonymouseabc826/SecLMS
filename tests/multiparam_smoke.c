/*
 * t8 multi-parameter set PC smoke test (REVIEW B13B16-R14: wired into the Makefile,
 * make build/multiparam_smoke):
 *   iterates w in {1,2,4,8} x h in {5,10,15} (one set each for SHA256 + SHAKE256):
 *   1. software path keygen -> sign -> verify correctness (byte-for-byte);
 *   2. tree cache (large budget picks the fastest tier, possibly the full j=h amount)
 *      sign_init + auth_path backend, consecutive multi-q signing matches the software
 *      reference byte-for-byte + verify passes.
 * Note: the full pure-software matrix (including W8 soft chains) takes a long time, so it
 * is not part of the default make test set.
 */
#include "lms.h"
#include "lms_internal.h"
#include "lms_subtree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void *p_alloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void p_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

static void make_priv(lms_private_key_t *priv, uint32_t lms_type, uint32_t lmots_type)
{
    uint8_t I[LMS_I_LEN];
    uint8_t seed[LMS_SEED_LEN];
    uint32_t i;

    for (i = 0; i < LMS_I_LEN; i++) {
        I[i] = (uint8_t)(0xa0u + i);
    }
    for (i = 0; i < LMS_SEED_LEN; i++) {
        seed[i] = (uint8_t)(0x10u + i);
    }
    if (lms_private_key_init(priv, lms_type, lmots_type, I, seed) != LMS_OK) {
        printf("  FAIL: private_key_init type=%x/%x\n", lms_type, lmots_type);
        failures++;
    }
}

static int run_one(uint32_t lms_type, uint32_t lmots_type)
{
    static const uint8_t msg[] = "multi-param smoke t8";
    lms_private_key_t priv;
    lms_private_key_t priv_ref;
    lms_public_key_t pub;
    uint8_t sig[LMS_MAX_SIGNATURE_LEN];
    uint8_t sig_ref[LMS_MAX_SIGNATURE_LEN];
    size_t written = 0u;
    size_t written_ref = 0u;
    lms_tree_config_t cfg;
    lms_tree_ctx_t ctx;
    uint32_t q;

    /* Software path: keygen + sign + verify. */
    make_priv(&priv, lms_type, lmots_type);
    if (lms_public_key_generate(&priv, &pub) != LMS_OK) {
        printf("  FAIL: keygen type=%x/%x\n", lms_type, lmots_type);
        failures++;
        return 0;
    }
    make_priv(&priv_ref, lms_type, lmots_type);
    if (lms_sign(&priv_ref, msg, sizeof(msg) - 1u, sig_ref, sizeof(sig_ref),
                 &written_ref) != LMS_OK ||
        lms_verify(&pub, msg, sizeof(msg) - 1u, sig_ref, written_ref) != LMS_OK) {
        printf("  FAIL: sw sign/verify type=%x/%x\n", lms_type, lmots_type);
        failures++;
        return 0;
    }

    /* Tree cache: large budget picks the fastest tier (H5/H10/H15 all full j=h, sublevels=1),
     * sign_init + auth path backend, consecutive multi-q signing matches the software reference. */
    if (lms_tree_configure(lms_type, (uint64_t)1u << 22, &cfg) != LMS_OK ||
        lms_tree_ctx_init(&ctx, &cfg, pub.I, NULL, NULL, p_alloc, p_free, NULL) != LMS_OK) {
        printf("  FAIL: tree cfg/init type=%x/%x\n", lms_type, lmots_type);
        failures++;
        return 0;
    }
    if (lms_tree_sign_init(&ctx, &priv) != LMS_OK) {
        printf("  FAIL: sign_init type=%x/%x\n", lms_type, lmots_type);
        failures++;
        lms_tree_ctx_free(&ctx);
        return 0;
    }
    lms_auth_path_backend_set(lms_subtree_auth_path_backend, &ctx);
    for (q = 0u; q < 4u && q < (uint32_t)(1u << cfg.height); q++) {
        lms_private_key_t priv_sw;
        lms_private_key_t priv_c;

        /* Independent software reference per q (a different q yields a different signature). */
        make_priv(&priv_sw, lms_type, lmots_type);
        priv_sw.q = q;
        if (lms_sign(&priv_sw, msg, sizeof(msg) - 1u, sig_ref, sizeof(sig_ref),
                     &written_ref) != LMS_OK) {
            printf("  FAIL: sw sign q=%u type=%x/%x\n", q, lms_type, lmots_type);
            failures++;
            break;
        }
        make_priv(&priv_c, lms_type, lmots_type);
        priv_c.q = q;
        if (lms_sign(&priv_c, msg, sizeof(msg) - 1u, sig, sizeof(sig), &written) != LMS_OK ||
            written != written_ref ||
            memcmp(sig, sig_ref, written) != 0) {
            printf("  FAIL: cached sign q=%u type=%x/%x\n", q, lms_type, lmots_type);
            failures++;
            break;
        }
        if (lms_verify(&pub, msg, sizeof(msg) - 1u, sig, written) != LMS_OK) {
            printf("  FAIL: cached verify q=%u type=%x/%x\n", q, lms_type, lmots_type);
            failures++;
            break;
        }
    }
    lms_auth_path_backend_set(NULL, NULL);
    lms_tree_ctx_free(&ctx);
    return 1;
}

static const char *w_name(uint32_t lmots_type)
{
    if (lmots_type == LMOTS_SHA256_N32_W1 || lmots_type == LMOTS_SHAKE256_N32_W1) {
        return "W1";
    }
    if (lmots_type == LMOTS_SHA256_N32_W2 || lmots_type == LMOTS_SHAKE256_N32_W2) {
        return "W2";
    }
    if (lmots_type == LMOTS_SHA256_N32_W8 || lmots_type == LMOTS_SHAKE256_N32_W8) {
        return "W8";
    }
    return "W4";
}

static const char *h_name(uint32_t lms_type)
{
    if (lms_type == LMS_SHA256_N32_H10 || lms_type == LMS_SHAKE256_N32_H10) {
        return "H10";
    }
    if (lms_type == LMS_SHA256_N32_H15 || lms_type == LMS_SHAKE256_N32_H15) {
        return "H15";
    }
    return "H5";
}

int main(void)
{
    static const uint32_t lmots_sha[] = {
        LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8
    };
    static const uint32_t lms_sha[] = {
        LMS_SHA256_N32_H5, LMS_SHA256_N32_H10, LMS_SHA256_N32_H15
    };
    static const uint32_t lmots_shake[] = {
        LMOTS_SHAKE256_N32_W1, LMOTS_SHAKE256_N32_W2, LMOTS_SHAKE256_N32_W4, LMOTS_SHAKE256_N32_W8
    };
    static const uint32_t lms_shake[] = {
        LMS_SHAKE256_N32_H5, LMS_SHAKE256_N32_H10, LMS_SHAKE256_N32_H15
    };
    size_t i;
    size_t j;

    for (i = 0u; i < sizeof(lmots_sha) / sizeof(lmots_sha[0]); i++) {
        for (j = 0u; j < sizeof(lms_sha) / sizeof(lms_sha[0]); j++) {
            printf("SHA256   %s %s ...\n", w_name(lmots_sha[i]), h_name(lms_sha[j]));
            run_one(lms_sha[j], lmots_sha[i]);
        }
    }
    for (i = 0u; i < sizeof(lmots_shake) / sizeof(lmots_shake[0]); i++) {
        for (j = 0u; j < sizeof(lms_shake) / sizeof(lms_shake[0]); j++) {
            printf("SHAKE256 %s %s ...\n", w_name(lmots_shake[i]), h_name(lms_shake[j]));
            run_one(lms_shake[j], lmots_shake[i]);
        }
    }
    if (failures == 0) {
        printf("ALL multiparam smoke PASS\n");
        return 0;
    }
    printf("FAILURES: %d\n", failures);
    return 1;
}
