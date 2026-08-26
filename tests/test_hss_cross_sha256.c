#include "hss.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t ref_param_set_t;
struct hss_working_key;

bool hss_generate_private_key(
    bool (*generate_random)(void *output, size_t length),
    unsigned levels,
    const ref_param_set_t *lm_type,
    const ref_param_set_t *lm_ots_type,
    bool (*update_private_key)(unsigned char *private_key, size_t len_private_key, void *context),
    void *context,
    unsigned char *public_key,
    size_t len_public_key,
    unsigned char *aux_data,
    size_t len_aux_data,
    void *info);
struct hss_working_key *hss_load_private_key(
    bool (*read_private_key)(unsigned char *private_key, size_t len_private_key, void *context),
    void *context,
    size_t memory_target,
    const unsigned char *aux_data,
    size_t len_aux_data,
    void *info);
void hss_free_working_key(struct hss_working_key *working_key);
bool hss_generate_signature(
    struct hss_working_key *working_key,
    bool (*update_private_key)(unsigned char *private_key, size_t len_private_key, void *context),
    void *context,
    const void *message,
    size_t message_len,
    unsigned char *signature,
    size_t signature_len,
    void *info);
bool hss_validate_signature(
    const unsigned char *public_key,
    const void *message,
    size_t message_len,
    const unsigned char *signature,
    size_t signature_len,
    void *info);
size_t hss_get_private_key_len(unsigned levels, const ref_param_set_t *lm_type, const ref_param_set_t *lm_ots_type);
size_t hss_get_public_key_len(unsigned levels, const ref_param_set_t *lm_type, const ref_param_set_t *lm_ots_type);
size_t hss_get_signature_len(unsigned levels, const ref_param_set_t *lm_type, const ref_param_set_t *lm_ots_type);

static int expect_true(bool ok, const char *label)
{
    if (!ok) {
        printf("FAIL: %s returned false\n", label);
        return 1;
    }
    return 0;
}

static int expect_ok(int status, const char *label)
{
    if (status != LMS_OK) {
        printf("FAIL: %s returned %d\n", label, status);
        return 1;
    }
    return 0;
}

static bool deterministic_random(void *output, size_t length)
{
    static uint8_t counter = 0x42u;
    size_t i;
    uint8_t *out = (uint8_t *)output;

    for (i = 0; i < length; i++) {
        out[i] = (uint8_t)(counter + (uint8_t)i);
    }
    counter = (uint8_t)(counter + (uint8_t)length + 1u);
    return true;
}

int main(void)
{
    static const uint8_t master_seed[HSS_MASTER_SEED_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    static const uint32_t our_lms_types[2] = { LMS_SHA256_N32_H5, LMS_SHA256_N32_H5 };
    static const uint32_t our_lmots_types[2] = { LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4 };
    static const ref_param_set_t ref_lms_types[2] = { LMS_SHA256_N32_H5, LMS_SHA256_N32_H5 };
    static const ref_param_set_t ref_lmots_types[2] = { LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4 };
    static const uint8_t msg[] = "cross validate sha256 hss";
    hss_private_key_t our_priv;
    hss_public_key_t our_pub;
    uint8_t our_sig[HSS_MAX_SIGNATURE_LEN];
    size_t our_sig_len = 0;
    uint8_t our_pub_std[HSS_PUBLIC_KEY_LEN];
    size_t ref_priv_len;
    size_t ref_pub_len;
    size_t ref_sig_len;
    /* Reference implementation L=2 SHA256 serialization buffer upper bound (REVIEW B13B16-R16:
     * originally a bare 64 magic number; the runtime guard cross-checked against the
     * hss_get_*_len return values is below; update this constant when changing L/parameter set). */
    enum { REF_PRIV_BUF_LEN = 64, REF_PUB_BUF_LEN = 64 };
    unsigned char ref_priv[REF_PRIV_BUF_LEN];
    unsigned char ref_pub[REF_PUB_BUF_LEN];
    unsigned char ref_sig[HSS_MAX_SIGNATURE_LEN];
    hss_public_key_t ref_pub_our;
    struct hss_working_key *working_key;
    int failures = 0;

    failures += expect_ok(hss_private_key_init(&our_priv, 2u, our_lms_types, our_lmots_types, master_seed), "our hss init");
    failures += expect_ok(hss_public_key_generate(&our_priv, &our_pub), "our hss pub");
    failures += expect_ok(hss_sign(&our_priv, msg, sizeof(msg) - 1u, our_sig, sizeof(our_sig), &our_sig_len), "our hss sign");
    failures += expect_ok(hss_public_key_serialize(&our_pub, our_pub_std, sizeof(our_pub_std)), "serialize our pub");
    failures += expect_true(hss_validate_signature(our_pub_std, msg, sizeof(msg) - 1u, our_sig, our_sig_len, NULL), "ref verify our signature");

    ref_priv_len = hss_get_private_key_len(2u, ref_lms_types, ref_lmots_types);
    ref_pub_len = hss_get_public_key_len(2u, ref_lms_types, ref_lmots_types);
    ref_sig_len = hss_get_signature_len(2u, ref_lms_types, ref_lmots_types);
    if (ref_priv_len > sizeof(ref_priv) || ref_pub_len > sizeof(ref_pub) || ref_sig_len > sizeof(ref_sig)) {
        printf("FAIL: reference buffer sizing invalid\n");
        return 1;
    }

    failures += expect_true(hss_generate_private_key(deterministic_random,
                                                     2u,
                                                     ref_lms_types,
                                                     ref_lmots_types,
                                                     NULL,
                                                     ref_priv,
                                                     ref_pub,
                                                     ref_pub_len,
                                                     NULL,
                                                     0u,
                                                     NULL),
                            "ref hss keygen");
    working_key = hss_load_private_key(NULL, ref_priv, 0u, NULL, 0u, NULL);
    failures += expect_true(working_key != NULL, "ref hss load");
    if (working_key != NULL) {
        failures += expect_true(hss_generate_signature(working_key,
                                                       NULL,
                                                       ref_priv,
                                                       msg,
                                                       sizeof(msg) - 1u,
                                                       ref_sig,
                                                       ref_sig_len,
                                                       NULL),
                                "ref hss sign");
        hss_free_working_key(working_key);
    }
    failures += expect_true(hss_validate_signature(ref_pub, msg, sizeof(msg) - 1u, ref_sig, ref_sig_len, NULL), "ref self verify");
    failures += expect_ok(hss_public_key_parse(&ref_pub_our, ref_pub, ref_pub_len), "parse ref pub");
    failures += expect_ok(hss_verify(&ref_pub_our, msg, sizeof(msg) - 1u, ref_sig, ref_sig_len), "our verify ref signature");

    if (failures) {
        printf("HSS cross validation failed: %d\n", failures);
        return 1;
    }

    puts("HSS SHA256 cross validation passed");
    return 0;
}
