#include "lms.h"
#include "../src/lms_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Maximum LM-OTS signature length (w=1 -> p=265): not defined in the library header, defined locally here (aligned with firmware). */
#define LMS_MAX_OTS_SIG_LEN (4u + LMS_N + LMS_MAX_OTS_P * LMS_N)

static uint64_t sign_backend_calls;
static uint64_t sign_backend_steps;
static uint64_t keygen_backend_calls;
static uint64_t keygen_backend_steps;

static int observe_keygen_chain(void *context,
                                const uint8_t I[LMS_I_LEN],
                                lms_hash_alg_t hash_alg,
                                uint32_t q,
                                uint32_t i,
                                uint32_t start,
                                uint32_t steps,
                                uint8_t value[LMS_N])
{
    (void)context;
    keygen_backend_calls++;
    keygen_backend_steps += steps;
    return lmots_chain_compute(I, hash_alg, q, i, start, steps, value);
}

static int observe_sign_chain(void *context,
                              const uint8_t I[LMS_I_LEN],
                              lms_hash_alg_t hash_alg,
                              uint32_t q,
                              uint32_t i,
                              uint32_t start,
                              uint32_t steps,
                              uint8_t value[LMS_N])
{
    (void)context;
    sign_backend_calls++;
    sign_backend_steps += steps;
    return lmots_chain_compute(I, hash_alg, q, i, start, steps, value);
}

/* LM-OTS signature length = type(4)+C(n)+y(p*n), derived from the parameter table (multi-parameter set, not the 67 special case). */
static size_t lmots_sig_len_of(uint32_t lmots_type)
{
    lmots_param_t param;

    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK) {
        return 0u;
    }
    return 4u + param.n + (size_t)param.p * param.n;
}

static void print_hex(const char *name, const uint8_t *bytes, size_t length)
{
    size_t index;
    printf("%s=", name);
    for (index = 0; index < length; index++) {
        printf("%02x", bytes[index]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t message[2048];        /* Large message buffer (--msg-bytes, <=2048B aligned with HASH_ONCE_RAM) */
    size_t message_len = 0u;
    uint32_t lms_type = LMS_SHAKE256_N32_H5;
    uint32_t lmots_type = LMOTS_SHAKE256_N32_W4;
    uint32_t sign_q = 0u;   /* --q=N: LMOTS signing uses an arbitrary q (default 0, so SEC_SIGN generates the expectation by ctr) */
    size_t lmots_sig_len;
    uint32_t expected_sig_len;
    lms_private_key_t private_key;
    lms_public_key_t public_key;
    lmots_chain_stats_t stats;
    uint8_t private_bytes[LMS_PRIVATE_KEY_LEN];
    uint8_t public_bytes[LMS_PUBLIC_KEY_LEN];
    uint8_t lmots_public[LMS_N];
    uint8_t lmots_signature[LMS_MAX_OTS_SIG_LEN];
    uint8_t signature[LMS_MAX_SIGNATURE_LEN];
    uint64_t lmots_keygen_calls;
    uint64_t lmots_keygen_steps;
    uint64_t lmots_sign_calls;
    uint64_t lmots_sign_steps;
    size_t signature_length = 0u;
    uint64_t public_key_calls;
    uint64_t public_key_steps;
    int i;

    /* Multi-parameter set (t8): --lms=<type> --lmots=<type> (decimal or 0x), default SHAKE256 W4/H5.
     * --msg-bytes=<N>: generate a large message (default 19B "RV32 hardware Verify" keeps compatibility).
     * --q=<N>: LMOTS_SIGNATURE uses an arbitrary q (default 0), so the board SEC_SIGN generates the expectation by ctr. */
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--lms=", 6u) == 0) {
            lms_type = (uint32_t)strtoul(argv[i] + 6, NULL, 0);
        } else if (strncmp(argv[i], "--lmots=", 8u) == 0) {
            lmots_type = (uint32_t)strtoul(argv[i] + 8, NULL, 0);
        } else if (strncmp(argv[i], "--msg-bytes=", 12u) == 0) {
            message_len = (size_t)strtoul(argv[i] + 12, NULL, 0);
            if (message_len > sizeof(message)) {
                message_len = sizeof(message);
            }
        } else if (strncmp(argv[i], "--q=", 4u) == 0) {
            sign_q = (uint32_t)strtoul(argv[i] + 4, NULL, 0);
        }
    }
    if (message_len == 0u) {
        static const char default_msg[] = "RV32 hardware Verify";
        memcpy(message, default_msg, sizeof(default_msg) - 1u);
        message_len = sizeof(default_msg) - 1u;
    } else {
        /* Large message: deterministic fill (not all zeros, to avoid degenerate edge cases) */
        for (i = 0; i < (int)message_len; i++) {
            message[i] = (uint8_t)(0xa0u + (unsigned)(i % 251));
        }
    }
    lmots_sig_len = lmots_sig_len_of(lmots_type);
    expected_sig_len = (uint32_t)lms_signature_len(lms_type, lmots_type);
    if (lmots_sig_len == 0u || expected_sig_len == 0u) {
        return 1;
    }

    /* The hash primitive is determined by the typecode of the --lms/--lmots parameter set;
     * the LMS_VECTOR_SHAKE256 compile macro is now a no-op (both branches were byte-identical,
     * removed by REVIEW B13B16-R2). */
    if (lms_private_key_init(&private_key, lms_type,
                             lmots_type, I, seed) != LMS_OK) {
        return 1;
    }
    private_key.q = sign_q;  /* The q field of the serialized PRIVATE_KEY matches LMOTS_SIGNATURE */
    lmots_keygen_chain_backend_set(observe_keygen_chain, NULL);
    if (lmots_public_from_private(&private_key, 0u, lmots_public) != LMS_OK) {
        return 1;
    }
    lmots_keygen_chain_backend_set(NULL, NULL);
    lmots_keygen_calls = keygen_backend_calls;
    lmots_keygen_steps = keygen_backend_steps;
    keygen_backend_calls = 0u;
    keygen_backend_steps = 0u;

    lmots_keygen_chain_backend_set(observe_keygen_chain, NULL);
    if (lms_public_key_generate(&private_key, &public_key) != LMS_OK) {
        return 1;
    }
    lmots_keygen_chain_backend_set(NULL, NULL);
    public_key_calls = keygen_backend_calls;
    public_key_steps = keygen_backend_steps;
    keygen_backend_calls = 0u;
    keygen_backend_steps = 0u;
    if (
        lms_public_key_serialize(&public_key, public_bytes, sizeof(public_bytes)) != LMS_OK ||
        lms_private_key_serialize(&private_key, private_bytes, sizeof(private_bytes)) != LMS_OK) {
        return 1;
    }

    lmots_sign_chain_backend_set(observe_sign_chain, NULL);
    if (lmots_sign(&private_key, sign_q, message, message_len,
                   lmots_signature, sizeof(lmots_signature)) != LMS_OK) {
        return 1;
    }
    lmots_sign_chain_backend_set(NULL, NULL);
    lmots_sign_calls = sign_backend_calls;
    lmots_sign_steps = sign_backend_steps;
    sign_backend_calls = 0u;
    sign_backend_steps = 0u;

    lmots_keygen_chain_backend_set(observe_keygen_chain, NULL);
    lmots_sign_chain_backend_set(observe_sign_chain, NULL);
    if (
        lms_sign(&private_key, message, message_len,
                 signature, sizeof(signature), &signature_length) != LMS_OK ||
        signature_length != expected_sig_len) {
        return 1;
    }
    lmots_sign_chain_backend_set(NULL, NULL);
    lmots_keygen_chain_backend_set(NULL, NULL);

    lmots_chain_stats_reset();
    if (lms_verify(&public_key, message, message_len,
                   signature, signature_length) != LMS_OK) {
        return 1;
    }
    lmots_chain_stats_get(&stats);

    print_hex("PRIVATE_KEY", private_bytes, sizeof(private_bytes));
    print_hex("PUBLIC_KEY", public_bytes, sizeof(public_bytes));
    print_hex("MESSAGE", message, message_len);
    print_hex("SIGNATURE", signature, signature_length);
    print_hex("LMOTS_PUBLIC_KEY", lmots_public, sizeof(lmots_public));
    print_hex("LMOTS_SIGNATURE", lmots_signature, lmots_sig_len);
    printf("CALLS=%llu\n", (unsigned long long)stats.calls);
    printf("STEPS=%llu\n", (unsigned long long)stats.steps);
    printf("SIGN_CALLS=%llu\n", (unsigned long long)sign_backend_calls);
    printf("SIGN_STEPS=%llu\n", (unsigned long long)sign_backend_steps);
    printf("KEYGEN_CALLS=%llu\n", (unsigned long long)public_key_calls);
    printf("KEYGEN_STEPS=%llu\n", (unsigned long long)public_key_steps);
    printf("FULL_SIGN_CALLS=%llu\n",
           (unsigned long long)(sign_backend_calls + keygen_backend_calls));
    printf("FULL_SIGN_STEPS=%llu\n",
           (unsigned long long)(sign_backend_steps + keygen_backend_steps));
    printf("LMOTS_KEYGEN_CALLS=%llu\n", (unsigned long long)lmots_keygen_calls);
    printf("LMOTS_KEYGEN_STEPS=%llu\n", (unsigned long long)lmots_keygen_steps);
    printf("LMOTS_SIGN_CALLS=%llu\n", (unsigned long long)lmots_sign_calls);
    printf("LMOTS_SIGN_STEPS=%llu\n", (unsigned long long)lmots_sign_steps);
    return 0;
}