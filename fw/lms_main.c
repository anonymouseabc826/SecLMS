/* LMS_FW_VERSION is repository-level version metadata (REVIEW B05B06-R3): this file belongs
 * to the PC demo; the SoC firmware (lms_soc_smoke.c) neither references nor reports the
 * version - board-test/forensic version correspondence relies on host bookkeeping;
 * changing firmware code must bump this macro in sync. */
#define LMS_FW_VERSION "0.1.283"
#include "lms.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    static const uint8_t message[] = "LMS demo message";

    lms_private_key_t priv;
    lms_public_key_t pub;
    uint8_t sig[LMS_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    printf("LMS firmware demo version %s\n", LMS_FW_VERSION);

    if (lms_private_key_init(&priv, LMS_SHAKE256_N32_H5, LMOTS_SHAKE256_N32_W4, I, seed) != LMS_OK) {
        puts("private key init failed");
        return 1;
    }
    if (lms_public_key_generate(&priv, &pub) != LMS_OK) {
        puts("public key generation failed");
        return 1;
    }
    if (lms_sign(&priv, message, strlen((const char *)message), sig, sizeof(sig), &sig_len) != LMS_OK) {
        puts("sign failed");
        return 1;
    }
    if (lms_verify(&pub, message, strlen((const char *)message), sig, sig_len) != LMS_OK) {
        puts("verify failed");
        return 1;
    }

    printf("LMS sign/verify ok, signature length: %u, next q: %u\n",
           (unsigned)sig_len,
           (unsigned)priv.q);
    return 0;
}