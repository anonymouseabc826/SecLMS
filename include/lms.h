#ifndef LMS_H
#define LMS_H

#include <stddef.h>
#include <stdint.h>

#define LMS_N 32u
#define LMS_I_LEN 16u
#define LMS_SEED_LEN 32u
#define LMS_MAX_HEIGHT 25u
#define LMS_MAX_OTS_P 265u
#define LMS_MAX_SIGNATURE_LEN (4u + 4u + LMS_N + LMS_MAX_OTS_P * LMS_N + 4u + LMS_MAX_HEIGHT * LMS_N)
#define LMS_PUBLIC_KEY_LEN (4u + 4u + LMS_I_LEN + LMS_N)
#define LMS_PRIVATE_KEY_LEN (4u + 4u + LMS_I_LEN + LMS_SEED_LEN + 4u)

typedef enum {
    LMS_OK = 0,
    LMS_ERR_INVALID = -1,
    LMS_ERR_BUFFER_TOO_SMALL = -2,
    LMS_ERR_EXHAUSTED = -3,
    LMS_ERR_VERIFY = -4
} lms_status_t;

/* lmstype value definitions:
 *   SHA256  (0x05-0x09) are the type values defined by the RFC 8554 standard.
 *   SHAKE256(0x15-0x19) and Haraka(0x25-0x29) are project-defined non-standard
 *   type values, not defined by RFC 8554 / NIST, used only for this project's
 *   international-algorithm extension experiments. */
typedef enum {
    LMS_SHA256_N32_H5 = 0x00000005u,
    LMS_SHA256_N32_H10 = 0x00000006u,
    LMS_SHA256_N32_H15 = 0x00000007u,
    LMS_SHA256_N32_H20 = 0x00000008u,
    LMS_SHA256_N32_H25 = 0x00000009u,
    /* Non-standard type values (project-defined; see comment above) */
    LMS_SHAKE256_N32_H5 = 0x00000015u,
    LMS_SHAKE256_N32_H10 = 0x00000016u,
    LMS_SHAKE256_N32_H15 = 0x00000017u,
    LMS_SHAKE256_N32_H20 = 0x00000018u,
    LMS_SHAKE256_N32_H25 = 0x00000019u,
    LMS_HARAKA_N32_H5 = 0x00000025u,
    LMS_HARAKA_N32_H10 = 0x00000026u,
    LMS_HARAKA_N32_H15 = 0x00000027u,
    LMS_HARAKA_N32_H20 = 0x00000028u,
    LMS_HARAKA_N32_H25 = 0x00000029u
} lms_type_t;

/* otstype value definitions:
 *   SHA256  (0x01-0x04) are the type values defined by the RFC 8554 standard.
 *   SHAKE256(0x11-0x14) and Haraka(0x21-0x24) are project-defined non-standard
 *   type values, not defined by RFC 8554 / NIST, used only for this project's
 *   international-algorithm extension experiments. */
typedef enum {
    LMOTS_SHA256_N32_W1 = 0x00000001u,
    LMOTS_SHA256_N32_W2 = 0x00000002u,
    LMOTS_SHA256_N32_W4 = 0x00000003u,
    LMOTS_SHA256_N32_W8 = 0x00000004u,
    /* Non-standard type values (project-defined; see comment above) */
    LMOTS_SHAKE256_N32_W1 = 0x00000011u,
    LMOTS_SHAKE256_N32_W2 = 0x00000012u,
    LMOTS_SHAKE256_N32_W4 = 0x00000013u,
    LMOTS_SHAKE256_N32_W8 = 0x00000014u,
    LMOTS_HARAKA_N32_W1 = 0x00000021u,
    LMOTS_HARAKA_N32_W2 = 0x00000022u,
    LMOTS_HARAKA_N32_W4 = 0x00000023u,
    LMOTS_HARAKA_N32_W8 = 0x00000024u
} lmots_type_t;

typedef struct {
    uint32_t lms_type;
    uint32_t lmots_type;
    uint8_t I[LMS_I_LEN];
    uint8_t root[LMS_N];
} lms_public_key_t;

typedef struct {
    uint32_t lms_type;
    uint32_t lmots_type;
    uint8_t I[LMS_I_LEN];
    uint8_t seed[LMS_SEED_LEN];
    uint32_t q;
} lms_private_key_t;

int lms_private_key_init(lms_private_key_t *priv,
                         uint32_t lms_type,
                         uint32_t lmots_type,
                         const uint8_t I[LMS_I_LEN],
                         const uint8_t seed[LMS_SEED_LEN]);

int lms_public_key_generate(const lms_private_key_t *priv,
                            lms_public_key_t *pub);

size_t lms_signature_len(uint32_t lms_type, uint32_t lmots_type);

int lms_public_key_serialize(const lms_public_key_t *pub,
                             uint8_t *out,
                             size_t out_len);

int lms_public_key_parse(lms_public_key_t *pub,
                         const uint8_t *in,
                         size_t in_len);

int lms_private_key_serialize(const lms_private_key_t *priv,
                              uint8_t *out,
                              size_t out_len);

int lms_private_key_parse(lms_private_key_t *priv,
                          const uint8_t *in,
                          size_t in_len);

int lms_sign(lms_private_key_t *priv,
             const uint8_t *message,
             size_t message_len,
             uint8_t *signature,
             size_t signature_len,
             size_t *written);

int lms_verify(const lms_public_key_t *pub,
               const uint8_t *message,
               size_t message_len,
               const uint8_t *signature,
               size_t signature_len);

#endif