#ifndef HSS_H
#define HSS_H

#include "lms.h"

#include <stddef.h>
#include <stdint.h>

#define HSS_MAX_LEVELS 8u
#define HSS_MASTER_SEED_LEN 32u
#define HSS_GENERATION_LEN 32u
#define HSS_PUBLIC_KEY_LEN (4u + LMS_PUBLIC_KEY_LEN)
#define HSS_MAX_SIGNATURE_LEN (4u + HSS_MAX_LEVELS * LMS_MAX_SIGNATURE_LEN + (HSS_MAX_LEVELS - 1u) * LMS_PUBLIC_KEY_LEN)

typedef struct {
	uint32_t levels;
	lms_public_key_t root_pub;
} hss_public_key_t;

/* HSS is PC-only (REVIEW B03-R3): hss_private_key_t is about 66KB (cert_sig dominates),
 * hss_sign copy-on-write peak is about 132KB, far beyond the SoC 128KiB RAM; RV32 firmware does not use HSS. */
typedef struct {
	uint32_t levels;
	uint8_t master_seed[HSS_MASTER_SEED_LEN];
	uint32_t lms_types[HSS_MAX_LEVELS];
	uint32_t lmots_types[HSS_MAX_LEVELS];
	uint8_t generation[HSS_MAX_LEVELS][HSS_GENERATION_LEN];
	lms_private_key_t keys[HSS_MAX_LEVELS];
	lms_public_key_t pubs[HSS_MAX_LEVELS];
	size_t cert_len[HSS_MAX_LEVELS - 1u];
	uint8_t cert_sig[HSS_MAX_LEVELS - 1u][LMS_MAX_SIGNATURE_LEN];
} hss_private_key_t;

int hss_private_key_init(hss_private_key_t *priv,
						 uint32_t levels,
						 const uint32_t *lms_types,
						 const uint32_t *lmots_types,
						 const uint8_t master_seed[HSS_MASTER_SEED_LEN]);

int hss_public_key_generate(const hss_private_key_t *priv,
							hss_public_key_t *pub);

int hss_public_key_serialize(const hss_public_key_t *pub,
						 uint8_t *out,
						 size_t out_len);

int hss_public_key_parse(hss_public_key_t *pub,
					 const uint8_t *in,
					 size_t in_len);

size_t hss_signature_len(const hss_private_key_t *priv);

int hss_sign(hss_private_key_t *priv,
			 const uint8_t *message,
			 size_t message_len,
			 uint8_t *signature,
			 size_t signature_len,
			 size_t *written);

int hss_verify(const hss_public_key_t *pub,
			   const uint8_t *message,
			   size_t message_len,
			   const uint8_t *signature,
			   size_t signature_len);

#endif