/*
 * Random source implementation A: deterministic derivation (default).
 *
 * Derives from the caller-supplied secret material via SHA-256 domain separation,
 * equivalent to the existing software baseline's C derivation (an "alternative
 * unpredictable process" permitted by RFC 8554). Used for phase-3 security-state
 * domain device_epoch/key_epoch/I/SEED generation; repeated calls with the same
 * context produce reproducible output, guaranteeing byte-identical KAT vectors.
 *
 * Domain separation: out_block = H("LMS-RND-DET" || u32str(counter) || ctx || ctx_len_be32)
 * counter increments on each call, ensuring multiple draws within one session never repeat.
 */
#include "lms_rnd.h"

#include <string.h>

#include "sha256.h"

static uint32_t det_counter;
static uint8_t det_ctx[64];
static size_t det_ctx_len;
static int det_seeded;

/* Set the derivation context from secret material; must seed before use, otherwise output is all zeros (detectable misuse) */
void lms_rnd_det_seed(const uint8_t *ctx, size_t len)
{
    if (len > sizeof(det_ctx)) {
        len = sizeof(det_ctx);
    }
    memcpy(det_ctx, ctx, len);
    det_ctx_len = len;
    det_counter = 0;
    det_seeded = 1;
}

static void det_block(uint8_t *out)
{
    SHA256_CTX h;
    uint8_t ctr_be[4];
    uint8_t len_be[4];
    static const char domain[] = "LMS-RND-DET";

    ctr_be[0] = (uint8_t)(det_counter >> 24);
    ctr_be[1] = (uint8_t)(det_counter >> 16);
    ctr_be[2] = (uint8_t)(det_counter >> 8);
    ctr_be[3] = (uint8_t)(det_counter);
    len_be[0] = (uint8_t)(det_ctx_len >> 24);
    len_be[1] = (uint8_t)(det_ctx_len >> 16);
    len_be[2] = (uint8_t)(det_ctx_len >> 8);
    len_be[3] = (uint8_t)(det_ctx_len);

    SHA256_Init(&h);
    SHA256_Update(&h, (const uint8_t *)domain, (unsigned int)(sizeof(domain) - 1));
    SHA256_Update(&h, ctr_be, sizeof(ctr_be));
    SHA256_Update(&h, det_ctx, (unsigned int)det_ctx_len);
    SHA256_Update(&h, len_be, sizeof(len_be));
    SHA256_Final(out, &h);

    det_counter++;
}

uint32_t lms_rnd32(void)
{
    uint8_t block[32];
    uint32_t v;

    if (!det_seeded) {
        return 0;
    }
    det_block(block);
    v = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
        ((uint32_t)block[2] << 8) | (uint32_t)block[3];
    memset(block, 0, sizeof(block));
    return v;
}

void lms_rnd(uint8_t *out, size_t len)
{
    uint8_t block[32];

    if (!det_seeded) {
        memset(out, 0, len);
        return;
    }
    while (len > 0) {
        size_t take = (len < sizeof(block)) ? len : sizeof(block);
        det_block(block);
        memcpy(out, block, take);
        out += take;
        len -= take;
    }
    memset(block, 0, sizeof(block));
}
