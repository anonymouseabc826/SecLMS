/*
 * Random source implementation B: fixed test-vector stub.
 *
 * Used only to verify that the lms_rnd*() interface is wired correctly and the
 * algorithm layer is unaware of the source. Outputs a predictable incrementing
 * sequence with no entropy; must not be used for real key material. Once a real
 * TRNG is integrated, implementation C replaces this file (interface unchanged).
 */
#include "lms_rnd.h"

static uint32_t stub_state = 0x9e3779b9u; /* fixed seed, golden-ratio constant, reproducible */

uint32_t lms_rnd32(void)
{
    /* xorshift32, deterministic and reproducible */
    uint32_t x = stub_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    stub_state = x;
    return x;
}

void lms_rnd(uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if ((i & 3u) == 0u) {
            (void)lms_rnd32();
        }
        out[i] = (uint8_t)(stub_state >> ((i & 3u) * 8u));
    }
}

/* No deterministic seed context under implementation B (the det-only interface is a no-op here;
 * 0.1.271 fix: the stub tier previously lacked this symbol, causing RND_IMPL=stub link failure, REVIEW G-M5). */
void lms_rnd_det_seed(const uint8_t *ctx, size_t len)
{
    (void)ctx;
    (void)len;
}
