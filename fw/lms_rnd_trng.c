/*
 * Random source implementation C: real TRNG (standalone MMIO peripheral, 0x17000000).
 *
 * Two random tiers (compile-time LMS_RND_TRNG_COND, default tier 2):
 *   Tier 1 (LMS_RND_TRNG_COND=1): read the TRNG RND register directly (raw words
 *         after CRC-8 compression); entropy characterization/diagnostics only.
 *   Tier 2 (LMS_RND_TRNG_COND=2, default): conditioning via the LMS HASH_ONCE command
 *         to the **currently enabled on-board hash core** (REVIEW B05B06-R10 fixes the old
 *         "SHA-256 conditioning" wording: SHAKE256 platform uses SHAKE256, hash follows
 *         HASH_IMPL) - keeps a 512bit raw buffer internally; when exhausted, one round:
 *         16 x RND (512bit) -> HASH_ONCE -> 256bit output, amortized ~149 cycles/word
 *         (trng_c1_plan section 4). Claims and actual consumption use this tier by default.
 *
 * Health check: on health_fail the TRNG peripheral gates RND to 0; this impl detects
 * STAT.health_fail, sets global trng_fault, and returns 0 (FACTORY_INIT/SEC_SIGN gating
 * can query trng_fault).
 *
 * SoC firmware only (direct MMIO); not part of the PC build (PC uses det/stub).
 */
#include "lms_rnd.h"

#include <string.h>

#include <stdint.h>

#define MMIO32(address) (*(volatile uint32_t *)(uintptr_t)(address))

/* TRNG standalone peripheral registers (rtl/lms_trng_mmio.v). */
#define TRNG_BASE     0x17000000u
#define TRNG_VERSION  (TRNG_BASE + 0x00u)
#define TRNG_CAP      (TRNG_BASE + 0x04u)
#define TRNG_CTRL     (TRNG_BASE + 0x08u)
#define TRNG_STAT     (TRNG_BASE + 0x0cu)
#define TRNG_RND      (TRNG_BASE + 0x10u)
#define TRNG_CTRL_ENABLE 1u
#define TRNG_STAT_HEALTH_FAIL 1u
#define TRNG_STAT_WORD_VALID  (1u << 8)

/* LMS hash accelerator (HASH_ONCE conditioning target; platform decided by HASH_IMPL). */
#define LMS_BASE          0x16000000u
#define LMS_COMMAND       (LMS_BASE + 0x008u)
#define LMS_CONTROL       (LMS_BASE + 0x00cu)
#define LMS_STATUS        (LMS_BASE + 0x010u)
#define LMS_ERROR         (LMS_BASE + 0x014u)
#define LMS_INPUT_LENGTH  (LMS_BASE + 0x018u)
#define LMS_OUTPUT_LENGTH (LMS_BASE + 0x01cu)
#define LMS_INPUT         (LMS_BASE + 0x100u)
#define LMS_OUTPUT        (LMS_BASE + 0x200u)
#define LMS_CMD_HASH_ONCE 1u
#define LMS_CTRL_START    1u
#define LMS_CTRL_CLEAR    2u
#define LMS_STATUS_BUSY   1u
#define LMS_STATUS_DONE   2u

#ifndef LMS_RND_TRNG_COND
#define LMS_RND_TRNG_COND 2u
#endif

/* Global TRNG health-fault flag: once set, lms_rnd*() returns 0; used for gating queries. */
volatile uint32_t trng_fault;

/* Tier-2 conditioning buffer: one HASH_ONCE round yields 32B (8 x 32bit words), consumed word by word. */
static uint8_t cond_buf[32];
static uint32_t cond_avail; /* remaining available words (0..8) */

/* Read one 32bit raw random word; on health_fail set trng_fault and return 0. */
static uint32_t trng_raw_word(void)
{
    uint32_t stat = MMIO32(TRNG_STAT);
    if ((stat & TRNG_STAT_HEALTH_FAIL) != 0u) {
        trng_fault = 1u;
        return 0u;
    }
    /* Wait for a valid word (TRNG free-runs, usually already ready). */
    while ((stat & TRNG_STAT_WORD_VALID) == 0u) {
        stat = MMIO32(TRNG_STAT);
        if ((stat & TRNG_STAT_HEALTH_FAIL) != 0u) {
            trng_fault = 1u;
            return 0u;
        }
    }
    return MMIO32(TRNG_RND);
}

/* Tier 2: one round of SHA-256 conditioning - 16 words (512bit) raw -> HASH_ONCE -> 256bit. */
static void trng_cond_refill(void)
{
    uint32_t index;

    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
    MMIO32(LMS_INPUT_LENGTH) = 64u;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    for (index = 0u; index < 16u; index++) {
        MMIO32(LMS_INPUT + index * 4u) = trng_raw_word();
    }
    if (trng_fault != 0u) {
        memset(cond_buf, 0, sizeof(cond_buf));
        cond_avail = 0u;
        return;
    }
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    if (MMIO32(LMS_STATUS) != LMS_STATUS_DONE || MMIO32(LMS_ERROR) != 0u) {
        trng_fault = 1u;
        memset(cond_buf, 0, sizeof(cond_buf));
        cond_avail = 0u;
        return;
    }
    for (index = 0u; index < 8u; index++) {
        uint32_t word = MMIO32(LMS_OUTPUT + index * 4u);
        cond_buf[index * 4u] = (uint8_t)word;
        cond_buf[index * 4u + 1u] = (uint8_t)(word >> 8);
        cond_buf[index * 4u + 2u] = (uint8_t)(word >> 16);
        cond_buf[index * 4u + 3u] = (uint8_t)(word >> 24);
    }
    cond_avail = 8u;
}

/* Tier 1: read raw words directly (characterization). Unused under default tier 2; kept for characterization builds. */
static uint32_t trng_direct_word(void) __attribute__((unused));
static uint32_t trng_direct_word(void)
{
    return trng_raw_word();
}

uint32_t lms_rnd32(void)
{
    if (trng_fault != 0u) {
        return 0u;
    }
#if LMS_RND_TRNG_COND == 1u
    return trng_direct_word();
#else
    {
        uint32_t used;
        uint32_t word;
        if (cond_avail == 0u) {
            trng_cond_refill();
            if (cond_avail == 0u) {
                return 0u;
            }
        }
        used = 8u - cond_avail;
        word = (uint32_t)cond_buf[used * 4u] |
               ((uint32_t)cond_buf[used * 4u + 1u] << 8) |
               ((uint32_t)cond_buf[used * 4u + 2u] << 16) |
               ((uint32_t)cond_buf[used * 4u + 3u] << 24);
        cond_avail--;
        return word;
    }
#endif
}

void lms_rnd(uint8_t *out, size_t len)
{
    size_t i;
    uint32_t word = 0u;

    for (i = 0u; i < len; i++) {
        if ((i & 3u) == 0u) {
            word = lms_rnd32();
        } else {
            word >>= 8;
        }
        out[i] = (uint8_t)word;
    }
}

/* No deterministic seed context under implementation C (the det-only interface is a no-op here). */
void lms_rnd_det_seed(const uint8_t *ctx, size_t len)
{
    (void)ctx;
    (void)len;
}
