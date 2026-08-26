/*
 * LMS random source abstraction interface (replaceable; see section 5)
 *
 * The algorithm/firmware layer only calls this interface, unaware of the random source;
 * the implementation is linked by compile-time selection:
 *   Implementation A: fw/lms_rnd_det.c  - deterministic derivation from the secret SEED/I/q
 *            (default; equivalent to the software baseline's C derivation, an "alternative
 *            unpredictable process" per RFC 8554), guaranteeing byte-identical KAT vectors.
 *   Implementation B: fw/lms_rnd_stub.c - fixed test vectors/simulation noise, interface validation only.
 *   Implementation C: fw/lms_rnd_trng.c - real TRNG (standalone MMIO peripheral 0x17000000,
 *            tier 2 SHA-256 conditioning default / tier 1 reads raw RND), SoC firmware
 *            only (not in the PC build). Makefile RND_IMPL=det|stub|trng selects.
 *
 * The C for current LMS chain batch tasks is still derived by v5 hardware from the internal SEED;
 * this interface first serves phase-3 security-state domains (device_epoch/key_epoch/I/SEED generation, etc.).
 */
#ifndef LMS_RND_H
#define LMS_RND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return a 4-byte random value */
uint32_t lms_rnd32(void);

/* Output len bytes of random data */
void lms_rnd(uint8_t *out, size_t len);

/* Implementation A only: set the deterministic derivation context from secret material;
 * impls B (stub) and C (TRNG) provide no-op empties (since 0.1.271, all three RND_IMPL
 * options link). When not seeded, lms_rnd*() returns 0, for misuse detection. */
void lms_rnd_det_seed(const uint8_t *ctx, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LMS_RND_H */
