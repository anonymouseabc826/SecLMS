#ifndef BENCH_CRYPTO_H
#define BENCH_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* SecLMS soft-core classic algorithm benchmark core (platform-independent, PC-verifiable):
 * wraps mbedTLS 2.28.9 (Apache-2.0) RSA-2048 / ECDSA P-256 operations,
 * shared by the SoC firmware (fw/lms_bench.c) and the PC self-check (bench/bench_native_check.c). */

/* Fixed benchmark message (64B, bytes 0x00..0x3f; firmware and host share the same constant) */
#define BENCH_MSG_LEN 64u

/* One-time init: parse the embedded RSA-2048 / EC P-256 private keys (static allocation, parsed once).
 * Returns 0 on success; non-zero on failure (negated mbedTLS error code). */
int bench_crypto_init(void);

/* SHA-256: msg[64] -> digest[32] */
void bench_sha256(const uint8_t msg[BENCH_MSG_LEN], uint8_t digest[32]);

/* RSA-2048 PKCS#1 v1.5 SHA-256 sign: msg -> sig[256] (raw big-endian). Returns 0 on success. */
int bench_rsa_sign(const uint8_t msg[BENCH_MSG_LEN], uint8_t sig[256]);

/* RSA-2048 PKCS#1 v1.5 SHA-256 verify: msg + sig[256]. Returns 0 = verify passed. */
int bench_rsa_verify(const uint8_t msg[BENCH_MSG_LEN], const uint8_t sig[256]);

/* ECDSA P-256 SHA-256 sign (RFC 6979 deterministic nonce): msg -> DER signature.
 * sig_buf has capacity *sig_cap; on success *sig_len holds the actual DER length. Returns 0 on success. */
int bench_ecdsa_sign(const uint8_t msg[BENCH_MSG_LEN], uint8_t *sig_buf,
                     size_t sig_cap, size_t *sig_len);

/* ECDSA P-256 SHA-256 verify (DER). Returns 0 = verify passed. */
int bench_ecdsa_verify(const uint8_t msg[BENCH_MSG_LEN], const uint8_t *sig,
                       size_t sig_len);

/* RSA blinding RNG callback (deterministic xorshift; the blinding factor is public, so a
 * fixed seed does not affect security and ensures reproducible measurements across runs). */
int bench_rng(void *ctx, unsigned char *out, size_t len);

#endif /* BENCH_CRYPTO_H */
