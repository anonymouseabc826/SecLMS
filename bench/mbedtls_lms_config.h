/**
 * \file mbedtls_lms_config.h
 *
 * \brief SecLMS soft-core benchmark minimal config (RSA-2048 + ECDSA P-256, no TLS/no entropy source)
 *
 * Purpose: same-platform benchmark of the classic algorithms (RSA/ECDSA) vs LMS on the Ibex RV32IMC SoC
 * (data support for the paper Motivation "LMS's favorable trade-offs relative to RSA/ECC").
 * - Benchmark target: mbedTLS 2.28.9 (external checkout, Apache-2.0 OR GPL-2.0-or-later;
 *   this project adopts Apache-2.0, NOTICE attribution)
 * - Trimmed to: RSA (PKCS#1 v1.5) + ECP P-256 + ECDSA (deterministic nonce) + SHA-256 only;
 *   no TLS/no entropy/no filesystem/no time.
 * - Memory: mbedtls_calloc/free macros hook directly to the bare-metal implementation
 *   (the bump/first-fit allocator in fw/lms_bench.c), bypassing libc (SoC firmware -nostdlib).
 * - Build: same toolchain as the LMS firmware (riscv64-unknown-elf-gcc -march=rv32imc -O2), no hand tuning.
 */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ---- Modules ----
 * RSA/ECDSA functional chain: bignum -> rsa/ecp/ecdsa -> pk/pk_parse (PEM/DER parsing of the embedded test keys)
 * -> md/sha256 (PKCS#1 v1.5 DigestInfo and det-ECDSA's HMAC_DRBG). */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDSA_DETERMINISTIC   /* mbedtls_ecdsa_sign_det_ext (RFC 6979 deterministic nonce, reproducible) */
#define MBEDTLS_HMAC_DRBG_C           /* used internally by det-ECDSA */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C

/* ---- Curves/parameters ---- */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_WINDOW_SIZE 4
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 1

/* ---- Big-number limits (RSA-2048 modulus 256B; the default 1024 suffices, keep it to guard boundaries) ---- */
#define MBEDTLS_MPI_MAX_SIZE 1024

/* ---- Platform: bare metal, no time/asm ---- */
/* MBEDTLS_PLATFORM_C: required by check_config on Windows; without PLATFORM_MEMORY defined,
 * platform.h still maps the mbedtls_calloc/free macros to calloc/free (the firmware provides the bare-metal implementation). */
#define MBEDTLS_PLATFORM_C
/* (MBEDTLS_HAVE_TIME / MBEDTLS_HAVE_ASM are not defined) */

/* RSA blinding needs an RNG: the firmware provides xorshift (deterministic seed; the blinding
 * factor is public, not secret); ECDSA takes the det path and consumes no RNG. */

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
