/*
 * SecLMS soft-core classic algorithm benchmark firmware (Ibex RV32IMC SoC, same platform as the LMS firmware)
 *
 * Purpose: cycles benchmark of RSA-2048 / ECDSA P-256 on the **same soft core** (Ibex RV32IMC,
 * riscv64-unknown-elf-gcc -march=rv32imc -O2, no hand tuning), compared against SecLMS
 * hardware/LMS pure-software (data support for the paper Motivation "LMS's favorable trade-offs
 * relative to RSA/ECC"). Crypto ops live in bench/bench_crypto.c (mbedTLS 2.28.9 trimmed,
 * external checkout).
 *
 * UART protocol (115200, same registers as the LMS firmware):
 *   Request: 1B command
 *     0x53 'S'  SHA-256 (64B fixed message) -> smoke test
 *     0x52 'R'  RSA-2048 PKCS#1 v1.5 SHA-256 sign
 *     0x56 'V'  RSA-2048 verify (then receive 256B signature)
 *     0x45 'E'  ECDSA P-256 sign (RFC 6979 deterministic nonce)
 *     0x44 'D'  ECDSA P-256 verify (then receive 1B length + DER signature)
 *   Response: 0x52 + status(1B: 0=OK/1=op failed/2=init failed) + cycles(4B LE) +
 *     payload ('S'=32B digest; 'R'=256B sig; 'E'=1B len+DER sig; 'V'/'D'=none)
 *   Timing: SOC_CYCLE_COUNT (0x10000010, same basis as the LMS board test, covers the whole op flow).
 *   Message: fixed 64B (bytes 0x00..0x3f), the host independently verifies with the same constant.
 */
#include "bench_crypto.h"

#include <stddef.h>
#include <stdint.h>

#define MMIO32(address) (*(volatile uint32_t *)(uintptr_t)(address))

#define UART_TX         0x10000000u
#define UART_TX_READY   0x10000004u
#define UART_RX         0x10000008u
#define UART_RX_READY   0x1000000cu
#define SOC_CYCLE_COUNT 0x10000010u
#define GPIO_OUT        0x10000018u   /* debug-stage marker (for smoke/board-test diagnostics): 0x01=main entered,
                                       0x02=key parsing done, 0xa5=command loop ready */

#define BENCH_RESPONSE  0x52u
#define BENCH_CMD_SHA   0x53u   /* 'S' */
#define BENCH_CMD_RSA_SIGN   0x52u  /* 'R' */
#define BENCH_CMD_RSA_VERIFY 0x56u  /* 'V' */
#define BENCH_CMD_EC_SIGN    0x45u  /* 'E' */
#define BENCH_CMD_EC_VERIFY  0x44u  /* 'D' */

static uint8_t g_msg[BENCH_MSG_LEN];

static uint8_t uart_getc(void)
{
    while (MMIO32(UART_RX_READY) == 0u) {
    }
    {
        uint8_t value = (uint8_t)MMIO32(UART_RX);
        /* 0.1.282: double-delivery dedup -- the board-level CW305 USB-UART path occasionally
         * delivers the same byte twice (measured: after a single write the firmware processed
         * 'S' twice -> double response, 76B). Right after reading, drain any **already pending**
         * duplicate byte (both copies sit in the FIFO on double delivery). Before ack takes
         * effect rdy may briefly stay 1, so distinguish "ack not yet in effect" from "duplicate
         * byte": reading once more discards the duplicate. */
        while (MMIO32(UART_RX_READY) != 0u) {
            /* wait for ack to take effect (rdy cleared) -- if rdy is set again by a duplicate byte, discard it this round */
            (void)MMIO32(UART_RX);
        }
        return value;
    }
}

static void uart_putc(uint8_t value)
{
    while (MMIO32(UART_TX_READY) == 0u) {
    }
    MMIO32(UART_TX) = value;
}

static void uart_put_u32(uint32_t value)
{
    uart_putc((uint8_t)value);
    uart_putc((uint8_t)(value >> 8));
    uart_putc((uint8_t)(value >> 16));
    uart_putc((uint8_t)(value >> 24));
}

/* Response frame: marker + status + cycles + payload */
static void respond(uint8_t status, uint32_t cycles)
{
    uart_putc(BENCH_RESPONSE);
    uart_putc(status);
    uart_put_u32(cycles);
}

int main(void)
{
    uint8_t cmd;
    uint32_t t0;
    uint32_t t1;
    int rc;
    int init_rc;

    for (size_t i = 0; i < BENCH_MSG_LEN; i++) {
        g_msg[i] = (uint8_t)i;
    }
    MMIO32(GPIO_OUT) = 0x01u;   /* main entered */
    init_rc = bench_crypto_init();
    MMIO32(GPIO_OUT) = 0x02u;   /* key parsing done (or failed) */

    for (;;) {
        MMIO32(GPIO_OUT) = 0xa5u;   /* command loop ready (set each round, diagnostic) */
        cmd = uart_getc();   /* double-delivery dedup happens inside uart_getc (drains concurrently pending duplicates after reading) */
        switch (cmd) {
        case BENCH_CMD_SHA: {
            uint8_t digest[32];
            t0 = MMIO32(SOC_CYCLE_COUNT);
            bench_sha256(g_msg, digest);
            t1 = MMIO32(SOC_CYCLE_COUNT);
            respond(init_rc == 0 ? 0u : 2u, t1 - t0);
            for (size_t i = 0; i < 32; i++) {
                uart_putc(digest[i]);
            }
            break;
        }
        case BENCH_CMD_RSA_SIGN: {
            uint8_t sig[256];
            t0 = MMIO32(SOC_CYCLE_COUNT);
            rc = bench_rsa_sign(g_msg, sig);
            t1 = MMIO32(SOC_CYCLE_COUNT);
            respond(init_rc != 0 ? 2u : (rc == 0 ? 0u : 1u), t1 - t0);
            for (size_t i = 0; i < 256; i++) {
                uart_putc(sig[i]);
            }
            break;
        }
        case BENCH_CMD_RSA_VERIFY: {
            uint8_t sig[256];
            for (size_t i = 0; i < 256; i++) {
                sig[i] = uart_getc();
            }
            t0 = MMIO32(SOC_CYCLE_COUNT);
            rc = bench_rsa_verify(g_msg, sig);
            t1 = MMIO32(SOC_CYCLE_COUNT);
            respond(init_rc != 0 ? 2u : (rc == 0 ? 0u : 1u), t1 - t0);
            break;
        }
        case BENCH_CMD_EC_SIGN: {
            uint8_t sig[80];
            size_t sig_len = 0u;
            t0 = MMIO32(SOC_CYCLE_COUNT);
            rc = bench_ecdsa_sign(g_msg, sig, sizeof(sig), &sig_len);
            t1 = MMIO32(SOC_CYCLE_COUNT);
            respond(init_rc != 0 ? 2u : (rc == 0 ? 0u : 1u), t1 - t0);
            if (rc == 0) {
                uart_putc((uint8_t)sig_len);
                for (size_t i = 0; i < sig_len; i++) {
                    uart_putc(sig[i]);
                }
            }
            break;
        }
        case BENCH_CMD_EC_VERIFY: {
            uint8_t sig[80];
            size_t sig_len = (size_t)uart_getc();
            if (sig_len > sizeof(sig)) {
                sig_len = sizeof(sig);
            }
            for (size_t i = 0; i < sig_len; i++) {
                sig[i] = uart_getc();
            }
            t0 = MMIO32(SOC_CYCLE_COUNT);
            rc = bench_ecdsa_verify(g_msg, sig, sig_len);
            t1 = MMIO32(SOC_CYCLE_COUNT);
            respond(init_rc != 0 ? 2u : (rc == 0 ? 0u : 1u), t1 - t0);
            break;
        }
        default:
            /* Unknown command: single-byte error response, prevents the host from waiting forever */
            uart_putc(BENCH_RESPONSE);
            uart_putc(3u);
            uart_put_u32(0u);
            break;
        }
    }
}
