/* PC timer: wall time of the same bench_crypto (mbedTLS 2.28.9 trimmed config) on x86,
 * cross-validated against the official mbedTLS benchmark (P-256 sign 2121/s, verify 612/s)
 * to confirm the config has no regression.
 * Usage: compile like bench_native_check (BENCH_NATIVE + libc), repeat N times and average. */
#include "bench_crypto.h"

#include <stdio.h>
#include <time.h>

static uint8_t g_msg[BENCH_MSG_LEN];

static double bench_ms(int reps, int (*fn)(void))
{
    clock_t t0 = clock();
    for (int i = 0; i < reps; i++) {
        if (fn() != 0) {
            printf("op failed at rep %d\n", i);
            return -1.0;
        }
    }
    clock_t t1 = clock();
    return 1000.0 * (double)(t1 - t0) / CLOCKS_PER_SEC / reps;
}

static int do_rsa_sign(void) { uint8_t sig[256]; return bench_rsa_sign(g_msg, sig); }
static int do_rsa_verify(void)
{
    static uint8_t sig[256];
    static int done = 0;
    if (!done) { if (bench_rsa_sign(g_msg, sig) != 0) return -1; done = 1; }
    return bench_rsa_verify(g_msg, sig);
}
static int do_ec_sign(void)
{
    uint8_t sig[80]; size_t len;
    return bench_ecdsa_sign(g_msg, sig, sizeof(sig), &len);
}
static int do_ec_verify(void)
{
    static uint8_t sig[80];
    static size_t len;
    static int done = 0;
    if (!done) { if (bench_ecdsa_sign(g_msg, sig, sizeof(sig), &len) != 0) return -1; done = 1; }
    return bench_ecdsa_verify(g_msg, sig, len);
}

int main(void)
{
    for (size_t i = 0; i < BENCH_MSG_LEN; i++) g_msg[i] = (uint8_t)i;
    if (bench_crypto_init() != 0) { printf("init FAIL\n"); return 1; }

    double t;
    t = bench_ms(200, do_rsa_verify);  printf("RSA-2048 verify : %8.3f ms/op (%d ops/s)\n", t, (int)(1000.0/t));
    t = bench_ms(20, do_rsa_sign);     printf("RSA-2048 sign  : %8.3f ms/op (%d ops/s)\n", t, (int)(1000.0/t));
    t = bench_ms(50, do_ec_sign);      printf("ECDSA P-256 sign: %8.3f ms/op (%d ops/s)\n", t, (int)(1000.0/t));
    t = bench_ms(20, do_ec_verify);    printf("ECDSA P-256 ver : %8.3f ms/op (%d ops/s)\n", t, (int)(1000.0/t));
    return 0;
}
