/*
 * Random source interface unit test (PC side).
 *
 * Verifies the replaceable interface (design spec §5):
 *  - Implementation A (deterministic derivation): unseeded output is 0; reproducible after
 *    seeding; consecutive values within the same session differ;
 *    lms_rnd() and lms_rnd32() have consistent byte order.
 *  - Interface abstraction: algorithms only call lms_rnd*(), unaware of the source (verified
 *    by linking this implementation or a stub at compile time).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "lms_rnd.h"

static int failures;

static void check(int condition, const char *message)
{
    if (!condition) {
        printf("FAIL: %s\n", message);
        failures++;
    }
}

int main(void)
{
    static const uint8_t ctx[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint32_t a;
    uint32_t b;
    uint8_t buf[20];

    /* Must output 0 when unseeded (detectable misuse) */
    check(lms_rnd32() == 0u, "unseeded lms_rnd32 must return 0");
    lms_rnd(buf, sizeof(buf));
    check(buf[0] == 0 && buf[sizeof(buf) - 1] == 0, "unseeded lms_rnd must return zeros");

    /* Reproducible after seeding */
    lms_rnd_det_seed(ctx, sizeof(ctx));
    a = lms_rnd32();
    b = lms_rnd32();
    check(a != 0u, "seeded first value non-zero");
    check(a != b, "consecutive values differ");

    lms_rnd_det_seed(ctx, sizeof(ctx));
    check(lms_rnd32() == a, "reseed reproduces first value");

    /* lms_rnd byte order matches lms_rnd32 (big-endian concatenation) */
    lms_rnd_det_seed(ctx, sizeof(ctx));
    lms_rnd(buf, sizeof(buf));
    check(buf[0] == (uint8_t)(a >> 24), "lms_rnd byte order matches lms_rnd32 (BE)");

    /* Different seeds produce different streams */
    {
        uint8_t other[16];
        uint32_t c;
        memcpy(other, ctx, sizeof(other));
        other[0] ^= 0xffu;
        lms_rnd_det_seed(ctx, sizeof(ctx));
        a = lms_rnd32();
        lms_rnd_det_seed(other, sizeof(other));
        c = lms_rnd32();
        check(a != c, "different seeds give different streams");
    }

    if (failures == 0) {
        puts("PASS: lms_rnd interface (deterministic impl A)");
        return 0;
    }
    printf("FAIL: %d check(s) failed\n", failures);
    return 1;
}
