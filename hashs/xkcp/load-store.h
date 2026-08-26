/* Minimal load-store.h equivalent for XKCP KeccakP-1600-inplace32BI.c
 * (XKCP original lives at lib/low/common/load-store.h; only XKCP_load32 /
 * XKCP_store32 are needed by the inplace32BI permutation). Little-endian. */
#ifndef XKCP_LOAD_STORE_H
#define XKCP_LOAD_STORE_H

#include <stdint.h>

static uint32_t XKCP_load32(const uint8_t *x)
{
    return (uint32_t)x[0] | ((uint32_t)x[1] << 8) |
           ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
}

static void XKCP_store32(uint8_t *x, uint32_t u)
{
    x[0] = (uint8_t)u;
    x[1] = (uint8_t)(u >> 8);
    x[2] = (uint8_t)(u >> 16);
    x[3] = (uint8_t)(u >> 24);
}

#endif /* XKCP_LOAD_STORE_H */
