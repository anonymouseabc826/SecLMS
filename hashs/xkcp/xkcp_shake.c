/* Minimal SHAKE256 adapter over XKCP KeccakP-1600-inplace32BI (SnP interface).
 * SHAKE256 rate = 136 bytes; domain padding 0x1F ... 0x80.
 * Independent of SimpleFIPS202/KeccakHash (avoids extra XKCP files).
 * Absorb + padding use XOR semantics (AddBytes/AddByte), matching the reference
 * sponge: multi-block inputs keep the previous permuted rate-region as the XOR
 * basis, and the 0x1F/0x80 overlap at rem==rate-1 becomes 0x9F automatically. */
#include <stddef.h>
#include <stdint.h>
#include "KeccakP-1600-SnP.h"

#define XKCP_SHAKE256_RATE 136u

void xkcp_shake256(uint8_t *out, size_t outlen,
                   const uint8_t *in, size_t inlen)
{
    KeccakP1600_state st;
    size_t full = inlen / XKCP_SHAKE256_RATE;
    size_t rem = inlen % XKCP_SHAKE256_RATE;
    size_t i;

    KeccakP1600_Initialize(&st);
    /* absorb full rate-blocks (XOR + permute) */
    for (i = 0; i < full; i++) {
        KeccakP1600_AddBytes(&st, in + i * XKCP_SHAKE256_RATE, 0, XKCP_SHAKE256_RATE);
        KeccakP1600_Permute_24rounds(&st);
    }
    /* remaining data + SHAKE padding, all XOR'd into the state */
    if (rem)
        KeccakP1600_AddBytes(&st, in + full * XKCP_SHAKE256_RATE, 0, (unsigned int)rem);
    KeccakP1600_AddByte(&st, 0x1Fu, (unsigned int)rem);
    KeccakP1600_AddByte(&st, 0x80u, (unsigned int)(XKCP_SHAKE256_RATE - 1));
    KeccakP1600_Permute_24rounds(&st);
    /* squeeze */
    while (outlen > XKCP_SHAKE256_RATE) {
        KeccakP1600_ExtractBytes(&st, out, 0, XKCP_SHAKE256_RATE);
        KeccakP1600_Permute_24rounds(&st);
        out += XKCP_SHAKE256_RATE;
        outlen -= XKCP_SHAKE256_RATE;
    }
    KeccakP1600_ExtractBytes(&st, out, 0, (unsigned int)outlen);
}
