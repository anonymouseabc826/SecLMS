#ifndef XKCP_SHAKE_H
#define XKCP_SHAKE_H

#include <stddef.h>
#include <stdint.h>

void xkcp_shake256(uint8_t *out, size_t outlen,
                   const uint8_t *in, size_t inlen);

#endif /* XKCP_SHAKE_H */
