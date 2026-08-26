#ifndef LMS_WORKSPACE_SHA256_H_
#define LMS_WORKSPACE_SHA256_H_

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_LEN 64u
#define SHA256_LEN 32u

typedef struct {
    uint32_t state[8];
    uint64_t bit_len;
    uint8_t buffer[SHA256_BLOCK_LEN];
    size_t buffer_len;
} SHA256_CTX;

void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const void *input, unsigned int input_len);
void SHA256_Final(unsigned char *output, SHA256_CTX *ctx);

#endif
