#ifndef LMS_HASH_API_H
#define LMS_HASH_API_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    LMS_HASH_SHA256 = 1,
    LMS_HASH_SHAKE256 = 2,
    LMS_HASH_HARAKA = 3
} lms_hash_alg_t;

/* Unified hash interface. LMS internally always calls with output_len = LMS_N (32).
 * output_len contract (REVIEW B03-R7/B04-R5): SHA-256 rejects > 32; Haraka
 * requires == 32; SHAKE256 is an XOF and does not validate (squeezes any
 * length). Callers needing a fixed length must validate it themselves. Thread
 * safety (REVIEW B03-R6): not thread-safe; callers must guarantee single-threaded
 * use (Haraka tweak is global state). */
int lms_hash(lms_hash_alg_t alg,
             const uint8_t *input,
             size_t input_len,
             uint8_t *output,
             size_t output_len);

#endif