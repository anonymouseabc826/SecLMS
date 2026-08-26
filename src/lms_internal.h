#ifndef LMS_INTERNAL_H
#define LMS_INTERNAL_H

#include "lms.h"

#include "hash_api.h"

#include <stddef.h>
#include <stdint.h>

/* REVIEW B03-R6: this library is not thread-safe (static mutable state such as
 * parameter-table cache/backend injection/Haraka init is unlocked); callers
 * must guarantee single-threaded use (PC/firmware are both single-threaded today). */

typedef struct {
    uint32_t type;
    lms_hash_alg_t hash_alg;
    uint32_t height;
    uint32_t n;
} lms_param_t;

typedef struct {
    uint32_t type;
    lms_hash_alg_t hash_alg;
    uint32_t n;
    uint32_t w;
    uint32_t p;
    uint32_t ls;
} lmots_param_t;

typedef struct {
    uint64_t calls;
    uint64_t steps;
} lmots_chain_stats_t;

typedef int (*lmots_chain_backend_fn)(void *context,
                                      const uint8_t I[LMS_I_LEN],
                                      lms_hash_alg_t hash_alg,
                                      uint32_t q,
                                      uint32_t i,
                                      uint32_t start,
                                      uint32_t steps,
                                      uint8_t value[LMS_N]);

/* REVIEW B03-R10: the following five backend typedefs have unified indentation
 * (previously drifted indentation from incremental multi-round edits). */
typedef int (*lmots_derive_chain_backend_fn)(void *context,
                                             const uint8_t I[LMS_I_LEN],
                                             lms_hash_alg_t hash_alg,
                                             uint32_t q,
                                             uint32_t i,
                                             uint32_t start,
                                             uint32_t steps,
                                             uint8_t output[LMS_N]);

typedef int (*lmots_randomizer_backend_fn)(void *context,
                                           const uint8_t I[LMS_I_LEN],
                                           lms_hash_alg_t hash_alg,
                                           uint32_t q,
                                           uint8_t output[LMS_N]);

typedef int (*lmots_keygen_backend_fn)(void *context,
                                       const uint8_t I[LMS_I_LEN],
                                       lms_hash_alg_t hash_alg,
                                       uint32_t q,
                                       uint32_t lmots_type,
                                       uint8_t output[LMS_N]);

typedef int (*lmots_sign_backend_fn)(void *context,
                                     const uint8_t I[LMS_I_LEN],
                                     lms_hash_alg_t hash_alg,
                                     uint32_t q,
                                     uint32_t lmots_type,
                                     const uint8_t *coefficients,
                                     uint8_t *outputs);

typedef int (*lmots_verify_backend_fn)(void *context,
                                       const uint8_t I[LMS_I_LEN],
                                       lms_hash_alg_t hash_alg,
                                       uint32_t q,
                                       uint32_t lmots_type,
                                       const uint8_t *coefficients,
                                       const uint8_t *inputs,
                                       uint8_t output[LMS_N]);

/* VERIFY_LEAF backend: after signature-chain verification yields K_q, the
 * hardware internally continues with D_LEAF = H(I||node_num||D_LEAF||K_q) and
 * outputs only the leaf node (one MMIO). When registered, lms_verify's
 * ots_pub + D_LEAF steps merge into a single hardware interaction. */
typedef int (*lmots_verify_leaf_backend_fn)(void *context,
                                            const uint8_t I[LMS_I_LEN],
                                            lms_hash_alg_t hash_alg,
                                            uint32_t q,
                                            uint32_t lmots_type,
                                            const uint8_t *coefficients,
                                            const uint8_t *inputs,
                                            uint32_t node_num,
                                            uint8_t leaf[LMS_N]);

/* D_INTR backend: computes D_INTR = H(I||node_num||D_INTR||left||right) directly,
 * replacing lms_internal_node's software SHA-256, for hardware HASH_ONCE
 * acceleration. Once registered, all Merkle-tree internal nodes in
 * KeyGen/Sign/Verify go through hardware. */
typedef int (*lms_intr_backend_fn)(void *context,
                                    const uint8_t I[LMS_I_LEN],
                                    lms_hash_alg_t hash_alg,
                                    uint32_t node_num,
                                    const uint8_t left[LMS_N],
                                    const uint8_t right[LMS_N],
                                    uint8_t out[LMS_N]);

/* Verify auth-path backend: runs N consecutive D_INTR levels from the leaf plus
 * the sibling sequence (path, h of them from leaf to root) up to the root,
 * replacing lms_root_from_signature's per-level lms_internal_node (one MMIO
 * interaction each). Uses the hardware chained D_INTR primitive
 * (CMD_D_INTR_CHAIN) to complete the auth path in one shot (Verify hot path).
 * OTSL/LMS semantic layering: VERIFY_LEAF handles OTS->leaf, this backend
 * handles the LMS tree hash chain; root comparison is still done in software
 * (lms_verify). NULL falls back to the current per-level behavior. */
typedef int (*lms_verify_authpath_backend_fn)(void *context,
    const uint8_t I[LMS_I_LEN], lms_hash_alg_t hash_alg,
    uint32_t node_num,              /* leaf's whole-tree node number (2^h+q) */
    const uint8_t leaf[LMS_N],      /* leaf D_LEAF */
    const uint8_t *path,            /* sibling sequence (height x LMS_N) */
    uint32_t height,
    uint8_t root[LMS_N]);

/* Message-hash backend: H(Q||C||message) replaces software SHA-256.
 * Threshold: prefix(I+q+D_MESG+C)=54B, RTL MAX_INPUT=128B, so message_len <= 74
 * uses HASH_ONCE, otherwise falls back to software. Once registered, the
 * message hash in lmots_sign/lmots_public_from_signature goes through the backend. */
typedef int (*lmots_message_hash_backend_fn)(void *context,
                                              const uint8_t I[LMS_I_LEN],
                                              lms_hash_alg_t hash_alg,
                                              uint32_t q,
                                              const uint8_t C[LMS_N],
                                              const uint8_t *message,
                                              size_t message_len,
                                              uint8_t Q[LMS_N + 2]);

/* Coefficients backend (CMD_MSG_Q_COEF hardware): one call yields Q + p
 * coefficients (superset incl. message hash); registered backends let
 * lmots_sign/lmots_public_from_signature/lmots_verify_leaf skip the software
 * checksum/coef loops (Q and coefficients both filled); non-LMS_OK -> software
 * fallback at the algorithm layer. */
typedef int (*lmots_coef_backend_fn)(void *context,
                                      const uint8_t I[LMS_I_LEN],
                                      lms_hash_alg_t hash_alg,
                                      uint32_t q,
                                      const uint8_t C[LMS_N],
                                      const uint8_t *message,
                                      size_t message_len,
                                      uint32_t lmots_type,
                                      uint8_t Q[LMS_N],
                                      uint8_t coefficients[LMS_MAX_OTS_P]);

/* Auth-path backend (design doc step 5): produces leaf q's auth path (h siblings
 * from leaf to root, h*n bytes, same order as the RFC 8554 signature path).
 * When registered, lms_do_sign uses it instead of the default lms_tree_node
 * recursive rebuild (Sign's slow root cause); NULL falls back to the current
 * behavior. Implementations may use the lms_subtree cache
 * (sign_advance+sign_auth_path) for lookup, O(h) with zero recomputation. */
typedef int (*lms_auth_path_backend_fn)(void *context,
                                        const lms_private_key_t *priv,
                                        uint32_t q,
                                        uint8_t *path);

#define D_MESG 0x8181u
#define D_PBLC 0x8080u
#define D_LEAF 0x8282u
#define D_INTR 0x8383u
#define LMOTS_C_PRG_DOMAIN 0x8585u

void lms_store_u16(uint8_t out[2], uint16_t value);
void lms_store_u32(uint8_t out[4], uint32_t value);
uint32_t lms_load_u32(const uint8_t in[4]);

int lms_get_lms_param(uint32_t type, lms_param_t *param);
int lms_get_lmots_param(uint32_t type, lmots_param_t *param);
int lms_get_private_hash_alg(const lms_private_key_t *priv, lms_hash_alg_t *hash_alg);
int lms_get_public_hash_alg(const lms_public_key_t *pub, lms_hash_alg_t *hash_alg);
size_t lms_signature_len(uint32_t lms_type, uint32_t lmots_type);

uint32_t lms_lmots_coef(const uint8_t *data, uint32_t i, uint32_t w);
uint32_t lms_lmots_checksum(const uint8_t *Q, uint32_t Q_len, uint32_t w, uint32_t ls);
int lms_hash_parts(const uint8_t *a, size_t a_len,
                   const uint8_t *b, size_t b_len,
                   const uint8_t *c, size_t c_len,
                   const uint8_t *d, size_t d_len,
                   lms_hash_alg_t hash_alg,
                   uint8_t out[LMS_N]);

int lmots_public_from_private(const lms_private_key_t *priv,
                              uint32_t q,
                              uint8_t pub[LMS_N]);
int lmots_private_value(const lms_private_key_t *priv,
                        uint32_t q,
                        uint32_t i,
                        uint8_t out[LMS_N]);
int lmots_public_from_signature(const uint8_t I[LMS_I_LEN],
                                lms_hash_alg_t hash_alg,
                                uint32_t q,
                                uint32_t expected_type,
                                const uint8_t *message,
                                size_t message_len,
                                const uint8_t *signature,
                                size_t signature_len,
                                uint8_t pub[LMS_N]);
int lmots_verify_leaf(const uint8_t I[LMS_I_LEN],
                      lms_hash_alg_t hash_alg,
                      uint32_t q,
                      uint32_t expected_type,
                      uint32_t node_num,
                      const uint8_t *message,
                      size_t message_len,
                      const uint8_t *signature,
                      size_t signature_len,
                      uint8_t leaf[LMS_N]);
int lmots_chain_compute(const uint8_t I[LMS_I_LEN],
                        lms_hash_alg_t hash_alg,
                        uint32_t q,
                        uint32_t i,
                        uint32_t start,
                        uint32_t steps,
                        uint8_t value[LMS_N]);
void lmots_keygen_chain_backend_set(lmots_chain_backend_fn backend, void *context);
void lmots_verify_chain_backend_set(lmots_chain_backend_fn backend, void *context);
void lmots_sign_chain_backend_set(lmots_chain_backend_fn backend, void *context);
void lmots_keygen_derive_backend_set(lmots_derive_chain_backend_fn backend, void *context);
void lmots_keygen_backend_set(lmots_keygen_backend_fn backend, void *context);
void lmots_sign_backend_set(lmots_sign_backend_fn backend, void *context);
void lmots_verify_backend_set(lmots_verify_backend_fn backend, void *context);
void lmots_verify_leaf_backend_set(lmots_verify_leaf_backend_fn backend, void *context);
void lmots_sign_derive_backend_set(lmots_derive_chain_backend_fn backend, void *context);
void lmots_sign_randomizer_backend_set(lmots_randomizer_backend_fn backend, void *context);
/* Register/unregister the auth-path backend (design doc step 5). backend==NULL
 * falls back to default recursion. */
void lms_auth_path_backend_set(lms_auth_path_backend_fn backend, void *context);
void lms_intr_backend_set(lms_intr_backend_fn backend, void *context);
/* REVIEW B03-R8: intr_backend is now a file-local static in lm_ots.c, accessed
 * only via the setter + available/run (aligned with the other backends'
 * "static + setter" encapsulation pattern). */
int lms_intr_backend_available(void);
int lms_intr_backend_run(const uint8_t I[LMS_I_LEN], lms_hash_alg_t hash_alg,
                         uint32_t node_num, const uint8_t left[LMS_N],
                         const uint8_t right[LMS_N], uint8_t out[LMS_N]);
void lms_verify_authpath_backend_set(lms_verify_authpath_backend_fn backend, void *context);
void lmots_message_hash_backend_set(lmots_message_hash_backend_fn backend, void *context);
void lmots_coef_backend_set(lmots_coef_backend_fn backend, void *context);
int lmots_sign(const lms_private_key_t *priv,
               uint32_t q,
               const uint8_t *message,
               size_t message_len,
               uint8_t *signature,
               size_t signature_len);
/* UART bridge task-RAM resident (Step 3) prepare: compute Sign's randomizer C
 * and Winternitz coefficients; signature y stays in task RAM to be read out by
 * the SoC-layer UART passthrough bridge (with lms_mmio_lmots_sign_taskram). */
int lmots_sign_prepare(const lms_private_key_t *priv,
                       uint32_t q,
                       const uint8_t *message,
                       size_t message_len,
                       uint8_t C[LMS_N],
                       uint8_t coefficients[LMS_MAX_OTS_P]);
/* UART bridge prepare: firmware reads Verify's C from the signature (type+C)
 * and computes Winternitz coefficients; signature y has already been written
 * to task RAM by the UART passthrough bridge (with
 * lms_mmio_lmots_verify_taskram). */
int lmots_public_from_signature_prepare(const uint8_t I[LMS_I_LEN],
                                        lms_hash_alg_t hash_alg,
                                        uint32_t q,
                                        uint32_t expected_type,
                                        const uint8_t *message,
                                        size_t message_len,
                                        const uint8_t C[LMS_N],
                                        uint8_t coefficients[LMS_MAX_OTS_P]);
void lmots_chain_stats_reset(void);
void lmots_chain_stats_get(lmots_chain_stats_t *stats);

int lms_tree_node(const lms_private_key_t *priv,
                  uint32_t node_num,
                  uint8_t out[LMS_N]);
int lms_internal_node(const uint8_t I[LMS_I_LEN],
                      lms_hash_alg_t hash_alg,
                      uint32_t node_num,
                      const uint8_t left[LMS_N],
                      const uint8_t right[LMS_N],
                      uint8_t out[LMS_N]);
int lms_root_from_signature(const lms_public_key_t *pub,
                            const uint8_t *message,
                            size_t message_len,
                            const uint8_t *signature,
                            size_t signature_len,
                            uint8_t root[LMS_N]);

int lms_do_sign(lms_private_key_t *priv,
                const uint8_t *message,
                size_t message_len,
                uint8_t *signature,
                size_t signature_len,
                size_t *written);

#endif