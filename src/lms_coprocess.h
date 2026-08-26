#ifndef LMS_COPROCESS_H
#define LMS_COPROCESS_H

/*
 * ⚠️ Status note (2026-08-05): historical implementation of the H5 full-tree
 * special case (j=h degenerate); NO LONGER used on the runtime path -- firmware
 * tree cache and auth-path backends uniformly go through `lms_subtree`
 * (`src/lms_subtree.{h,c}`, generic subtree + incremental building). Kept only as the paper's H5 full-tree baseline;
 * do not extend it here, use lms_subtree.
 *
 * LMS-layer (Merkle tree) software/hardware co-processing pipeline (software side).
 *
 * Design baseline (decided 2026-07-30):
 *   - Hardware (RoT) computes at most up to the LM-OTS layer K_q / Y / K_v
 *     (D_PBLC pub-key candidates/chain values); never touches the tree layers
 *     (D_LEAF/D_INTR/building/auth path/T[1] comparison are all in software).
 *   - This module is the "software side" tree co-processing: via the injected
 *     K_q source it wires the hardware-produced LM-OTS public keys leaf by leaf
 *     into a Merkle tree (D_LEAF/D_INTR in software) and verifies the tree.
 *
 * Decoupling: no direct MMIO/hardware dependency. The K_q source is an
 * injectable callback (lms_coprocess_ots_pub_fn), defaulting to
 * lmots_public_from_private -- pure software while no backend is registered;
 * automatic hardware once lms_mmio_lmots_keygen_*_enable() registers the
 * hardware backend. The module is thus oblivious to software/hardware; the
 * upper layer just switches backends, this module stays unchanged.
 *
 * Does not modify any existing file in src/; only adds. No function changes
 * lms_private_key_t's q.
 */

#include "lms.h"

#include <stddef.h>
#include <stdint.h>

/* Memory budget: full Merkle tree of 2^(h+1)-1 n-byte nodes; only ~2 KiB when
 * fixed at H5. Upper bound at H10 (2047 nodes x 32B ≈ 64 KiB), enough to cover
 * the paper's parameter range and far below the cost of "putting the tree in
 * the FPGA" -- the tree stays on the software side (PC/host/large-RAM RV32 SoC). */
#define LMS_COPROCESS_MAX_HEIGHT 10u
#define LMS_COPROCESS_MAX_NODES ((1u << (LMS_COPROCESS_MAX_HEIGHT + 1u)) - 1u)

/* K_q source: LM-OTS public key (D_PBLC candidate) of leaf q, same semantics as
 * lmots_public_from_private; via MMIO through the backend in HW co-processing,
 * software chain in pure software. */
typedef int (*lms_coprocess_ots_pub_fn)(void *context,
                                        const lms_private_key_t *priv,
                                        uint32_t q,
                                        uint8_t ots_pub[LMS_N]);

typedef struct {
    uint32_t lms_type;    /* LMS parameter set (determines height/hash_alg) */
    uint32_t height;      /* h */
    uint32_t n;           /* hash output length in bytes (=LMS_N) */
    uint32_t leaf_count;  /* 2^h */
    uint8_t I[LMS_I_LEN]; /* key identifier */
    /* Full Merkle tree, 1-based: T[1]=root, T[2^h .. 2^(h+1)-1]=leaves; index 0
     * unused. Embeds 65,536B (H10 upper bound), test-only (REVIEW B03-R12):
     * the runtime path has been replaced by lms_subtree; this struct is only
     * for standalone tests and the H5 full-tree baseline; do not instantiate
     * on the stack/128KiB SoC. */
    uint8_t nodes[LMS_COPROCESS_MAX_NODES + 1u][LMS_N];
} lms_coprocess_tree_t;

/* Initialize the tree context (does not write nodes; building is done by build). */
int lms_coprocess_tree_init(lms_coprocess_tree_t *tree,
                            uint32_t lms_type,
                            const uint8_t I[LMS_I_LEN]);

/* KeyGen co-processing: D_LEAF each leaf of the streaming K_q (q=0..2^h-1) into
 * the tree, then bottom-up D_INTR computes all internal nodes and root T[1].
 * ots_pub==NULL uses the default source lmots_public_from_private; repeated
 * calls recompute from scratch (idempotent). */
int lms_coprocess_build(lms_coprocess_tree_t *tree,
                        const lms_private_key_t *priv,
                        lms_coprocess_ots_pub_fn ots_pub,
                        void *ots_pub_context);

/* Get the root T[1]. */
int lms_coprocess_root(const lms_coprocess_tree_t *tree, uint8_t root[LMS_N]);

/* Get a node's value (1-based index; for debugging/assembly). */
int lms_coprocess_node(const lms_coprocess_tree_t *tree,
                       uint32_t node_num,
                       uint8_t out[LMS_N]);

/* Generate the auth path of leaf q (siblings, h of them from leaf to root, in
 * the same order as the RFC 8554 signature path). */
int lms_coprocess_auth_path(const lms_coprocess_tree_t *tree,
                            uint32_t q,
                            uint8_t *path /* h * n bytes */);

/* Verify co-processing: given the LM-OTS pub-key candidate K_v (hardware chain
 * completion) and the auth path, software rebuilds the root via D_LEAF +
 * per-level D_INTR and compares it with the expected root; returns LMS_OK
 * (root match) / LMS_ERR_VERIFY. */
int lms_coprocess_root_from_kv(const lms_coprocess_tree_t *tree,
                               uint32_t q,
                               const uint8_t kv[LMS_N],
                               const uint8_t *auth_path /* h * n bytes */,
                               uint8_t root[LMS_N]);

/* Convenience: verify the tree using this tree as the expected root
 * (root_from_kv + comparison against T[1]). */
int lms_coprocess_verify(const lms_coprocess_tree_t *tree,
                         uint32_t q,
                         const uint8_t kv[LMS_N],
                         const uint8_t *auth_path);

#endif /* LMS_COPROCESS_H */
