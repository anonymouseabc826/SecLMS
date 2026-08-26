#ifndef LMS_SUBTREE_H
#define LMS_SUBTREE_H

/*
 * LMS tree-layer SW/HW co-processing (phase 2): memory_target-driven subtrees + incremental auth paths.
 *
 * Design doc: §11 SW/HW pipeline and batched K_q contract.
 *
 * Relationship with src/lms_coprocess.{h,c} (decoupled, decided 2026-07-30):
 *   - **Zero coupling** with lms_coprocess: no include, no call, no shared internal structures.
 *   - lms_coprocess is the j=h full-tree special case (compile-time fixed buffers, H5 stopgap), untouched;
 *     this module is the more general memory_target-driven subtree version, supporting H5~H20, allocated at runtime by budget.
 *   - Both exist and are tested independently; named lms_subtree to avoid clashing with src/lms_tree.c
 *     (lms_tree_node etc. tree primitives).
 *
 * Environment dependence converges to two injection points (design doc §2):
 *   1. memory_target: runtime memory budget (not compile-time), deciding subtree size j and levels;
 *   2. allocator callbacks: PC=malloc/free, RV32 SoC=static pool; this module never calls malloc directly.
 *
 * Hardware never touches tree levels: this module only builds trees / looks up auth paths in software;
 * K_q comes from the injected callback (hardware backend or pure-software lmots_public_from_private),
 * hardware at most to the LM-OTS K_q.
 *
 * Tree traversal machinery (subtree splitting / ACTIVE·NEXT double buffering / incremental building /
 * propagation constraints) borrows the hash-sigs public technique, not an innovation (design doc §10).
 * This file only does the configurator (design doc §8 step 1); building / lookup / incremental building come in later steps.
 *
 * Do not modify any existing file under src/; only add new ones.
 */

#include "lms.h"

#include <stddef.h>
#include <stdint.h>

/* Lower bound for the subtree size scan (same as hash-sigs MIN_SUBTREE=2; j=1 is meaningless). */
#define LMS_SUBTREE_MIN_J 2u

/* Configurator's preference result for choosing j (mirrors hss_alloc.c's search_status semantics). */
typedef enum {
    LMS_TREE_FIT_NONE = 0,      /* no feasible j found (theoretically impossible) */
    LMS_TREE_FIT_OVERBUDGET,    /* all feasible j exceed the budget; take the smallest-memory option */
    LMS_TREE_FIT_WITHIN_BUDGET  /* some feasible j ≤ memory_target exist; take the fastest option */
} lms_tree_fit_t;

/* Config result: subtree parameters selected for a given lms_type and memory_target. */
typedef struct {
    uint32_t lms_type;      /* input: LMS parameter set */
    uint32_t height;        /* parsed tree height h */
    uint32_t n;             /* hash output size in bytes (=LMS_N) */
    uint32_t subtree_size;  /* selected subtree size j */
    uint32_t sublevels;     /* ceil(h / j) */
    uint64_t est_memory;    /* estimated memory in bytes (nodes+stack, same accounting as actual allocation; see estimate_memory) */
    lms_tree_fit_t fit;     /* selection preference (≤budget / over-budget takes minimum) */
} lms_tree_config_t;

/* Allocator callbacks (injection point 2): PC injects malloc/free, RV32 SoC injects static-pool slices.
 * context is owned by the caller (NULL for PC, or a static-pool descriptor for RV32).
 * This module never calls malloc directly; all buffers are allocated/freed through these callbacks. */
typedef void *(*lms_tree_alloc_fn)(void *context, size_t size);
typedef void (*lms_tree_free_fn)(void *context, void *ptr);

/* ---- Data structures (design doc §3, environment-independent; field semantics aligned with hash-sigs struct subtree/merkle_level) ---- */

/* In-subtree node indexing convention: 1-based array order (heap-order), root=1, node r's left child=2r, right child=2r+1.
 * A subtree of height j has 2^(j+1)-1 nodes (index 0 unused); the nodes[] layout matches lms_coprocess. */

/* A subtree: height j, holding a node buffer + an incremental-building traversal stack (borrowed from hash-sigs struct subtree). */
typedef struct {
    uint32_t height;        /* j: this subtree's height (top subtree may be < j, i.e. top_subtree_size) */
    uint32_t level;         /* this subtree's root level in the whole Merkle tree (0=leaf level, h=root) */
    uint32_t levels_below;  /* levels below this subtree's root (= level; used for stack merging / auth-path location) */
    uint32_t tree_height;   /* whole Merkle tree height h (for global node numbering; filled at init) */
    uint64_t left_leaf;     /* leftmost leaf covered by this subtree, in global leaf order (0..2^h-1) */
    uint64_t current_index; /* incremental-building progress: leaves merged so far; complete=this subtree's leaf count 2^height */
    uint8_t *nodes;         /* allocated: 2^(height+1) * n bytes, 1-based heap-order (index 0 empty) */
    uint8_t *stack;         /* incremental-building traversal stack: height * n bytes (holds unpaired left nodes) */
} lms_subtree_t;

/* One level (sublevel): ACTIVE + UPCOMING dual subtrees (single-tree LMS semantics).
 * Naming note (decided 2026-07-30): upcoming is the "successor subtree within the same
 * tree after the current ACTIVE is exhausted", incrementally built between signatures
 * and promoted when ACTIVE runs out. Not called NEXT (to avoid misreading as multi-level
 * HSS's "next Merkle tree" NEXT_TREE — a single tree has only one Merkle tree), nor
 * BUILDING (that is multi-level HSS's pre-build concept for the parent level). */
typedef struct {
    lms_subtree_t active;    /* used for current signatures: auth-path lookup source, always built */
    lms_subtree_t upcoming;  /* same-tree successor: incrementally built between signatures via K_q source, leaf by leaf */
    int has_upcoming;        /* whether upcoming is allocated / being built (top subtree has none, has_upcoming=0) */
} lms_sublevel_t;

/* Tree co-processing context (whole Merkle tree = sublevels subtree layers).
 * Holds the injection points (K_q source + allocator); K_q source semantics match
 * lmots_public_from_private: produces leaf q's LM-OTS public key candidate (hardware
 * backend or pure software; this module is unaware of which). */
typedef int (*lms_subtree_ots_pub_fn)(void *context,
                                      const lms_private_key_t *priv,
                                      uint32_t q,
                                      uint8_t ots_pub[LMS_N]);

/* Leaf direct-output callback (for hardware KEYGEN_LEAF): returns D_LEAF = H(I||node_num||D_LEAF||K_q)
 * directly, skipping the ots_pub→lms_hash_parts two steps. When non-NULL, subtree_compute_leaf uses it first.
 * context is owned by the caller (e.g. lms_mmio_client_t *). */
typedef int (*lms_subtree_leaf_fn)(void *context,
                                    const lms_private_key_t *priv,
                                    uint32_t q,
                                    uint8_t leaf[LMS_N]);

typedef struct {
    uint32_t lms_type;      /* LMS parameter set */
    uint32_t height;        /* h */
    uint32_t n;             /* hash output size in bytes (=LMS_N) */
    uint32_t subtree_size;  /* j (chosen by the configurator) */
    uint32_t sublevels;     /* ceil(h / j) */
    uint32_t top_subtree_size; /* top subtree height = h - (sublevels-1)*j (may be < j) */
    uint32_t hash_alg;      /* hash algorithm (lms_hash_alg_t value; parsed from lms_type and filled at build time) */
    uint8_t I[LMS_I_LEN];   /* key identifier */
    lms_sublevel_t *levels; /* allocated: sublevels sublevels */
    /* injection points */
    lms_subtree_ots_pub_fn ots_pub; /* K_q source (default lmots_public_from_private when NULL) */
    void *ots_pub_ctx;
    lms_subtree_leaf_fn leaf_fn;     /* leaf direct-output callback (falls back to ots_pub + lms_hash_parts when NULL) */
    void *leaf_fn_ctx;
    lms_tree_alloc_fn alloc;
    lms_tree_free_fn free;
    void *alloc_ctx;
} lms_tree_ctx_t;

/*
 * Configurator (design doc §4 + §8 step 1; formulas taken from hash-sigs hss_alloc.c).
 *
 * Given lms_type and a runtime memory_target, scan candidate subtree sizes j ∈ [MIN_J .. h]:
 *   - single tree (levels=1) has no parent-level propagation constraint; j is limited only
 *     by memory_target and the "fastest" preference;
 *   - estimated memory est_memory(j) = subtree nodes + traversal stack (compute_level_memory_usage
 *     semantics, degenerated for levels=1: bottom sublevels-1 double subtrees + top single subtree);
 *   - selection rules (taken from hss_alloc.c:355-405): prefer the j with fewest sublevels (fastest)
 *     among those ≤ memory_target; on ties take the smaller-memory one; if all j exceed the budget,
 *     take the smallest-memory option (fit=OVERBUDGET; the caller may degrade/fall back accordingly).
 *
 * Returns LMS_OK on success; invalid lms_type / config==NULL returns LMS_ERR_INVALID.
 * This function is pure computation: no allocation, no hardware access, environment-independent.
 */
int lms_tree_configure(uint32_t lms_type,
                       uint64_t memory_target,
                       lms_tree_config_t *config);

/* Estimate memory usage for a given (height, j) in bytes (nodes+stack). Exposed for tests / budget scanning.
 * Unified accounting (option A): est_memory = actual allocation (excluding levels[] structure overhead),
 * strictly matching the data part of lms_tree_ctx_allocated_bytes; memory_target is a true, trustworthy lower bound. */
uint64_t lms_tree_estimate_memory(uint32_t height,
                                  uint32_t subtree_size,
                                  uint32_t n,
                                  uint32_t *sublevels_out);

/* updates propagation constraints (hash-sigs compute_updates_generated/required; exposed for testing).
 * A single tree with levels=1 has no parent level, so the configurator does not enforce them; kept for later multi-level / verification and test alignment. */
uint64_t lms_tree_updates_generated(uint32_t height, uint32_t subtree);
uint64_t lms_tree_updates_required(uint32_t height, uint32_t subtree);

/* ---- Context lifecycle (design doc §8 step 2: data structures + allocator injection) ----
 *
 * Memory layout is allocated through the injected allocator; the total ≈ lms_tree_estimate_memory(h, j, n)
 * (nodes+stack) plus the levels[] array (sublevels * sizeof(lms_sublevel_t), structure overhead, not counted in est).
 * This step only builds an "empty skeleton": allocates all buffers and initializes fields;
 * **tree building / node filling happens in later steps**.
 */

/*
 * Initialize the tree co-processing context: per config, allocate all nodes/stack buffers of the
 * sublevels subtree layers via the injected allocator, and initialize the fields
 * (level/levels_below/left_leaf/current_index=0).
 *
 * Parameters:
 *   ctx         output context (storage provided by caller; this function only fills it; internal buffers via alloc)
 *   config      result of lms_tree_configure (determines sublevels/j/each subtree height)
 *   I           key identifier (16 bytes, copied into ctx)
 *   ots_pub     K_q source (may be NULL → default lmots_public_from_private at build time)
 *   ots_pub_ctx K_q source context
 *   alloc/free  injected allocator (must be non-NULL; this module never calls malloc directly)
 *   alloc_ctx   allocator context (NULL when PC=malloc; points to the static pool on RV32)
 *
 * Returns LMS_OK on success; any allocation failure rolls back the allocated buffers and returns LMS_ERR_INVALID.
 * This step does not build the tree (node contents unfilled); building is done by the later ACTIVE build interface.
 */
int lms_tree_ctx_init(lms_tree_ctx_t *ctx,
                      const lms_tree_config_t *config,
                      const uint8_t I[LMS_I_LEN],
                      lms_subtree_ots_pub_fn ots_pub,
                      void *ots_pub_ctx,
                      lms_tree_alloc_fn alloc,
                      lms_tree_free_fn free,
                      void *alloc_ctx);

/* Free all buffers allocated through the allocator in the context (levels[] and each subtree's nodes/stack).
 * Safe to call repeatedly / on an uninitialized ctx (internally null-checked). After this call ctx must not be reused; re-init it. */
void lms_tree_ctx_free(lms_tree_ctx_t *ctx);

/* Set the leaf direct-output callback: when non-NULL, subtree_compute_leaf calls it first to obtain
 * D_LEAF directly, skipping ots_pub + lms_hash_parts. Used for hardware KEYGEN_LEAF and similar scenarios. */
void lms_subtree_set_leaf_fn(lms_tree_ctx_t *ctx, lms_subtree_leaf_fn fn, void *fn_ctx);

/* Compute the total bytes actually allocated through the allocator for ctx (levels[] + each subtree's nodes + stack).
 * For tests / budget verification: should be ≈ est_memory (nodes+stack) + sublevels*sizeof(lms_sublevel_t). */
uint64_t lms_tree_ctx_allocated_bytes(const lms_tree_ctx_t *ctx);

/* ---- ACTIVE building + auth-path lookup (design doc §8 step 3) ---- */

/*
 * Build the ACTIVE subtrees in one pass (KeyGen semantics, option A).
 *
 * Structure and algorithm are general (any sublevels), but **this step supports only sublevels==1
 * (the j=h full-tree special case)**: the single ACTIVE subtree is then the whole tree, leaves=real
 * leaves (via K_q source ots_pub → D_LEAF), root=whole-tree root, logically closed.
 * **All D_LEAF/D_INTR hash prefixes use whole-tree node numbers** (not subtree-local indices),
 * guaranteeing byte-for-byte agreement with lms_tree_node / lms_public_key_generate.
 *
 * Upper-level subtree leaves in the multi-sublevel case (required for H20) depend on "lower-level
 * subtrees built one by one in rotation + prev_node reusing the lower-level root" (hash-sigs
 * subtree_add_next_node incremental building), which is design-doc step 4; this step returns
 * LMS_ERR_INVALID for sublevels!=1 (explicitly unsupported, never silently wrong). **The interface/
 * structure is not specialized for sublevels=1; when H20 arrives, only the incremental-building
 * primitives need to be added, the structure stays unchanged** (option A functionality + option B interface).
 *
 * Must not be called during signing (Reserve→Commit); only at KeyGen/init stage (see design doc §5).
 * This function does not touch priv->q (read-only private key; derives leaf public keys).
 *
 * priv->lms_type must equal ctx->lms_type. ots_pub==NULL (as set at ctx init) uses the default
 * lmots_public_from_private (pure software when no hardware backend is registered; automatically
 * goes through the hardware chain once registered).
 * Returns LMS_OK on success; sublevels!=1 / failure returns LMS_ERR_INVALID.
 */
int lms_tree_build_active(lms_tree_ctx_t *ctx, const lms_private_key_t *priv);

/* Get the whole-tree root T[1] (= the top ACTIVE subtree's root). lms_tree_build_active must be called first. */
int lms_tree_root(const lms_tree_ctx_t *ctx, uint8_t root[LMS_N]);

/*
 * Generate leaf q's authentication path (siblings, h of them from leaf to root, matching RFC 8554
 * signature path order). Look up and memcpy-join from each sublevel's ACTIVE subtree nodes[] (O(h),
 * zero recomputation).
 * path buffer must be ≥ h * n bytes. Precondition (REVIEW B03-R9): for sublevels==1 go through
 * lms_tree_build_active; for multiple sublevels go through lms_tree_sign_init + lms_tree_sign_advance
 * so every level's ACTIVE is ready (lms_tree_sign_auth_path forwards to this function).
 */
int lms_tree_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path);

/* ---- Incremental building (design doc §8 step 4; required for multi-sublevel / H15+) ----
 *
 * Streaming tree building for a single-tree LMS: for a subtree of height sub_h, merge leaves one by
 * one (leaf values provided externally), using a stack of depth sub_h to hold "unpaired left nodes",
 * merging D_INTR upward to the subtree root. This is the standard log-space Merkle tree building
 * (borrowed from hash-sigs subtree_add_next_node, a public technique).
 * Difference from hash-sigs multi-level HSS: our subtree leaves are directly computed node values
 * (bottom=D_LEAF output, upper=lower subtree root), with no "levels below leaves" concept, so the
 * stack is used only within this subtree.
 */

/*
 * Merge one leaf into a subtree (advance incremental building by one step).
 *
 * sub         target subtree (current_index marks merged leaf count; complete=2^sub->height)
 * leaf_value  this leaf's value (already computed by caller: bottom=D_LEAF(K_q) output, upper=lower subtree root)
 * I           key identifier (D_INTR prefix)
 * hash_alg    hash algorithm
 * n           hash output size in bytes (=LMS_N)
 *
 * In-subtree node D_INTR prefixes use whole-tree node numbers (derived from sub->level/left_leaf/current_index),
 * guaranteeing byte-for-byte agreement with lms_tree_node.
 *
 * Returns: 1 = this step completed the subtree root (subtree done); 0 = merged but not yet complete;
 * LMS_ERR_INVALID = error (including merging again into a completed subtree).
 */
int lms_tree_add_next_node(lms_subtree_t *sub,
                           const uint8_t leaf_value[LMS_N],
                           const uint8_t I[LMS_I_LEN],
                           uint32_t hash_alg,
                           uint32_t n);

/* ---- Step 4 phase B: KeyGen streaming root generation + auth-path cache (design doc §8.1) ----
 *
 * KeyGen root generation and the signature cache are two independent operations (matching hash-sigs' actual architecture):
 *   keygen_root    one-pass streaming public-key root over 2^h leaves, memory O(sublevels) in-building subtrees;
 *   sign_init      build each level's ACTIVE subtree cache for q=0 (covering the real-leaf segment containing q, once before signing);
 *   sign_auth_path look up and join the auth path (O(h) zero recomputation, same as lms_tree_auth_path);
 *   sign_advance   cache-invalidation rebuild: when q leaves some level's ACTIVE cache segment, rebuild that
 *                  level as the subtree covering q via subtree_build_at (pure software, not double-buffered incremental building; see below).
 *
 * Cache model (decided 2026-07-30: cache-invalidation rebuild, not hash-sigs' double-buffered incremental building):
 *   Tree levels are pure software (hardware never touches trees), no real-time flattening constraint, so we **do not**
 *   implement hash-sigs multi-level HSS's ACTIVE/UPCOMING double-buffered + incremental-per-leaf-between-signatures state
 *   machine. Each level caches only one ACTIVE subtree; consecutive signature q's mostly fall within the same subtree set
 *   (cache hit: O(h) lookup, zero recomputation); only when q crosses some level's subtree boundary is that level rebuilt
 *   (bottom frequency 1/2^j, higher levels lower). UPCOMING buffers serve only as temporary scratch for subtree_build_at's
 *   recursive building; they carry no signature-cache semantics.
 * Must not call keygen_root/sign_init/sign_advance during signing (Reserve→Commit) (see design doc §5).
 */

/*
 * Stream-generate the public-key root from subtrees (KeyGen semantics). One pass over all 2^h real
 * leaves: each time the bottom ACTIVE completes a subtree, its root is merged as one leaf of the upper
 * level's ACTIVE, level by level up to the top root = public-key root.
 * Memory O(sublevels) in-building subtrees (H15 full build is 2MiB, exceeding the SoC's 128KiB, so streaming is required).
 * This function exclusively owns ctx (resets all subtrees; keeps no signature cache). Does not touch priv->q.
 * Returns LMS_OK on success; root receives the 32-byte public-key root (= lms_public_key_generate's pub->root).
 */
int lms_tree_keygen_root(lms_tree_ctx_t *ctx,
                         const lms_private_key_t *priv,
                         uint8_t root[LMS_N]);

/*
 * Build the cache for signing: build each level's ACTIVE subtree for q=0 (sublevel0 covers real leaves
 * [0,2^j); upper levels have leaves=sequence of lower subtree roots, built recursively). Only the subtree
 * covering the real-leaf segment containing q is cached; no successor subtree is pre-built (UPCOMING is
 * only build scratch). Called once before signing.
 * Returns LMS_OK on success; LMS_ERR_INVALID on failure.
 */
int lms_tree_sign_init(lms_tree_ctx_t *ctx, const lms_private_key_t *priv);

/*
 * Generate leaf q's authentication path (table lookup, same as lms_tree_auth_path, O(h) zero recomputation).
 * Before calling, each level's ACTIVE must cover q (for q=0 it covers after sign_init; for q>0 call
 * sign_advance first to rotate ACTIVE to the subtree covering q). path buffer must be ≥ h * n bytes.
 */
int lms_tree_sign_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path);

/*
 * Cache-invalidation rebuild: make every level's ACTIVE cover q.
 * Check levels bottom-up: if a level's ACTIVE cache segment does not contain q (q outside
 * [leaf_lo, leaf_lo+2^level)), rebuild that level as the subtree covering q via subtree_build_at;
 * if it contains q, skip (cache hit).
 * The top level (covering all real leaves) is never rebuilt. Consecutive signatures mostly hit the cache
 * (O(h) lookup); only crossing a subtree boundary rebuilds the corresponding level. Call before each
 * signature with the latest q to guarantee sign_auth_path(q) hits. Does not touch priv->q.
 * Returns LMS_OK; out-of-range q / rebuild failure returns LMS_ERR_INVALID.
 */
int lms_tree_sign_advance(lms_tree_ctx_t *ctx,
                          const lms_private_key_t *priv,
                          uint32_t q);

/* ---- Design doc step 5: lms_sign auth-path backend adaptation ----
 *
 * Wraps lms_tree_ctx_t as an auth-path backend for lms_sign.c (lms_auth_path_backend_fn
 * signature). Registration (in a translation unit that includes lms_internal.h):
 *   lms_auth_path_backend_set(lms_subtree_auth_path_backend, ctx);
 * Afterwards lms_sign/lms_do_sign's auth path goes through this cache (sign_advance first to
 * make it hit, then sign_auth_path lookup, O(h) zero recomputation), replacing the default
 * lms_tree_node recursive rebuild.
 * context is the lms_tree_ctx_t* (must have been sign_init'ed; priv is passed by lms_do_sign).
 * Unregister (fall back to default recursive): lms_auth_path_backend_set(NULL, NULL).
 * Does not touch priv->q (q increment remains lms_do_sign's job).
 */
int lms_subtree_auth_path_backend(void *context,
                                  const lms_private_key_t *priv,
                                  uint32_t q,
                                  uint8_t *path);

#endif /* LMS_SUBTREE_H */
