/* LMS tree-layer co-processing (phase 2): memory_target-driven subtree configurator.
 *
 * Implements the design-doc §4/§8 step 1.
 * Memory estimation and j-selection rules taken from the hash-sigs hss_alloc.c (public
 * technique, not an innovation; see §10):
 *   - compute_level_memory_usage  -> lms_tree_estimate_memory (levels=1 / root degenerate)
 *   - compute_updates_generated/required -> lms_tree_updates_generated/required
 *   - selection loop (hss_alloc.c:355-405) -> lms_tree_configure
 *
 * Single-tree LMS (levels=1) vs. hash-sigs multi-level HSS simplifications:
 *   - no parent level, hence no cross-level "updates_generated >= updates_required"
 *     propagation constraint; the formulas are still implemented (test alignment + later
 *     multi-level extension), but the configurator does not enforce them.
 *   - root tree have_next_subtree=0; top level has no BUILDING subtree (same as hss_alloc's
 *     i==0 special case).
 *
 * Environment-independent: never malloc's, touches hardware, or reads/writes state here;
 * only pure integer computation.
 */

#include "lms_subtree.h"
#include "lms_internal.h"

#include <string.h>

/* Bytes for one subtree's node buffer of height sub_h: 2^(sub_h+1) * n.
 * 1-based indexing (index 0 is an empty slot, same as lms_coprocess): the subtree has
 * 2^(sub_h+1)-1 valid nodes (indices 1..2^(sub_h+1)-1); plus index 0's empty slot, 2^(sub_h+1) slots total. */
static uint64_t subtree_nodes_bytes(uint32_t sub_h, uint32_t n)
{
    uint64_t node_slots = ((uint64_t)2u << sub_h); /* 2^(sub_h+1) slots (incl. index-0 empty slot) */
    return node_slots * n;
}

/* ---- updates propagation constraints (taken from hss_alloc.c) ---- */

uint64_t lms_tree_updates_generated(uint32_t height, uint32_t subtree)
{
    uint32_t num_sublevels;

    if (subtree == 0u) {
        return 0u;
    }
    /* Special case: if the tree consists of 1 subtree, send an update each signature. */
    if (height <= subtree) {
        return (uint64_t)1u << height;
    }
    num_sublevels = (height + subtree - 1u) / subtree;
    /* An update for every node covered by the next-to-top subtree. */
    return (uint64_t)1u << ((num_sublevels - 1u) * subtree);
}

uint64_t lms_tree_updates_required(uint32_t height, uint32_t subtree)
{
    uint32_t num_sublevels;

    if (subtree == 0u) {
        return 0u;
    }
    num_sublevels = (height + subtree - 1u) / subtree;
    /* num_sublevels-1 for BUILDING subtrees + 1 for NEXT + 1 for parent. */
    return (uint64_t)num_sublevels + 1u;
}

/* ---- Memory estimation (unified accounting: est_memory = data-part allocation; option A, decided 2026-07-30) ----
 *
 * Semantics: returns the "nodes+stack" bytes ctx actually allocates through the allocator; also notes the
 * levels[] structure overhead (sublevels * sizeof(lms_sublevel_t); REVIEW B03-R11 corrected the old
 * "trustworthy lower bound" wording — actual allocation = est_memory + levels[] overhead > est_memory,
 * on the order of ~sublevels×88B), strictly matching the data part of lms_tree_ctx_allocated_bytes.
 * The subtree mechanism borrows from hash-sigs (public technique), but the memory model is simplified to
 * this module's ACTIVE/NEXT double buffering, not a byte-for-byte copy of compute_level_memory_usage.
 *
 * sublevels = ceil(height / j); top = height - (sublevels-1)*j.
 * Per sublevel s (sub_h = (s<sublevels-1)? j : top):
 *   ACTIVE: nodes=2^(sub_h+1)*n (1-based, incl. index-0 empty slot) + stack=sub_h*n
 *   NEXT (only when s<sublevels-1; none at the top): same as ACTIVE.
 */
uint64_t lms_tree_estimate_memory(uint32_t height,
                                  uint32_t subtree_size,
                                  uint32_t n,
                                  uint32_t *sublevels_out)
{
    uint32_t sublevels;
    uint32_t top_subtree_size;
    uint64_t memory_used = 0u;
    uint32_t s;

    if (subtree_size == 0u || n == 0u) {
        if (sublevels_out) {
            *sublevels_out = 0u;
        }
        return 0u;
    }

    sublevels = (height + subtree_size - 1u) / subtree_size;
    if (sublevels == 0u) {
        sublevels = 1u;
    }
    top_subtree_size = height - (sublevels - 1u) * subtree_size;

    for (s = 0u; s < sublevels; s++) {
        uint32_t sub_h = (s + 1u < sublevels) ? subtree_size : top_subtree_size;
        uint64_t nodes_bytes = subtree_nodes_bytes(sub_h, n);
        uint64_t stack_bytes = (uint64_t)sub_h * n;
        memory_used += nodes_bytes + stack_bytes;      /* ACTIVE */
        if (s + 1u < sublevels) {
            memory_used += nodes_bytes + stack_bytes;  /* NEXT (non-top level) */
        }
    }

    if (sublevels_out) {
        *sublevels_out = sublevels;
    }
    return memory_used;
}

/* ---- Configurator (selection loop taken from hss_alloc.c:355-405) ---- */

int lms_tree_configure(uint32_t lms_type,
                       uint64_t memory_target,
                       lms_tree_config_t *config)
{
    lms_param_t param;
    uint32_t height;
    uint32_t n;
    uint32_t j;

    /* selection state (three-state semantics taken from hss_alloc.c search_status). */
    int found_overbudget = 0;
    int found_within = 0;
    uint64_t best_mem = 0u;
    uint32_t best_levels = 0u;
    uint32_t best_j = 0u;

    if (config == NULL) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lms_param(lms_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    height = param.height;
    n = param.n;
    if (height == 0u || n == 0u || height > LMS_MAX_HEIGHT) {
        return LMS_ERR_INVALID;
    }

    /* Scan candidate subtree sizes j ∈ [MIN_J .. height].
     * A single tree (levels=1) has no parent level, so no propagation constraint is enforced
     * (hss_alloc's levels==1 branch).
     * Selection preference:
     *   - prefer feasible j with ≤ memory_target and fewest sublevels (fastest); on ties take the smaller-memory one;
     *   - if all exceed the budget, take the smallest-memory option (fit=OVERBUDGET).
     */
    for (j = LMS_SUBTREE_MIN_J; j <= height; j++) {
        uint32_t sub_levels = 0u;
        uint64_t mem = lms_tree_estimate_memory(height, j, n, &sub_levels);

        if (mem > memory_target) {
            /* over budget: adopt only when there is no solution yet, or when it uses less memory than the known over-budget solution. */
            if ((found_overbudget || found_within) && mem > best_mem) {
                continue;
            }
            found_overbudget = 1;
        } else {
            /* ≤budget: skip if a faster (fewer sublevels) or equally fast but smaller ≤budget solution already exists. */
            if (found_within) {
                if (sub_levels > best_levels) {
                    continue;
                }
                if (sub_levels == best_levels && mem > best_mem) {
                    continue;
                }
            }
            found_within = 1;
        }

        best_j = j;
        best_mem = mem;
        best_levels = sub_levels;
    }

    if (!found_overbudget && !found_within) {
        /* Cannot happen (a non-empty j scan range always has a solution); defensive return. */
        return LMS_ERR_INVALID;
    }

    memset(config, 0, sizeof(*config));
    config->lms_type = lms_type;
    config->height = height;
    config->n = n;
    config->subtree_size = best_j;
    config->sublevels = best_levels;
    config->est_memory = best_mem;
    config->fit = found_within ? LMS_TREE_FIT_WITHIN_BUDGET : LMS_TREE_FIT_OVERBUDGET;
    return LMS_OK;
}

/* ---- Context lifecycle (design doc §8 step 2) ----
 *
 * Sublevel geometry (an h-level Merkle tree is split into sublevels segments of subtree height j,
 * from leaves to root):
 *   sublevel s (s=0 bottommost/contains leaves, s=sublevels-1 topmost):
 *     sub_h        = (s < sublevels-1) ? j : top_subtree_size   this subtree's own height
 *     root_level   = s*j + sub_h          subtree root's level in the whole tree (top=h)
 *     leaf_level   = s*j                  subtree leaves' level in the whole tree
 *     levels_below = s*j                  whole-tree levels below the subtree root
 *   where top_subtree_size = h - (sublevels-1)*j (top may be < j).
 * Example h=5,j=2,sublevels=3,top=1: s0{sub_h2,root2,below0} s1{sub_h2,root4,below2} s2{sub_h1,root5,below4}.
 *
 * Memory layout (via the injected allocator; never malloc directly):
 *   levels[]       = sublevels * sizeof(lms_sublevel_t)
 *   each sublevel s's ACTIVE subtree: nodes=(2^(sub_h+1)-1)*n + stack=sub_h*n (top's stack may be empty)
 *   UPCOMING subtree (only when s < sublevels-1; top has_upcoming=0): same size as above.
 * This step only builds an empty skeleton (allocation + field init); node contents are filled by the later
 * ACTIVE build interface.
 */

/* Free one subtree's buffers (null-checked, idempotent). */
static void subtree_free_buffers(lms_subtree_t *sub,
                                 lms_tree_free_fn free_fn,
                                 void *alloc_ctx)
{
    if (sub == NULL || free_fn == NULL) {
        return;
    }
    if (sub->nodes != NULL) {
        free_fn(alloc_ctx, sub->nodes);
        sub->nodes = NULL;
    }
    if (sub->stack != NULL) {
        free_fn(alloc_ctx, sub->stack);
        sub->stack = NULL;
    }
}

/* Initialize one subtree's fields and allocate its buffers.
 * sub_h/level/levels_below/left_leaf are given by the caller per the geometry; n is the hash length.
 * When want_stack is non-zero, allocate a sub_h*n traversal stack. On failure, roll back and return LMS_ERR_INVALID. */
static int subtree_init_buffers(lms_subtree_t *sub,
                                uint32_t sub_h,
                                uint32_t level,
                                uint32_t levels_below,
                                uint32_t tree_height,
                                uint64_t left_leaf,
                                uint32_t n,
                                int want_stack,
                                lms_tree_alloc_fn alloc,
                                lms_tree_free_fn free_fn,
                                void *alloc_ctx)
{
    uint64_t nodes_bytes;

    memset(sub, 0, sizeof(*sub));
    sub->height = sub_h;
    sub->level = level;
    sub->levels_below = levels_below;
    sub->tree_height = tree_height;
    sub->left_leaf = left_leaf;
    sub->current_index = 0u;

    nodes_bytes = subtree_nodes_bytes(sub_h, n);
    sub->nodes = (uint8_t *)alloc(alloc_ctx, (size_t)nodes_bytes);
    if (sub->nodes == NULL) {
        return LMS_ERR_INVALID;
    }
    memset(sub->nodes, 0, (size_t)nodes_bytes);

    if (want_stack && sub_h > 0u) {
        sub->stack = (uint8_t *)alloc(alloc_ctx, (size_t)sub_h * n);
        if (sub->stack == NULL) {
            subtree_free_buffers(sub, free_fn, alloc_ctx);
            return LMS_ERR_INVALID;
        }
        memset(sub->stack, 0, (size_t)sub_h * n);
    } else {
        sub->stack = NULL;
    }
    return LMS_OK;
}

int lms_tree_ctx_init(lms_tree_ctx_t *ctx,
                      const lms_tree_config_t *config,
                      const uint8_t I[LMS_I_LEN],
                      lms_subtree_ots_pub_fn ots_pub,
                      void *ots_pub_ctx,
                      lms_tree_alloc_fn alloc,
                      lms_tree_free_fn free_fn,
                      void *alloc_ctx)
{
    uint32_t sublevels;
    uint32_t j;
    uint32_t top;
    uint32_t n;
    uint32_t s;
    lms_param_t param;

    if (ctx == NULL || config == NULL || I == NULL || alloc == NULL || free_fn == NULL) {
        return LMS_ERR_INVALID;
    }
    sublevels = config->sublevels;
    j = config->subtree_size;
    n = config->n;
    if (sublevels == 0u || j < LMS_SUBTREE_MIN_J || n == 0u ||
        config->height == 0u || config->height > LMS_MAX_HEIGHT) {
        return LMS_ERR_INVALID;
    }
    top = config->height - (sublevels - 1u) * j;
    if (lms_get_lms_param(config->lms_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->lms_type = config->lms_type;
    ctx->height = config->height;
    ctx->n = n;
    ctx->subtree_size = j;
    ctx->sublevels = sublevels;
    ctx->top_subtree_size = top;
    ctx->hash_alg = (uint32_t)param.hash_alg;
    memcpy(ctx->I, I, LMS_I_LEN);
    ctx->ots_pub = ots_pub;
    ctx->ots_pub_ctx = ots_pub_ctx;
    ctx->leaf_fn = NULL;
    ctx->leaf_fn_ctx = NULL;
    ctx->alloc = alloc;
    ctx->free = free_fn;
    ctx->alloc_ctx = alloc_ctx;

    /* Allocate the levels[] array. */
    ctx->levels = (lms_sublevel_t *)alloc(alloc_ctx,
                                          (size_t)sublevels * sizeof(lms_sublevel_t));
    if (ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    memset(ctx->levels, 0, (size_t)sublevels * sizeof(lms_sublevel_t));

    /* Initialize each sublevel's ACTIVE (+ NEXT, non-top) subtree. */
    for (s = 0u; s < sublevels; s++) {
        uint32_t sub_h = (s + 1u < sublevels) ? j : top;
        uint32_t root_level = s * j + sub_h;
        uint32_t levels_below = s * j;
        /* Leftmost leaf covered by this subtree: ACTIVE initially covers the whole tree's leftmost [0, 2^sub_h). */
        uint64_t left_leaf = 0u;
        int has_upcoming = (s + 1u < sublevels) ? 1 : 0;
        lms_sublevel_t *sl = &ctx->levels[s];

        if (subtree_init_buffers(&sl->active, sub_h, root_level, levels_below,
                                 config->height, left_leaf, n, 1 /* stack */,
                                 alloc, free_fn, alloc_ctx) != LMS_OK) {
            lms_tree_ctx_free(ctx);
            return LMS_ERR_INVALID;
        }
        sl->has_upcoming = has_upcoming;
        if (has_upcoming) {
            /* UPCOMING subtree pre-built: initially isomorphic to ACTIVE, covering the tree's next segment
             * (left_leaf advances via incremental building at rotation; here placeholder "next segment" = 2^sub_h,
             * corrected during the building phase). */
            if (subtree_init_buffers(&sl->upcoming, sub_h, root_level, levels_below,
                                     config->height, left_leaf + ((uint64_t)1u << sub_h),
                                     n, 1, alloc, free_fn, alloc_ctx) != LMS_OK) {
                lms_tree_ctx_free(ctx);
                return LMS_ERR_INVALID;
            }
        }
    }
    return LMS_OK;
}

void lms_tree_ctx_free(lms_tree_ctx_t *ctx)
{
    uint32_t s;

    if (ctx == NULL) {
        return;
    }
    if (ctx->levels != NULL && ctx->free != NULL) {
        for (s = 0u; s < ctx->sublevels; s++) {
            lms_sublevel_t *sl = &ctx->levels[s];
            subtree_free_buffers(&sl->active, ctx->free, ctx->alloc_ctx);
            if (sl->has_upcoming) {
                subtree_free_buffers(&sl->upcoming, ctx->free, ctx->alloc_ctx);
            }
        }
        ctx->free(ctx->alloc_ctx, ctx->levels);
        ctx->levels = NULL;
    }
    ctx->sublevels = 0u;
}

uint64_t lms_tree_ctx_allocated_bytes(const lms_tree_ctx_t *ctx)
{
    uint64_t total = 0u;
    uint32_t s;

    if (ctx == NULL || ctx->levels == NULL) {
        return 0u;
    }
    total += (uint64_t)ctx->sublevels * sizeof(lms_sublevel_t);
    for (s = 0u; s < ctx->sublevels; s++) {
        const lms_sublevel_t *sl = &ctx->levels[s];
        uint32_t sub_h = sl->active.height;
        uint64_t nodes_bytes = subtree_nodes_bytes(sub_h, ctx->n);
        uint64_t stack_bytes = (sl->active.stack != NULL) ? (uint64_t)sub_h * ctx->n : 0u;
        total += nodes_bytes + stack_bytes;
        if (sl->has_upcoming) {
            total += nodes_bytes +
                     ((sl->upcoming.stack != NULL) ? (uint64_t)sub_h * ctx->n : 0u);
        }
    }
    return total;
}

void lms_subtree_set_leaf_fn(lms_tree_ctx_t *ctx, lms_subtree_leaf_fn fn, void *fn_ctx)
{
    if (ctx != NULL) {
        ctx->leaf_fn = fn;
        ctx->leaf_fn_ctx = fn_ctx;
    }
}

/* ---- ACTIVE building + auth-path lookup (design doc §8 step 3) ---- */

/* Default K_q source: forwards to lmots_public_from_private (pure software when no backend is
 * registered; automatically goes through the hardware chain once a hardware backend is registered). */
static int default_ots_pub(void *context,
                           const lms_private_key_t *priv,
                           uint32_t q,
                           uint8_t ots_pub[LMS_N])
{
    (void)context;
    return lmots_public_from_private(priv, q, ots_pub);
}

/* Subtree-local index (1-based heap-order) -> whole-tree node number.
 * Subtree height sub_h, root at whole-tree level root_level, covering the segment
 * [left_leaf, left_leaf+2^sub_h) at whole-tree level (root_level-sub_h); h is the whole-tree height.
 * Mapping (see design-doc derivation): subtree root's whole-tree number k0 = left_leaf >> sub_h (at level root_level);
 * local (depth d, in-level order k, local=2^d+k) maps to number (k0<<d)+k at whole-tree level root_level-d;
 * the k-th node at whole-tree level r has number 2^(h-r) + k. */
static uint32_t subtree_local_to_global(uint32_t h,
                                        uint32_t sub_h,
                                        uint32_t root_level,
                                        uint64_t left_leaf,
                                        uint32_t local)
{
    uint64_t k0 = left_leaf >> sub_h;
    uint32_t d = 0u;
    uint32_t k;
    uint32_t r;

    while ((1u << (d + 1u)) <= local) {
        d++;
    }
    k = local - (1u << d);
    r = root_level - d;
    return (uint32_t)((1u << (h - r)) + ((uint32_t)(k0 << d) + k));
}

/* Build one ACTIVE subtree's internal nodes (leaves already in place): bottom-up D_INTR with
 * whole-tree numbers as prefixes.
 * leaf_provider supplies each local leaf's value (sublevel0=real-leaf D_LEAF already filled;
 * upper=lower subtree root). */
static int subtree_build_internal(lms_tree_ctx_t *ctx, lms_subtree_t *sub)
{
    uint32_t local;

    /* Local node count = 2^(sub_h+1)-1; internal nodes local ∈ [1, 2^sub_h - 1], bottom-up. */
    for (local = (1u << sub->height) - 1u; local >= 1u; local--) {
        uint32_t node_num = subtree_local_to_global(ctx->height, sub->height,
                                                    sub->level, sub->left_leaf, local);
        if (lms_internal_node(ctx->I, (lms_hash_alg_t)ctx->hash_alg, node_num,
                              sub->nodes + (size_t)(local * 2u) * ctx->n,
                              sub->nodes + (size_t)(local * 2u + 1u) * ctx->n,
                              sub->nodes + (size_t)local * ctx->n) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
        /* The root node (local==1) ends the loop naturally: local is uint32, terminated by the for
         * condition (local >= 1u); no explicit break needed (REVIEW B03-R5). */
    }
    return LMS_OK;
}

int lms_tree_build_active(lms_tree_ctx_t *ctx, const lms_private_key_t *priv)
{
    lms_subtree_ots_pub_fn ots_pub;
    uint8_t ots_pub_buf[LMS_N];
    uint32_t s;

    if (ctx == NULL || priv == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;

    /* Structure is general (any sublevels), but this step supports only sublevels==1 (the j=h full-tree
     * special case): the single ACTIVE subtree is then the whole tree, leaves=real leaves, root=whole-tree
     * root, logically closed. Multi-sublevel upper leaves depend on "lower subtrees built one by one in
     * rotation + prev_node reusing the lower root" (hash-sigs subtree_add_next_node incremental building),
     * which is design-doc step 4; this step explicitly returns unsupported rather than silently computing
     * wrong results. The interface/structure is not specialized for sublevels=1; when H20 arrives, only the
     * incremental-building primitives need to be added; the structure stays unchanged. */
    if (ctx->sublevels != 1u) {
        return LMS_ERR_INVALID;
    }

    for (s = 0u; s < ctx->sublevels; s++) {
        lms_sublevel_t *sl = &ctx->levels[s];
        lms_subtree_t *active = &sl->active;
        uint32_t sub_h = active->height;
        uint32_t leaf_count = 1u << sub_h;
        uint32_t leaf_base_local = 1u << sub_h; /* local leaf start index (1-based heap-order) */
        uint32_t i;

        /* With sublevels==1, s==0: the single ACTIVE (whole tree), leaves = real leaves.
         * Produce the LM-OTS public key via the K_q source → D_LEAF (with whole-tree numbers as prefix). */
        for (i = 0u; i < leaf_count; i++) {
            uint32_t local = leaf_base_local + i;
            uint32_t node_num = subtree_local_to_global(ctx->height, sub_h,
                                                        active->level,
                                                        active->left_leaf, local);
            uint32_t q = (uint32_t)(active->left_leaf + i); /* whole-tree leaf number = global q */
            uint8_t prefix[LMS_I_LEN + 4 + 2];

            if (ots_pub(ctx->ots_pub_ctx, priv, q, ots_pub_buf) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            memcpy(prefix, ctx->I, LMS_I_LEN);
            lms_store_u32(prefix + LMS_I_LEN, node_num);
            lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);
            if (lms_hash_parts(prefix, sizeof(prefix), ots_pub_buf, LMS_N,
                               NULL, 0, NULL, 0, (lms_hash_alg_t)ctx->hash_alg,
                               active->nodes + (size_t)local * ctx->n) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
        }

        /* Build internal nodes (D_INTR, whole-tree number prefixes). */
        if (subtree_build_internal(ctx, active) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }
    return LMS_OK;
}

int lms_tree_root(const lms_tree_ctx_t *ctx, uint8_t root[LMS_N])
{
    const lms_subtree_t *top;

    if (ctx == NULL || root == NULL || ctx->levels == NULL || ctx->sublevels == 0u) {
        return LMS_ERR_INVALID;
    }
    top = &ctx->levels[ctx->sublevels - 1u].active;
    memcpy(root, top->nodes + (size_t)1u * ctx->n, ctx->n);
    return LMS_OK;
}

int lms_tree_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path)
{
    uint32_t path_idx = 0u;
    uint64_t leaf_pos = q; /* current node's leaf offset within its subtree's covered segment */
    uint32_t s;

    if (ctx == NULL || path == NULL || ctx->levels == NULL || ctx->sublevels == 0u) {
        return LMS_ERR_INVALID;
    }
    if ((uint64_t)q >= ((uint64_t)1u << ctx->height)) {
        return LMS_ERR_INVALID;
    }

    /* Leaf-to-root (RFC 8554 signature path order, matching lms_coprocess_auth_path):
     * each sublevel contributes sub_h siblings (table-lookup memcpy, O(h) zero recomputation).
     * With sublevels==1 these are the whole-tree siblings (node_num=2^h+q; per level sibling=node_num^1, node_num/=2). */
    for (s = 0u; s < ctx->sublevels; s++) {
        const lms_subtree_t *active = &ctx->levels[s].active;
        uint32_t sub_h = active->height;
        uint32_t local = (1u << sub_h) + (uint32_t)(leaf_pos & ((1u << sub_h) - 1u));
        uint32_t d;

        for (d = 0u; d < sub_h; d++) {
            uint32_t sibling = local ^ 1u;
            memcpy(path + (size_t)path_idx * ctx->n,
                   active->nodes + (size_t)sibling * ctx->n, ctx->n);
            path_idx++;
            local /= 2u;
        }
        /* This sublevel's root's whole-tree leaf offset = leaf_pos >> sub_h (fed to the upper level's positioning). */
        leaf_pos >>= sub_h;
    }
    return LMS_OK;
}

/* ---- Incremental building (design doc §8 step 4) ----
 *
 * Single-tree LMS streaming building: merge leaves one by one into a subtree of height sub_h (leaf
 * values provided externally), using a stack of depth sub_h to hold "unpaired left nodes", merging
 * D_INTR upward to the subtree root.
 *
 * Stack semantics (isomorphic to hash-sigs subtree_add_next_node, but no levels_below here — a single-
 * tree subtree's leaves are directly computed node values, with no "levels below the leaves"):
 *   stack[i*n] (i ∈ [0, sub_h)) = computed "orphaned left node" at height i (waiting for its right sibling).
 *   Merging the ci-th leaf (leaf number ci from 0; local index local=2^sub_h + ci):
 *     cur = leaf_value; walk up the subtree; if the current node is a right node (ci's bit is 1), merge
 *     with the stack-top left node (D_INTR, whole-tree number prefix), until a left node (store in
 *     stack) or the root.
 * All subtree nodes (leaves + internal) are written to nodes[] (1-based heap-order); D_INTR prefixes
 * use whole-tree numbers.
 */

int lms_tree_add_next_node(lms_subtree_t *sub,
                           const uint8_t leaf_value[LMS_N],
                           const uint8_t I[LMS_I_LEN],
                           uint32_t hash_alg,
                           uint32_t n)
{
    uint32_t sub_h;
    uint64_t ci;         /* current leaf number (within subtree, from 0) */
    uint32_t local;      /* leaf's local index in the subtree (1-based heap-order) */
    uint8_t cur[LMS_N];
    uint64_t leaf_seq;   /* leaf number used for odd/even checks (shifted right while merging) */
    uint32_t i;          /* current stack height */

    if (sub == NULL || leaf_value == NULL || I == NULL || n == 0u || n > LMS_N) {
        return LMS_ERR_INVALID;
    }
    sub_h = sub->height;
    if (sub_h == 0u || sub_h > LMS_MAX_HEIGHT) {
        return LMS_ERR_INVALID;
    }
    ci = sub->current_index;
    if (ci >= ((uint64_t)1u << sub_h)) {
        return LMS_ERR_INVALID; /* subtree already complete */
    }
    if (sub->nodes == NULL || sub->stack == NULL) {
        return LMS_ERR_INVALID;
    }

    /* Write the leaf value into nodes[local] (local 1-based heap-order). */
    local = (uint32_t)((1u << sub_h) + ci);
    memcpy(sub->nodes + (size_t)local * n, leaf_value, n);
    memcpy(cur, leaf_value, n);

    /* Merge upward along the subtree: leaf_seq tracks the current node's parity at its level (merge with the stack top for right nodes). */
    leaf_seq = ci;
    i = 0u;
    for (;;) {
        uint32_t cur_local = (uint32_t)((1u << (sub_h - i)) + (leaf_seq >> 0u));
        uint32_t node_num;

        if (cur_local == 1u) {
            /* reached the subtree root (cur is the root value, already written to nodes[1]). */
            break;
        }
        if ((leaf_seq & 1u) == 0u) {
            /* left node: store in the stack, waiting for the right sibling. */
            memcpy(sub->stack + (size_t)i * n, cur, n);
            break;
        }
        /* right node: merge with the stack top (left sibling) into the parent (D_INTR, whole-tree number prefix). */
        leaf_seq >>= 1u;
        {
            uint32_t parent_local = cur_local >> 1u;
            /* The parent's local index within the subtree, parent_local (depth i+1); its whole-tree number: */
            node_num = subtree_local_to_global(sub->tree_height, sub_h,
                                               sub->level, sub->left_leaf,
                                               parent_local);
            if (lms_internal_node(I, (lms_hash_alg_t)hash_alg, node_num,
                                  sub->stack + (size_t)i * n, cur,
                                  sub->nodes + (size_t)parent_local * n) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            memcpy(cur, sub->nodes + (size_t)parent_local * n, n);
        }
        i++;
    }

    sub->current_index = ci + 1u;
    /* Completion check: after merging the last leaf, the root is computed. */
    return (sub->current_index >= ((uint64_t)1u << sub_h)) ? 1 : 0;
}

/* ---- Step 4 phase B: KeyGen streaming root generation + auth-path cache (design doc §8.1) ----
 *
 * Architecture (matching hash-sigs: KeyGen root generation and the signature cache are two independent operations):
 *   - lms_tree_keygen_root: one-pass traversal of 2^h leaves, subtrees stream-generate the public-key root,
 *     memory O(sublevels) in-building subtrees (H15 full build is 2MiB, exceeding the SoC's 128KiB, so
 *     streaming is required). Only produces the root; keeps no signature cache.
 *   - lms_tree_sign_init: build each level's ACTIVE subtree cache for q=0 (once before signing).
 *   - lms_tree_sign_auth_path: table lookup and join (same as lms_tree_auth_path, O(h) zero recomputation).
 *   - lms_tree_sign_advance: cache-invalidation rebuild (see the function comment).
 *
 * Cache model (decided 2026-07-30: cache-invalidation rebuild, not hash-sigs' double-buffered incremental building):
 *   Tree levels are pure software (hardware never touches trees), no real-time flattening constraint, so we
 *   **do not** implement multi-level HSS's ACTIVE/UPCOMING double-buffered + incremental-per-leaf-between-
 *   signatures state machine. Each level caches only one ACTIVE subtree; consecutive signature q's mostly fall
 *   in the same subtree group (cache hit: O(h) lookup, zero recomputation); only crossing a subtree boundary
 *   rebuilds that level via subtree_build_at (bottom frequency 1/2^j, higher levels lower). UPCOMING buffers
 *   serve only as temporary scratch for subtree_build_at's recursive building; they carry no signature-cache
 *   semantics.
 *
 * Subtree-covered real-leaf segment (cache-hit check): a sublevel s subtree's root is at whole-tree level
 * root_level (=s*j+height), covering 2^root_level real leaves, segment [leaf_lo, leaf_lo+2^root_level).
 * leaf_lo is derived from left_leaf (leaf-level number) via subtree_leaf_lo. The top level (root_level=h,
 * covering all real leaves) is never rebuilt.
 */

/* Compute a real leaf's D_LEAF value: if leaf_fn is registered, prefer the hardware direct output (skipping
 * K_q out of hardware + software SHA-256); otherwise produce the LM-OTS public key via the K_q source →
 * prefix (whole-tree leaf number) → hash. */
static int subtree_compute_leaf(lms_tree_ctx_t *ctx,
                                const lms_private_key_t *priv,
                                lms_subtree_ots_pub_fn ots_pub,
                                uint32_t q,
                                uint8_t leaf[LMS_N])
{
    uint8_t ots_pub_buf[LMS_N];
    uint8_t prefix[LMS_I_LEN + 4 + 2];
    uint32_t node_num = (uint32_t)((1u << ctx->height) + q); /* whole-tree leaf node number */

    if (ctx->leaf_fn != NULL) {
        (void)ots_pub;
        return ctx->leaf_fn(ctx->leaf_fn_ctx, priv, q, leaf);
    }
    if (ots_pub(ctx->ots_pub_ctx, priv, q, ots_pub_buf) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    memcpy(prefix, ctx->I, LMS_I_LEN);
    lms_store_u32(prefix + LMS_I_LEN, node_num);
    lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);
    return lms_hash_parts(prefix, sizeof(prefix), ots_pub_buf, LMS_N,
                          NULL, 0, NULL, 0, (lms_hash_alg_t)ctx->hash_alg, leaf);
}

/* Merge one real leaf into the bottom subtree (sublevel0) (leaf computed on the fly for q via the K_q source).
 * Returns add_next_node's result (1=this subtree completed). */
static int subtree_push_leaf(lms_tree_ctx_t *ctx,
                             const lms_private_key_t *priv,
                             lms_subtree_ots_pub_fn ots_pub,
                             lms_subtree_t *sub,
                             uint32_t q,
                             uint8_t leaf[LMS_N])
{
    if (subtree_compute_leaf(ctx, priv, ots_pub, q, leaf) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    return lms_tree_add_next_node(sub, leaf, ctx->I, ctx->hash_alg, ctx->n);
}

/* Reset a subtree to an "empty in-building state covering the given left_leaf". */
static void subtree_reset_to(lms_subtree_t *sub, uint64_t left_leaf)
{
    sub->left_leaf = left_leaf;
    sub->current_index = 0u;
}

/* Fully build one sublevel0 (bottom, leaves=real leaves) subtree, covering the real-leaf segment [left_leaf, ...).
 * Leaf values are computed on the fly as D_LEAF via the K_q source. left_leaf is the global real-leaf number. */
static int subtree_build_bottom(lms_tree_ctx_t *ctx,
                                const lms_private_key_t *priv,
                                lms_subtree_ots_pub_fn ots_pub,
                                lms_subtree_t *sub,
                                uint64_t left_leaf)
{
    uint32_t count = 1u << sub->height;
    uint32_t i;
    uint8_t leaf[LMS_N];
    int done = 0;

    subtree_reset_to(sub, left_leaf);
    for (i = 0u; i < count; i++) {
        done = subtree_push_leaf(ctx, priv, ots_pub, sub,
                                 (uint32_t)(left_leaf + i), leaf);
        if (done < 0) {
            return LMS_ERR_INVALID;
        }
    }
    return (done == 1) ? LMS_OK : LMS_ERR_INVALID;
}

/* Fully build one upper-level (sublevel≥1, leaves=lower subtree roots) subtree.
 * Leaf values come from the externally provided sequence lower_roots[0..2^sub_h-1] (= the lower level's
 * corresponding subtree roots).
 * left_leaf is the leftmost leaf this subtree covers, numbered in its own "leaf level" (for whole-tree
 * numbering). */
static int subtree_build_upper(lms_tree_ctx_t *ctx,
                               lms_subtree_t *sub,
                               uint64_t left_leaf,
                               const uint8_t *lower_roots)
{
    uint32_t count = 1u << sub->height;
    uint32_t i;
    int done = 0;

    subtree_reset_to(sub, left_leaf);
    for (i = 0u; i < count; i++) {
        done = lms_tree_add_next_node(sub, lower_roots + (size_t)i * ctx->n,
                                      ctx->I, ctx->hash_alg, ctx->n);
        if (done < 0) {
            return LMS_ERR_INVALID;
        }
    }
    return (done == 1) ? LMS_OK : LMS_ERR_INVALID;
}

/* Build the root of the sublevel s subtree covering the real-leaf segment starting at leaf_lo; store the
 * result in scratch.
 *   - s==0: leaves=real leaves, directly subtree_build_bottom (leaf_lo is a real-leaf number).
 *   - s>=1: leaves=roots of the 2^(scratch->height) sublevel(s-1) subtrees, built recursively one by one
 *     (each uses its level sublevel(s-1)'s upcoming buffer as scratch; further down, sublevel(s-2)'s
 *     upcoming……each level's upcoming is independent, so recursion does not conflict). Each level's roots
 *     are stored in **separately allocated** buffers (via ctx->alloc, freed right after building) — to
 *     avoid multiple levels sharing one roots buffer and overwriting each other.
 * scratch's geometry fields (level/levels_below/tree_height) are set by this function per sublevel s.
 * leaf_lo is always a global real-leaf number. After building, scratch->nodes[1*n] is this subtree's root. */
static int subtree_build_at(lms_tree_ctx_t *ctx,
                            const lms_private_key_t *priv,
                            lms_subtree_ots_pub_fn ots_pub,
                            uint32_t s,
                            uint64_t leaf_lo,
                            lms_subtree_t *scratch)
{
    uint32_t j = ctx->subtree_size;

    scratch->level = s * j + scratch->height;
    scratch->levels_below = s * j;
    scratch->tree_height = ctx->height;

    if (s == 0u) {
        return subtree_build_bottom(ctx, priv, ots_pub, scratch, leaf_lo);
    }
    {
        lms_subtree_t *lower_scratch = &ctx->levels[s - 1u].upcoming;
        uint32_t cnt = 1u << scratch->height;   /* this level's leaf count = number of lower subtrees */
        /* Real leaves covered by each lower subtree = 2^(lower subtree root's whole-tree level) = 2^((s-1)*j + lower_height). */
        uint32_t lower_root_level = (s - 1u) * j + lower_scratch->height;
        uint64_t lower_span = (uint64_t)1u << lower_root_level;
        uint8_t *my_roots;  /* this level's independent roots staging (lower recursion allocates its own; no overlap) */
        uint32_t k;
        int rc;

        my_roots = (uint8_t *)ctx->alloc(ctx->alloc_ctx, (size_t)cnt * ctx->n);
        if (my_roots == NULL) {
            return LMS_ERR_INVALID;
        }
        rc = LMS_OK;
        for (k = 0u; k < cnt; k++) {
            if (subtree_build_at(ctx, priv, ots_pub, s - 1u,
                                 leaf_lo + (uint64_t)k * lower_span,
                                 lower_scratch) != LMS_OK) {
                rc = LMS_ERR_INVALID;
                break;
            }
            memcpy(my_roots + (size_t)k * ctx->n,
                   lower_scratch->nodes + (size_t)1u * ctx->n, ctx->n);
        }
        if (rc == LMS_OK) {
            /* This level's subtree left_leaf = leftmost leaf's number in its own "leaf level" (not the real-leaf number).
             * A sublevel s subtree's leaves are at whole-tree level s*j, each leaf covering 2^(s*j) real leaves, so
             * the leaf-level start number = leaf_lo >> (s*j). This is subtree_local_to_global's semantics
             * (k0 = left_leaf >> sub_h gives the subtree root's number at its leaf level). */
            rc = subtree_build_upper(ctx, scratch, leaf_lo >> (s * j), my_roots);
        }
        ctx->free(ctx->alloc_ctx, my_roots);
        return rc;
    }
}

int lms_tree_keygen_root(lms_tree_ctx_t *ctx,
                         const lms_private_key_t *priv,
                         uint8_t root[LMS_N])
{
    lms_subtree_ots_pub_fn ots_pub;
    uint64_t total_leaves;
    uint64_t q;
    uint8_t leaf[LMS_N];
    uint32_t s;

    if (ctx == NULL || priv == NULL || root == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;
    total_leaves = (uint64_t)1u << ctx->height;

    /* Reset all ACTIVE subtrees (keygen exclusively owns ctx; only ACTIVE is used for streaming root
     * generation; no signature cache is kept).
     * Note: do not touch has_upcoming (it reflects the buffer allocation decided by ctx_init; free relies
     * on it to release the UPCOMING buffers; zeroing it would leak UPCOMING nodes/stack). UPCOMING buffers
     * are not used by keygen. */
    for (s = 0u; s < ctx->sublevels; s++) {
        subtree_reset_to(&ctx->levels[s].active, 0u);
        ctx->levels[s].upcoming.current_index = 0u;
    }

    /* Iterate over real leaves: each time the bottom ACTIVE completes a subtree → merge its root as one leaf of the upper ACTIVE → level by level to the top. */
    for (q = 0u; q < total_leaves; q++) {
        lms_subtree_t *bot = &ctx->levels[0].active;
        int done = subtree_push_leaf(ctx, priv, ots_pub, bot, (uint32_t)q, leaf);
        if (done < 0) {
            return LMS_ERR_INVALID;
        }
        if (done == 1) {
            memcpy(leaf, bot->nodes + (size_t)1u * ctx->n, ctx->n);
            subtree_reset_to(bot, bot->left_leaf + ((uint64_t)1u << bot->height));
            for (s = 1u; s < ctx->sublevels; s++) {
                lms_subtree_t *up = &ctx->levels[s].active;
                int udone = lms_tree_add_next_node(up, leaf, ctx->I,
                                                   ctx->hash_alg, ctx->n);
                if (udone < 0) {
                    return LMS_ERR_INVALID;
                }
                if (udone != 1) {
                    break; /* this level not full yet; stop going upward */
                }
                memcpy(leaf, up->nodes + (size_t)1u * ctx->n, ctx->n);
                subtree_reset_to(up, up->left_leaf + ((uint64_t)1u << up->height));
            }
        }
    }

    /* Top-level ACTIVE root = public-key root. */
    memcpy(root, ctx->levels[ctx->sublevels - 1u].active.nodes + (size_t)1u * ctx->n,
           ctx->n);
    return LMS_OK;
}

int lms_tree_sign_init(lms_tree_ctx_t *ctx, const lms_private_key_t *priv)
{
    lms_subtree_ots_pub_fn ots_pub;
    uint32_t s;

    if (ctx == NULL || priv == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;

    /* Build each level's ACTIVE for q=0 (covering the real-leaf segment [0, ...)): subtree_build_at
     * bottom-up; sublevel0 leaves=real leaves; sublevel s(≥1) leaves=roots of the lower 2^j subtrees
     * (recursion uses each level's upcoming as scratch; at this point upcoming carries no signature-cache
     * semantics; each level's roots staging is separately allocated).
     * Cache-invalidation rebuild model: only one ACTIVE subtree per level is cached (covering the real-leaf
     * segment containing q); UPCOMING is not pre-built; when q goes out of range, sign_advance rebuilds the
     * corresponding level. */
    for (s = 0u; s < ctx->sublevels; s++) {
        if (subtree_build_at(ctx, priv, ots_pub, s, 0u,
                             &ctx->levels[s].active) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }
    return LMS_OK;
}

int lms_tree_sign_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path)
{
    if (ctx == NULL || path == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    /* Lookup logic matches lms_tree_auth_path (O(h) zero recomputation, RFC 8554 leaf-to-root order). */
    return lms_tree_auth_path(ctx, q, path);
}

/* The leftmost real-leaf number of the real-leaf segment a subtree covers (derived from geometry; unrelated
 * to the left_leaf semantics).
 * A sublevel s subtree's root is at whole-tree level root_level = s*j + height, covering 2^root_level real leaves.
 * Its covered segment's leftmost real leaf = the root's number at level root_level << root_level.
 * The root's in-level number = (left_leaf (leaf-level number) >> height) (k0 semantics), hence
 * leftmost real leaf = k0 << root_level. level/height/left_leaf are all set at build time and directly usable. */
static uint64_t subtree_leaf_lo(const lms_subtree_t *sub)
{
    uint64_t k0 = sub->left_leaf >> sub->height; /* subtree root's number at its leaf level */
    return k0 << sub->level;                     /* × 2^root_level = covered real-leaf start */
}

/* Real leaves covered by a subtree = 2^(root's whole-tree level) = 2^sub->level. */
static uint64_t subtree_leaf_span(const lms_subtree_t *sub)
{
    return (uint64_t)1u << sub->level;
}

int lms_tree_sign_advance(lms_tree_ctx_t *ctx,
                          const lms_private_key_t *priv,
                          uint32_t q)
{
    lms_subtree_ots_pub_fn ots_pub;
    uint32_t s;

    if (ctx == NULL || priv == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    if ((uint64_t)q >= ((uint64_t)1u << ctx->height)) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;

    /* Cache-invalidation rebuild (pure software, no hardware constraints, no double-buffered incremental
     * building): each level's ACTIVE caches "one subtree covering a real-leaf segment". When q leaves a
     * level's cached segment, rebuild that level as the subtree covering q via subtree_build_at.
     * Consecutive signatures mostly keep subtrees unchanged; only crossing a subtree boundary rebuilds the
     * corresponding level (bottom frequency 1/2^j, higher levels lower). The top level (covering all real
     * leaves) is never rebuilt. */
    for (s = 0u; s + 1u < ctx->sublevels; s++) {
        lms_subtree_t *active = &ctx->levels[s].active;
        uint64_t lo = subtree_leaf_lo(active);
        uint64_t span = subtree_leaf_span(active);
        uint64_t new_lo;

        if ((uint64_t)q - lo < span) {
            continue; /* q is inside this level's cached segment; no rebuild needed */
        }
        /* Rebuild this level's ACTIVE as the subtree covering q: segment start = floor(q/span)*span. */
        new_lo = ((uint64_t)q / span) * span;
        if (subtree_build_at(ctx, priv, ots_pub, s, new_lo, active) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }
    return LMS_OK;
}

/* ---- Design doc step 5: lms_sign auth-path backend adaptation ---- */

int lms_subtree_auth_path_backend(void *context,
                                  const lms_private_key_t *priv,
                                  uint32_t q,
                                  uint8_t *path)
{
    lms_tree_ctx_t *ctx = (lms_tree_ctx_t *)context;

    if (ctx == NULL || priv == NULL || path == NULL) {
        return LMS_ERR_INVALID;
    }
    /* First make every level's ACTIVE cover q (zero rebuild on cache hit), then look up and join the auth path. */
    if (lms_tree_sign_advance(ctx, priv, q) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    return lms_tree_sign_auth_path(ctx, q, path);
}
