#include "lms_coprocess.h"

#include "lms_internal.h"

#include <string.h>

/* Default K_q source: forwards directly to lmots_public_from_private.
 * Pure software chain while no hardware backend is registered; automatically
 * hardware after lms_mmio_lmots_keygen_*_enable(). */
static int default_ots_pub(void *context,
                           const lms_private_key_t *priv,
                           uint32_t q,
                           uint8_t ots_pub[LMS_N])
{
    (void)context;
    return lmots_public_from_private(priv, q, ots_pub);
}

int lms_coprocess_tree_init(lms_coprocess_tree_t *tree,
                            uint32_t lms_type,
                            const uint8_t I[LMS_I_LEN])
{
    lms_param_t param;

    if (!tree || !I) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lms_param(lms_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (param.height == 0u || param.height > LMS_COPROCESS_MAX_HEIGHT) {
        return LMS_ERR_INVALID;
    }

    memset(tree, 0, sizeof(*tree));
    tree->lms_type = lms_type;
    tree->height = param.height;
    tree->n = param.n;
    tree->leaf_count = 1u << param.height;
    memcpy(tree->I, I, LMS_I_LEN);
    return LMS_OK;
}

int lms_coprocess_build(lms_coprocess_tree_t *tree,
                        const lms_private_key_t *priv,
                        lms_coprocess_ots_pub_fn ots_pub,
                        void *ots_pub_context)
{
    lms_hash_alg_t hash_alg;
    uint8_t ots_pub_buf[LMS_N];
    uint32_t leaf_base;
    uint32_t q;
    uint32_t r;

    if (!tree || !priv || tree->leaf_count == 0u) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != tree->lms_type) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (!ots_pub) {
        ots_pub = default_ots_pub;
    }

    leaf_base = tree->leaf_count;

    /* Leaf by leaf: K_q = LM-OTS public key (possibly via hardware backend); D_LEAF in software. */
    for (q = 0; q < tree->leaf_count; q++) {
        uint8_t prefix[LMS_I_LEN + 4 + 2];

        if (ots_pub(ots_pub_context, priv, q, ots_pub_buf) != LMS_OK) {
            return LMS_ERR_INVALID;
        }

        memcpy(prefix, tree->I, LMS_I_LEN);
        lms_store_u32(prefix + LMS_I_LEN, leaf_base + q);
        lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);
        if (lms_hash_parts(prefix, sizeof(prefix), ots_pub_buf, LMS_N,
                           NULL, 0, NULL, 0, hash_alg,
                           tree->nodes[leaf_base + q]) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }

    /* Bottom-up: internal nodes D_INTR (software). */
    for (r = leaf_base; r-- > 1u; ) {
        if (lms_internal_node(tree->I, hash_alg, r,
                              tree->nodes[r * 2u],
                              tree->nodes[r * 2u + 1u],
                              tree->nodes[r]) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }

    return LMS_OK;
}

int lms_coprocess_root(const lms_coprocess_tree_t *tree, uint8_t root[LMS_N])
{
    if (!tree || !root || tree->leaf_count == 0u) {
        return LMS_ERR_INVALID;
    }
    memcpy(root, tree->nodes[1], LMS_N);
    return LMS_OK;
}

int lms_coprocess_node(const lms_coprocess_tree_t *tree,
                       uint32_t node_num,
                       uint8_t out[LMS_N])
{
    if (!tree || !out || tree->leaf_count == 0u) {
        return LMS_ERR_INVALID;
    }
    if (node_num == 0u || node_num > (tree->leaf_count * 2u - 1u)) {
        return LMS_ERR_INVALID;
    }
    memcpy(out, tree->nodes[node_num], LMS_N);
    return LMS_OK;
}

int lms_coprocess_auth_path(const lms_coprocess_tree_t *tree,
                            uint32_t q,
                            uint8_t *path)
{
    uint32_t node_num;
    uint32_t i;

    if (!tree || !path || tree->leaf_count == 0u) {
        return LMS_ERR_INVALID;
    }
    if (q >= tree->leaf_count) {
        return LMS_ERR_INVALID;
    }

    node_num = tree->leaf_count + q;
    for (i = 0; i < tree->height; i++) {
        uint32_t sibling = node_num ^ 1u;
        memcpy(path + (size_t)i * tree->n, tree->nodes[sibling], tree->n);
        node_num /= 2u;
    }
    return LMS_OK;
}

int lms_coprocess_root_from_kv(const lms_coprocess_tree_t *tree,
                               uint32_t q,
                               const uint8_t kv[LMS_N],
                               const uint8_t *auth_path,
                               uint8_t root[LMS_N])
{
    lms_hash_alg_t hash_alg;
    uint8_t node[LMS_N];
    uint8_t sibling[LMS_N];
    uint32_t node_num;
    uint32_t i;

    if (!tree || !kv || !auth_path || !root || tree->leaf_count == 0u) {
        return LMS_ERR_INVALID;
    }
    if (q >= tree->leaf_count) {
        return LMS_ERR_INVALID;
    }
    /* hash_alg is determined by lms_type; build a temporary public-key view to reuse the parsing. */
    {
        lms_param_t param;
        if (lms_get_lms_param(tree->lms_type, &param) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
        hash_alg = param.hash_alg;
    }

    node_num = tree->leaf_count + q;

    /* D_LEAF (software). */
    {
        uint8_t prefix[LMS_I_LEN + 4 + 2];
        memcpy(prefix, tree->I, LMS_I_LEN);
        lms_store_u32(prefix + LMS_I_LEN, node_num);
        lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);
        if (lms_hash_parts(prefix, sizeof(prefix), kv, LMS_N,
                           NULL, 0, NULL, 0, hash_alg, node) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }

    /* Per-level D_INTR (software); direction decided by node parity. */
    for (i = 0; i < tree->height; i++) {
        memcpy(sibling, auth_path + (size_t)i * tree->n, tree->n);
        if ((node_num & 1u) == 0u) {
            if (lms_internal_node(tree->I, hash_alg, node_num / 2u,
                                  node, sibling, node) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
        } else {
            if (lms_internal_node(tree->I, hash_alg, node_num / 2u,
                                  sibling, node, node) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
        }
        node_num /= 2u;
    }

    memcpy(root, node, LMS_N);
    return LMS_OK;
}

int lms_coprocess_verify(const lms_coprocess_tree_t *tree,
                         uint32_t q,
                         const uint8_t kv[LMS_N],
                         const uint8_t *auth_path)
{
    uint8_t root[LMS_N];
    uint8_t expected[LMS_N];
    uint8_t diff = 0;
    uint32_t i;

    if (lms_coprocess_root_from_kv(tree, q, kv, auth_path, root) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (lms_coprocess_root(tree, expected) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    for (i = 0; i < LMS_N; i++) {
        diff |= (uint8_t)(root[i] ^ expected[i]);
    }
    return diff == 0 ? LMS_OK : LMS_ERR_VERIFY;
}
