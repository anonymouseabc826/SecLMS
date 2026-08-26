#include "lms_internal.h"

#include <string.h>

static int lms_leaf(const lms_private_key_t *priv,
                    uint32_t q,
                    uint8_t out[LMS_N])
{
    uint8_t ots_pub[LMS_N];
    uint8_t prefix[LMS_I_LEN + 4 + 2];
    lms_param_t lms_param;
    lms_hash_alg_t hash_alg;
    uint32_t node_num;

    if (lms_get_lms_param(priv->lms_type, &lms_param) != LMS_OK ||
        lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    node_num = (1u << lms_param.height) + q;
    if (lmots_public_from_private(priv, q, ots_pub) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    memcpy(prefix, priv->I, LMS_I_LEN);
    lms_store_u32(prefix + LMS_I_LEN, node_num);
    lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);

    return lms_hash_parts(prefix, sizeof(prefix), ots_pub, LMS_N, NULL, 0, NULL, 0, hash_alg, out);
}

int lms_internal_node(const uint8_t I[LMS_I_LEN],
                      lms_hash_alg_t hash_alg,
                      uint32_t node_num,
                      const uint8_t left[LMS_N],
                      const uint8_t right[LMS_N],
                      uint8_t out[LMS_N])
{
    if (lms_intr_backend_available()) {
        return lms_intr_backend_run(I, hash_alg, node_num, left, right, out);
    }
    {
        uint8_t prefix[LMS_I_LEN + 4 + 2];
        memcpy(prefix, I, LMS_I_LEN);
        lms_store_u32(prefix + LMS_I_LEN, node_num);
        lms_store_u16(prefix + LMS_I_LEN + 4, D_INTR);
        return lms_hash_parts(prefix, sizeof(prefix), left, LMS_N, right, LMS_N, NULL, 0, hash_alg, out);
    }
}

int lms_tree_node(const lms_private_key_t *priv,
                  uint32_t node_num,
                  uint8_t out[LMS_N])
{
    lms_param_t lms_param;
    uint32_t leaf_base;
    uint8_t left[LMS_N];
    uint8_t right[LMS_N];
    lms_hash_alg_t hash_alg;

    if (lms_get_lms_param(priv->lms_type, &lms_param) != LMS_OK ||
        lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    leaf_base = 1u << lms_param.height;
    if (node_num >= leaf_base) {
        return lms_leaf(priv, node_num - leaf_base, out);
    }

    if (lms_tree_node(priv, node_num * 2u, left) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (lms_tree_node(priv, node_num * 2u + 1u, right) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    return lms_internal_node(priv->I, hash_alg, node_num, left, right, out);
}
