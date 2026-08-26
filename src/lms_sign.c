#include "lms_internal.h"

/* Auth-path backend (design doc step 5): falls back to lms_tree_node recursion
 * (current behavior) when NULL. */
static lms_auth_path_backend_fn auth_path_backend;
static void *auth_path_backend_context;

void lms_auth_path_backend_set(lms_auth_path_backend_fn backend, void *context)
{
    auth_path_backend = backend;
    auth_path_backend_context = backend ? context : NULL;
}

/* REVIEW B03-R8: lms_intr_backend_set moved into lm_ots.c with its
 * encapsulation (intr_backend became static). */

int lms_do_sign(lms_private_key_t *priv,
                const uint8_t *message,
                size_t message_len,
                uint8_t *signature,
                size_t signature_len,
                size_t *written)
{
    lms_param_t lms_param;
    lmots_param_t ots_param;
    size_t needed;
    uint32_t q;
    uint32_t node_num;
    uint32_t i;
    uint8_t *path;

    if (!priv || !signature || (!message && message_len != 0)) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lms_param(priv->lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(priv->lmots_type, &ots_param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    needed = lms_signature_len(priv->lms_type, priv->lmots_type);
    if (signature_len < needed) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }
    if (priv->q >= (1u << lms_param.height)) {
        return LMS_ERR_EXHAUSTED;
    }

    q = priv->q;
    lms_store_u32(signature, q);

    if (lmots_sign(priv, q, message, message_len, signature + 4,
                   4u + ots_param.n + ots_param.p * ots_param.n) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    lms_store_u32(signature + 4u + 4u + ots_param.n + ots_param.p * ots_param.n, priv->lms_type);
    path = signature + 4u + 4u + ots_param.n + ots_param.p * ots_param.n + 4u;

    if (auth_path_backend) {
        /* Registered auth-path backend (e.g. lms_subtree cache lookup, O(h) with zero recomputation). */
        if (auth_path_backend(auth_path_backend_context, priv, q, path) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    } else {
        /* Default: recursive rebuild of each sibling via lms_tree_node (Sign's slow root cause; kept as fallback). */
        node_num = (1u << lms_param.height) + q;
        for (i = 0; i < lms_param.height; i++) {
            uint32_t sibling = node_num ^ 1u;
            if (lms_tree_node(priv, sibling, path + i * lms_param.n) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            node_num /= 2u;
        }
    }

    priv->q++;
    if (written) {
        *written = needed;
    }

    return LMS_OK;
}
