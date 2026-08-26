#include "lms_internal.h"

#include <string.h>

/* Verify auth-path backend (CMD_D_INTR_CHAIN chained primitive): completes the
 * whole auth path in one shot */
static lms_verify_authpath_backend_fn verify_authpath_backend;
static void *verify_authpath_backend_context;

void lms_verify_authpath_backend_set(lms_verify_authpath_backend_fn backend,
                                     void *context)
{
    verify_authpath_backend = backend;
    verify_authpath_backend_context = backend ? context : NULL;
}

int lms_root_from_signature(const lms_public_key_t *pub,
                            const uint8_t *message,
                            size_t message_len,
                            const uint8_t *signature,
                            size_t signature_len,
                            uint8_t root[LMS_N])
{
    lms_param_t lms_param;
    lmots_param_t ots_param;
    const uint8_t *ots_sig;
    const uint8_t *path;
    uint8_t node[LMS_N];
    uint8_t sibling[LMS_N];
    lms_hash_alg_t hash_alg;
    uint32_t q;
    uint32_t node_num;
    uint32_t i;
    size_t ots_len;
    size_t expected_len;

    if (!pub || !signature) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lms_param(pub->lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(pub->lmots_type, &ots_param) != LMS_OK ||
        lms_get_public_hash_alg(pub, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    ots_len = 4u + ots_param.n + ots_param.p * ots_param.n;
    expected_len = 4u + ots_len + 4u + lms_param.height * lms_param.n;
    if (signature_len != expected_len) {
        return LMS_ERR_INVALID;
    }

    q = lms_load_u32(signature);
    if (q >= (1u << lms_param.height)) {
        return LMS_ERR_VERIFY;
    }

    ots_sig = signature + 4;
    if (lms_load_u32(ots_sig + ots_len) != pub->lms_type) {
        return LMS_ERR_VERIFY;
    }
    path = ots_sig + ots_len + 4;

    node_num = (1u << lms_param.height) + q;
    /* Get the leaf in one step: chain verify -> K_q -> D_LEAF (all hardware
     * when a VERIFY_LEAF backend is registered, replacing the previous
     * public_from_signature + software D_LEAF two steps). */
    if (lmots_verify_leaf(pub->I, hash_alg, q, pub->lmots_type, node_num,
                          message, message_len, ots_sig, ots_len, node) != LMS_OK) {
        return LMS_ERR_VERIFY;
    }

    /* Auth path: completed in one shot when a chained D_INTR primitive backend
     * is registered (leaf + sibling sequence -> root); otherwise falls back to
     * the current behavior (per-level lms_internal_node -> HASH_ONCE per interaction). */
    if (verify_authpath_backend) {
        if (verify_authpath_backend(verify_authpath_backend_context, pub->I, hash_alg,
                                    node_num, node, path, lms_param.height, root) != LMS_OK) {
            return LMS_ERR_VERIFY;
        }
    } else {
        for (i = 0; i < lms_param.height; i++) {
            memcpy(sibling, path + i * lms_param.n, lms_param.n);
            if ((node_num & 1u) == 0u) {
                if (lms_internal_node(pub->I, hash_alg, node_num / 2u, node, sibling, node) != LMS_OK) {
                    return LMS_ERR_INVALID;
                }
            } else {
                if (lms_internal_node(pub->I, hash_alg, node_num / 2u, sibling, node, node) != LMS_OK) {
                    return LMS_ERR_INVALID;
                }
            }
            node_num /= 2u;
        }
        memcpy(root, node, LMS_N);
    }
    return LMS_OK;
}
