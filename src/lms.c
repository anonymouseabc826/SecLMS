#include "lms.h"

#include "lms_internal.h"

#include <string.h>

int lms_private_key_init(lms_private_key_t *priv,
                         uint32_t lms_type,
                         uint32_t lmots_type,
                         const uint8_t I[LMS_I_LEN],
                         const uint8_t seed[LMS_SEED_LEN])
{
    lms_param_t lms_param;
    lmots_param_t ots_param;

    if (!priv || !I || !seed) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lms_param(lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(lmots_type, &ots_param) != LMS_OK ||
        lms_param.hash_alg != ots_param.hash_alg) {
        return LMS_ERR_INVALID;
    }

    priv->lms_type = lms_type;
    priv->lmots_type = lmots_type;
    memcpy(priv->I, I, LMS_I_LEN);
    memcpy(priv->seed, seed, LMS_SEED_LEN);
    priv->q = 0;

    return LMS_OK;
}

int lms_public_key_generate(const lms_private_key_t *priv,
                            lms_public_key_t *pub)
{
    if (!priv || !pub) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lms_param(priv->lms_type, NULL) != LMS_OK ||
        lms_get_lmots_param(priv->lmots_type, NULL) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    pub->lms_type = priv->lms_type;
    pub->lmots_type = priv->lmots_type;
    memcpy(pub->I, priv->I, LMS_I_LEN);

    return lms_tree_node(priv, 1, pub->root);
}

int lms_public_key_serialize(const lms_public_key_t *pub,
                             uint8_t *out,
                             size_t out_len)
{
    if (!pub || !out) {
        return LMS_ERR_INVALID;
    }
    if (out_len < LMS_PUBLIC_KEY_LEN) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }

    lms_store_u32(out, pub->lms_type);
    lms_store_u32(out + 4, pub->lmots_type);
    memcpy(out + 8, pub->I, LMS_I_LEN);
    memcpy(out + 8 + LMS_I_LEN, pub->root, LMS_N);

    return LMS_OK;
}

int lms_public_key_parse(lms_public_key_t *pub,
                         const uint8_t *in,
                         size_t in_len)
{
    lms_param_t lms_param;
    lmots_param_t ots_param;

    if (!pub || !in || in_len != LMS_PUBLIC_KEY_LEN) {
        return LMS_ERR_INVALID;
    }

    pub->lms_type = lms_load_u32(in);
    pub->lmots_type = lms_load_u32(in + 4);
    if (lms_get_lms_param(pub->lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(pub->lmots_type, &ots_param) != LMS_OK ||
        lms_param.hash_alg != ots_param.hash_alg) {
        return LMS_ERR_INVALID;
    }
    memcpy(pub->I, in + 8, LMS_I_LEN);
    memcpy(pub->root, in + 8 + LMS_I_LEN, LMS_N);

    return LMS_OK;
}

int lms_private_key_serialize(const lms_private_key_t *priv,
                              uint8_t *out,
                              size_t out_len)
{
    if (!priv || !out) {
        return LMS_ERR_INVALID;
    }
    if (out_len < LMS_PRIVATE_KEY_LEN) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }

    lms_store_u32(out, priv->lms_type);
    lms_store_u32(out + 4, priv->lmots_type);
    memcpy(out + 8, priv->I, LMS_I_LEN);
    memcpy(out + 8 + LMS_I_LEN, priv->seed, LMS_SEED_LEN);
    lms_store_u32(out + 8 + LMS_I_LEN + LMS_SEED_LEN, priv->q);

    return LMS_OK;
}

int lms_private_key_parse(lms_private_key_t *priv,
                          const uint8_t *in,
                          size_t in_len)
{
    lms_param_t lms_param;
    lmots_param_t ots_param;

    if (!priv || !in || in_len != LMS_PRIVATE_KEY_LEN) {
        return LMS_ERR_INVALID;
    }

    priv->lms_type = lms_load_u32(in);
    priv->lmots_type = lms_load_u32(in + 4);
    if (lms_get_lms_param(priv->lms_type, &lms_param) != LMS_OK ||
        lms_get_lmots_param(priv->lmots_type, &ots_param) != LMS_OK ||
        lms_param.hash_alg != ots_param.hash_alg) {
        return LMS_ERR_INVALID;
    }
    memcpy(priv->I, in + 8, LMS_I_LEN);
    memcpy(priv->seed, in + 8 + LMS_I_LEN, LMS_SEED_LEN);
    priv->q = lms_load_u32(in + 8 + LMS_I_LEN + LMS_SEED_LEN);
    if (priv->q > (1u << lms_param.height)) {
        return LMS_ERR_INVALID;
    }

    return LMS_OK;
}

int lms_sign(lms_private_key_t *priv,
             const uint8_t *message,
             size_t message_len,
             uint8_t *signature,
             size_t signature_len,
             size_t *written)
{
    return lms_do_sign(priv, message, message_len, signature, signature_len, written);
}

int lms_verify(const lms_public_key_t *pub,
               const uint8_t *message,
               size_t message_len,
               const uint8_t *signature,
               size_t signature_len)
{
    uint8_t root[LMS_N];
    uint8_t diff = 0;
    uint32_t i;

    if (!pub || !signature || (!message && message_len != 0)) {
        return LMS_ERR_INVALID;
    }
    if (lms_root_from_signature(pub, message, message_len, signature, signature_len, root) != LMS_OK) {
        return LMS_ERR_VERIFY;
    }

    for (i = 0; i < LMS_N; i++) {
        diff |= (uint8_t)(root[i] ^ pub->root[i]);
    }

    return diff == 0 ? LMS_OK : LMS_ERR_VERIFY;
}
