#include "lms_internal.h"

#include <string.h>

static lmots_chain_stats_t chain_stats;
static lmots_chain_backend_fn keygen_chain_backend;
static void *keygen_chain_backend_context;
static lmots_chain_backend_fn verify_chain_backend;
static void *verify_chain_backend_context;
static lmots_chain_backend_fn sign_chain_backend;
static void *sign_chain_backend_context;
static lmots_derive_chain_backend_fn keygen_derive_backend;
static void *keygen_derive_backend_context;
static lmots_keygen_backend_fn keygen_backend;
static void *keygen_backend_context;
static lmots_sign_backend_fn sign_backend;
static void *sign_backend_context;
static lmots_verify_backend_fn verify_backend;
static void *verify_backend_context;
static lmots_verify_leaf_backend_fn verify_leaf_backend;
static void *verify_leaf_backend_context;
static lmots_derive_chain_backend_fn sign_derive_backend;
static void *sign_derive_backend_context;
static lmots_randomizer_backend_fn sign_randomizer_backend;
static void *sign_randomizer_backend_context;
static lms_intr_backend_fn intr_backend;
static void *intr_backend_context;
static lmots_message_hash_backend_fn message_hash_backend;
static void *message_hash_backend_context;
static lmots_coef_backend_fn coef_backend;
static void *coef_backend_context;

/* REVIEW B03-R8: intr_backend encapsulation (static + setter + available/run),
 * aligned with the other backends' "file-local static + *_backend_set" pattern. */
void lms_intr_backend_set(lms_intr_backend_fn backend, void *context)
{
    intr_backend = backend;
    intr_backend_context = backend ? context : NULL;
}

int lms_intr_backend_available(void)
{
    return intr_backend != 0;
}

int lms_intr_backend_run(const uint8_t I[LMS_I_LEN], lms_hash_alg_t hash_alg,
                         uint32_t node_num, const uint8_t left[LMS_N],
                         const uint8_t right[LMS_N], uint8_t out[LMS_N])
{
    if (!intr_backend) {
        return LMS_ERR_INVALID;
    }
    return intr_backend(intr_backend_context, I, hash_alg, node_num, left, right, out);
}

void lmots_keygen_chain_backend_set(lmots_chain_backend_fn backend, void *context)
{
    keygen_chain_backend = backend;
    keygen_chain_backend_context = backend ? context : NULL;
}

void lmots_verify_chain_backend_set(lmots_chain_backend_fn backend, void *context)
{
    verify_chain_backend = backend;
    verify_chain_backend_context = backend ? context : NULL;
}

void lmots_sign_chain_backend_set(lmots_chain_backend_fn backend, void *context)
{
    sign_chain_backend = backend;
    sign_chain_backend_context = backend ? context : NULL;
}

void lmots_keygen_derive_backend_set(lmots_derive_chain_backend_fn backend, void *context)
{
    keygen_derive_backend = backend;
    keygen_derive_backend_context = backend ? context : NULL;
}

void lmots_keygen_backend_set(lmots_keygen_backend_fn backend, void *context)
{
    keygen_backend = backend;
    keygen_backend_context = backend ? context : NULL;
}

void lmots_sign_backend_set(lmots_sign_backend_fn backend, void *context)
{
    sign_backend = backend;
    sign_backend_context = backend ? context : NULL;
}

void lmots_verify_backend_set(lmots_verify_backend_fn backend, void *context)
{
    verify_backend = backend;
    verify_backend_context = backend ? context : NULL;
}

void lmots_verify_leaf_backend_set(lmots_verify_leaf_backend_fn backend, void *context)
{
    verify_leaf_backend = backend;
    verify_leaf_backend_context = backend ? context : NULL;
}

void lmots_sign_derive_backend_set(lmots_derive_chain_backend_fn backend, void *context)
{
    sign_derive_backend = backend;
    sign_derive_backend_context = backend ? context : NULL;
}

void lmots_sign_randomizer_backend_set(lmots_randomizer_backend_fn backend, void *context)
{
    sign_randomizer_backend = backend;
    sign_randomizer_backend_context = backend ? context : NULL;
}

void lmots_message_hash_backend_set(lmots_message_hash_backend_fn backend, void *context)
{
    message_hash_backend = backend;
    message_hash_backend_context = backend ? context : NULL;
}

void lmots_coef_backend_set(lmots_coef_backend_fn backend, void *context)
{
    coef_backend = backend;
    coef_backend_context = backend ? context : NULL;
}

void lmots_chain_stats_reset(void)
{
    memset(&chain_stats, 0, sizeof(chain_stats));
}

void lmots_chain_stats_get(lmots_chain_stats_t *stats)
{
    if (stats) {
        *stats = chain_stats;
    }
}

int lmots_private_value(const lms_private_key_t *priv,
                        uint32_t q,
                        uint32_t i,
                        uint8_t out[LMS_N])
{
    uint8_t prefix[LMS_I_LEN + 4 + 2 + 1 + LMS_SEED_LEN];
    lms_hash_alg_t hash_alg;

    if (!priv || !out || i > UINT16_MAX ||
        lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    memcpy(prefix, priv->I, LMS_I_LEN);
    lms_store_u32(prefix + LMS_I_LEN, q);
    lms_store_u16(prefix + LMS_I_LEN + 4, (uint16_t)i);
    prefix[LMS_I_LEN + 6] = 0xffu;
    memcpy(prefix + LMS_I_LEN + 7, priv->seed, LMS_SEED_LEN);

    return lms_hash(hash_alg, prefix, sizeof(prefix), out, LMS_N) == 0 ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_randomizer(const lms_private_key_t *priv,
                            uint32_t q,
                            uint8_t out[LMS_N])
{
    lms_hash_alg_t hash_alg;

    if (lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (sign_randomizer_backend) {
        return sign_randomizer_backend(sign_randomizer_backend_context,
                                       priv->I, hash_alg, q, out);
    }

    {
    uint8_t prefix[LMS_I_LEN + 4 + 2 + LMS_SEED_LEN];
    memcpy(prefix, priv->I, LMS_I_LEN);
    lms_store_u32(prefix + LMS_I_LEN, q);
    lms_store_u16(prefix + LMS_I_LEN + 4, LMOTS_C_PRG_DOMAIN);
    memcpy(prefix + LMS_I_LEN + 6, priv->seed, LMS_SEED_LEN);

    return lms_hash(hash_alg, prefix, sizeof(prefix), out, LMS_N) == 0 ? LMS_OK : LMS_ERR_INVALID;
    }
}

int lmots_chain_compute(const uint8_t I[LMS_I_LEN],
                        lms_hash_alg_t hash_alg,
                        uint32_t q,
                        uint32_t i,
                        uint32_t start,
                        uint32_t steps,
                        uint8_t value[LMS_N])
{
    uint8_t buf[LMS_I_LEN + 4 + 2 + 1 + LMS_N];
    uint32_t j;

    if (!I || !value || i > UINT16_MAX || start > UINT8_MAX ||
        steps > UINT8_MAX || start + steps > UINT8_MAX) {
        return LMS_ERR_INVALID;
    }

    memcpy(buf, I, LMS_I_LEN);
    lms_store_u32(buf + LMS_I_LEN, q);
    lms_store_u16(buf + LMS_I_LEN + 4, (uint16_t)i);
    chain_stats.calls++;

    for (j = start; j < start + steps; j++) {
        buf[LMS_I_LEN + 6] = (uint8_t)j;
        memcpy(buf + LMS_I_LEN + 7, value, LMS_N);
        if (lms_hash(hash_alg, buf, sizeof(buf), value, LMS_N) != 0) {
            return LMS_ERR_INVALID;
        }
        chain_stats.steps++;
    }

    return LMS_OK;
}

static int lmots_keygen_chain_compute(const uint8_t I[LMS_I_LEN],
                                      lms_hash_alg_t hash_alg,
                                      uint32_t q,
                                      uint32_t i,
                                      uint32_t start,
                                      uint32_t steps,
                                      uint8_t value[LMS_N])
{
    int status;

    if (!keygen_chain_backend) {
        return lmots_chain_compute(I, hash_alg, q, i, start, steps, value);
    }

    chain_stats.calls++;
    status = keygen_chain_backend(keygen_chain_backend_context,
                                  I, hash_alg, q, i, start, steps, value);
    if (status == LMS_OK) {
        chain_stats.steps += steps;
    }
    return status;
}

static int lmots_verify_chain_compute(const uint8_t I[LMS_I_LEN],
                                      lms_hash_alg_t hash_alg,
                                      uint32_t q,
                                      uint32_t i,
                                      uint32_t start,
                                      uint32_t steps,
                                      uint8_t value[LMS_N])
{
    int status;

    if (!verify_chain_backend) {
        return lmots_chain_compute(I, hash_alg, q, i, start, steps, value);
    }

    chain_stats.calls++;
    status = verify_chain_backend(verify_chain_backend_context,
                                  I, hash_alg, q, i, start, steps, value);
    if (status == LMS_OK) {
        chain_stats.steps += steps;
    }
    return status;
}

static int lmots_sign_chain_compute(const uint8_t I[LMS_I_LEN],
                                    lms_hash_alg_t hash_alg,
                                    uint32_t q,
                                    uint32_t i,
                                    uint32_t start,
                                    uint32_t steps,
                                    uint8_t value[LMS_N])
{
    int status;

    if (!sign_chain_backend) {
        return lmots_chain_compute(I, hash_alg, q, i, start, steps, value);
    }

    chain_stats.calls++;
    status = sign_chain_backend(sign_chain_backend_context,
                                I, hash_alg, q, i, start, steps, value);
    if (status == LMS_OK) {
        chain_stats.steps += steps;
    }
    return status;
}

static int lmots_message_hash(const uint8_t I[LMS_I_LEN],
                              lms_hash_alg_t hash_alg,
                              uint32_t q,
                              const uint8_t C[LMS_N],
                              const uint8_t *message,
                              size_t message_len,
                              uint8_t Q[LMS_N + 2])
{
    if (message_hash_backend) {
        return message_hash_backend(message_hash_backend_context,
                                    I, hash_alg, q, C,
                                    message, message_len, Q);
    }

    {
    uint8_t prefix[LMS_I_LEN + 4 + 2 + LMS_N];
    uint8_t digest[LMS_N];

    if (!message && message_len != 0) {
        return LMS_ERR_INVALID;
    }

    memcpy(prefix, I, LMS_I_LEN);
    lms_store_u32(prefix + LMS_I_LEN, q);
    lms_store_u16(prefix + LMS_I_LEN + 4, D_MESG);
    memcpy(prefix + LMS_I_LEN + 6, C, LMS_N);

    if (lms_hash_parts(prefix, sizeof(prefix), message, message_len, NULL, 0, NULL, 0, hash_alg, digest) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    memcpy(Q, digest, LMS_N);
    return LMS_OK;
    }
}

int lmots_public_from_signature(const uint8_t I[LMS_I_LEN],
                                lms_hash_alg_t hash_alg,
                                uint32_t q,
                                uint32_t expected_type,
                                const uint8_t *message,
                                size_t message_len,
                                const uint8_t *signature,
                                size_t signature_len,
                                uint8_t pub[LMS_N])
{
    lmots_param_t param;
    uint8_t Q[LMS_N + 2];
    uint8_t chain_value[LMS_N];
    uint8_t pub_buf[LMS_MAX_OTS_P * LMS_N];
    uint8_t coefficients[LMS_MAX_OTS_P];
    const uint8_t *C;
    const uint8_t *y;
    uint32_t checksum;
    uint32_t i;

    if (lms_get_lmots_param(expected_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (!signature || signature_len != 4u + param.n + param.p * param.n) {
        return LMS_ERR_INVALID;
    }
    if (lms_load_u32(signature) != expected_type) {
        return LMS_ERR_VERIFY;
    }

    C = signature + 4;
    y = C + param.n;

    if (param.hash_alg != hash_alg) {
        return LMS_ERR_INVALID;
    }
    /* coef_backend: one hardware call yields Q + coefficients (incl. message hash); falls back to software on failure. */
    {
        int coef_ok = 0;
        if (coef_backend &&
            coef_backend(coef_backend_context, I, hash_alg, q, C,
                         message, message_len, expected_type,
                         Q, coefficients) == LMS_OK) {
            coef_ok = 1;
        }
        if (!coef_ok) {
            if (lmots_message_hash(I, hash_alg, q, C, message, message_len, Q) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            checksum = lms_lmots_checksum(Q, param.n, param.w, param.ls);
            lms_store_u16(Q + param.n, (uint16_t)checksum);
            if (verify_backend) {
                for (i = 0; i < param.p; i++) {
                    coefficients[i] = (uint8_t)lms_lmots_coef(Q, i, param.w);
                }
            }
        }
    }
    if (verify_backend) {
        return verify_backend(verify_backend_context, I, hash_alg, q,
                              expected_type, coefficients, y, pub);
    }

    for (i = 0; i < param.p; i++) {
        uint32_t a = lms_lmots_coef(Q, i, param.w);
        memcpy(chain_value, y + i * param.n, param.n);
        if (lmots_verify_chain_compute(I, hash_alg, q, i, a,
                                       ((1u << param.w) - 1u) - a,
                                       chain_value) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
        memcpy(pub_buf + i * param.n, chain_value, param.n);
    }

    {
        uint8_t prefix[LMS_I_LEN + 4 + 2];
        memcpy(prefix, I, LMS_I_LEN);
        lms_store_u32(prefix + LMS_I_LEN, q);
        lms_store_u16(prefix + LMS_I_LEN + 4, D_PBLC);
        return lms_hash_parts(prefix, sizeof(prefix), pub_buf, param.p * param.n, NULL, 0, NULL, 0, hash_alg, pub);
    }
}

int lmots_verify_leaf(const uint8_t I[LMS_I_LEN],
                      lms_hash_alg_t hash_alg,
                      uint32_t q,
                      uint32_t expected_type,
                      uint32_t node_num,
                      const uint8_t *message,
                      size_t message_len,
                      const uint8_t *signature,
                      size_t signature_len,
                      uint8_t leaf[LMS_N])
{
    lmots_param_t param;
    uint8_t Q[LMS_N + 2];
    uint8_t coefficients[LMS_MAX_OTS_P];
    const uint8_t *C;
    const uint8_t *y;
    uint32_t checksum;
    uint32_t i;

    if (lms_get_lmots_param(expected_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (!signature || signature_len != 4u + param.n + param.p * param.n) {
        return LMS_ERR_INVALID;
    }
    if (lms_load_u32(signature) != expected_type) {
        return LMS_ERR_VERIFY;
    }

    C = signature + 4;
    y = C + param.n;

    if (param.hash_alg != hash_alg) {
        return LMS_ERR_INVALID;
    }
    /* coef_backend: one hardware call yields Q + coefficients (incl. message hash); falls back to software on failure. */
    {
        int coef_ok = 0;
        if (coef_backend &&
            coef_backend(coef_backend_context, I, hash_alg, q, C,
                         message, message_len, expected_type,
                         Q, coefficients) == LMS_OK) {
            coef_ok = 1;
        }
        if (!coef_ok) {
            if (lmots_message_hash(I, hash_alg, q, C, message, message_len, Q) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            checksum = lms_lmots_checksum(Q, param.n, param.w, param.ls);
            lms_store_u16(Q + param.n, (uint16_t)checksum);
            for (i = 0; i < param.p; i++) {
                coefficients[i] = (uint8_t)lms_lmots_coef(Q, i, param.w);
            }
        }
    }
    if (verify_leaf_backend) {
        /* One hardware interaction: chain verify -> K_q -> D_LEAF -> leaf */
        return verify_leaf_backend(verify_leaf_backend_context, I, hash_alg, q,
                                   expected_type, coefficients, y, node_num, leaf);
    }

    /* Fallback: public_from_signature yields K_q + software D_LEAF */
    {
        uint8_t pub[LMS_N];
        if (lmots_public_from_signature(I, hash_alg, q, expected_type,
                                        message, message_len,
                                        signature, signature_len, pub) != LMS_OK) {
            return LMS_ERR_VERIFY;
        }
        {
            uint8_t prefix[LMS_I_LEN + 4 + 2];
            memcpy(prefix, I, LMS_I_LEN);
            lms_store_u32(prefix + LMS_I_LEN, node_num);
            lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);
            return lms_hash_parts(prefix, sizeof(prefix), pub, LMS_N,
                                  NULL, 0, NULL, 0, hash_alg, leaf);
        }
    }
}

int lmots_public_from_private(const lms_private_key_t *priv,
                              uint32_t q,
                              uint8_t pub[LMS_N])
{
    lmots_param_t param;
    lms_hash_alg_t hash_alg;
    uint8_t chain_value[LMS_N];
    uint8_t pub_buf[LMS_MAX_OTS_P * LMS_N];
    uint32_t i;

    if (lms_get_lmots_param(priv->lmots_type, &param) != LMS_OK ||
        lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (keygen_backend) {
        return keygen_backend(keygen_backend_context, priv->I, hash_alg, q,
                              priv->lmots_type, pub);
    }

    for (i = 0; i < param.p; i++) {
        uint32_t steps = (1u << param.w) - 1u;
        if (keygen_derive_backend) {
            chain_stats.calls++;
            if (keygen_derive_backend(keygen_derive_backend_context,
                                      priv->I, hash_alg, q, i, 0, steps,
                                      chain_value) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            chain_stats.steps += steps;
        } else {
            if (lmots_private_value(priv, q, i, chain_value) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            if (lmots_keygen_chain_compute(priv->I, hash_alg, q, i, 0,
                                           steps, chain_value) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
        }
        memcpy(pub_buf + i * param.n, chain_value, param.n);
    }

    {
        uint8_t prefix[LMS_I_LEN + 4 + 2];
        memcpy(prefix, priv->I, LMS_I_LEN);
        lms_store_u32(prefix + LMS_I_LEN, q);
        lms_store_u16(prefix + LMS_I_LEN + 4, D_PBLC);
        return lms_hash_parts(prefix, sizeof(prefix), pub_buf, param.p * param.n, NULL, 0, NULL, 0, hash_alg, pub);
    }
}

int lmots_sign(const lms_private_key_t *priv,
               uint32_t q,
               const uint8_t *message,
               size_t message_len,
               uint8_t *signature,
               size_t signature_len)
{
    lmots_param_t param;
    lms_hash_alg_t hash_alg;
    uint8_t Q[LMS_N + 2];
    uint8_t chain_value[LMS_N];
    uint8_t coefficients[LMS_MAX_OTS_P];
    uint32_t checksum;
    uint32_t i;

    if (lms_get_lmots_param(priv->lmots_type, &param) != LMS_OK ||
        lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (param.hash_alg != hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (!signature || signature_len < 4u + param.n + param.p * param.n) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }

    lms_store_u32(signature, priv->lmots_type);
    if (lmots_randomizer(priv, q, signature + 4) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    /* coef_backend (hardware Q+checksum+coefficients, superset incl. message
     * hash): one call yields Q + coefficients; on failure/not registered ->
     * fall back to the software checksum/coef loops (Q filled by hardware
     * message_hash or software). */
    {
        int coef_ok = 0;
        if (coef_backend &&
            coef_backend(coef_backend_context, priv->I, hash_alg, q, signature + 4,
                         message, message_len, priv->lmots_type,
                         Q, coefficients) == LMS_OK) {
            coef_ok = 1;
        }
        if (!coef_ok) {
            if (lmots_message_hash(priv->I, hash_alg, q, signature + 4,
                                   message, message_len, Q) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            checksum = lms_lmots_checksum(Q, param.n, param.w, param.ls);
            lms_store_u16(Q + param.n, (uint16_t)checksum);
            if (sign_backend) {
                for (i = 0; i < param.p; i++) {
                    coefficients[i] = (uint8_t)lms_lmots_coef(Q, i, param.w);
                }
            }
        }
    }
    if (sign_backend) {
        return sign_backend(sign_backend_context, priv->I, hash_alg, q,
                            priv->lmots_type, coefficients,
                            signature + 4u + param.n);
    }

    for (i = 0; i < param.p; i++) {
        uint32_t a = lms_lmots_coef(Q, i, param.w);
        if (sign_derive_backend) {
            chain_stats.calls++;
            if (sign_derive_backend(sign_derive_backend_context,
                                    priv->I, hash_alg, q, i, 0, a,
                                    chain_value) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            chain_stats.steps += a;
        } else {
            if (lmots_private_value(priv, q, i, chain_value) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            if (lmots_sign_chain_compute(priv->I, hash_alg, q, i, 0, a,
                                         chain_value) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
        }
        memcpy(signature + 4u + param.n + i * param.n, chain_value, param.n);
    }

    return LMS_OK;
}

/* UART bridge prepare (Step 3): Sign's randomizer C and Winternitz coefficients
 * (reuses internal lmots_randomizer/lmots_message_hash, avoiding firmware
 * duplicating the Q/checksum/coef logic). */
int lmots_sign_prepare(const lms_private_key_t *priv,
                       uint32_t q,
                       const uint8_t *message,
                       size_t message_len,
                       uint8_t C[LMS_N],
                       uint8_t coefficients[LMS_MAX_OTS_P])
{
    lmots_param_t param;
    lms_hash_alg_t hash_alg;
    uint8_t Q[LMS_N + 2];
    uint32_t checksum;
    uint32_t i;

    if (lms_get_lmots_param(priv->lmots_type, &param) != LMS_OK ||
        lms_get_private_hash_alg(priv, &hash_alg) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (param.hash_alg != hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (lmots_randomizer(priv, q, C) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    /* coef_backend: one hardware call yields Q + coefficients (incl. message hash); falls back to software on failure. */
    {
        int coef_ok = 0;
        if (coef_backend &&
            coef_backend(coef_backend_context, priv->I, hash_alg, q, C,
                         message, message_len, priv->lmots_type,
                         Q, coefficients) == LMS_OK) {
            coef_ok = 1;
        }
        if (!coef_ok) {
            if (lmots_message_hash(priv->I, hash_alg, q, C, message, message_len, Q) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            checksum = lms_lmots_checksum(Q, param.n, param.w, param.ls);
            lms_store_u16(Q + param.n, (uint16_t)checksum);
            for (i = 0; i < param.p; i++) {
                coefficients[i] = (uint8_t)lms_lmots_coef(Q, i, param.w);
            }
        }
    }
    return LMS_OK;
}

/* UART bridge prepare (Step 3): Verify's C is read from the signature by
 * firmware; computes Winternitz coefficients. */
int lmots_public_from_signature_prepare(const uint8_t I[LMS_I_LEN],
                                        lms_hash_alg_t hash_alg,
                                        uint32_t q,
                                        uint32_t expected_type,
                                        const uint8_t *message,
                                        size_t message_len,
                                        const uint8_t C[LMS_N],
                                        uint8_t coefficients[LMS_MAX_OTS_P])
{
    lmots_param_t param;
    uint8_t Q[LMS_N + 2];
    uint32_t checksum;
    uint32_t i;

    if (lms_get_lmots_param(expected_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (param.hash_alg != hash_alg) {
        return LMS_ERR_INVALID;
    }
    /* coef_backend: one hardware call yields Q + coefficients (incl. message hash); falls back to software on failure. */
    {
        int coef_ok = 0;
        if (coef_backend &&
            coef_backend(coef_backend_context, I, hash_alg, q, C,
                         message, message_len, expected_type,
                         Q, coefficients) == LMS_OK) {
            coef_ok = 1;
        }
        if (!coef_ok) {
            if (lmots_message_hash(I, hash_alg, q, C, message, message_len, Q) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            checksum = lms_lmots_checksum(Q, param.n, param.w, param.ls);
            lms_store_u16(Q + param.n, (uint16_t)checksum);
            for (i = 0; i < param.p; i++) {
                coefficients[i] = (uint8_t)lms_lmots_coef(Q, i, param.w);
            }
        }
    }
    return LMS_OK;
}
