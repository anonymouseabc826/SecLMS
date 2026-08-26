#include "hss.h"

#include "lms_internal.h"

#include <stdlib.h>
#include <string.h>

/* Byte-order access reuses lms_store_u32/lms_load_u32 (lms_internal.h), no local copies
 * (REVIEW B03-R4). */

static int lms_capacity(const lms_private_key_t *key, uint32_t *cap)
{
    lms_param_t param;
    if (lms_get_lms_param(key->lms_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    *cap = 1u << param.height;
    return LMS_OK;
}

static int derive_level_material(const hss_private_key_t *priv,
                                 uint32_t level,
                                 const uint8_t generation[HSS_GENERATION_LEN],
                                 uint8_t I[LMS_I_LEN],
                                 uint8_t seed[LMS_SEED_LEN])
{
    uint8_t input[HSS_MASTER_SEED_LEN + 4 + HSS_GENERATION_LEN + 1];
    uint8_t digest[LMS_N];
    lms_param_t lms_param;
    lms_hash_alg_t hash_alg;

    /* REVIEW B03-R1: the derivation PRF uses the hash function of this level's parameter set
     * (RFC 8554 §6.1), no longer hardcoded to LMS_HASH_SHA256. SHAKE256/Haraka are project-custom
     * typecodes: they run self-consistently here but are not interoperable with the RFC reference
     * (SHA256-path interop tests remain). */
    if (lms_get_lms_param(priv->lms_types[level], &lms_param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    hash_alg = lms_param.hash_alg;

    memcpy(input, priv->master_seed, HSS_MASTER_SEED_LEN);
    lms_store_u32(input + HSS_MASTER_SEED_LEN, level);
    memcpy(input + HSS_MASTER_SEED_LEN + 4, generation, HSS_GENERATION_LEN);

    input[HSS_MASTER_SEED_LEN + 4 + HSS_GENERATION_LEN] = 0x49u;
    if (lms_hash(hash_alg, input, sizeof(input), digest, sizeof(digest)) != 0) {
        return LMS_ERR_INVALID;
    }
    memcpy(I, digest, LMS_I_LEN);

    input[HSS_MASTER_SEED_LEN + 4 + HSS_GENERATION_LEN] = 0x53u;
    if (lms_hash(hash_alg, input, sizeof(input), seed, LMS_SEED_LEN) != 0) {
        return LMS_ERR_INVALID;
    }

    return LMS_OK;
}

static int build_level(hss_private_key_t *priv, uint32_t level)
{
    uint8_t I[LMS_I_LEN];
    uint8_t seed[LMS_SEED_LEN];

    if (derive_level_material(priv, level, priv->generation[level], I, seed) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (lms_private_key_init(&priv->keys[level],
                             priv->lms_types[level],
                             priv->lmots_types[level],
                             I,
                             seed) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (lms_public_key_generate(&priv->keys[level], &priv->pubs[level]) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    return LMS_OK;
}

static int increment_generation(uint8_t generation[HSS_GENERATION_LEN])
{
    size_t i = HSS_GENERATION_LEN;

    while (i > 0u) {
        i--;
        generation[i]++;
        if (generation[i] != 0u) {
            return LMS_OK;
        }
    }

    return LMS_ERR_EXHAUSTED;
}

static int sign_child_certificate(hss_private_key_t *priv, uint32_t parent_level)
{
    uint8_t child_pub[LMS_PUBLIC_KEY_LEN];
    size_t sig_len = 0;

    if (parent_level + 1u >= priv->levels) {
        return LMS_ERR_INVALID;
    }
    if (lms_public_key_serialize(&priv->pubs[parent_level + 1u], child_pub, sizeof(child_pub)) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (lms_sign(&priv->keys[parent_level],
                 child_pub,
                 sizeof(child_pub),
                 priv->cert_sig[parent_level],
                 sizeof(priv->cert_sig[parent_level]),
                 &sig_len) != LMS_OK) {
        return LMS_ERR_EXHAUSTED;
    }
    priv->cert_len[parent_level] = sig_len;
    return LMS_OK;
}

static int refresh_level_if_exhausted(hss_private_key_t *priv, uint32_t level)
{
    uint32_t cap;
    uint32_t j;

    if (lms_capacity(&priv->keys[level], &cap) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (priv->keys[level].q < cap) {
        return LMS_OK;
    }
    if (level == 0u) {
        return LMS_ERR_EXHAUSTED;
    }
    if (refresh_level_if_exhausted(priv, level - 1u) != LMS_OK) {
        return LMS_ERR_EXHAUSTED;
    }

    if (increment_generation(priv->generation[level]) != LMS_OK) {
        return LMS_ERR_EXHAUSTED;
    }
    if (build_level(priv, level) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (sign_child_certificate(priv, level - 1u) != LMS_OK) {
        return LMS_ERR_EXHAUSTED;
    }

    for (j = level + 1u; j < priv->levels; j++) {
        if (increment_generation(priv->generation[j]) != LMS_OK) {
            return LMS_ERR_EXHAUSTED;
        }
        if (build_level(priv, j) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
        if (sign_child_certificate(priv, j - 1u) != LMS_OK) {
            return LMS_ERR_EXHAUSTED;
        }
    }

    return LMS_OK;
}

int hss_private_key_init(hss_private_key_t *priv,
                         uint32_t levels,
                         const uint32_t *lms_types,
                         const uint32_t *lmots_types,
                         const uint8_t master_seed[HSS_MASTER_SEED_LEN])
{
    uint32_t i;

    if (!priv || !lms_types || !lmots_types || !master_seed) {
        return LMS_ERR_INVALID;
    }
    if (levels == 0u || levels > HSS_MAX_LEVELS) {
        return LMS_ERR_INVALID;
    }

    memset(priv, 0, sizeof(*priv));
    priv->levels = levels;
    memcpy(priv->master_seed, master_seed, HSS_MASTER_SEED_LEN);

    /* REVIEW B03-R1: RFC 8554 §6.1 requires all HSS levels to use the same hash; mixed-hash
     * parameter sets (e.g., SHA256 LMS + SHAKE LM-OTS) are explicitly rejected here (previously
     * they silently produced non-standard structures). */
    for (i = 1; i < levels; i++) {
        lms_param_t p0, pi;
        lmots_param_t o0, oi;
        if (lms_get_lms_param(lms_types[0], &p0) != LMS_OK ||
            lms_get_lms_param(lms_types[i], &pi) != LMS_OK ||
            lms_get_lmots_param(lmots_types[0], &o0) != LMS_OK ||
            lms_get_lmots_param(lmots_types[i], &oi) != LMS_OK ||
            p0.hash_alg != pi.hash_alg || o0.hash_alg != oi.hash_alg ||
            p0.hash_alg != o0.hash_alg) {
            return LMS_ERR_INVALID;
        }
    }

    for (i = 0; i < levels; i++) {
        priv->lms_types[i] = lms_types[i];
        priv->lmots_types[i] = lmots_types[i];
        if (build_level(priv, i) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }

    for (i = 0; i + 1u < levels; i++) {
        if (sign_child_certificate(priv, i) != LMS_OK) {
            return LMS_ERR_EXHAUSTED;
        }
    }

    return LMS_OK;
}

int hss_public_key_generate(const hss_private_key_t *priv,
                            hss_public_key_t *pub)
{
    if (!priv || !pub || priv->levels == 0u) {
        return LMS_ERR_INVALID;
    }

    pub->levels = priv->levels;
    pub->root_pub = priv->pubs[0];
    return LMS_OK;
}

int hss_public_key_serialize(const hss_public_key_t *pub,
                             uint8_t *out,
                             size_t out_len)
{
    if (!pub || !out) {
        return LMS_ERR_INVALID;
    }
    if (out_len < HSS_PUBLIC_KEY_LEN) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }

    lms_store_u32(out, pub->levels);
    return lms_public_key_serialize(&pub->root_pub, out + 4u, out_len - 4u);
}

int hss_public_key_parse(hss_public_key_t *pub,
                         const uint8_t *in,
                         size_t in_len)
{
    if (!pub || !in || in_len != HSS_PUBLIC_KEY_LEN) {
        return LMS_ERR_INVALID;
    }

    pub->levels = lms_load_u32(in);
    if (pub->levels == 0u || pub->levels > HSS_MAX_LEVELS) {
        return LMS_ERR_INVALID;
    }

    return lms_public_key_parse(&pub->root_pub, in + 4u, in_len - 4u);
}

size_t hss_signature_len(const hss_private_key_t *priv)
{
    size_t total = 4u;
    uint32_t i;
    size_t final_len;

    if (!priv || priv->levels == 0u) {
        return 0;
    }

    for (i = 0; i + 1u < priv->levels; i++) {
        if (priv->cert_len[i] == 0u) {
            return 0;
        }
        total += priv->cert_len[i] + LMS_PUBLIC_KEY_LEN;
    }

    final_len = lms_signature_len(priv->lms_types[priv->levels - 1u], priv->lmots_types[priv->levels - 1u]);
    if (final_len == 0u) {
        return 0;
    }
    total += final_len;
    return total;
}

int hss_sign(hss_private_key_t *priv,
             const uint8_t *message,
             size_t message_len,
             uint8_t *signature,
             size_t signature_len,
             size_t *written)
{
    hss_private_key_t *next_priv;
    size_t needed;
    uint32_t i;
    size_t off = 0;
    size_t final_len = 0;

    if (!priv || !signature || (!message && message_len != 0) || priv->levels == 0u) {
        return LMS_ERR_INVALID;
    }

    needed = hss_signature_len(priv);
    if (needed == 0u || signature_len < needed) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }

    next_priv = (hss_private_key_t *)malloc(sizeof(*next_priv));
    if (!next_priv) {
        return LMS_ERR_INVALID;
    }
    memcpy(next_priv, priv, sizeof(*next_priv));

    if (refresh_level_if_exhausted(next_priv, next_priv->levels - 1u) != LMS_OK) {
        free(next_priv);
        return LMS_ERR_EXHAUSTED;
    }

    lms_store_u32(signature + off, next_priv->levels - 1u);
    off += 4u;

    for (i = 0; i + 1u < next_priv->levels; i++) {
        uint8_t child_pub[LMS_PUBLIC_KEY_LEN];
        size_t cert_len = next_priv->cert_len[i];
        if (lms_public_key_serialize(&next_priv->pubs[i + 1u], child_pub, sizeof(child_pub)) != LMS_OK) {
            free(next_priv);
            return LMS_ERR_INVALID;
        }
        memcpy(signature + off, next_priv->cert_sig[i], cert_len);
        off += cert_len;
        memcpy(signature + off, child_pub, sizeof(child_pub));
        off += sizeof(child_pub);
    }

    if (lms_sign(&next_priv->keys[next_priv->levels - 1u],
                 message,
                 message_len,
                 signature + off,
                 signature_len - off,
                 &final_len) != LMS_OK) {
        free(next_priv);
        return LMS_ERR_EXHAUSTED;
    }
    off += final_len;

    memcpy(priv, next_priv, sizeof(*priv));
    free(next_priv);

    if (written) {
        *written = off;
    }
    return LMS_OK;
}

int hss_verify(const hss_public_key_t *pub,
               const uint8_t *message,
               size_t message_len,
               const uint8_t *signature,
               size_t signature_len)
{
    lms_public_key_t current;
    uint32_t levels;
    uint32_t i;
    size_t off = 0;

    if (!pub || !signature || (!message && message_len != 0) || pub->levels == 0u) {
        return LMS_ERR_INVALID;
    }
    if (signature_len < 4u) {
        return LMS_ERR_INVALID;
    }

    levels = lms_load_u32(signature + off) + 1u;
    off += 4u;
    if (levels != pub->levels || levels == 0u || levels > HSS_MAX_LEVELS) {
        return LMS_ERR_VERIFY;
    }

    current = pub->root_pub;

    for (i = 0; i + 1u < levels; i++) {
        lms_public_key_t next_pub;
        uint8_t child_pub[LMS_PUBLIC_KEY_LEN];
        size_t cert_len = lms_signature_len(current.lms_type, current.lmots_type);

        if (cert_len == 0u || off + cert_len + LMS_PUBLIC_KEY_LEN > signature_len) {
            return LMS_ERR_INVALID;
        }

        if (lms_verify(&current,
                       signature + off + cert_len,
                       LMS_PUBLIC_KEY_LEN,
                       signature + off,
                       cert_len) != LMS_OK) {
            return LMS_ERR_VERIFY;
        }
        memcpy(child_pub, signature + off + cert_len, LMS_PUBLIC_KEY_LEN);
        if (lms_public_key_parse(&next_pub, child_pub, sizeof(child_pub)) != LMS_OK) {
            return LMS_ERR_VERIFY;
        }
        current = next_pub;
        off += cert_len + LMS_PUBLIC_KEY_LEN;
    }

    if (off > signature_len) {
        return LMS_ERR_INVALID;
    }

    return lms_verify(&current, message, message_len, signature + off, signature_len - off);
}
