/*
 * LMS phase-3 security state domain implementation (spec §3/§4/§6/§8/§9.1/§9.2,
 * impl_roadmap steps 4+5)
 *
 * STATE_REC codec + HMAC orchestration + STATE_COMMIT primitive (step 4);
 * FSM + CMD_FACTORY_INIT (simulated PUF/FE_GEN/KDF) + CMD_BOOT (FE_REP/slot
 * selection/conservative burn) (step 5).
 * HMAC executes in hardware with K_STATE (lms_mmio_hmac_kstate); K_STATE is
 * unreadable and never leaves hardware;
 * firmware only orchestrates: build body||AAD → call HMAC → take first 16B as tag
 * → commit to A/B slot.
 *
 * Key hierarchy (spec §4): PUF_RESP --FE_GEN/FE_REP--> K_DEV --KDF--> K_WRAP/K_STATE.
 * Prototype simulated PUF = fixed challenge-response (no real PUF; stated honestly
 * in the paper);
 * helper_data is a fixed 32B placeholder (dev_epoch randomizes K_WRAP/K_STATE derivation);
 * K_DEV exists only transiently in firmware RAM, cleared after use, never persisted.
 * Until CMD_SEC_SIGN (step 6) is implemented, device context is bound via lms_rnd_det_seed.
 */
#include "lms_sec_state.h"

#include <string.h>

#include "lms_rnd.h"
#include "sha256.h"

/* 0.1.281 (deploy model B): global TRNG health-fault flag (fw/lms_rnd_trng.c) —
 * exists only when RND_IMPL=trng (deploy build default) is linked; used as the
 * fail-closed gate for on-site SEED/I generation in keygen_new (health_fail →
 * refuse, no SEED). */
#ifdef LMS_RND_IMPL_TRNG
extern volatile uint32_t trng_fault;
#endif

/* ---- STATE_REC layout (minimal sufficient, fixed 64B, all big-endian) ----
 * body(48) || tag(16). Fixed single-device scheme keeps only irreplaceable fields:
 *   magic(4) || state(2) || ctr(4) || txid(4) || reserved(34)
 * Device binding (vs. cross-device migration) is done by PUF-derived K_STATE;
 * unique version number by txid(=sim_mc) (vs. persistent-state replay); fixed
 * scheme has no version/rotation/multi-key, hence no version/epoch/key_handle;
 * mc has no consumer so dropped; reserved_q expressible via ctr (burn ctr+1);
 * prev_digest has no irreplaceable role under RoT secrecy so dropped. */
#define SEC_MAGIC_STATE   0x4c4d5353u  /* "LMSS" */

#define SEC_OFF_MAGIC     0u
#define SEC_OFF_STATE     4u
#define SEC_OFF_CTR       6u
#define SEC_OFF_TXID      10u
#define SEC_BODY_LEN      48u
#define SEC_OFF_TAG       48u
/* reserved region: offset 14..47 (34B, zero-filled, placeholder for future extensions, no semantics). */
#define SEC_OFF_RESERVED  14u

/* AAD = slot_id(1B): binds the slot (prevents A/B swap; cannot go in body or the
 * dual-slot memcmp on equal tx would never match). Device/key binding is via K_STATE (PUF-derived). */
#define SEC_AAD_LEN       1u
/* HMAC message = body(48) || slot_id(1) = 49B (≤119, hardware inner ≤3 blocks). */
#define SEC_HMAC_MSG_LEN  (SEC_BODY_LEN + SEC_AAD_LEN)

/* Simulated PUF: fixed challenge-response (prototype has no real PUF; spec §4
 * permits a simulated model). response is fixed 32B; FE_GEN/FE_REP share the same
 * response so FACTORY_INIT and BOOT rebuild the same K_DEV. */
#define SEC_PUF_RESP_LEN 32u
#define SEC_HELPER_LEN   32u

/* KDF domain separation (spec §4): K_x = H("LMS-KDF" || 0x00 || label || 0x00 || K_DEV). */
#define SEC_KDF_DOMAIN "LMS-KDF"
#define SEC_KDF_LABEL_WRAP  "wrap"
#define SEC_KDF_LABEL_STATE "state"

/* ---- module-internal state (never exported) ---- */
static lms_mmio_client_t *sec_client;
static uint8_t  sec_slots[2][SEC_STATE_REC_LEN];  /* A/B dual slots (firmware RAM mirror) */
static uint8_t  sec_slot_valid[2];
static uint8_t  sec_active_slot;                   /* 0=A, 1=B */
static uint16_t sec_state;                         /* current hw_state */
static uint32_t sec_ctr;                           /* current ctr */
static uint32_t sec_last_tx;                       /* last_committed_tx */
static uint8_t  sec_factory_locked;                /* set to 1 after FACTORY_INIT */
static uint8_t  sec_key_loaded;                    /* set to 1 after BOOT success (SEED unwrapped) */
static uint8_t  sec_keygen_pending;                /* set to 1 when recovery sees ST_KEYGEN_PENDING */
static uint8_t  sec_helper[SEC_HELPER_LEN];        /* FE helper_data (DEV_CTX persistent domain) */
static uint8_t  sec_boot_valid[2];                 /* diagnostics: BOOT dual-slot rec_valid results */
static uint8_t  sec_wrapped_blob[LMS_MMIO_WRAPPED_LEN]; /* P1-6: wrapped_seed (produced by FACTORY_INIT / host reload) */
static uint8_t  sec_wrapped_valid;                 /* P1-6: blob valid (deploy BOOT unwraps from it, treats as factory-loaded) */
static uint8_t  sec_key_I[LMS_I_LEN];               /* current active key's public-key ID (KDF context, not secret; KEYGEN generates / host reloads) */
static uint32_t sec_key_index;                       /* generation index of the current active key (0,1,2...; pure bookkeeping, not secure against rollback — for multi-key rotation) */
#if defined(LMS_MMIO_SOC_PROFILE)
/* secure Sign segment profile (carried out via response frame [28..31]/[44..47],
 * extern in smoke.c):
 * commit1=Reserve commit, dosign=lmots_sign, commit2=Commit commit */
#define SEC_PROF_MMIO32(address) (*(volatile uint32_t *)(uintptr_t)(address))
#define SEC_PROF_CYCLE_COUNT    0x10000010u
uint32_t sec_prof_commit1_cycles;
uint32_t sec_prof_dosign_cycles;
uint32_t sec_prof_commit2_cycles;
/* state_commit internal breakdown (commit1 path): stc=lms_mmio_state_commit fused
 * transaction (sim_mc+1 + HMAC(body) in one command), enc=encode_body+slot
 * write+post-write check; mc/tag=two-step fallback path (no CAP_STATE_COMMIT
 * platform) segments */
uint32_t sec_prof_stc_cycles;
uint32_t sec_prof_enc_cycles;
uint32_t sec_prof_mc_cycles;
uint32_t sec_prof_tag_cycles;
#endif

/* ---- big-endian read/write ---- */
static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* ---- build AAD (1B = slot_id) ---- */
static void build_aad(uint8_t aad[SEC_AAD_LEN], uint8_t slot_id)
{
    aad[0] = slot_id;
}

/* ---- compute STATE_REC HMAC tag (first 16B). Done in hardware; K_STATE never leaves hardware. ---- */
static int compute_tag(const uint8_t body[SEC_BODY_LEN], uint8_t slot_id,
                       uint8_t tag[SEC_STATE_TAG_LEN])
{
    uint8_t msg[SEC_HMAC_MSG_LEN];
    uint8_t aad[SEC_AAD_LEN];
    uint8_t full[LMS_N];
    int status;

    build_aad(aad, slot_id);
    memcpy(msg, body, SEC_BODY_LEN);
    memcpy(msg + SEC_BODY_LEN, aad, SEC_AAD_LEN);
    status = lms_mmio_hmac_kstate(sec_client, msg, SEC_HMAC_MSG_LEN, full);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    memcpy(tag, full, SEC_STATE_TAG_LEN);
    return LMS_MMIO_OK;
}

/* ---- encode STATE_REC body (48B, without tag) ---- */
static void encode_body(uint8_t body[SEC_BODY_LEN], uint16_t state, uint32_t ctr,
                        uint32_t tx_id)
{
    put_be32(body + SEC_OFF_MAGIC, SEC_MAGIC_STATE);
    put_be16(body + SEC_OFF_STATE, state);
    put_be32(body + SEC_OFF_CTR, ctr);
    put_be32(body + SEC_OFF_TXID, tx_id);
    /* reserved region (14..47) zero-filled: placeholder for future extensions, no semantics. */
    memset(body + SEC_OFF_RESERVED, 0, SEC_BODY_LEN - SEC_OFF_RESERVED);
}

/* ---- validate one STATE_REC (magic/tag). Returns 1=valid.
 * Failure reason exposed via sec_rec_diag[slot] (0=ok 1=magic 3=tag-hw 4=tag-cmp). */
static uint8_t sec_rec_diag[2];
static int rec_valid(const uint8_t rec[SEC_STATE_REC_LEN], uint8_t slot_id)
{
    uint8_t tag[SEC_STATE_TAG_LEN];

    sec_rec_diag[slot_id] = 0u;
    if (get_be32(rec + SEC_OFF_MAGIC) != SEC_MAGIC_STATE) {
        sec_rec_diag[slot_id] = 1u;
        return 0;
    }
    if (compute_tag(rec, slot_id, tag) != LMS_MMIO_OK) {
        sec_rec_diag[slot_id] = 3u;
        return 0;
    }
    if (memcmp(tag, rec + SEC_OFF_TAG, SEC_STATE_TAG_LEN) != 0) {
        sec_rec_diag[slot_id] = 4u;
        return 0;
    }
    return 1;
}

/* Lightweight post-write check: verify only magic + in-slot tag vs. expected, no
 * HMAC recompute. Used right after compute_tag in state_commit (each of the 2
 * state commits per signature saves one duplicate HMAC core borrow); BOOT/external
 * full validation of persisted records still uses rec_valid. Post-write semantics
 * preserved: a tag corrupted during memcpy is still caught (tag-cmp failure). */
static int rec_valid_check(const uint8_t rec[SEC_STATE_REC_LEN], uint8_t slot_id,
                           const uint8_t expected_tag[SEC_STATE_TAG_LEN])
{
    sec_rec_diag[slot_id] = 0u;
    if (get_be32(rec + SEC_OFF_MAGIC) != SEC_MAGIC_STATE) {
        sec_rec_diag[slot_id] = 1u;
        return 0;
    }
    if (memcmp(rec + SEC_OFF_TAG, expected_tag, SEC_STATE_TAG_LEN) != 0) {
        sec_rec_diag[slot_id] = 4u;
        return 0;
    }
    return 1;
}

/* Whether both slots have never been written with any STATE_REC (all zero).
 * Distinguishes a "fresh device (never COMMIT after FACTORY_INIT, no released
 * σ_q)" from "signing state existed but both slots are corrupted/tampered" — the
 * latter falling back to ctr=0 would reuse a released q (violating the invariant
 * Release(σ_q) => Committed(CTR>=q+1)), so service must be refused. */
static int slots_all_zero(void)
{
    uint32_t index;
    uint32_t k;
    for (index = 0u; index < 2u; index++) {
        for (k = 0u; k < SEC_STATE_REC_LEN; k++) {
            if (sec_slots[index][k] != 0u) {
                return 0;
            }
        }
    }
    return 1;
}

/* ---- key-hierarchy primitives (spec §4/§9.1/§9.2) ---- */

/* Simulated PUF: fixed challenge-response (prototype has no real PUF). */
static void sim_puf_read(uint8_t resp[SEC_PUF_RESP_LEN])
{
    uint32_t index;
    for (index = 0u; index < SEC_PUF_RESP_LEN; index++) {
        resp[index] = (uint8_t)(0x60u + index);
    }
}

/* FE_GEN: simulated fuzzy extractor, outputs helper_data (placeholder) and K_DEV.
 * K_DEV = H("LMS-FE" || puf_resp || CTX); helper is a fixed placeholder (a real
 * FE uses it for error correction; the prototype PUF has no noise, so helper does
 * not participate in rebuild and only serves as DEV_CTX persistence placeholder). */
static void fe_gen(const uint8_t puf_resp[SEC_PUF_RESP_LEN], uint8_t ctx,
                   uint8_t helper[SEC_HELPER_LEN], uint8_t k_dev[LMS_N])
{
    SHA256_CTX h;
    static const char domain[] = "LMS-FE";
    uint32_t index;

    SHA256_Init(&h);
    SHA256_Update(&h, (const uint8_t *)domain, (unsigned int)(sizeof(domain) - 1u));
    SHA256_Update(&h, puf_resp, SEC_PUF_RESP_LEN);
    SHA256_Update(&h, &ctx, 1u);
    SHA256_Final(k_dev, &h);
    for (index = 0u; index < SEC_HELPER_LEN; index++) {
        helper[index] = (uint8_t)(0xa0u + index);
    }
}

/* FE_REP: rebuild K_DEV from helper_data. Prototype helper does not participate
 * (PUF has no noise); deriving with the same formula as FE_GEN restores the same K_DEV. */
static void fe_rep(const uint8_t puf_resp[SEC_PUF_RESP_LEN],
                   const uint8_t helper[SEC_HELPER_LEN], uint8_t ctx,
                   uint8_t k_dev[LMS_N])
{
    uint8_t dummy[SEC_HELPER_LEN];
    (void)helper;
    fe_gen(puf_resp, ctx, dummy, k_dev);
}

/* KDF (spec §4, per-key level): K_{x,i} = H("LMS-KDF" || 0x00 || label || 0x00 || I_i || 0x00 || K_DEV).
 * I_i = the key's 16B public-key ID; provides cross-key isolation (leaking one
 * key's K_WRAP_i/K_STATE_i does not affect other keys).
 * K_DEV is the device-level PUF root (rebuilt via FE_GEN/FE_REP, cleared after use). */
static void sec_kdf(const uint8_t k_dev[LMS_N], const uint8_t I[LMS_I_LEN],
                    const char *label, size_t label_len, uint8_t out[LMS_N])
{
    SHA256_CTX h;
    uint8_t zero = 0u;

    SHA256_Init(&h);
    SHA256_Update(&h, (const uint8_t *)SEC_KDF_DOMAIN, sizeof(SEC_KDF_DOMAIN) - 1u);
    SHA256_Update(&h, &zero, 1u);
    SHA256_Update(&h, (const uint8_t *)label, (unsigned int)label_len);
    SHA256_Update(&h, &zero, 1u);
    SHA256_Update(&h, I, LMS_I_LEN);   /* per-key context: this key's 16B public-key ID */
    SHA256_Update(&h, &zero, 1u);
    SHA256_Update(&h, k_dev, LMS_N);
    SHA256_Final(out, &h);
}

/* Load K_WRAP_i/K_STATE_i into hardware-unreadable slots (per-key level, ctx=I_i;
 * prototype writes via INSECURE staging; zero firmware copies right after). */
static int sec_load_hw_keys_i(const uint8_t k_dev[LMS_N], const uint8_t I[LMS_I_LEN])
{
    uint8_t k_wrap[LMS_N];
    uint8_t k_state[LMS_N];
    int status;

    sec_kdf(k_dev, I, SEC_KDF_LABEL_WRAP, sizeof(SEC_KDF_LABEL_WRAP) - 1u, k_wrap);
    sec_kdf(k_dev, I, SEC_KDF_LABEL_STATE, sizeof(SEC_KDF_LABEL_STATE) - 1u, k_state);
    status = lms_mmio_key_slot_load_test(sec_client, LMS_MMIO_KEY_KWRAP, k_wrap);
    if (status == LMS_MMIO_OK) {
        status = lms_mmio_key_slot_load_test(sec_client, LMS_MMIO_KEY_KSTATE, k_state);
    }
    memset(k_wrap, 0, sizeof(k_wrap));
    memset(k_state, 0, sizeof(k_state));
    return status;
}

/* ---- KEYGEN (prerequisite for producing a public key with the current key) ----
 * I/SEED sources **compile-time isolated** (INSECURE_TEST_MODE convention):
 *   - test (LMS_FW_SEC_TEST_MODE defined): I from **external input** (sec_key_I,
 *     host supplies = vector I at FACTORY_INIT, KAT reproducible byte-for-byte);
 *     SEED from slot value (0x63 externally loaded).
 *   - deploy (undefined): I generated by **in-domain TRNG** (no external
 *     interface, not compiled into external-input logic); SEED from slot value
 *     (BOOT recovers via wrapped→UNWRAP; plaintext never persisted).
 * Both conventions share one flow: derive K_WRAP_i/K_STATE_i
 * (KDF(K_DEV,label,I_i)) → wrap(slot SEED) → output I for keygen_impl; K_DEV
 * is recoverable from PUF via FE_REP. */
int sec_keygen_key(uint8_t I[LMS_I_LEN])
{
    uint8_t puf_resp[SEC_PUF_RESP_LEN];
    uint8_t k_dev[LMS_N];
    uint8_t wrapped[LMS_MMIO_WRAPPED_LEN];
    int status;

#ifdef LMS_FW_SEC_TEST_MODE
    memcpy(I, sec_key_I, LMS_I_LEN);   /* test: external input I (host supplies = vector I) */
#else
    lms_rnd(I, LMS_I_LEN);             /* deploy: I generated by in-domain TRNG (no external interface) */
    memcpy(sec_key_I, I, LMS_I_LEN);
#endif

    sim_puf_read(puf_resp);
    fe_rep(puf_resp, sec_helper, 0u, k_dev);
    status = sec_load_hw_keys_i(k_dev, sec_key_I);  /* K_WRAP_i/K_STATE_i = KDF(K_DEV, label, I_i) */
    memset(puf_resp, 0, sizeof(puf_resp));
    memset(k_dev, 0, sizeof(k_dev));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    status = lms_mmio_wrap_seed(sec_client, wrapped);        /* wrap(slot SEED value) with K_WRAP_i */
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }
    memcpy(sec_wrapped_blob, wrapped, LMS_MMIO_WRAPPED_LEN);
    sec_wrapped_valid = 1u;
    sec_key_loaded = 1u;
    memset(wrapped, 0, sizeof(wrapped));
    return SEC_OK;
}

/* ---- KEYGEN_NEW (multi-key rotation: generate and activate a **new key**,
 *        atomically retiring the old key) ----
 * vs. sec_keygen_key: the latter re-runs keygen on the "current active key" (I
 * and SEED fixed); the former generates a **brand-new** key (new I + new SEED):
 *   ① derive K_WRAP_i/K_STATE_i = KDF(K_DEV, label, I_new);
 *   ② wrap new SEED → wrapped blob (host persists);
 *   ③ ★ clear both STATE_REC slots + reset ctr=0/state=IDLE/active_slot=0 — after
 *      key switch K_STATE changes, old tags (old K_STATE) mismatch → must clear
 *      (else next BOOT would ERROR_LOCKED);
 *   ④ active key index +1, key_loaded=1, factory_locked=1.
 * I/SEED sources **compile-time isolated** (INSECURE_TEST_MODE, same as
 * sec_keygen_key):
 *   - test (LMS_FW_SEC_TEST_MODE): I external input (sec_key_I, host = vector I,
 *     KAT byte-reproducible); SEED from slot value (0x63 loaded) — **no RTL
 *     blocking in test config** (INSECURE_TEST_MODE=1).
 *   - deploy (undefined, 0.1.281 model B): **new SEED + new I generated on-site
 *     by in-device TRNG** (RND_IMPL=trng, DEPLOY=1; health_fail → fail-closed,
 *     no SEED); SEED → slot 0 via lms_mmio_seed_load_safe
 *     (CMD_SEED_WRITE_SAFE, controlled load, not in UART request table) —
 *     plaintext SEED_LOAD gate (rtl/lms_hash_cmd_check.v:152) unchanged, test
 *     builds unaffected.
 * Returns SEC_OK on success (I_new filled with actual I), else error code. */
int sec_keygen_new(uint8_t I_new[LMS_I_LEN])
{
    uint8_t puf_resp[SEC_PUF_RESP_LEN];
    uint8_t k_dev[LMS_N];
    uint8_t wrapped[LMS_MMIO_WRAPPED_LEN];
    int status;

#ifdef LMS_FW_SEC_TEST_MODE
    /* test: I = caller external input (host supplies the new-key vector I, KAT byte-reproducible). */
    memcpy(sec_key_I, I_new, LMS_I_LEN);   /* use the passed-in new-key I (unique per key), not the old sec_key_I */
#else
    /* deploy (model B): new SEED + new I both generated on-site by in-device TRNG. */
    {
        uint8_t new_seed[LMS_SEED_LEN];

        /* Fetch I and SEED first, then check health (avoids half-switch: SEED
         * changed but I failed); lms_rnd outputs all-zero on health_fail
         * (trng_fault set) → explicitly refuse. */
        lms_rnd(sec_key_I, LMS_I_LEN);
        lms_rnd(new_seed, LMS_SEED_LEN);
#ifdef LMS_RND_IMPL_TRNG
        if (trng_fault != 0u) {
            memset(sec_key_I, 0, sizeof(sec_key_I));
            memset(new_seed, 0, sizeof(new_seed));
            return SEC_ERR_AUTH;   /* TRNG health_fail: fail-closed, no new key produced */
        }
#endif
        memcpy(I_new, sec_key_I, LMS_I_LEN);   /* device-generated I back to caller (for tree build / host record) */

        /* New SEED enters slot 0 via controlled load (plaintext SEED_LOAD gate unchanged). */
        status = lms_mmio_seed_load_safe(sec_client, new_seed);
        memset(new_seed, 0, sizeof(new_seed));
        if (status != LMS_MMIO_OK) {
            memset(sec_key_I, 0, sizeof(sec_key_I));
            return SEC_ERR_AUTH;
        }
    }
#endif

    sim_puf_read(puf_resp);
    fe_rep(puf_resp, sec_helper, 0u, k_dev);
    status = sec_load_hw_keys_i(k_dev, sec_key_I);   /* K_WRAP_i/K_STATE_i = KDF(K_DEV, label, I_new) */
    memset(puf_resp, 0, sizeof(puf_resp));
    memset(k_dev, 0, sizeof(k_dev));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    /* ② wrap the new key's slot SEED (0x63 loaded) → wrapped blob (host persists). */
    status = lms_mmio_wrap_seed(sec_client, wrapped);
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }
    memcpy(sec_wrapped_blob, wrapped, LMS_MMIO_WRAPPED_LEN);
    sec_wrapped_valid = 1u;
    memset(wrapped, 0, sizeof(wrapped));

    /* ③ new key has no signing history: clear both STATE_REC slots + reset. */
    memset(sec_slots[0], 0, sizeof(sec_slots[0]));
    memset(sec_slots[1], 0, sizeof(sec_slots[1]));
    sec_slot_valid[0] = 0u;
    sec_slot_valid[1] = 0u;
    sec_active_slot = 0u;
    sec_state = SEC_ST_IDLE;
    sec_ctr = 0u;
    sec_last_tx = 0u;

    /* ④ new key ready. */
    sec_key_loaded = 1u;
    sec_factory_locked = 1u;
    sec_keygen_pending = 0u;
    sec_key_index++;
    return SEC_OK;
}

void sec_init(lms_mmio_client_t *client)
{
    sec_client = client;
    memset(sec_slots, 0, sizeof(sec_slots));
    sec_slot_valid[0] = 0u;
    sec_slot_valid[1] = 0u;
    sec_active_slot = 0u;
    sec_state = SEC_ST_BOOTING;
    sec_ctr = 0u;
    sec_last_tx = 0u;
    sec_factory_locked = 0u;
    sec_key_loaded = 0u;
    sec_keygen_pending = 0u;
    memset(sec_helper, 0, sizeof(sec_helper));
    sec_key_index = 0u;
}


uint16_t sec_hw_state(void)
{
    return sec_state;
}

uint32_t sec_last_committed_tx(void)
{
    return sec_last_tx;
}

/* ---- STATE_COMMIT primitive (spec §8) ----
 * tx=mc_next() → HMAC tag → write inactive slot → read back, verify tag →
 * switch active → update snapshot. Returns 1=success (RSP_COMMIT_OK), 0=failure.
 * 0.1.256: mc_step + HMAC fused into single CMD_STATE_COMMIT transaction (tx/tag
 * both hardware-produced);
 * 0.1.258: branch on CAP_STATE_COMMIT — without it (SHA-256 platform) fall back
 * to two steps (mc_step + HMAC_KSTATE(49B), same as 0.1.254 and before). */

/* Common commit tail (REVIEW B07-R4: old two-step/fused paths' duplicated
 * "write slot→verify→switch active→snapshot" collapsed to one point). tx
 * monotonic check → F5 direct slot write (encode_body idempotent — two-step
 * path already computed tag from body buffer, same params re-encode to same
 * bytes) → write tag → lightweight post-write check (magic + tag compare, no
 * HMAC recompute; M4 edge: bad tag from spurious core_done not caught by
 * self-compare — BOOT's rec_valid full recompute backstops) → switch active +
 * update snapshot. On failure, clear inactive slot's valid. */
static int commit_finish(uint8_t inactive, uint16_t new_state, uint32_t ctr,
                         uint32_t tx, const uint8_t tag[SEC_STATE_TAG_LEN])
{
    if (tx <= sec_last_tx) {
        return 0;  /* tx rollback: reject */
    }
    encode_body(sec_slots[inactive], new_state, ctr, tx);
    memcpy(sec_slots[inactive] + SEC_OFF_TAG, tag, SEC_STATE_TAG_LEN);
    if (!rec_valid_check(sec_slots[inactive], inactive, tag)) {
        sec_slot_valid[inactive] = 0u;
        return 0;
    }
    sec_slot_valid[inactive] = 1u;
    sec_active_slot = inactive;
    sec_last_tx = tx;
    sec_state = new_state;
    sec_ctr = ctr;
    return 1;
}

static int state_commit(uint16_t new_state, uint32_t ctr)
{
    uint8_t inactive;
    uint8_t body[SEC_BODY_LEN];
    uint8_t tag[SEC_STATE_TAG_LEN];
    uint32_t tx;
    int status;
    int rc;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t sc_prof_t0 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    uint32_t sc_prof_t1 = 0u;
    uint32_t sc_prof_t2 = 0u;
#endif

    inactive = (uint8_t)(1u - sec_active_slot);

    if ((sec_client->capabilities & LMS_MMIO_CAP_STATE_COMMIT) != 0u) {
        /* tx_id must not come from software: it must come from the hardware
         * monotonic counter (sim_mc). CMD_STATE_COMMIT (fused): sim_mc+1 →
         * HMAC(body) single transaction outputs tx + tag. aad = inactive slot
         * number (binds slot). */
        status = lms_mmio_state_commit(sec_client, new_state, ctr, inactive, &tx, tag);
        if (status != LMS_MMIO_OK) {
            return 0;
        }
#if defined(LMS_MMIO_SOC_PROFILE)
        sc_prof_t1 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
        sec_prof_stc_cycles = sc_prof_t1 - sc_prof_t0;
#endif
        rc = commit_finish(inactive, new_state, ctr, tx, tag);
#if defined(LMS_MMIO_SOC_PROFILE)
        if (rc != 0) {
            sec_prof_enc_cycles = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT) - sc_prof_t1;
        }
#endif
        return rc;
    }

    /* Two-step fallback (no CAP_STATE_COMMIT, e.g. SHA-256 platform):
     * mc_step gets hardware-monotonic tx → encode_body → HMAC_KSTATE(49B) yields tag. */
    status = lms_mmio_mc_step(sec_client, &tx);
    if (status != LMS_MMIO_OK) {
        return 0;
    }
    if (tx <= sec_last_tx) {
        return 0;  /* tx rollback: reject (fail-fast before HMAC, saves one core borrow) */
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    sc_prof_t1 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_mc_cycles = sc_prof_t1 - sc_prof_t0;
#endif
    encode_body(body, new_state, ctr, tx);
    status = compute_tag(body, inactive, tag);
    if (status != LMS_MMIO_OK) {
        sec_slot_valid[inactive] = 0u;
        return 0;
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    sc_prof_t2 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_tag_cycles = sc_prof_t2 - sc_prof_t1;
#endif
    rc = commit_finish(inactive, new_state, ctr, tx, tag);
#if defined(LMS_MMIO_SOC_PROFILE)
    if (rc != 0) {
        sec_prof_enc_cycles = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT) - sc_prof_t2;
    }
#endif
    return rc;
}

/* ---- CMD_FACTORY_INIT (spec §9.1) ----
 * simulated PUF → FE_GEN → KDF loads K_WRAP/K_STATE → generate device context →
 * wrapped_seed → clear K_DEV. Refused once factory_locked. */
static int sec_factory_init(const uint8_t I[LMS_I_LEN], uint8_t response[32])
{
    uint8_t puf_resp[SEC_PUF_RESP_LEN];
    uint8_t k_dev[LMS_N];
    uint8_t seed[LMS_SEED_LEN];
    uint8_t wrapped[LMS_MMIO_WRAPPED_LEN];
    uint32_t index;
    int status;

#if !defined(LMS_FW_SEC_TEST_MODE)
    /* P1-6 (0.1.274): deploy builds reject FACTORY_INIT — factory provisioning
     * (incl. plaintext SEED load) belongs to factory/test config; deploy devices
     * accept only wrapped blob reload + BOOT unwrap to restore SEED. */
    (void)puf_resp; (void)k_dev; (void)seed; (void)wrapped; (void)index;
    response[2] = SEC_ERR_UNSUPPORTED;
    return SEC_ERR_UNSUPPORTED;
#endif

    if (sec_factory_locked != 0u) {
        return SEC_ERR_FACTORY_LOCKED;
    }

    sim_puf_read(puf_resp);
    fe_gen(puf_resp, 0u, sec_helper, k_dev);
    /* First key's I: host-provided (deploy=TRNG, factory reload held; debug=fixed
     * vector); KDF context (sec_key_I) so FACTORY_INIT wrap and later BOOT unwrap agree. */
    memcpy(sec_key_I, I, LMS_I_LEN);
    status = sec_load_hw_keys_i(k_dev, sec_key_I);
    memset(puf_resp, 0, sizeof(puf_resp));
    memset(k_dev, 0, sizeof(k_dev));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    /* wrapped_seed: prototype uses a deterministic SEED (true-random SEED is a KeyGen extension, spec §9.3). */
    for (index = 0u; index < LMS_SEED_LEN; index++) {
        seed[index] = (uint8_t)index;
    }
    status = lms_mmio_seed_load_test(sec_client, 0u, seed);
    memset(seed, 0, sizeof(seed));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }
    status = lms_mmio_wrap_seed(sec_client, wrapped);
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    /* P1-6 (0.1.274): keep the full wrapped blob (host fetches and persists via
     * WRAPPED_READ_LO/HI; deploy builds restore SEED via WRAP_LOAD + BOOT unwrap). */
    memcpy(sec_wrapped_blob, wrapped, LMS_MMIO_WRAPPED_LEN);
    sec_wrapped_valid = 1u;

    sec_factory_locked = 1u;
    sec_keygen_pending = 0u;

    /* RSP_DEVCTX: magic "F" || helper first 8B || wrapped first 12B (no epoch/handle). */
    response[4] = 0x46u;
    for (index = 0u; index < 8u; index++) {
        response[20u + index] = sec_helper[index];
        response[28u + index] = (index < 4u) ? wrapped[index] : 0u;
    }
    memset(wrapped, 0, sizeof(wrapped));
    return SEC_OK;
}

/* ---- CMD_BOOT (spec §9.2) ----
 * FE_REP rebuilds K_DEV → KDF loads K_WRAP_i/K_STATE_i (ctx=active key I, host
 * reload) → unwrap SEED → dual-slot selection (tag ok, larger tx wins; same tx
 * different content → locked) → ST_RESERVED conservative burn. */
uint16_t sec_boot(const uint8_t I[LMS_I_LEN])
{
    sec_state = SEC_ST_BOOTING;
    {
        uint8_t puf_resp[SEC_PUF_RESP_LEN];
        uint8_t k_dev[LMS_N];
        uint8_t valid[2];
        uint32_t tx[2];
        int8_t chosen;
        uint16_t rec_state;
        uint32_t rec_ctr;
        int status;

        memcpy(sec_key_I, I, LMS_I_LEN);
        sim_puf_read(puf_resp);
        fe_rep(puf_resp, sec_helper, 0u, k_dev);
        status = sec_load_hw_keys_i(k_dev, sec_key_I);
        memset(puf_resp, 0, sizeof(puf_resp));
        memset(k_dev, 0, sizeof(k_dev));
        if (status != LMS_MMIO_OK) {
            sec_state = SEC_ST_ERROR_LOCKED;
            return sec_state;
        }
        sec_key_loaded = 1u;

#if !defined(LMS_FW_SEC_TEST_MODE)
        /* P1-6 (0.1.274): deploy builds restore SEED via wrapped→UNWRAP (no
         * plaintext persisted). Valid blob ⇒ factory-loaded (FACTORY_INIT rejected
         * in deploy, volatile factory_locked proxied by wrapped_valid); unwrap tag
         * failure → ERROR_LOCKED (fail-closed). Test builds unchanged (SEED via
         * test load path, zero regression). */
        if (sec_wrapped_valid != 0u) {
            status = lms_mmio_unwrap_seed(sec_client, sec_wrapped_blob);
            sec_factory_locked = 1u;
            if (status != LMS_MMIO_OK) {
                sec_state = SEC_ST_ERROR_LOCKED;
                return sec_state;
            }
        }
#endif

        /* Validate both slots. */
        valid[0] = (uint8_t)rec_valid(sec_slots[0], 0u);
        valid[1] = (uint8_t)rec_valid(sec_slots[1], 1u);
        sec_boot_valid[0] = valid[0];
        sec_boot_valid[1] = valid[1];
        tx[0] = get_be32(sec_slots[0] + SEC_OFF_TXID);
        tx[1] = get_be32(sec_slots[1] + SEC_OFF_TXID);

        chosen = -1;
        if (valid[0] != 0u && valid[1] != 0u) {
            if (tx[0] == tx[1]) {
                /* Same tx_id: compare record content (body 48B, excluding tag) —
                 * same → accept (chosen=0); different → inconsistent, locked.
                 * REVIEW B07-R2: old code memcmp'd the whole 64B record, but the
                 * two slots' tags come from hardware with slot-distinguishing AAD
                 * and are never equal, so "same content → accept" never held and
                 * every same-tx case mislocked (fail-closed). Comparing body now
                 * matches the comment. */
                if (memcmp(sec_slots[0], sec_slots[1], SEC_OFF_TAG) != 0) {
                    sec_state = SEC_ST_ERROR_LOCKED;
                    return sec_state;
                }
                chosen = 0;
            } else {
                chosen = (tx[0] > tx[1]) ? 0 : 1;
            }
        } else if (valid[0] != 0u) {
            chosen = 0;
        } else if (valid[1] != 0u) {
            chosen = 1;
        }

        if (chosen < 0) {
            /* Both slots invalid. */
            if (sec_factory_locked != 0u) {
                if (slots_all_zero()) {
                    /* Fresh device (never COMMIT after FACTORY_INIT): slots never
                     * written, no released σ_q, legitimately starts at ctr=0. */
                    sec_state = SEC_ST_IDLE;
                    sec_ctr = 0u;
                } else {
                    /* Both slots have history but all checks fail: state
                     * corrupted/tampered. CTR monotonicity unprovable; falling
                     * back to 0 would reuse a released q (violates Release(σ_q)
                     * => Committed(CTR>=q+1)) → refuse service (ERROR_LOCKED),
                     * recover via external manual intervention. */
                    sec_state = SEC_ST_ERROR_LOCKED;
                    return sec_state;
                }
            } else {
                /* Uninitialized and no state: stay BOOTING, wait for FACTORY_INIT. */
                return sec_state;
            }
        } else {
            sec_active_slot = (uint8_t)chosen;
            sec_slot_valid[0] = valid[0];
            sec_slot_valid[1] = valid[1];
            sec_last_tx = tx[chosen];
            rec_state = get_be16(sec_slots[chosen] + SEC_OFF_STATE);
            rec_ctr = get_be32(sec_slots[chosen] + SEC_OFF_CTR);

            if (rec_state == SEC_ST_RESERVED) {
                /* Conservative burn: q was reserved but never completed; burn q
                 * on recovery (Reserve recorded ctr=q, so new ctr = rec_ctr+1 = q+1). */
                if (!state_commit(SEC_ST_IDLE, rec_ctr + 1u)) {
                    sec_state = SEC_ST_ERROR_LOCKED;
                    return sec_state;
                }
            } else if (rec_state == SEC_ST_KEYGEN_PENDING) {
                /* KeyGen incomplete: not a signable key, must re-run KeyGen. */
                sec_keygen_pending = 1u;
                sec_state = SEC_ST_KEYGEN_PENDING;
                sec_ctr = rec_ctr;
            } else if (rec_state == SEC_ST_IDLE || rec_state == SEC_ST_EXHAUSTED) {
                sec_state = rec_state;
                sec_ctr = rec_ctr;
            } else {
                sec_state = SEC_ST_ERROR_LOCKED;
                return sec_state;
            }
        }

        /* BOOT does not predict exhaustion (key h unknown, 2^h varies with
         * parameter set): exhaustion judged at sign time in sec_sign with max_ctr
         * (caller resolves from lms_type) (0.1.243 full parameter set). An
         * EXHAUSTED record is still restored to EXHAUSTED via the rec_state branch above. */
        /* BOOT success (FE_REP rebuilt K_DEV and loaded keys) proves the device is initialized. */
        if (sec_state != SEC_ST_ERROR_LOCKED && sec_state != SEC_ST_BOOTING) {
            sec_factory_locked = 1u;
        }
    }
    return sec_state;
}

/* Conservative-burn state read (diagnostics/tests): current ctr. */
uint32_t sec_ctr_value(void)
{
    return sec_ctr;
}

/* Whether hardware keys are loaded (BOOT/FACTORY_INIT succeeded). */
uint8_t sec_key_ready(void)
{
    return sec_key_loaded;
}

/* Whether KeyGen is in an incomplete state (set on recovery at ST_KEYGEN_PENDING). */
uint8_t sec_keygen_pending_flag(void)
{
    return sec_keygen_pending;
}

/* Host persistent-domain bridge: export active slot's full 64B (incl. tag). */
void sec_export_active(uint8_t out[SEC_STATE_REC_LEN])
{
    memcpy(out, sec_slots[sec_active_slot], SEC_STATE_REC_LEN);
}

/* ---- CMD_SEC_SIGN atomicity (spec §9.4, step 6) ----
 * Core invariant: Release(σ_q) => Committed(CTR >= q+1).
 * Forbidden: release-then-commit; using CTR instead of TX_ID; software-provided tx_id.
 * max_ctr = ctr cap (= 2^h, passed by the caller resolved from the key's
 * lms_type; 0.1.243 parameterized: H5=32 / H10=1024 / H15=32768, supports the
 * full safe parameter set).
 * Single-key fixed scheme: no key_handle (cross-key isolation is the multi-key
 * scenario's concern; none currently). */
int sec_sign(uint32_t max_ctr,
             int (*do_sign)(uint32_t q, void *ctx), void *ctx,
             uint32_t *q_out)
{
    uint32_t q;
    int sign_rc;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t sec_prof_t0 = 0u;
    uint32_t sec_prof_t1 = 0u;
    uint32_t sec_prof_t2 = 0u;
    uint32_t sec_prof_t3 = 0u;
#endif

    if (q_out != 0) {
        *q_out = 0u;
    }
    /* Entry gating (§9.4/§10/§13 test 10). */
    if (sec_state == SEC_ST_ERROR_LOCKED) {
        return SEC_ERR_LOCKED;
    }
    if (sec_state != SEC_ST_IDLE) {
        return SEC_RSP_BUSY;  /* BOOTING/RESERVED/KEYGEN_PENDING */
    }
    if (sec_key_loaded == 0u) {
        return SEC_ERR_LOCKED;
    }
    if (max_ctr == 0u || sec_ctr >= max_ctr) {
        sec_state = SEC_ST_EXHAUSTED;
        return SEC_ERR_EXHAUSTED;
    }

    q = sec_ctr;
#if defined(LMS_MMIO_SOC_PROFILE)
    sec_prof_t0 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
#endif
    /* Reserve (commit first, sign after): if power is lost now, q is burned on recovery. */
    if (!state_commit(SEC_ST_RESERVED, q)) {
        /* Reserve commit failed: conservatively burn q, forbid release. */
        (void)state_commit(SEC_ST_IDLE, q + 1u);
        return SEC_ERR_COMMIT;
    }

#if defined(LMS_MMIO_SOC_PROFILE)
    sec_prof_t1 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_commit1_cycles = sec_prof_t1 - sec_prof_t0;
#endif
    /* Sign batch task (v5 fused derive+sign; SEED never leaves hardware). */
    sign_rc = (do_sign != 0) ? do_sign(q, ctx) : LMS_ERR_INVALID;

#if defined(LMS_MMIO_SOC_PROFILE)
    sec_prof_t2 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_dosign_cycles = sec_prof_t2 - sec_prof_t1;
#endif
    /* Commit before release (blocking): no signature output without RSP_COMMIT_OK. */
    if (sign_rc == LMS_OK &&
        state_commit(SEC_ST_IDLE, q + 1u)) {
#if defined(LMS_MMIO_SOC_PROFILE)
        sec_prof_t3 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
        sec_prof_commit2_cycles = sec_prof_t3 - sec_prof_t2;
#endif
        if (q_out != 0) {
            *q_out = q;
        }
        return SEC_OK;
    }

    /* Sign or Commit failure: q already consumed by Reserve; burn conservatively (ctr=q+1), no release. */
    (void)state_commit(SEC_ST_IDLE, q + 1u);
    return (sign_rc != LMS_OK) ? SEC_ERR_PATH : SEC_ERR_COMMIT;
}

/* UART COMMIT legal-transition whitelist (0.1.269 H1 hardening).
 * External interface must not break the core invariant Release(σ_q) =>
 * Committed(CTR >= q+1):
 * ① ctr monotonic (call site rejects ctr < sec_ctr first);
 * ② only transitions internal flows use (ctr advances or holds, per transition).
 * Internal state_commit calls (sec_sign/sec_boot) bypass this whitelist,
 * behavior unchanged. */
static int sec_uart_commit_allowed(uint16_t new_state, uint32_t ctr)
{
    switch (sec_state) {
    case SEC_ST_IDLE:
        /* Reserve RESERVED(q)/tree-build KEYGEN_PENDING/manual advance/
         * exhaustion marking: ctr must not roll back (== tightly coupled
         * reservation, > test skip; neither breaks the invariant).
         * REVIEW B07-R9 documented boundary: allowing RESERVED/EXHAUSTED at
         * ctr==sec_ctr lets the host "reserve without signing" or lock out early
         * (availability cost, not a security break); part of the declared
         * surface of the "host is persistent authority" threat model, same
         * family as M5 (no watchdog). */
        if (new_state == SEC_ST_RESERVED || new_state == SEC_ST_KEYGEN_PENDING ||
            new_state == SEC_ST_IDLE || new_state == SEC_ST_EXHAUSTED) {
            return ctr >= sec_ctr;
        }
        return 0;
    case SEC_ST_RESERVED:
        /* Commit/burn IDLE(ctr=q+1): ctr must advance (no in-place re-sign). */
        if (new_state == SEC_ST_IDLE) {
            return ctr > sec_ctr;
        }
        return 0;
    case SEC_ST_KEYGEN_PENDING:
        /* Tree build done, back to IDLE: ctr holds or advances. */
        if (new_state == SEC_ST_IDLE) {
            return ctr >= sec_ctr;
        }
        return 0;
    default:
        /* BOOTING/ERROR_LOCKED/EXHAUSTED: no legal outgoing transition. */
        return 0;
    }
}

/* ---- Security-domain UART command dispatch ----
 * response[32]: payload written back into the caller's 48B frame ([16..47]). */
int sec_handle_uart_cmd(uint8_t sub, const uint8_t *params, uint8_t response[32])
{
    uint32_t new_state;
    uint32_t ctr;
    uint8_t slot;
    uint32_t index;
    int rc;

    memset(response, 0, 32u);
    response[0] = sub;
    response[2] = SEC_OK;
    response[3] = (uint8_t)(sec_slot_valid[0] | (uint8_t)(sec_slot_valid[1] << 1));

    if (sub == SEC_SUB_COMMIT) {
        /* params = new_state(4BE) || ctr(4BE) || reserved_q(4BE).
         * reserved_q is a UART test parameter (no longer stored in body; ignored).
         * Gating: ERROR_LOCKED rejected; BOOTING (not FACTORY_INIT/BOOT) rejected. */
        if (sec_state == SEC_ST_ERROR_LOCKED) {
            response[2] = SEC_ERR_LOCKED;
            return SEC_ERR_LOCKED;
        }
        if (sec_state == SEC_ST_BOOTING) {
            response[2] = SEC_RSP_BUSY;
            return SEC_RSP_BUSY;
        }
        new_state = get_be32(params + 0) & 0xffffu;
        ctr = get_be32(params + 4);
        (void)get_be32(params + 8);
        /* 0.1.269 H1 hardening: UART COMMIT is an external interface; any
         * (new_state, ctr) rollback could break the invariant (e.g. COMMIT(IDLE,
         * ctr=0) → re-sign released q=0). Enforce ctr monotonicity + legal
         * transition whitelist; internal state_commit calls unaffected. */
        if (ctr < sec_ctr || !sec_uart_commit_allowed((uint16_t)new_state, ctr)) {
            response[2] = SEC_ERR_COMMIT;
            return SEC_ERR_COMMIT;
        }
        if (state_commit((uint16_t)new_state, ctr)) {
            put_be32(response + 4, sec_last_tx);
            put_be32(response + 8, (uint32_t)sec_state);
            put_be32(response + 12, sec_ctr);
        } else {
            response[2] = SEC_ERR_COMMIT;
        }
        response[3] = (uint8_t)(sec_slot_valid[0] | (uint8_t)(sec_slot_valid[1] << 1));
        return (int)response[2];
    }
    if (sub == SEC_SUB_READ_ACTIVE) {
        /* Read active slot's first 28B (response payload cap). */
        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_slots[sec_active_slot][index];
        }
        return 0;
    }
    if (sub == SEC_SUB_READ_SLOT) {
        slot = params[0];
        if (slot > 1u || sec_slot_valid[slot] == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_slots[slot][index];
        }
        return 0;
    }
    if (sub == SEC_SUB_INJECT_TAG) {
#if defined(LMS_FW_SEC_TEST_MODE)
        /* Fault injection: corrupt one byte of the active slot's tag (tests rollback/tag rejection). */
        sec_slots[sec_active_slot][SEC_OFF_TAG] ^= 0xffu;
        return 0;
#else
        /* 0.1.269 H4 hardening: fault injection is a test-only backdoor; deploy
         * builds (LMS_FW_SEC_TEST_MODE undefined) always reject, narrowing the
         * attack surface. */
        response[2] = SEC_ERR_UNSUPPORTED;
        return SEC_ERR_UNSUPPORTED;
#endif
    }
    if (sub == SEC_SUB_FACTORY_INIT) {
        rc = sec_factory_init(params, response);   /* params = first key I(16B), host-provided */
        response[2] = (uint8_t)rc;
        return rc;
    }
    if (sub == SEC_SUB_BOOT) {
        (void)sec_boot(params);   /* params = active key I(16B), host reload */
        put_be32(response + 4, (uint32_t)sec_state);
        put_be32(response + 8, sec_ctr);
        put_be32(response + 12, sec_last_tx);
        response[20] = sec_factory_locked;
        response[21] = sec_key_loaded;
        response[24] = sec_boot_valid[0];
        response[25] = sec_boot_valid[1];
        response[26] = sec_rec_diag[0];
        response[27] = sec_rec_diag[1];
        response[22] = sec_keygen_pending;
        response[23] = sec_active_slot;
        return 0;
    }
    if (sub == SEC_SUB_GET_STATE) {
        put_be32(response + 4, (uint32_t)sec_state);
        put_be32(response + 8, sec_ctr);
        put_be32(response + 12, sec_last_tx);
        response[20] = sec_factory_locked;
        response[21] = sec_key_loaded;
        response[22] = sec_keygen_pending;
        response[23] = sec_active_slot;
        return 0;
    }
    if (sub == SEC_SUB_NVM_LOAD) {
        /* Host reload of persistent domain: params = slot(1) || 64B STATE_REC.
         * REVIEW B07-R8 (assessed, behavior unchanged): valid=1 here means "slot
         * loaded", not "authenticity verified" — full validation (magic + tag
         * recompute, all-zero = fresh device) happens only in BOOT's
         * rec_valid/slots_all_zero; legitimate reload flows include "all-zero
         * record after NVM erase" (boot7b test), so loading must not reject on magic. */
        slot = params[0];
        if (slot > 1u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        memcpy(sec_slots[slot], params + 1, SEC_STATE_REC_LEN);
        sec_slot_valid[slot] = 1u;
        response[3] = (uint8_t)(sec_slot_valid[0] | (uint8_t)(sec_slot_valid[1] << 1));
        return 0;
    }
    if (sub == SEC_SUB_NVM_READ) {
        /* Host fetch of persistent domain: return the slot's body first 28B. */
        slot = params[0];
        if (slot > 1u || sec_slot_valid[slot] == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_slots[slot][index];
        }
        return 0;
    }
    if (sub == SEC_SUB_MC_LOAD) {
        /* Host reload of sim_mc persistent domain (spec §7: restore the monotonic counter's initial value from host after power-on). */
        if (lms_mmio_mc_load(sec_client, get_be32(params + 0)) != LMS_MMIO_OK) {
            response[2] = SEC_ERR_AUTH;
            return SEC_ERR_AUTH;
        }
        return 0;
    }
    if (sub == SEC_SUB_WRAP_LOAD) {
        /* P1-6 (0.1.274): host reloads 48B wrapped blob (deploy BOOT unwraps to restore SEED). */
        memcpy(sec_wrapped_blob, params, LMS_MMIO_WRAPPED_LEN);
        sec_wrapped_valid = 1u;
        return 0;
    }
    if (sub == SEC_SUB_WRAPPED_READ_LO) {
        /* Host fetches wrapped blob's first 28B (persisted after FACTORY_INIT
         * produced it; response body cap 28B, same convention as NVM_READ). */
        if (sec_wrapped_valid == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_wrapped_blob[index];
        }
        return 0;
    }
    if (sub == SEC_SUB_WRAPPED_READ_HI) {
        /* Host fetches wrapped blob's last 20B (blob[28..47]). */
        if (sec_wrapped_valid == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 20u; index++) {
            response[4u + index] = sec_wrapped_blob[28u + index];
        }
        return 0;
    }
    response[2] = SEC_ERR_UNSUPPORTED;
    return SEC_ERR_UNSUPPORTED;
}
