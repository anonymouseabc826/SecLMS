#ifndef LMS_MMIO_H
#define LMS_MMIO_H

#include "lms.h"
#include "hash_api.h"

#include <stddef.h>
#include <stdint.h>

#define LMS_MMIO_VERSION_0_1 0x00000001u
#define LMS_MMIO_VERSION_0_2 0x00000002u
#define LMS_MMIO_VERSION_0_3 0x00000003u
#define LMS_MMIO_VERSION_0_4 0x00000004u
#define LMS_MMIO_VERSION_0_5 0x00000005u
#define LMS_MMIO_VERSION_0_6 0x00000006u
#define LMS_MMIO_VERSION_0_7 0x00000007u

#define LMS_MMIO_CAP_SHA256   (1u << 0)
#define LMS_MMIO_CAP_HASH_ONCE (1u << 1)
#define LMS_MMIO_CAP_CHAIN     (1u << 2)
#define LMS_MMIO_CAP_DERIVE_CHAIN (1u << 3)
#define LMS_MMIO_CAP_INSECURE_TEST_MODE (1u << 4)
#define LMS_MMIO_CAP_LMOTS_KEYGEN (1u << 5)
#define LMS_MMIO_CAP_LMOTS_SIGN (1u << 6)
#define LMS_MMIO_CAP_LMOTS_VERIFY (1u << 7)
#define LMS_MMIO_CAP_SIM_MC   (1u << 8)
#define LMS_MMIO_CAP_WRAP     (1u << 9)
#define LMS_MMIO_CAP_HMAC_KSTATE (1u << 10)
#define LMS_MMIO_CAP_LMOTS_KEYGEN_LEAF (1u << 11)
#define LMS_MMIO_CAP_SHAKE256  (1u << 12)  /* SHAKE256 primitive support (VERSION=0x01) */
#define LMS_MMIO_CAP_D_INTR_CHAIN (1u << 13) /* CMD_D_INTR_CHAIN chained authentication path primitive (S6, both platforms) */
#define LMS_MMIO_CAP_MSG_Q_COEF (1u << 14) /* message hash->Q->checksum->coefficients (CMD_MSG_Q_COEF) */
#define LMS_MMIO_CAP_STATE_COMMIT (1u << 15) /* CMD_STATE_COMMIT fused command (0.1.256, SHAKE256; without this bit, falls back to two steps) */
#define LMS_MMIO_CAP_PROBE_REQUIRED LMS_MMIO_CAP_SHA256
#define LMS_MMIO_CAP_V0_REQUIRED \
    (LMS_MMIO_CAP_SHA256 | LMS_MMIO_CAP_HASH_ONCE | LMS_MMIO_CAP_CHAIN)

#define LMS_MMIO_REG_VERSION       0x000u
#define LMS_MMIO_REG_CAPABILITY    0x004u
#define LMS_MMIO_REG_COMMAND       0x008u
#define LMS_MMIO_REG_CONTROL       0x00cu
#define LMS_MMIO_REG_STATUS        0x010u
#define LMS_MMIO_REG_ERROR         0x014u
#define LMS_MMIO_REG_INPUT_LENGTH  0x018u
#define LMS_MMIO_REG_OUTPUT_LENGTH 0x01cu
#define LMS_MMIO_REG_CYCLE_COUNT   0x020u
#define LMS_MMIO_REG_ARG_Q         0x024u
#define LMS_MMIO_REG_ARG_I         0x028u
#define LMS_MMIO_REG_ARG_START     0x02cu
#define LMS_MMIO_REG_ARG_STEPS     0x030u
#define LMS_MMIO_REG_ARG_KEY       0x034u
#define LMS_MMIO_REG_TASK_ADDR     0x038u
#define LMS_MMIO_REG_TASK_DATA     0x03cu
#define LMS_MMIO_REG_IDENTIFIER    0x040u
#define LMS_MMIO_REG_SIM_MC        0x060u  /* space consolidation: moved here from 0x044 (fixes overlap with IDENTIFIER) */
#define LMS_MMIO_REG_ARG_LEAF_NODE 0x050u
#define LMS_MMIO_REG_SEED          0x080u
#define LMS_MMIO_REG_WRAPPED       0x0a0u
#define LMS_MMIO_REG_KWRAP         0x0e0u
#define LMS_MMIO_REG_INPUT         0x100u
#define LMS_MMIO_REG_OUTPUT        0x200u

#define LMS_MMIO_CMD_HASH_ONCE 1u
#define LMS_MMIO_CMD_CHAIN     2u
#define LMS_MMIO_CMD_SEED_LOAD 3u
#define LMS_MMIO_CMD_DERIVE_CHAIN 4u
#define LMS_MMIO_CMD_DERIVE_RANDOMIZER 5u
#define LMS_MMIO_CMD_LMOTS_KEYGEN 6u
#define LMS_MMIO_CMD_LMOTS_SIGN 7u
#define LMS_MMIO_CMD_LMOTS_VERIFY 8u
/* Batch-task extension range 0x09-0x0f (space consolidation): actually uses 0x0e/0x0f
 * (KEYGEN_LEAF/VERIFY_LEAF); 0x09-0x0d reserved (the security-domain range 0x10-0x17 was moved
 * here from the original 0x09-0x0d; the two ranges do not overlap or reuse). */
#define LMS_MMIO_CMD_LMOTS_KEYGEN_LEAF 14u
#define LMS_MMIO_CMD_LMOTS_VERIFY_LEAF 15u
/* Security-domain range 0x10-0x17 (space consolidation: moved here from 0x09-0x0d): MC/WRAP/HMAC/STATE_COMMIT. */
#define LMS_MMIO_CMD_MC_STEP 16u
#define LMS_MMIO_CMD_MC_LOAD 17u
#define LMS_MMIO_CMD_WRAP_SEED 18u
#define LMS_MMIO_CMD_UNWRAP_SEED 19u
#define LMS_MMIO_CMD_HMAC_KSTATE 20u
#define LMS_MMIO_CMD_STATE_COMMIT 21u  /* 0x15: mc_step+HMAC(body) fusion (SEC state commit) */
/* Authentication/large-message range 0x18-0x1f (space consolidation: D_INTR 0x10->0x18, HASH_ONCE_RAM 0x11->0x19) */
#define LMS_MMIO_CMD_D_INTR_CHAIN 24u
#define LMS_MMIO_CMD_HASH_ONCE_RAM 25u   /* 0x19: multi-block absorb from task RAM input (level 0) */
#define LMS_MMIO_CMD_MSG_Q_COEF 26u       /* 0x1a: message hash->Q->checksum->coefficients (P1 single block) */
/* 0x1c (0.1.281, deploy model B): controlled SEED load -- same data flow as SEED_LOAD(arg_key=0)
 * (REG_SEED staging + ACT_DONE_SEED latch), but deploy (INSECURE_TEST_MODE=0) also allows it.
 * Security property: this command is **not in the UART request table** (only the firmware-internal
 * keygen_new flow calls it); the SEED is generated on-device by TRNG and enters slot 0 through it;
 * the plaintext SEED_LOAD gating (lms_hash_cmd_check.v) is unchanged. */
#define LMS_MMIO_CMD_SEED_WRITE_SAFE 28u  /* 0x1c */

#define LMS_MMIO_WRAPPED_LEN 48u
#define LMS_MMIO_KEY_SEED 0u
#define LMS_MMIO_KEY_KWRAP 1u
#define LMS_MMIO_KEY_KSTATE 2u

#define LMS_MMIO_CTRL_START (1u << 0)
#define LMS_MMIO_CTRL_CLEAR (1u << 1)

#define LMS_MMIO_STATUS_BUSY  (1u << 0)
#define LMS_MMIO_STATUS_DONE  (1u << 1)
#define LMS_MMIO_STATUS_ERROR (1u << 2)

#define LMS_MMIO_HW_ERR_NONE                0u
#define LMS_MMIO_HW_ERR_UNSUPPORTED_COMMAND 1u
#define LMS_MMIO_HW_ERR_BUSY                2u
#define LMS_MMIO_HW_ERR_INPUT_LENGTH        3u
#define LMS_MMIO_HW_ERR_OUTPUT_LENGTH       4u
#define LMS_MMIO_HW_ERR_CHAIN_INDEX         5u
#define LMS_MMIO_HW_ERR_CHAIN_RANGE         6u
#define LMS_MMIO_HW_ERR_CONTROL             7u
#define LMS_MMIO_HW_ERR_INTERNAL            15u

#define LMS_MMIO_OUTPUT_LEN 32u
#define LMS_MMIO_MAX_INPUT  128u
#define LMS_MMIO_HASH_ONCE_RAM_MAX 2048u   /* HASH_ONCE_RAM input limit (M=16x128B) */
/* Winternitz w parameterization (stage 2, w∈{1,2,4,8}): coefficient/chain-value buffers are
 * statically allocated for the largest class W1 (p=265) and actually used according to the p/w
 * derived from lmots_type. RTL coefficients are **packed compactly** (32/w per word, keeping the
 * boundary at 32 so it does not collide with the task-RAM y region; see hash_w_param_plan §13.4). */
#define LMS_MMIO_MAX_COEFFICIENTS LMS_MAX_OTS_P
#define LMS_MMIO_MAX_CHAIN_BYTES (LMS_MAX_OTS_P * LMS_N)
#define LMS_MMIO_TASK_CHAIN_WORD_BASE 32u
/* Winternitz w runtime parameter (for RTL batch tasks, added in stage 1): w (1/2/4/8) must be written before a batch-task START. */
#define LMS_MMIO_REG_ARG_W      0x054u
/* Task-RAM stream region start (REVIEW B08-R4 fix: aligned with the production RTL coefficient
 * region boundary 32; the original 17 was the obsolete value from the deleted lms_sha256_ops.v,
 * and no caller falls in the 17..31 range -- a pure documentation fix):
 * REG_TASK_DATA writes/reads auto-increment for addresses ≥32; <32 is the coefficient region,
 * written per word with explicit addresses. */
#define LMS_MMIO_TASK_STREAM_BASE 32u

typedef enum {
    LMS_MMIO_OK = 0,
    LMS_MMIO_ERR_INVALID = -1,
    LMS_MMIO_ERR_PROTOCOL = -2,
    LMS_MMIO_ERR_HARDWARE = -3,
    LMS_MMIO_ERR_TIMEOUT = -4
} lms_mmio_status_t;

/* Hash descriptor: encapsulates all constants specific to one hash primitive.
 * Each lms_mmio_client_t binds to one descriptor after probe,
 * and all later operations obtain the hash type through the descriptor, with no hardcoding. */
typedef struct {
    lms_hash_alg_t hash_alg;         /* LMS_HASH_SHA256 / LMS_HASH_SHAKE256 */
    uint32_t       version;          /* expected VERSION register value */
    uint32_t       probe_cap;        /* capability bit to probe for */
    uint32_t       max_input_bytes;  /* HASH_ONCE maximum input */
    const char    *name;             /* for debugging */
} lms_mmio_hash_desc_t;

extern const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHA256;
extern const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHAKE256;

typedef uint32_t (*lms_mmio_read32_fn)(void *context, uint32_t offset);
typedef void (*lms_mmio_write32_fn)(void *context, uint32_t offset, uint32_t value);

typedef struct {
    void *context;
    lms_mmio_read32_fn read32;
    lms_mmio_write32_fn write32;
} lms_mmio_bus_t;

typedef struct {
    lms_mmio_bus_t bus;
    uint32_t timeout_polls;
    uint32_t capabilities;
    uint32_t last_hw_error;
    uint32_t fallback_count;
    uint64_t hardware_chain_count;
    uint64_t hardware_chain_cycles;
    uint64_t hardware_derive_count;
    uint64_t hardware_derive_cycles;
    uint64_t hardware_keygen_count;
    uint64_t hardware_keygen_cycles;
    uint64_t hardware_sign_count;
    uint64_t hardware_sign_cycles;
    uint64_t hardware_verify_count;
    uint64_t hardware_verify_cycles;
    uint64_t hardware_hash_once_count;
    uint64_t hardware_hash_once_cycles;
#if defined(LMS_MMIO_SOC_PROFILE)
    /* SoC segmented profile (debug builds only): the three SoC cycle segments
     * (write params / wait DONE / read back) of the last LM-OTS Sign/Verify command. */
    uint32_t prof_write_cycles;
    uint32_t prof_wait_cycles;
    uint32_t prof_read_cycles;
#endif
    uint32_t key_handle;
    int allow_fallback;
    int probed;
    int coef_ready;   /* P1.5: coefficients already left in hardware coefficient_words (set after MSG_Q_COEF keep mode) */
    const lms_mmio_hash_desc_t *hash_desc;  /* hash descriptor bound after probe */
    /* Randomizer C source (TRNG-C scheme, decided in session 2026-08-22, scheme A: backend reads
     * directly). Priority: randomizer_c_slot non-NULL -> copy from the C_LOAD slot (fixed debug
     * test vector); else trng_fill_c non-NULL -> callback reads 32B from the security-domain TRNG
     * (deploy, health-gated fail-closed); else return an error. The C source is configured by
     * firmware per INSECURE_TEST_MODE. */
    const uint8_t *randomizer_c_slot;   /* debug C_LOAD slot (LMS_N bytes), NULL=not configured */
    int  (*trng_fill_c)(void *context, uint8_t out[LMS_N]);  /* deploy TRNG fill callback */
    void *trng_context;                 /* context passed to trng_fill_c */
} lms_mmio_client_t;

void lms_mmio_bus_init_direct(lms_mmio_bus_t *bus, volatile void *base);
int lms_mmio_client_init(lms_mmio_client_t *client,
                         const lms_mmio_bus_t *bus,
                         uint32_t timeout_polls,
                         int allow_fallback);
int lms_mmio_probe(lms_mmio_client_t *client);
int lms_mmio_hash_once(lms_mmio_client_t *client,
                       const uint8_t *input,
                       size_t input_len,
                       uint8_t output[LMS_N],
                       uint32_t *cycles);
/* HASH_ONCE_RAM: multi-block absorb from task RAM (starting at word 32) input (≤LMS_MMIO_HASH_ONCE_RAM_MAX).
 * The input is contiguous bytes; hardware chunks it by the SHAKE256 rate (last-block padding handled in hardware). */
int lms_mmio_hash_once_ram(lms_mmio_client_t *client,
                           const uint8_t *input,
                           size_t input_len,
                           uint8_t output[LMS_N],
                           uint32_t *cycles);
/* MSG_Q_COEF: one command completes message hash->Q->checksum->coefficients (P1 single block, L=54+m ≤128).
 * Input I/q/C/message/lmots_type; output Q[32B] + coefficients[p] (unpacked byte array).
 * coefficients==NULL -> coefficients **left in hardware** coefficient_words (no read-back, P1.5 keep mode).
 * Without CAP_MSG_Q_COEF returns LMS_MMIO_ERR_PROTOCOL (caller falls back to software). */
int lms_mmio_msg_q_coef(lms_mmio_client_t *client,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        const uint8_t C[LMS_N],
                        const uint8_t *message,
                        size_t message_len,
                        uint32_t lmots_type,
                        uint8_t Q[LMS_N],
                        uint8_t coefficients[LMS_MAX_OTS_P],
                        uint32_t *cycles);
int lms_mmio_chain(lms_mmio_client_t *client,
                   const uint8_t I[LMS_I_LEN],
                   uint32_t q,
                   uint32_t i,
                   uint32_t start,
                   uint32_t steps,
                   uint8_t value[LMS_N],
                   uint32_t *cycles);
int lms_mmio_seed_load_test(lms_mmio_client_t *client,
                            uint32_t key_handle,
                            const uint8_t seed[LMS_SEED_LEN]);
/* Controlled SEED load (0.1.281, deploy model B): same data flow as seed_load_test (REG_SEED
 * staging + command latch), but does **not depend on CAP_INSECURE_TEST_MODE** -- deploy
 * (INSECURE_TEST_MODE=0) also allows it. Only the firmware-internal keygen_new flow calls it
 * (the command is not in the UART request table); requires CAP_WRAP (security-domain build).
 * The plaintext SEED_LOAD gating (rtl/lms_hash_cmd_check.v) is unchanged. */
int lms_mmio_seed_load_safe(lms_mmio_client_t *client,
                            const uint8_t seed[LMS_SEED_LEN]);
int lms_mmio_derive_chain(lms_mmio_client_t *client,
                          uint32_t key_handle,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t i,
                          uint32_t start,
                          uint32_t steps,
                          uint8_t output[LMS_N],
                          uint32_t *cycles);
int lms_mmio_derive_randomizer(lms_mmio_client_t *client,
                               uint32_t key_handle,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint8_t output[LMS_N],
                               uint32_t *cycles);
    int lms_mmio_lmots_keygen(lms_mmio_client_t *client,
                         uint32_t key_handle,
                         const uint8_t I[LMS_I_LEN],
                         uint32_t q,
                         uint32_t lmots_type,
                         uint8_t output[LMS_N],
                         uint32_t *cycles);
    /* KEYGEN_LEAF: K_q stays in hardware; internally continues with D_LEAF = H(I||node_num||D_LEAF||K_q),
     * outputting only the leaf node. node_num = 2^h + q (whole-tree 1-based node number). */
    int lms_mmio_lmots_keygen_leaf(lms_mmio_client_t *client,
                         uint32_t key_handle,
                         const uint8_t I[LMS_I_LEN],
                         uint32_t q,
                         uint32_t node_num,
                         uint32_t lmots_type,
                         uint8_t output[LMS_N],
                         uint32_t *cycles);
int lms_mmio_lmots_sign(lms_mmio_client_t *client,
                        uint32_t key_handle,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        uint32_t lmots_type,
                        const uint8_t coefficients[LMS_MAX_OTS_P],
                        uint8_t outputs[LMS_MAX_OTS_P * LMS_N],
                        uint32_t *cycles);
int lms_mmio_lmots_verify(lms_mmio_client_t *client,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t coefficients[LMS_MAX_OTS_P],
                          const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                          uint8_t output[LMS_N],
                          uint32_t *cycles);
/* UART bridge task-RAM resident variant (Step 3): the signature y has already been written to
 * task RAM by the SoC-layer UART pass-through bridge (verify) or remains in task RAM for the
 * bridge to read out (sign), skipping the 2144B MMIO transfer between firmware and task RAM.
 * Used only for the LM-OTS UART command path; the LMS layer (tree building/verification) still uses the standard functions. */
int lms_mmio_lmots_sign_taskram(lms_mmio_client_t *client,
                                uint32_t key_handle,
                                const uint8_t I[LMS_I_LEN],
                                uint32_t q,
                                uint32_t lmots_type,
                                const uint8_t coefficients[LMS_MAX_OTS_P],
                                uint32_t *cycles);
int lms_mmio_lmots_verify_taskram(lms_mmio_client_t *client,
                                  const uint8_t I[LMS_I_LEN],
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t coefficients[LMS_MAX_OTS_P],
                                  uint8_t output[LMS_N],
                                  uint32_t *cycles);
/* VERIFY_LEAF: after signature-chain verification computes K_q, hardware internally continues
 * with D_LEAF = H(I||node_num||D_LEAF||K_q), outputting only the leaf node (one MMIO, eliminating
 * the second interaction where software reads back K_q and then issues HASH_ONCE).
 * node_num = 2^h + q (whole-tree 1-based node number). The capability reuses CAP_LMOTS_VERIFY. */
int lms_mmio_lmots_verify_leaf(lms_mmio_client_t *client,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint32_t node_num,
                               uint32_t lmots_type,
                               const uint8_t coefficients[LMS_MAX_OTS_P],
                               const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                               uint8_t output[LMS_N],
                               uint32_t *cycles);
/* VERIFY_LEAF bridge variant: the signature y has already been written to task RAM by the UART pass-through bridge (skips the inputs transfer). */
int lms_mmio_lmots_verify_leaf_taskram(lms_mmio_client_t *client,
                                       const uint8_t I[LMS_I_LEN],
                                       uint32_t q,
                                       uint32_t node_num,
                                       uint32_t lmots_type,
                                       const uint8_t coefficients[LMS_MAX_OTS_P],
                                       uint8_t output[LMS_N],
                                       uint32_t *cycles);
/* Standard backend activation (the SEED never leaves hardware; it is injected into the slot
 * internally via SEC WRAP/UNWRAP). Registers only the fused backend (all chains in one MMIO),
 * not the single-step chain/derive. */
int lms_mmio_lmots_keygen_enable(lms_mmio_client_t *client, uint32_t key_handle);
int lms_mmio_lmots_sign_enable(lms_mmio_client_t *client, uint32_t key_handle);
void lms_mmio_lmots_keygen_disable(void);
int lms_mmio_lmots_verify_enable(lms_mmio_client_t *client);
void lms_mmio_lmots_verify_disable(void);
void lms_mmio_lmots_sign_disable(void);

/* Debug/test backend activation (the SEED is injected externally via the bus seed_load_test;
 * requires INSECURE_TEST_MODE). Registers chain + derive + fused backends, allowing both
 * single-step and fused call paths. */
int lms_mmio_lmots_keygen_enable_insecure(lms_mmio_client_t *client);
int lms_mmio_lmots_sign_enable_insecure(lms_mmio_client_t *client);

/* Phase 3 v6: sim_mc monotonic counter and wrapped_seed wrapping. */
int lms_mmio_mc_read(lms_mmio_client_t *client, uint32_t *value);
int lms_mmio_mc_step(lms_mmio_client_t *client, uint32_t *value);

/* CMD_STATE_COMMIT: sim_mc+1 (tx hardware monotonic) -> HMAC(body=magic||state||ctr||tx||reserved||aad)
 * in one transaction, outputting tx + tag (first 16B). Both tx and tag are produced by hardware;
 * K_STATE never leaves hardware. */
int lms_mmio_state_commit(lms_mmio_client_t *client,
                          uint16_t new_state, uint32_t ctr, uint8_t aad,
                          uint32_t *tx_out, uint8_t tag[16]);
int lms_mmio_mc_load(lms_mmio_client_t *client, uint32_t value);
/* Load K_WRAP/K_STATE (INSECURE_TEST_MODE staging, for the prototype; the KDF comes in a later step). */
int lms_mmio_key_slot_load_test(lms_mmio_client_t *client,
                                uint32_t key_slot,
                                const uint8_t key[LMS_SEED_LEN]);
/* wrap: SEED slot -> 48B wrapped_seed (ciphertext+tag, readable, not secret). */
int lms_mmio_wrap_seed(lms_mmio_client_t *client,
                       uint8_t wrapped[LMS_MMIO_WRAPPED_LEN]);
/* unwrap: 48B wrapped_seed -> SEED slot (tag verified, plaintext never lands). */
int lms_mmio_unwrap_seed(lms_mmio_client_t *client,
                         const uint8_t wrapped[LMS_MMIO_WRAPPED_LEN]);
/* Generic HMAC-SHA256(K_STATE, input). K_STATE resides in a hardware slot (unreadable).
 * input_len ≤ 119 (inner ≤3 blocks). Outputs the full 32B HMAC; the caller truncates the first 16B as the tag. */
int lms_mmio_hmac_kstate(lms_mmio_client_t *client,
                         const uint8_t *input,
                         size_t input_len,
                         uint8_t output[LMS_N]);

#endif