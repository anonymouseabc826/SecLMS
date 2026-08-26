/*
 * LMS phase-3 security state domain (spec §3.3/§8)
 *
 * The only new module; exposes just two functions externally (impl_roadmap §2 coupling control):
 *   sec_boot()              — power-on recovery (fully implemented in step 5; stub for now)
 *   sec_handle_uart_cmd()   — security-domain UART command dispatch (STATE_COMMIT test-driven)
 *
 * Internal structs stay out of this header. Algorithm layer (src/) untouched;
 * HMAC runs in hardware with K_STATE via lms_mmio_hmac_kstate() (K_STATE unreadable, never leaves hardware).
 */
#ifndef LMS_SEC_STATE_H
#define LMS_SEC_STATE_H

#include <stdint.h>

#include "lms_mmio.h"

#ifdef __cplusplus
extern "C" {
#endif

/* FSM states (spec §6). */
#define SEC_ST_ERROR_LOCKED   0u
#define SEC_ST_IDLE           1u
#define SEC_ST_RESERVED       2u
#define SEC_ST_KEYGEN_PENDING 3u
#define SEC_ST_EXHAUSTED      4u
#define SEC_ST_BOOTING        5u

/* STATE_REC fixed length 64B. */
#define SEC_STATE_REC_LEN 64u
#define SEC_STATE_TAG_LEN 16u

/* sec_handle_uart_cmd subcommands. */
#define SEC_SUB_COMMIT      0x01u
#define SEC_SUB_READ_ACTIVE 0x02u
#define SEC_SUB_READ_SLOT   0x03u
#define SEC_SUB_INJECT_TAG  0x04u
#define SEC_SUB_BOOT        0x05u
#define SEC_SUB_FACTORY_INIT 0x06u
#define SEC_SUB_GET_STATE   0x07u
#define SEC_SUB_NVM_LOAD    0x08u  /* params: slot(1) || 64B rec (host reloads persistent domain) */
#define SEC_SUB_NVM_READ    0x09u  /* params: slot(1); response body first 28B (host fetches persistent domain) */
#define SEC_SUB_MC_LOAD     0x0au  /* params: value(4BE) (host reloads sim_mc persistent domain) */
#define SEC_SUB_WRAP_LOAD   0x0bu  /* P1-6 (0.1.274): params = 48B wrapped blob (host reload; used by deploy BOOT unwrap) */
#define SEC_SUB_WRAPPED_READ_LO 0x0cu  /* no params; response body first 28B (wrapped[0..27], host fetch) */
#define SEC_SUB_WRAPPED_READ_HI 0x0du  /* no params; response body first 20B (wrapped[28..47], host fetch) */

/* Error codes (spec §10). */
#define SEC_OK                0u
#define SEC_RSP_BUSY          1u
#define SEC_ERR_LOCKED        2u
#define SEC_ERR_COMMIT        3u
#define SEC_ERR_AUTH          4u
#define SEC_ERR_PATH          5u
#define SEC_ERR_EXHAUSTED     6u
#define SEC_ERR_PARAM         7u  /* REVIEW B07-R6: invalid param/slot (no longer reuses magic 1=SEC_RSP_BUSY) */
#define SEC_ERR_FACTORY_LOCKED 8u
#define SEC_ERR_UNSUPPORTED   9u

/* Initialize the security state domain (bind MMIO client, clear A/B slots and
 * the committed snapshot, enter ST_BOOTING; not signable before FACTORY_INIT/BOOT).
 * Must be called after lms_mmio_client_init. */
void sec_init(lms_mmio_client_t *client);

/* Power-on recovery (spec §9.2): FE_REP rebuilds K_DEV → KDF → unwrap SEED →
 * dual-slot selection (tag ok and larger tx wins; same tx different content → locked) →
 * ST_RESERVED conservative burn (commit ST_IDLE ctr=q+1).
 * Returns the current hw_state (SEC_ST_*). */
uint16_t sec_boot(const uint8_t I[LMS_I_LEN]);
int sec_keygen_key(uint8_t I[LMS_I_LEN]);
/* Multi-key rotation (2026-08-22): generate and activate a **new key** (old key
 * retired atomically). Implemented only in test config (LMS_FW_SEC_TEST_MODE);
 * deploy builds return SEC_ERR_UNSUPPORTED (see
 * deploy/deploy_pending_20260822.md §1). I_new in test = external input (host supplies vector I). */
int sec_keygen_new(uint8_t I_new[LMS_I_LEN]);

/* Handle one security-domain UART command.
 *   sub      subcommand (SEC_SUB_*)
 *   params   input params (COMMIT: 12B = new_state(4BE)||ctr(4BE)||reserved_q(4BE);
 *            READ_SLOT: 1B = slot; others ignored)
 *   response output payload (32B, written back into caller's 48B frame [16..47])
 * Returns 0=success, non-zero=error code. */
int sec_handle_uart_cmd(uint8_t sub, const uint8_t *params, uint8_t response[32]);

/* Read-only snapshot: current hw_state and last_committed_tx (diagnostics). */
uint16_t sec_hw_state(void);
uint32_t sec_last_committed_tx(void);

/* Diagnostic/test read-only snapshot (step 5). */
uint32_t sec_ctr_value(void);
uint8_t sec_key_ready(void);
uint8_t sec_keygen_pending_flag(void);

/* Host persistent-domain bridge (spec §7 host file model): copy the active slot's
 * full 64B to the caller's buffer (firmware syncs via NVM_SYNC; host fetches without knowing the tag). */
void sec_export_active(uint8_t out[SEC_STATE_REC_LEN]);

/* SEC_SIGN atomicity (spec §9.4, step 6).
 * Orchestration: gating (IDLE/key ready/not exhausted/q==ctr) →
 *   Reserve (commit ST_RESERVED(q) first) → do_sign callback (v5 fused derive+sign,
 *   SEED never leaves hardware) → Commit (ST_IDLE ctr=q+1) → release.
 * On sign-callback or Commit failure: state_burn (commit ctr=q+1, q consumed), no release.
 * do_sign provided by firmware service layer (fills lmots_signature incl. C/Y; LMS_OK on success).
 * max_ctr = sign state machine ctr cap (= 2^h, h = key tree height; exhausted if sec_ctr >= max_ctr).
 * Single-key fixed scheme: no key_handle (cross-key isolation is the multi-key scenario's concern).
 * Returns SEC_OK on success (*q_out=signed q), else an error code (§10). */
int sec_sign(uint32_t max_ctr,
             int (*do_sign)(uint32_t q, void *ctx), void *ctx,
             uint32_t *q_out);

#ifdef __cplusplus
}
#endif

#endif /* LMS_SEC_STATE_H */
