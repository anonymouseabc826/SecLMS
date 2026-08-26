#include <stdint.h>
#include <string.h>

#include "lms.h"
#include "lms_internal.h"
#include "lms_mmio.h"
#include "lms_rnd.h"
#include "lms_sec_state.h"
#include "lms_subtree.h"

/* ---- Compile-time hash selection (injected by Makefile FW_HASH_FLAGS) ----
 * Parameter sets (LM-OTS w, LMS h) are no longer compile-time fixed; they
 * are parsed from command-frame private-key bytes (lms_private_key_parse
 * reads lms_type/lmots_type → lms_get_lms_param/lms_get_lmots_param gives
 * h/w/p/n), and firmware dispatches by parameter set. HW acceleration
 * lmots_hw_supported(): both engines parameterized over w∈{1,2,4,8} → all w. */
/* REVIEW B05B06-R4: SoC builds are always single-platform (single HASH_IMPL
 * value), so the two macros never coexist; if a both build (PC/test only)
 * occurs, this block silently picks SHA256 in defined order—intentional, to
 * match the `#if defined` style below (do not revert to bare `#if FW_HASH_*`). */
#if defined(FW_HASH_SHA256)
#define FW_HASH_ALG   LMS_HASH_SHA256
#define FW_LMOTS_W4   LMOTS_SHA256_N32_W4
#elif defined(FW_HASH_SHAKE256)
#define FW_HASH_ALG   LMS_HASH_SHAKE256
#define FW_LMOTS_W4   LMOTS_SHAKE256_N32_W4
#else
#error "No hash algorithm selected (define FW_HASH_SHA256 or FW_HASH_SHAKE256)"
#endif

#define MMIO32(address) (*(volatile uint32_t *)(uintptr_t)(address))

#define UART_TX           0x10000000u
#define UART_TX_READY     0x10000004u
#define UART_RX           0x10000008u
#define UART_RX_READY     0x1000000cu
#define SOC_CYCLE_COUNT   0x10000010u
#define GPIO_OUT          0x10000018u
#define LMS_BASE          0x16000000u
#define LMS_COMMAND       (LMS_BASE + 0x008u)
#define LMS_CONTROL       (LMS_BASE + 0x00cu)
#define LMS_STATUS        (LMS_BASE + 0x010u)
#define LMS_ERROR         (LMS_BASE + 0x014u)
#define LMS_INPUT_LENGTH  (LMS_BASE + 0x018u)
#define LMS_OUTPUT_LENGTH (LMS_BASE + 0x01cu)
#define LMS_CYCLE_COUNT   (LMS_BASE + 0x020u)
#define LMS_ARG_Q         (LMS_BASE + 0x024u)
#define LMS_ARG_I         (LMS_BASE + 0x028u)
#define LMS_ARG_START     (LMS_BASE + 0x02cu)
#define LMS_ARG_STEPS     (LMS_BASE + 0x030u)
#define LMS_IDENTIFIER    (LMS_BASE + 0x040u)
#define LMS_INPUT         (LMS_BASE + 0x100u)
#define LMS_OUTPUT        (LMS_BASE + 0x200u)

#define LMS_CMD_HASH_ONCE 1u
#define LMS_CMD_CHAIN     2u
#define LMS_CMD_DERIVE_CHAIN 4u
#define LMS_CMD_DERIVE_RANDOMIZER 5u
#define LMS_CMD_D_INTR_CHAIN 0x18u   /* Space hardening: moved here from 0x10 (auth/large-message region 0x18-0x1f) */
#define LMS_CTRL_START    1u
#define LMS_CTRL_CLEAR    2u
#define LMS_STATUS_BUSY   1u
#define LMS_STATUS_DONE   2u
#define LMS_TASK_ADDR     (LMS_BASE + 0x038u)
#define LMS_TASK_DATA     (LMS_BASE + 0x03cu)
#define LMS_ARG_LEAF_NODE (LMS_BASE + 0x050u)

/* TRNG standalone peripheral (C1, address region 0x17000000, rtl/lms_trng_mmio.v). */
#define TRNG_BASE     0x17000000u
#define TRNG_VERSION  (TRNG_BASE + 0x00u)
#define TRNG_CAP      (TRNG_BASE + 0x04u)
#define TRNG_CTRL     (TRNG_BASE + 0x08u)
#define TRNG_STAT     (TRNG_BASE + 0x0cu)
#define TRNG_RND      (TRNG_BASE + 0x10u)
#define TRNG_APT      (TRNG_BASE + 0x14u)

/* SPI flash peripheral (M1 access verification, region 0x19000000, rtl/lms_flash_spi.v).
 * On-board SPI NOR (S25FL132K/AT25SF321/MX25L3233F), SCK via CCLK/STARTUPE2. */
#define FLASH_BASE     0x19000000u
#define FLASH_VERSION  (FLASH_BASE + 0x00u)
#define FLASH_CTRL     (FLASH_BASE + 0x04u)
#define FLASH_STATUS   (FLASH_BASE + 0x08u)
#define FLASH_RESP0    (FLASH_BASE + 0x0cu)   /* B4  */
#define FLASH_RESP1    (FLASH_BASE + 0x10u)   /* K12 */
#define FLASH_RESP2    (FLASH_BASE + 0x14u)   /* J14 */
#define FLASH_RESP3    (FLASH_BASE + 0x18u)   /* K15 */
#define FLASH_RESP4    (FLASH_BASE + 0x1cu)   /* L13 */
#define FLASH_OP       (FLASH_BASE + 0x20u)   /* 0=JEDEC probe; 1=byte write (WREN+PP) */
#define FLASH_ADDR     (FLASH_BASE + 0x24u)
#define FLASH_BYTE     (FLASH_BASE + 0x28u)

/* UART↔task-RAM passthrough bridge (Step 3, region 0x18000000, rtl/lms_uart_bridge.v).
 * CTRL write: [0]=start [1]=dir (0=RX→RAM, 1=RAM→TX); read: busy/done/error. */
#define BRIDGE_BASE   0x18000000u
#define BRIDGE_CTRL   (BRIDGE_BASE + 0x00u)
#define BRIDGE_ADDR   (BRIDGE_BASE + 0x04u)
#define BRIDGE_LEN    (BRIDGE_BASE + 0x08u)
#define BRIDGE_START  1u
#define BRIDGE_CLEAR  2u
#define BRIDGE_DIR_RX 0u
#define BRIDGE_DIR_TX 2u
#define BRIDGE_BUSY   1u
#define BRIDGE_DONE   2u
#define BRIDGE_ERROR  4u
#define BRIDGE_Y_ADDR 32u                    /* Task-RAM signature y start word (length varies with w, see sign_y_len) */

#define UART_REQUEST_HASH 0x48u
#define UART_REQUEST_CHAIN 0x43u
#define UART_REQUEST_VERIFY 0x56u
#define UART_REQUEST_SIGN_TEST 0x53u
#define UART_REQUEST_KEYGEN_TEST 0x4bu
#define UART_REQUEST_LMOTS_KEYGEN_TEST 0x60u
#define UART_REQUEST_LMOTS_SIGN_TEST 0x61u
#define UART_REQUEST_LMOTS_VERIFY_TEST 0x62u
#define UART_REQUEST_SEED_LOAD_TEST 0x63u
/* Randomizer C load (TRNG-C scheme, finalized 2026-08-22): the 0x6C debug path
 * injects a fixed 32B test vector as the LM-OTS randomizer C (deterministic
 * signatures → reproducible KAT/TVLA). 0x6x slots: 0x60-0x63 used, 0x64/0x65
 * removed, 0x66/0x67 secure trio, 0x6D/0x6E TVLA diagnostics. Deploy builds
 * (no LMS_FW_SEC_TEST_MODE) hard-reject ERR_INSECURE_DISABLED(0x0a). */
#define UART_REQUEST_C_LOAD 0x6Cu
/* 0x64/0x65 (secure LM-OTS stateless machines) removed (decided at 0.1.240:
 * only insecure/secure two-way split, 0x64/0x65 intermediate states dropped;
 * cleaned up at 0.1.254) */
/* ==== UART command domain partition (high nibble = functional domain, linear
 * within domain; read this section before changing commands: pitfalls manual
 * section I "global command-code occupancy table") ====
 *  0x4x  crypto primitives/test functions (plaintext key + test-vector path):
 *        HASH/CHAIN/KEYGEN_TEST/SIGN_TEST etc.
 *  0x5x  secure-domain state machine + TRNG / SPI-flash diagnostics:
 *        SEC_SIGN / SEC_STATE / NVM_SYNC / TRNG read / flash probe
 *  0x6x  secure LMS + key lifecycle + randomizer/TVLA diagnostics:
 *        0x66 SEC_LMS_SIGN / 0x67 SEC_LMS_KEYGEN (secure trio)
 *        0x68 SEC_LMS_KEYGEN_NEW (multi-key rotation, registered 2026-08-22)
 *        0x6C C_LOAD / 0x6D DERIVE_RANDOMIZER / 0x6E PRF_CHAIN (randomizer + TVLA diagnostics) */
/* Secure LMS trio (full secure-scheme scope, 0x66/0x67): SEC_LMS_SIGN = sec_sign
 * state machine + tree-cache auth path (full LMS signature); SEC_LMS_KEYGEN =
 * SEC-slot SEED builds the tree, produces public key. No plaintext SEED in input
 * (SEED lives in the SEC slot); signature q is set by the SEC ctr. */
#define UART_REQUEST_SEC_LMS_SIGN 0x66u
#define UART_REQUEST_SEC_LMS_KEYGEN 0x67u
/* 0x68 SEC_LMS_KEYGEN_NEW (key lifecycle/rotation, 2026-08-22): generates and
 * activates **one new key**; a single command atomically retires the old key
 * and activates the new one. I/SEED sources isolated at compile time: test
 * (LMS_FW_SEC_TEST_MODE) = host I + 0x63 preloaded SEED; deploy (0.1.281 model
 * B) = on-device TRNG generates new SEED+I in the field (controlled load into
 * slot; plaintext SEED_LOAD gating unchanged). */
#define UART_REQUEST_SEC_LMS_KEYGEN_NEW 0x68u
#define UART_RESPONSE     0x52u
/* Secure-domain commands (phase 3, 0x5x block). 0x52 NVM_SYNC differs in
 * meaning from response opcode 0x52. */
#define UART_REQUEST_NVM_SYNC 0x52u
#define NVM_SYNC_SUB_PUSH_LO  0x01u
#define NVM_SYNC_SUB_PUSH_HI  0x02u
#define NVM_SYNC_SUB_READ     0x03u
#define NVM_SYNC_SUB_READ_HI  0x04u
#define NVM_SYNC_SUB_READ_MID 0x05u
#define NVM_STATE_LEN         64u
#define NVM_CHUNK_LEN         32u
#define NVM_CRC_LEN           2u
/* Secure state-domain commands (step 4: STATE_COMMIT/HMAC orchestration test driver). */
#define UART_REQUEST_SEC_STATE 0x55u
/* SEC_SIGN atomic command (step 6, spec §9.4). */
#define UART_REQUEST_SEC_SIGN  0x54u
/* TRNG diagnostic commands (C1.3): 0x58 reads random words, 0x59 reads
 * status/health counters. Diagnostic path only. Note: 0x56 is taken by
 * UART_REQUEST_VERIFY (early builds misused 0x56/0x57, conflicting with
 * VERIFY); 0x5x already holds 0x52/0x54/0x55, so TRNG uses 0x58/0x59. */
#define UART_REQUEST_TRNG_READ   0x58u
#define UART_REQUEST_TRNG_STATUS 0x59u
/* TRNG_READ_ACK (C1-1): reliable acquisition command echoing batch sequence
 * number seq plus data CRC8. 0x5A is free (0x5x holds 0x52/0x54/0x55/0x56/
 * 0x58/0x59). Request cmd||count||seq; response 48B frame ([36..39]=count,
 * [40]=seq echo) followed by count*4B random words + 1B CRC8. 0x58 kept
 * for backward compatibility, unchanged. */
#define UART_REQUEST_TRNG_READ_ACK 0x5Au
/* SPI flash probe (M1, 2026-08-18): 0x5B triggers JEDEC-ID readback, reporting
 * read-back bytes of the 5 MISO candidate pins (pins down the FPGA flash read
 * path by measurement). Request cmd(1); response see flash_probe_from_uart. */
#define UART_REQUEST_FLASH_PROBE 0x5Bu
/* SPI flash write-path verification (M1b, 2026-08-18): 0x5C triggers a hardware
 * transaction WREN + page program (1 byte). Request cmd || a2 || a1 || a0
 * (24-bit big-endian address) || data(1). Response see flash_prog_from_uart. */
#define UART_REQUEST_FLASH_PROG 0x5Cu
/* SPI flash raw-command diagnostic (M1b): 0x5D sends a single-byte command
 * (e.g. WREN); use SAM3U to read STATUS to verify WEL. */
#define UART_REQUEST_FLASH_CMD 0x5Du
/* TVLA single-PRF isolation (2026-08-18, scheme-1 supplement): 0x6D executes
 * CMD_DERIVE_RANDOMIZER exactly once (C = SHAKE256(I||q||0x8585||SEED), 1 block,
 * SEED fed directly into Keccak). SEED reuses the hardware slot (preloaded via
 * 0x63 SEED_LOAD; script loads before sampling); request cmd || I[16] || q_u32_le.
 * Response 48B frame + 32B C (return_digest=1 reads back via LMS_OUTPUT).
 * Use: SLotH-style "single PRF call, single peak" TVLA plot (KeyGen 67's dense
 * derive + 1005 chain-step pipeline cannot isolate a single peak). */
#define UART_REQUEST_DERIVE_RANDOMIZER 0x6Du
/* Multi-PRF chain (2026-08-21, SLotH Fig.6 replication substitute): 0x6E runs
 * M consecutive software PRFs C_i = SHAKE256(I || u32_le(q+i) || 0x8585 ||
 * SEED) (same computation as 0x6D); trigger at the head of the chain (scheme A
 * fixed HASH_ONCE); acquisition window truncated to the first 73k cycles →
 * contains only the first (plus start of second) call, replicating the
 * "full-signature PRF/chain calls truncated" structure.
 * Request cmd || I[16] || q_u32_le || M_u32_le (M∈[1,16], default 4). */
#define UART_REQUEST_PRF_CHAIN 0x6Eu
/* TVLA isolated single x_q[i] (2026-08-25, side-channel SEED-leak characterization
 * fix): 0x6F executes CMD_DERIVE_CHAIN exactly once with arg_steps=0 (x_q[i] =
 * H(I||u32(q)||u16(i)||0xff||SEED), 1 block, SEED fed directly into Keccak;
 * requires ALLOW_XQ_DERIVE=1 build to pass the M3 gate, rejected in deploy).
 * SEED reuses the hardware slot (preloaded via 0x63, outside the acquisition
 * window); request cmd || I[16] || q_u32_le || i_u16_le.
 * **x_q[i] is never read back** (private-key element, confidential) — response
 * carries only status/cycles/hits (return_digest=0); verification uses an
 * independent oracle (SW SHAKE256 with same params). TVLA/INSECURE_TEST_MODE
 * builds only. */
#define UART_REQUEST_DERIVE_XQ 0x6Fu
#define VERIFY_MESSAGE_MAX 2048u   /* UART message cap: aligned with HASH_ONCE_RAM input cap (M=16=2048B) */
#define VERIFY_SIGNATURE_LEN 2348u /* W4/H5: 4(q)+4(ots)+32(C)+2144(y)+4(lms)+5*32(path) */
#define LMOTS_W4_SIGNATURE_LEN (4u + LMS_N + 67u * LMS_N)
/* LM-OTS signature length for the largest parameter set (w=1 → p=265): type(4)+C(32)+y(p*32). */
#define LMS_MAX_OTS_SIG_LEN (4u + LMS_N + LMS_MAX_OTS_P * LMS_N)

/* ---- Runtime parameter-set helpers (w∈{1,2,4,8} × h∈{5,10,15}, t8) ----
 * Private-key bytes carry lms_type/lmots_type; lms_private_key_parse resolves
 * them, then dispatches by parameter set:
 *   - w∈{1,2,4,8}: hardware MMIO acceleration (both engines parameterized
 *     over all w, REVIEW B05B06-R5); w∉{1,2,4,8}: pure-software LM-OTS.
 *   - h selects tree-cache config (lms_tree_configure picks a tier by
 *     memory_target). Lengths derive from lms_get_lmots_param (p = chain
 *     count), no hard-coded 67. */
static uint32_t lmots_sig_len_type(uint32_t lmots_type)
{
    lmots_param_t param;

    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK) {
        return 0u;
    }
    return 4u + param.n + param.p * param.n;
}

/* Signature y-segment length (= p*n), for UART-bridge passthrough / software
 * direct read. */
static uint32_t lmots_y_len_type(uint32_t lmots_type)
{
    lmots_param_t param;

    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK) {
        return 0u;
    }
    return param.p * param.n;
}

/* MQC short-message read window base = 32 + y_words (after the y region, per w):
 * W4=568 (y 2144B→word 567), W2=1096 (y 4256B→word 1095), W8=304 (y 1088B);
 * W1 (y 8480B fills all 2152 task-RAM words) has no separate region → 568 (W1
 * verify reads y in software; task RAM empty). Large messages (>74B) fixed at
 * 568 (message region 582; w unknown at receive time, cannot be dynamic). */
static uint32_t mqc_msg_base(uint32_t y_len)
{
    uint32_t base = 32u + y_len / 4u;
    return (base >= 2152u) ? 568u : base;
}

static uint32_t lmots_sig_len_priv(const lms_private_key_t *priv)
{
    return lmots_sig_len_type(priv->lmots_type);
}

/* Whether hardware MMIO acceleration is available:
 *   both platform engines are parameterized over w∈{1,2,4,8} (SHAKE256 stages
 *   1/2, SHA-256 S5) → all w usable in hardware.
 * w∉{1,2,4,8} (n changes etc.) → fall back to pure-software LM-OTS. */
static int lmots_hw_supported(uint32_t lmots_type)
{
    lmots_param_t param;

    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK) {
        return 0;
    }
    return param.w == 1u || param.w == 2u || param.w == 4u || param.w == 8u;
}

static uint32_t hardware_hits;
static lms_mmio_client_t verify_client;

/* 0.1.271 stack hardening (REVIEW G-C1, P0-1): handler-local buffers of
 * 2KB/8.5-9.3KB became file-scope shared statics (single-threaded UART
 * service, no reentrancy; commands run mutually exclusively, so sharing is
 * safe). Stack frame peak fell from ~30KB to <2KB (32K stack headroom
 * restored); bss grows ~12KB (within 96K budget). */
static uint8_t s_uart_msg[VERIFY_MESSAGE_MAX];                /* 2048: shared message buffer */
static uint8_t s_uart_sig[LMS_MAX_SIGNATURE_LEN];             /* 9324: shared LMS signature (9324)/LM-OTS signature (8516) */
static uint8_t s_uart_auth_tail[4u + LMS_MAX_HEIGHT * LMS_N]; /* 804: shared verify auth-path tail */
static uint32_t sign_y_in_taskram;   /* LM-OTS/LMS Sign signature y stays in task RAM; read out via UART bridge */
static uint32_t lmots_out_sig_len;   /* Current LM-OTS Sign actual signature length (used by serve_uart transmit) */
static uint32_t sign_y_len;          /* Current signature y-segment length (p×n, for bridge TX passthrough, varies with w) */

/* F2 (Phase 3): seed_load fingerprint tracking — skip the duplicate SEED_LOAD
 * transaction when the hardware seed slot already holds the same seed (saves
 * ~150-300 cycles per op). The prototype loads only one fixed seed everywhere
 * (vector/0x63/SEC domain all 0..31), so fingerprint comparison is safe; 0x63
 * explicit loads always run and update the fingerprint; SEC-domain
 * FACTORY_INIT/BOOT unwrap restores the same-value seed, no conflict. If
 * multiple seed values are introduced later, invalidate this tracking at the
 * SEC-domain boundary. */
static uint8_t s_seed_slot_valid;
static uint8_t s_seed_slot[LMS_SEED_LEN];

/* Randomizer C slot (TRNG-C scheme, finalized 2026-08-22, scheme A): fixed 32B
 * test vector loaded via C_LOAD(0x6C) on the debug path, used as the LM-OTS
 * Sign randomizer C (deterministic signatures → reproducible KAT/TVLA). Valid
 * under test config (LMS_FW_SEC_TEST_MODE); C_LOAD is hard-rejected in deploy. */
static uint8_t s_c_slot[LMS_N];
static uint8_t s_c_slot_valid;

static int fw_seed_load(const uint8_t seed[LMS_SEED_LEN])
{
    if (s_seed_slot_valid != 0u &&
        memcmp(s_seed_slot, seed, LMS_SEED_LEN) == 0) {
        return LMS_MMIO_OK;
    }
    if (lms_mmio_seed_load_test(&verify_client, 0u, seed) != LMS_MMIO_OK) {
        return LMS_MMIO_ERR_INVALID;
    }
    memcpy(s_seed_slot, seed, LMS_SEED_LEN);
    s_seed_slot_valid = 1u;
    return LMS_MMIO_OK;
}
#if defined(LMS_MMIO_SOC_PROFILE)
/* secure 0x66 Sign segmented profile (carried in response frame
 * [32..35]/[36..39]/[40..43]): enable=hardware enable transaction;
 * sec_sign=2×state_commit+lmots_sign; tail=assembly/auth-path/disable */
static uint32_t prof_sec_enable_cycles;
static uint32_t prof_sec_sign_cycles;
static uint32_t prof_sec_tail_cycles;
/* sec_sign breakdown inside lms_sec_state.c (commit1/dosign/commit2) and
 * state_commit breakdown (mc/tag), carried via frame [28..31]/[44..47] */
extern uint32_t sec_prof_commit1_cycles;
extern uint32_t sec_prof_dosign_cycles;
extern uint32_t sec_prof_commit2_cycles;
extern uint32_t sec_prof_stc_cycles;
extern uint32_t sec_prof_enc_cycles;
#endif
/* NVM volatile staging slot (STATE_REC mirror, host persistent-domain
 * re-fill). Split into lo/hi halves, each with its own CRC16. */
static uint8_t nvm_state[NVM_STATE_LEN];
static uint16_t nvm_crc[NVM_STATE_LEN / NVM_CHUNK_LEN];
static uint8_t nvm_valid[NVM_STATE_LEN / NVM_CHUNK_LEN];

static uint8_t uart_getc(void)
{
    while (MMIO32(UART_RX_READY) == 0u) {
    }
    return (uint8_t)MMIO32(UART_RX);
}

static void uart_putc(uint8_t value)
{
    while (MMIO32(UART_TX_READY) == 0u) {
    }
    MMIO32(UART_TX) = value;
}

static void uart_put_u32(uint32_t value)
{
    uart_putc((uint8_t)value);
    uart_putc((uint8_t)(value >> 8));
    uart_putc((uint8_t)(value >> 16));
    uart_putc((uint8_t)(value >> 24));
}

/* Start the UART↔task-RAM passthrough bridge and wait for completion
 * (dir: 0=RX→RAM, 1=RAM→TX). len must be a multiple of 4. Returns 0=success,
 * -1=error (core busy / invalid length). Pure-software baseline
 * (LMS_FW_NO_HW_ACCEL) does not reference this function (no bridge); marked
 * unused to avoid warnings. */
static int __attribute__((unused))
bridge_run(uint32_t dir, uint32_t addr, uint32_t len)
{
    MMIO32(BRIDGE_ADDR) = addr;
    MMIO32(BRIDGE_LEN) = len;
    /* Read barrier: consecutive MMIO stores (ADDR/LEN/CTRL) may be merged or
     * committed out of order under the ibex pipeline/write buffer; when the
     * CTRL start write arrives, byte_left_r has not yet been updated from
     * LEN, and the bridge reports error on byte_left==0. One read-back forces
     * the earlier stores to commit. */
    (void)MMIO32(BRIDGE_CTRL);
    MMIO32(BRIDGE_CTRL) = BRIDGE_START | dir;
    while ((MMIO32(BRIDGE_CTRL) & BRIDGE_BUSY) != 0u) {
    }
    if ((MMIO32(BRIDGE_CTRL) & BRIDGE_ERROR) != 0u) {
        MMIO32(BRIDGE_CTRL) = BRIDGE_CLEAR;
        return -1;
    }
    MMIO32(BRIDGE_CTRL) = BRIDGE_CLEAR;
    return 0;
}

static uint32_t uart_get_u32(void)
{
    uint32_t value = uart_getc();
    value |= (uint32_t)uart_getc() << 8;
    value |= (uint32_t)uart_getc() << 16;
    value |= (uint32_t)uart_getc() << 24;
    return value;
}

/* UART frame message length: 1 byte → 2-byte big-endian (supports >255B
 * messages, aligned with 1KB/2KB large messages). */
static uint32_t uart_get_u16(void)
{
    return ((uint32_t)uart_getc() << 8) | (uint32_t)uart_getc();
}

/* CRC-8/SMBUS (poly 0x07, init 0x00, no reflection), same as the serial
 * CRC-8 in lms_trng.v. Bit-wise MSB-first; used by TRNG_READ_ACK to append a
 * 1B check over the count*4B data. */
static uint8_t crc8_update(uint8_t crc, uint8_t byte)
{
    uint8_t bit;
    crc ^= byte;
    for (bit = 0u; bit < 8u; bit++) {
        crc = (crc & 0x80u) != 0u ? (uint8_t)((crc << 1) ^ 0x07u) : (uint8_t)(crc << 1);
    }
    return crc;
}

static uint8_t crc8_block(const uint8_t *data, uint32_t length)
{
    uint8_t crc = 0u;
    uint32_t index;
    for (index = 0u; index < length; index++) {
        crc = crc8_update(crc, data[index]);
    }
    return crc;
}

static void uart_read_bytes(uint8_t *output, uint32_t length)
{
    uint32_t index;
    for (index = 0; index < length; index++) {
        output[index] = uart_getc();
    }
}

static void uart_discard(uint32_t length)
{
    while (length-- > 0u) {
        (void)uart_getc();
    }
}

static void uart_read_window(uint32_t base, uint32_t length)
{
    uint32_t offset;
    uint32_t word = 0u;
    for (offset = 0; offset < length; offset++) {
        word |= (uint32_t)uart_getc() << (8u * (offset & 3u));
        if ((offset & 3u) == 3u || offset + 1u == length) {
            MMIO32(base + (offset & ~3u)) = word;
            word = 0u;
        }
    }
}

/* Level 1 (message via UART-bridge passthrough): large messages were already
 * written by the bridge to task-RAM word 582 (MQC multi-block message region,
 * base=568). hw_coef_backend sets a consumed flag; on unavailable/fallback it
 * is cleared and data is read back from task RAM.
 * Defined near task_read_words below (only forward-declared earlier in this
 * file). */
static int s_msg_in_ram;
static void task_read_words(uint32_t word_base, uint8_t *bytes, uint32_t length);

static uint32_t hash_once_from_uart(uint32_t input_length, uint32_t *cycles)
{
    uint32_t offset;

    if (input_length > 128u) {
        for (offset = 0; offset < input_length; offset++) {
            (void)uart_getc();
        }
        *cycles = 0u;
        return 0u;
    }

    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
    MMIO32(LMS_INPUT_LENGTH) = input_length;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;

    uart_read_window(LMS_INPUT, input_length);

    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
}

/* TVLA single-PRF isolation (0x6D, 2026-08-18 scheme-1 supplement): executes
 * CMD_DERIVE_RANDOMIZER exactly once. Request cmd || I[16] || q_u32_le; SEED
 * uses the hardware slot (preloaded via 0x63; do NOT load inside this command—
 * a load transaction would put SEED plaintext bus power onto the trace and
 * break the clean "single PRF call" surface).
 * Output C = SHAKE256(I||q||0x8585||SEED) stays in LMS_OUTPUT; the response
 * frame reads it back via return_digest. */
static uint32_t derive_randomizer_from_uart(uint32_t *cycles)
{
    uint32_t q;
#if LMS_TVLA_RANDOM_DELAY
    /* Scheme B (2026-08-19 lightweight mitigation): insert a TRNG-random wait
     * before DERIVE to break the fixed phase alignment of a single PRF to the
     * trigger edge → single-point t is thinned out (each trace's DERIVE start
     * phase is random). Wait = random 0..1023 cycles of idle (CPU loop), the
     * random value read from TRNG_RND. TVLA mitigation evaluation only
     * (Makefile LMS_TVLA_RANDOM_DELAY=1), off by default, zero impact on
     * normal builds. Note: the wait precedes START, busy is not set, and SCA
     * is not triggered. */
    {
        volatile uint32_t wait;
        uint32_t rnd = MMIO32(TRNG_RND);
        for (wait = (rnd & 0x3ffu); wait != 0u; wait--) {
            __asm__ volatile ("" ::: "memory");
        }
    }
#endif

#if LMS_FW_NO_HW_ACCEL
    /* Pure-software baseline (software single-PRF reference, 2026-08-21):
     * software computes C = SHAKE256(I || u32_le(q) || 0x8585 || SEED), same
     * operation/window/trigger as hardware 0x6D, directly comparing CPU vs
     * accelerator leakage strength. SEED read from firmware memory s_seed_slot
     * (preloaded via 0x63, load outside the acquisition window, same scope as
     * hardware); I/q read byte-by-byte from the request (uart_read_window
     * writes the MMIO window, not reusable in software mode).
     * Software SHAKE256 ~19K cycles/block ≈ 1.2ms @15.6MHz (acquirable). */
    uint8_t prefix[16u + 4u + 2u];
    uint8_t digest[LMS_N];
    uint32_t idx;
    for (idx = 0u; idx < 16u; idx++) {
        prefix[idx] = uart_getc();
    }
    q = uart_get_u32();
    lms_store_u32(prefix + 16u, q);
    prefix[20u] = 0x85u;
    prefix[21u] = 0x85u;
    if (s_seed_slot_valid == 0u) {
        return 0u; /* 0x63 preload not executed */
    }
    /* Scheme A (2026-08-21): SCA trigger calibration — in pure-software mode
     * the engine is always idle (stream_busy always 0), so sca_trigger (busy
     * rising edge, rtl/lms_soc.v) never fires → Husky cannot trigger
     * acquisition. Before the software PRF, run one hardware HASH_ONCE on
     * fixed data (32B all-zero, public and identical across fixed/random
     * groups, no SEED difference, no TVLA pollution): busy rising edge → SCA
     * 512-cycle wide pulse (start edge), then the software PRF (~19K cycles)
     * falls inside the acquisition window. I/q were already read above
     * (trigger phase bound to operation start); after HASH_ONCE completes,
     * wait for busy to fall, engine silent, then enter the software hash —
     * trigger edge → PRF phase has no I/O wait, stable trace-to-trace. */
    {
        uint32_t zi;
        MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
        MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
        MMIO32(LMS_INPUT_LENGTH) = 32u;
        MMIO32(LMS_OUTPUT_LENGTH) = 32u;
        for (zi = 0u; zi < 8u; zi++) {
            MMIO32(LMS_INPUT + 4u * zi) = 0u;   /* 32B all-zero fixed trigger data */
        }
        MMIO32(LMS_CONTROL) = LMS_CTRL_START;
        while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
        }
    }
    (void)lms_hash_parts(prefix, sizeof(prefix), s_seed_slot, LMS_SEED_LEN,
                         NULL, 0u, NULL, 0u, FW_HASH_ALG, digest);
    memcpy(s_uart_msg, digest, LMS_N);
    *cycles = 0u;
    return LMS_STATUS_DONE;
#else
    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_DERIVE_RANDOMIZER;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    uart_read_window(LMS_IDENTIFIER, 16u);
    q = uart_get_u32();
    MMIO32(LMS_ARG_Q) = q;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
#endif
}

/* TVLA isolated single x_q[i] (0x6F, 2026-08-25 side-channel SEED-leak
 * characterization fix): exactly one CMD_DERIVE_CHAIN (arg_steps=0), x_q[i] =
 * H(I||u32(q)||u16(i)||0xff||SEED), 1 block, SEED fed directly into Keccak.
 * Requires ALLOW_XQ_DERIVE=1 build to pass the M3 gate (rejected in deploy).
 * SEED reuses the hardware slot (preloaded via 0x63, outside the acquisition
 * window); request cmd || I[16] || q_u32_le || i_u16_le.
 * **x_q[i] is never read back** (private-key element, confidential) — response
 * carries only status/cycles (return_digest=0); verification uses an
 * independent oracle (SW SHAKE256 with same params). TVLA/INSECURE_TEST_MODE
 * builds only. */
static uint32_t derive_xq_from_uart(uint32_t *cycles)
{
    uint32_t q;
    uint16_t i;
#if LMS_FW_NO_HW_ACCEL
    /* Pure-software baseline (software single x_q[i] definition, 2026-08-25):
     * x_q[i]=SHAKE256(I||u32(q)||u16(i)||0xff||SEED). SEED read from s_seed_slot
     * (preloaded via 0x63, outside the acquisition window); same
     * operation/window/trigger as hardware 0x6F. */
    uint8_t prefix[16u + 4u + 2u + 1u];
    uint8_t digest[LMS_N];
    uint32_t idx;
    for (idx = 0u; idx < 16u; idx++) {
        prefix[idx] = uart_getc();
    }
    q = uart_get_u32();
    i = uart_get_u16();
    lms_store_u32(prefix + 16u, q);          /* u32str(q) big-endian */
    prefix[20u] = (uint8_t)(i >> 8u);        /* u16str(i) big-endian high byte */
    prefix[21u] = (uint8_t)(i & 0xffu);      /* u16str(i) big-endian low byte */
    prefix[22u] = 0xffu;                     /* u8str(0xff) */
    if (s_seed_slot_valid == 0u) {
        return 0u; /* 0x63 preload not executed */
    }
    /* Scheme A: engine always idle in software mode → first run one public
     * fixed HASH_ONCE to trigger SCA (same as 0x6D). */
    {
        uint32_t zi;
        MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
        MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
        MMIO32(LMS_INPUT_LENGTH) = 32u;
        MMIO32(LMS_OUTPUT_LENGTH) = 32u;
        for (zi = 0u; zi < 8u; zi++) {
            MMIO32(LMS_INPUT + 4u * zi) = 0u;
        }
        MMIO32(LMS_CONTROL) = LMS_CTRL_START;
        while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
        }
    }
    (void)lms_hash_parts(prefix, sizeof(prefix), s_seed_slot, LMS_SEED_LEN,
                         NULL, 0u, NULL, 0u, FW_HASH_ALG, digest);
    (void)digest;   /* not read back (confidential); response carries no digest */
    *cycles = 0u;
    return LMS_STATUS_DONE;
#else
    /* Hardware path: single DERIVE_CHAIN (arg_steps=0 derives x_q[i]). I to
     * IDENTIFIER window, q→ARG_Q, i→ARG_I, start=0, steps=0. **OUTPUT is not
     * read back** (private-key element). */
    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_DERIVE_CHAIN;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    uart_read_window(LMS_IDENTIFIER, 16u);
    q = uart_get_u32();
    i = uart_get_u16();
    MMIO32(LMS_ARG_Q) = q;
    MMIO32(LMS_ARG_I) = (uint32_t)i;
    MMIO32(LMS_ARG_START) = 0u;
    MMIO32(LMS_ARG_STEPS) = 0u;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
#endif
}

/* Multi-PRF chain (0x6E, 2026-08-21): M consecutive software PRFs (C_i =
 * SHAKE256(I||q+i||0x8585||SEED), same computation/window as 0x6D), trigger at
 * the head of the chain — replicates the SLotH Fig.6 structure (a full
 * signature's PRF/chain calls truncated to the first 73k cycles → contains
 * only the first call). SEED read from s_seed_slot (preloaded via 0x63,
 * outside the acquisition window); I/q/M read byte-by-byte from the request. */
static uint32_t prf_chain_from_uart(uint32_t *cycles)
{
    uint8_t prefix[16u + 4u + 2u];
    uint8_t digest[LMS_N];
    uint32_t q;
    uint32_t m;
    uint32_t idx;
    uint32_t k;

    for (idx = 0u; idx < 16u; idx++) {
        prefix[idx] = uart_getc();
    }
    q = uart_get_u32();
    m = uart_get_u32();
    if (m == 0u || m > 16u) {
        m = 4u; /* default 4 times */
    }
    if (s_seed_slot_valid == 0u) {
        return 0u; /* 0x63 preload not executed */
    }
    /* Scheme-A trigger (head of chain): fixed 32B zero-data HASH_ONCE → busy
     * rising-edge SCA pulse; then the M software PRFs fall inside the
     * acquisition window (first 73k cycles). */
    {
        uint32_t zi;
        MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
        MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
        MMIO32(LMS_INPUT_LENGTH) = 32u;
        MMIO32(LMS_OUTPUT_LENGTH) = 32u;
        for (zi = 0u; zi < 8u; zi++) {
            MMIO32(LMS_INPUT + 4u * zi) = 0u;   /* 32B all-zero fixed trigger data */
        }
        MMIO32(LMS_CONTROL) = LMS_CTRL_START;
        while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
        }
    }
    prefix[20u] = 0x85u;
    prefix[21u] = 0x85u;
    for (k = 0u; k < m; k++) {
        lms_store_u32(prefix + 16u, q + k);
        (void)lms_hash_parts(prefix, sizeof(prefix), s_seed_slot, LMS_SEED_LEN,
                             NULL, 0u, NULL, 0u, FW_HASH_ALG, digest);
    }
    memcpy(s_uart_msg, digest, LMS_N);
    *cycles = 0u;
    return LMS_STATUS_DONE;
}

static uint32_t chain_from_uart(uint32_t *cycles)
{
    uint32_t q;
    uint32_t i;
    uint32_t start;
    uint32_t steps;

    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_CHAIN;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    uart_read_window(LMS_IDENTIFIER, 16u);
    q = uart_get_u32();
    i = uart_getc();
    i |= (uint32_t)uart_getc() << 8;
    start = uart_getc();
    steps = uart_getc();
    uart_read_window(LMS_INPUT, 32u);
    MMIO32(LMS_ARG_Q) = q;
    MMIO32(LMS_ARG_I) = i;
    MMIO32(LMS_ARG_START) = start;
    MMIO32(LMS_ARG_STEPS) = steps;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
}

#if !LMS_FW_NO_HW_ACCEL
/* Switch the LM-OTS hardware backend by parameter-set w (defined below in this
 * file; verify_from_uart calls it first). */
static void set_hw_lmots(int enable);
/* VERIFY_LEAF backend (MMIO version + bridge taskram version), defined below
 * in this file. When verify_from_uart is bridged, the taskram variant is
 * registered first so lms_verify's leaf hash reads the real y directly from
 * task RAM. */
static int hw_verify_leaf(void *context,
                          const uint8_t I[LMS_I_LEN],
                          lms_hash_alg_t hash_alg,
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t *coefficients,
                          const uint8_t *inputs,
                          uint32_t node_num,
                          uint8_t leaf[LMS_N]);
static int hw_verify_leaf_taskram(void *context,
                                  const uint8_t I[LMS_I_LEN],
                                  lms_hash_alg_t hash_alg,
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t *coefficients,
                                  const uint8_t *inputs,
                                  uint32_t node_num,
                                  uint8_t leaf[LMS_N]);
#endif /* !LMS_FW_NO_HW_ACCEL */

static uint32_t verify_from_uart(uint32_t *cycles, uint32_t *total_cycles)
{
    uint8_t public_key_bytes[LMS_PUBLIC_KEY_LEN];
    uint8_t signature_hdr[40];              /* q(4)+ots_type(4)+C(32), read by software */
    /* message/signature/signature_tail use file-scope shared statics
     * (0.1.271 stack hardening G-C1). */
    lms_public_key_t public_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    uint32_t total_start;
    uint32_t message_length;
    uint32_t signature_length;
    uint32_t y_len;
    uint32_t path_len;
    uint32_t ots_type;
    uint32_t lms_type;
    int y_in_taskram = 0;
    int status;

    uart_read_bytes(public_key_bytes, sizeof(public_key_bytes));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length + LMS_MAX_SIGNATURE_LEN);
        *cycles = 0u;
        *total_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
    s_msg_in_ram = 0;
#if !LMS_FW_NO_HW_ACCEL
    if (message_length > 74u) {
        /* Level 1: large messages go through the UART-bridge passthrough to
         * task-RAM word 582 (MQC message region, padded to 4B alignment). MQC
         * read window base=568 (header word 568 + message word 582, outside
         * the y region). Verify does not build a tree (the task-RAM message
         * region is not covered by KEYGEN_LEAF), y read directly in software. */
        const uint32_t pad = (message_length + 3u) & ~3u;
        if (bridge_run(BRIDGE_DIR_RX, 582u, pad) == 0) {
            s_msg_in_ram = 1;
        } else {
            uart_read_bytes(s_uart_msg, message_length);
        }
    } else
#endif
    {
        uart_read_bytes(s_uart_msg, message_length);
    }
    /* Signature = q(4)+ots_type(4)+C(32)+y(p*n)+lms_type(4)+path(h*n).
     * Signature header q+ots_type+C read by software; y written to task RAM
     * by the UART passthrough bridge (W4) or read directly by software;
     * signature tail lms_type+auth path read by software. y length is set by
     * ots_type (w), auth-path length by the tail's lms_type (h); the full
     * signature buffer is assembled with a placeholder y for lms_verify to
     * parse (y values take no part in coefficient/auth-path computation; when
     * verify_leaf uses the taskram variant, hardware reads the real y
     * directly). */
    uart_read_bytes(signature_hdr, sizeof(signature_hdr));
    /* Signature ots_type is 4B big-endian (00 00 00 13), so uart_get_u32
     * (little-endian) cannot be used. */
    ots_type = ((uint32_t)signature_hdr[4] << 24) |
               ((uint32_t)signature_hdr[5] << 16) |
               ((uint32_t)signature_hdr[6] << 8) |
               (uint32_t)signature_hdr[7];
    y_len = lmots_y_len_type(ots_type);
    if (y_len == 0u) {
        /* Invalid ots_type: discard the remaining signature (y + lms_type +
         * path), then reject. */
        uart_discard(LMS_MAX_SIGNATURE_LEN - 40u);
        *cycles = 0u;
        *total_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
#if !LMS_FW_NO_HW_ACCEL
    /* Switch the hardware backend by signature ots_type (hardware supports
     * w∈{1,2,4,8}; otherwise pure-software LM-OTS). y must be received before
     * computing coefficients: if parsing/hashing started first, y would
     * arrive at the uart_rx FIFO in the meantime and be overwritten/dropped,
     * and the bridge would stall on missing y bytes (same constraint as the
     * standalone LM-OTS Verify). Use the bridge passthrough only when
     * hardware is available; otherwise y is read directly by software (the
     * #else branch below). Level 1: after message bridge passthrough, if
     * hardware is unavailable → read back from memory (needed by the
     * software path). */
    set_hw_lmots(lmots_hw_supported(ots_type));
    if (s_msg_in_ram && !lmots_hw_supported(ots_type)) {
        task_read_words(582u, s_uart_msg, message_length);
        s_msg_in_ram = 0;
    }
#if defined(FW_HASH_SHAKE256)
    if (32u + y_len / 4u <= ((message_length <= 74u) ? mqc_msg_base(y_len) : 568u)) {
#else
    /* SHA-256 (no MQC hardware): the message hash of large messages goes
     * through HASH_ONCE_RAM (task-RAM word32 region); a y passthrough to
     * word32 would be overwritten by the message hash → for large messages y
     * is read directly by software (MMIO verify_leaf, which rewrites task RAM
     * over the message region at verify time). Short messages (≤74B) keep
     * bridge passthrough with zero regression. */
    if (message_length <= 74u && 32u + y_len / 4u <= mqc_msg_base(y_len)) {
#endif
        /* Short y (y end ≤ that w's MQC base, W4=568/W2=1096/W8=304; large
         * message 568): MQC read window base = 32+y_words (outside the y
         * region), y written by the UART-bridge passthrough starting at
         * task-RAM word 32 → verify_leaf (taskram variant) reads the real y
         * directly (msg_q_coef header word mqc_base + message word
         * mqc_base+14 do not overlap). Receive y before computing
         * coefficients (bridge stalls on missing y bytes). W1 (y 8480B fills
         * task RAM) has no separate region → software direct read. */
        if (bridge_run(BRIDGE_DIR_RX, BRIDGE_Y_ADDR, y_len) != 0) {
            *cycles = 0u;
            *total_cycles = 0u;
            return 0u;
        }
        y_in_taskram = 1;
    } else {
        /* W1 (y 8480B fills task RAM) / large message: y read directly into
         * the signature buffer by software; verify_leaf uses the MMIO version
         * (writes y to task RAM at verify time, overwriting the message
         * region). */
        memcpy(s_uart_sig, signature_hdr, sizeof(signature_hdr));
        uart_read_bytes(s_uart_sig + sizeof(signature_hdr), y_len);
    }
#else
    /* Pure-software baseline: no UART bridge; signature y read directly into
     * the signature buffer by software. */
    memcpy(s_uart_sig, signature_hdr, sizeof(signature_hdr));
    uart_read_bytes(s_uart_sig + sizeof(signature_hdr), y_len);
#endif
    /* First read the 4B signature-tail lms_type (big-endian), parse h → path
     * length → read path → assemble. */
    uart_read_bytes(s_uart_auth_tail, 4u);
    lms_type = ((uint32_t)s_uart_auth_tail[0] << 24) |
               ((uint32_t)s_uart_auth_tail[1] << 16) |
               ((uint32_t)s_uart_auth_tail[2] << 8) |
               (uint32_t)s_uart_auth_tail[3];
    signature_length = lms_signature_len(lms_type, ots_type);
    if (signature_length < 40u + y_len + 4u + LMS_N ||
        signature_length > LMS_MAX_SIGNATURE_LEN) {
        /* lms_type/length invalid: discard the remaining signature, then
         * reject. */
        uart_discard(LMS_MAX_SIGNATURE_LEN);
        *cycles = 0u;
        *total_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
    path_len = signature_length - (40u + y_len + 4u);
    uart_read_bytes(s_uart_auth_tail + 4u, path_len);
    /* Assemble the full signature: the W4 etc. bridge scope needs
     * memcpy(hdr); the y segment is a placeholder (F1 removed the y-placeholder
     * memset: the leaf-verify taskram variant reads the real y directly from
     * task RAM, and signature parsing skips that segment by offset; W1/large
     * messages already read y by software above). Assemble last (FIFO is
     * empty then, no backlog drop). */
    if (y_in_taskram) {
        memcpy(s_uart_sig, signature_hdr, sizeof(signature_hdr));
    }
    memcpy(s_uart_sig + sizeof(signature_hdr) + y_len, s_uart_auth_tail,
           4u + path_len);

    total_start = MMIO32(SOC_CYCLE_COUNT); /* End-to-end start point (includes software orchestration + hashing) */
    count_before = verify_client.hardware_verify_count;
    cycles_before = verify_client.hardware_verify_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    verify_client.last_hw_error = 0u;
#if !LMS_FW_NO_HW_ACCEL
    /* Bridge mode (hardware available and y in task RAM): leaf verify uses the
     * taskram variant (MMIO version restored after verify). Large messages
     * (y read by software, y_in_taskram=0) keep the MMIO version
     * (hw_verify_leaf registered by set_hw_lmots, which writes y to task RAM
     * over the message region at verify time). */
    if (lmots_hw_supported(ots_type) && y_in_taskram) {
        lmots_verify_leaf_backend_set(hw_verify_leaf_taskram, &verify_client);
    }
#endif
    status = lms_public_key_parse(&public_key, public_key_bytes, sizeof(public_key_bytes));
    if (status == LMS_OK) {
        status = lms_verify(&public_key, s_uart_msg, message_length,
                            s_uart_sig, signature_length);
    }
#if !LMS_FW_NO_HW_ACCEL
    if (lmots_hw_supported(ots_type)) {
        lmots_verify_leaf_backend_set(hw_verify_leaf, &verify_client);
    }
#endif
    hardware_hits += (uint32_t)(verify_client.hardware_verify_count - count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_verify_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_hash_once_cycles - hash_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t sign_from_uart(uint8_t signature[LMS_MAX_SIGNATURE_LEN],
                               uint32_t *signature_length,
                               uint32_t *next_q,
                               uint32_t *cycles,
                               uint32_t *total_cycles,
                               uint32_t *steady_total_cycles,
                               uint32_t *parse_cycles);

#if !LMS_FW_NO_HW_ACCEL
/* ---- Sign auth-path tree cache (design doc step 6b, multi-parameter h since t8) ----
 *
 * Lets sign_from_uart reuse the lms_subtree tree cache (software RAM) across
 * multiple signatures of the same key, replacing the default lms_tree_node
 * recursive rebuild (root cause of slow Sign). UART protocol unchanged,
 * sec_state semantics untouched — the cache is just a "memo of already
 * computed LM-OTS public keys", unrelated to the signing state machine.
 *
 * Cache key = key fingerprint (I 16B + seed 32B, direct memcmp of fields
 * inside the private-key struct). Consecutive signs with the same key:
 * fingerprint match reuses the cache and registers the backend; mismatch
 * (key changed) invalidates the old cache and re-runs sign_init (otherwise a
 * stale subtree would produce a wrong auth path — a correctness issue that
 * must be handled).
 *
 * Configured dynamically by parameter-set h: lms_tree_configure(priv->lms_type,
 * TREE_MEMORY_TARGET) picks a tier (this firmware's budget always selects
 * j=5: H5 full special-case sublevels=1 / H10 sublevels=2 / H15 sublevels=3).
 * H10 full (j=h=10) needs 64KiB, over the SoC memory budget, so it degrades
 * dynamically to multiple sublevels; on PC/large-memory environments, raising
 * TREE_MEMORY_TARGET makes configure auto-select the j=h full tier. The static
 * pool uses an arena (no malloc).
 *
 * Key scope (remember the "tree cache's KeyGen semantic boundary"): building
 * tree leaves uses KeyGen semantics (produces public K_q via the default
 * ots_pub=lmots_public_from_private), not Sign semantics, and does not break
 * state management.
 */

/* Static-pool arena: covers the total ctx_init allocation of the largest tier
 * (H15 j=5 sublevels=3) — levels[3] + ACTIVE/UPCOMING nodes per level
 * (5×2048B) + stack (5×160B) ≈ 11.4KiB. Arena (sequential cursor) + reset
 * adapts to any parameter-set tier (this firmware's configure always selects
 * j=5, sublevels ≤ 3; see the est_memory check in tree_cache_ensure). */
/* Tree-cache static-pool arena: data area must cover the H15 (j=5,
 * sublevels=3) sign_init tree-build peak = est_memory(11040) + levels[3]
 * (~264B) + subtree_build_at temporary my_roots nesting peak (2×1024B=2048B)
 * ≈ 13.4KiB → 16KiB. The original 11104B exhausted the arena through my_roots
 * allocation (1024B each, level-1 recursion 32 times) → tree build failed →
 * fell back to recursion (root cause of W4_H15 Sign task-RAM y overwrite:
 * tree_pool_free is a no-op, my_roots never reclaimed). */
static uint8_t s_tree_arena[3u * sizeof(lms_sublevel_t) + 16384u];
static uint32_t s_tree_arena_used;
static uint8_t *s_tree_pool_last_ptr;   /* Most recent allocation block start (for LIFO reclamation) */
static uint32_t s_tree_pool_last_size;

/* Static-pool allocator: sequential allocation from the arena. Records the
 * most recent block (last_ptr/last_size) for LIFO reclamation. */
static void *tree_pool_alloc(void *context, size_t size)
{
    uint32_t aligned;
    void *ptr;
    (void)context;
    aligned = (uint32_t)((size + 3u) & ~((size_t)3u));
    if (s_tree_arena_used + aligned > (uint32_t)sizeof(s_tree_arena)) {
        return NULL;
    }
    ptr = s_tree_arena + s_tree_arena_used;
    s_tree_arena_used += aligned;
    s_tree_pool_last_ptr = (uint8_t *)ptr;
    s_tree_pool_last_size = aligned;
    return ptr;
}

/* Static-pool free: only strict LIFO reclamation supported (satisfied by
 * subtree_build_at's nested temporary my_roots alloc/free); non-LIFO frees
 * conservatively no-op (never corrupts other blocks, guarantees correctness). */
static void tree_pool_free(void *context, void *ptr)
{
    (void)context;
    if (ptr != NULL && (uint8_t *)ptr == s_tree_pool_last_ptr) {
        s_tree_arena_used -= s_tree_pool_last_size;
        s_tree_pool_last_ptr = NULL;
        s_tree_pool_last_size = 0u;
    }
}

/* Reset the static-pool cursor (called before tree_cache_ensure rebuilds the
 * cache; arena space is reusable). */
static void tree_pool_reset(void)
{
    s_tree_arena_used = 0u;
    s_tree_pool_last_ptr = NULL;
    s_tree_pool_last_size = 0u;
}

/* Tree-cache state: ctx + bound key fingerprint + whether sign_init ran.
 * Fingerprint = I(16)+seed(32)+lms_type(4)+lmots_type(4): consecutive signs of
 * the same key (same I+seed+parameter set) reuse the cache; a different key or
 * parameter set (test vectors often keep fixed I+seed and only change type)
 * must rebuild, otherwise a stale tree root with the same I+seed yields wrong
 * public keys/auth paths (exposed by t8 running W4_H5→W4_H10 back to back). */
static lms_tree_ctx_t s_tree_ctx;
static uint8_t s_tree_key_fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];
static int s_tree_cache_valid;   /* 1=cache has run sign_init and is bound to the fingerprint */

/* Invalidate the tree cache (called on key change / parameter mismatch). */
static void tree_cache_invalidate(void)
{
    lms_auth_path_backend_set(NULL, NULL);
    lms_tree_ctx_free(&s_tree_ctx);
    s_tree_cache_valid = 0;
}

/* Hardware KEYGEN_LEAF callback: one MMIO completes KEYGEN + D_LEAF.
 * node_num = full tree leaf node number = 2^h + q (h parsed from priv->lms_type,
 * supports H5/H10/H15, no hard-coded H5's 32). Registered for all
 * w∈{1,2,4,8} (tree_cache_ensure decides via lmots_hw_supported);
 * w∉{1,2,4,8} falls to software (REVIEW B05B06-R5). */
static int hw_keygen_leaf(void *context,
                          const lms_private_key_t *priv,
                          uint32_t q,
                          uint8_t leaf[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    lms_param_t lparam;
    uint32_t node_num;

    if (lms_get_lms_param(priv->lms_type, &lparam) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    node_num = (1u << lparam.height) + q;
    return lms_mmio_lmots_keygen_leaf(client, 0u, priv->I, q, node_num,
                                      priv->lmots_type, leaf, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

/* Message-hash backend large-block assembly buffer (0.1.269 F11 stack
 * hardening): the 2KB no longer lives on the task stack. */
static uint8_t hw_msg_hash_buf_small[128];
static uint8_t hw_msg_hash_buf_large[2048];

/* Message-hash backend: short messages go through HASH_ONCE (single block via
 * hardware register input), medium messages through HASH_ONCE_RAM (multi-block
 * absorb from task RAM, level 0); only over-limit or hardware failure falls
 * back to software. Thresholds: prefix(I+q+D_MESG+C)=54B; HASH_ONCE uses RTL
 * input_words 128B → message_len ≤ 74; HASH_ONCE_RAM uses task RAM ≤2048B →
 * message_len ≤ 1994 (54+1994=2048). HASH_ONCE per block: SHAKE256 ~12 hw
 * cycles (Keccak unroll-2); software RV32 ~17.4-19.5K/block → hardware is
 * always ~40-60× better, so 74B/1KB are capacity boundaries, not performance
 * ones (a 1KB message after hardware chunking gives Sign steady ≈29.5K,
 * roughly on par with 74B). */
static int hw_message_hash_backend(void *context,
                                   const uint8_t I[LMS_I_LEN],
                                   lms_hash_alg_t hash_alg,
                                   uint32_t q,
                                   const uint8_t C[LMS_N],
                                   const uint8_t *message,
                                   size_t message_len,
                                   uint8_t Q[LMS_N + 2])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    uint8_t digest[LMS_N];
    (void)hash_alg;

    /* Threshold check: prefix(54) + message_len ≤ 128 → HASH_ONCE (single block) */
    if (message_len <= 74u) {
        uint8_t *buf = hw_msg_hash_buf_small;
        size_t total = 54u + message_len;
        memcpy(buf, I, LMS_I_LEN);
        lms_store_u32(buf + LMS_I_LEN, q);
        lms_store_u16(buf + LMS_I_LEN + 4, D_MESG);
        memcpy(buf + LMS_I_LEN + 6, C, LMS_N);
        if (message_len > 0u) {
            memcpy(buf + 54, message, message_len);
        }
        if (lms_mmio_hash_once(client, buf, (uint32_t)total,
                               digest, NULL) == LMS_MMIO_OK) {
            memcpy(Q, digest, LMS_N);
            return LMS_OK;
        }
        /* HASH_ONCE failed (hardware error or allow_fallback=0) → fall into
         * the software path */
    }

    /* 74 < message_len ≤ 1994: HASH_ONCE_RAM (multi-block absorb from task
     * RAM). Assemble prefix+message and write task RAM once; hardware chunks
     * by rate (final-block padding handled in hardware). static 2KB (not on
     * the stack). */
    if (message_len <= 1994u) {
        uint8_t *buf = hw_msg_hash_buf_large;
        size_t total = 54u + message_len;
        memcpy(buf, I, LMS_I_LEN);
        lms_store_u32(buf + LMS_I_LEN, q);
        lms_store_u16(buf + LMS_I_LEN + 4, D_MESG);
        memcpy(buf + LMS_I_LEN + 6, C, LMS_N);
        if (message_len > 0u) {
            memcpy(buf + 54, message, message_len);
        }
        if (lms_mmio_hash_once_ram(client, buf, (uint32_t)total,
                                   digest, NULL) == LMS_MMIO_OK) {
            memcpy(Q, digest, LMS_N);
            return LMS_OK;
        }
        /* HASH_ONCE_RAM failed → fall into the software path */
    }

    /* Over the cap (>1994B) or hardware failure: software SHA-256 */
    {
        uint8_t prefix[LMS_I_LEN + 4 + 2 + LMS_N];
        memcpy(prefix, I, LMS_I_LEN);
        lms_store_u32(prefix + LMS_I_LEN, q);
        lms_store_u16(prefix + LMS_I_LEN + 4, D_MESG);
        memcpy(prefix + LMS_I_LEN + 6, C, LMS_N);
        if (lms_hash_parts(prefix, sizeof(prefix),
                           message, message_len,
                           NULL, 0, NULL, 0,
                           FW_HASH_ALG, digest) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
        memcpy(Q, digest, LMS_N);
        return LMS_OK;
    }
}

/* coef backend (CMD_MSG_Q_COEF hardware): one MMIO completes message hash→Q→
 * checksum→coefficients. P1 single block (L=54+m ≤128); over-limit or
 * hardware failure returns non-LMS_OK and the algorithm layer falls back to
 * software (hw_message_hash_backend + software checksum/coef loop). On
 * success: Q + coefficients are filled. */
static int hw_coef_backend(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t q,
                           const uint8_t C[LMS_N],
                           const uint8_t *message,
                           size_t message_len,
                           uint32_t lmots_type,
                           uint8_t Q[LMS_N],
                           uint8_t coefficients[LMS_MAX_OTS_P])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    const uint8_t *msg = message;
    (void)hash_alg;
    (void)Q;   /* Q not read back: the algorithm layer's coef_backend success
                  branch does not consume it */
    /* P1.5 keep mode: coefficients stay in hardware coefficient_words (not
     * read back), coef_ready set for the SIGN/VERIFY backend to consume
     * (skips coefficient packing + task-RAM write). On failure (>74B etc.)
     * falls back to software. P2 multi-block (>74B) + level 1: the message
     * was already written by the bridge passthrough to task-RAM word 582 →
     * pass NULL. Q is also not read back (Q==NULL): the algorithm layer's
     * coef_backend success branch does not consume Q (signature output is
     * only type+C+y), saving 8 MMIO reads. */
    client->coef_ready = 0;
    if (s_msg_in_ram && message_len > 74u) {
        msg = NULL;
    }
    if (lms_mmio_msg_q_coef(client, I, q, C, msg, message_len, lmots_type,
                            NULL, NULL, NULL) == LMS_MMIO_OK) {
        s_msg_in_ram = 0;
        client->coef_ready = 1;
        return LMS_OK;
    }
    /* Fallback on failure: when the message is in task RAM, read it back into
     * the software buffer (the algorithm layer's software coef needs an
     * in-memory message) */
    if (msg == NULL) {
        task_read_words(582u, (uint8_t *)message, (uint32_t)message_len);
    }
    s_msg_in_ram = 0;
    return LMS_ERR_INVALID;
}

/* Global D_INTR backend: all lms_internal_node calls go through HASH_ONCE
 * (full KeyGen/Sign/Verify coverage) */
static int hw_intr_backend(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t node_num,
                           const uint8_t left[LMS_N],
                           const uint8_t right[LMS_N],
                           uint8_t out[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    uint8_t msg[LMS_I_LEN + 4 + 2 + 2 * LMS_N]; /* 16+4+2+32+32 = 86B */
    (void)hash_alg;
    memcpy(msg, I, LMS_I_LEN);
    lms_store_u32(msg + LMS_I_LEN, node_num);
    lms_store_u16(msg + LMS_I_LEN + 4, D_INTR);
    memcpy(msg + LMS_I_LEN + 6, left, LMS_N);
    memcpy(msg + LMS_I_LEN + 6 + LMS_N, right, LMS_N);
    return lms_mmio_hash_once(client, msg, sizeof(msg), out, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

/* VERIFY_LEAF backend: one MMIO completes chain verify → K_q → D_LEAF
 * (eliminates the second interaction of software reading back K_q and
 * issuing another HASH_ONCE). After registration, lms_verify's leaf hash
 * runs in hardware. All w∈{1,2,4,8}; not registered for w∉{1,2,4,8}
 * (REVIEW B05B06-R5). */
static int hw_verify_leaf(void *context,
                          const uint8_t I[LMS_I_LEN],
                          lms_hash_alg_t hash_alg,
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t *coefficients,
                          const uint8_t *inputs,
                          uint32_t node_num,
                          uint8_t leaf[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {
        /* P1.5: coefficients already in hardware coefficient_words, skip
         * packing + write */
        client->coef_ready = 0;
        return lms_mmio_lmots_verify_leaf(client, I, q, node_num, lmots_type,
                                          NULL, inputs, leaf, NULL)
            == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_verify_leaf(client, I, q, node_num, lmots_type,
                                      coefficients, inputs, leaf, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

/* VERIFY_LEAF bridge taskram variant: signature y was already written by the
 * UART passthrough bridge to task RAM[32..567] (skips inputs transfer).
 * Registered by firmware verify_from_uart when bridged; lms_verify's leaf
 * hash reads the real y from task RAM (inputs argument ignored). Same w scope
 * as hw_verify_leaf. */
static int hw_verify_leaf_taskram(void *context,
                                  const uint8_t I[LMS_I_LEN],
                                  lms_hash_alg_t hash_alg,
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t *coefficients,
                                  const uint8_t *inputs,
                                  uint32_t node_num,
                                  uint8_t leaf[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    (void)inputs;
    if (client->coef_ready) {
        /* P1.5: coefficients already in hardware coefficient_words, skip
         * packing + write */
        client->coef_ready = 0;
        return lms_mmio_lmots_verify_leaf_taskram(client, I, q, node_num, lmots_type,
                                                  NULL, leaf, NULL)
            == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_verify_leaf_taskram(client, I, q, node_num, lmots_type,
                                              coefficients, leaf, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

/* Task-RAM write (word-aligned fast path, write side auto-increments): one
 * ADDR + consecutive DATA. */
static void task_write_words(uint32_t word_base, const uint8_t *bytes, uint32_t length)
{
    uint32_t i;
    uint32_t word;
    MMIO32(LMS_TASK_ADDR) = word_base;
    (void)MMIO32(LMS_STATUS);   /* Read barrier: force the task_addr_r store to commit */
    for (i = 0u; i < length; i += 4u) {
        word = (uint32_t)bytes[i] | ((uint32_t)bytes[i + 1u] << 8) |
               ((uint32_t)bytes[i + 2u] << 16) | ((uint32_t)bytes[i + 3u] << 24);
        MMIO32(LMS_TASK_DATA) = word;
    }
}

/* Task-RAM read (read side does not auto-increment): ADDR+DATA per word. Used
 * by the level-1 bridge-passthrough fallback path (message already written to
 * task RAM by the bridge; read back into the software buffer when hardware is
 * unavailable). */
static void task_read_words(uint32_t word_base, uint8_t *bytes, uint32_t length)
{
    uint32_t i;
    for (i = 0u; i < length; i += 4u) {
        MMIO32(LMS_TASK_ADDR) = word_base + i / 4u;
        (void)MMIO32(LMS_STATUS);   /* Read barrier: force the task_addr_r store to commit */
        {
            uint32_t word = MMIO32(LMS_TASK_DATA);
            uint32_t j;
            for (j = 0u; j < 4u && i + j < length; j++) {
                bytes[i + j] = (uint8_t)(word >> (8u * j));
            }
        }
    }
}

/* Verify auth-path chained D_INTR primitive (CMD_D_INTR_CHAIN): one MMIO
 * completes the entire auth path (leaf + sibling sequence → N consecutive
 * D_INTR layers → root). OTS/LMS semantic layering: VERIFY_LEAF handles
 * OTS→leaf (leaf as the starting left), this backend handles the LMS tree
 * hash chain, and root comparison is still done in software by lms_verify.
 * Both platform wrappers are implemented (REVIEW B05B06-R5). */
static int hw_dintr_authpath(void *context,
                             const uint8_t I[LMS_I_LEN],
                             lms_hash_alg_t hash_alg,
                             uint32_t node_num,
                             const uint8_t *leaf,
                             const uint8_t *path,
                             uint32_t height,
                             uint8_t root[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    uint32_t i;
    (void)hash_alg;
    /* Task RAM: word32..39 = starting left (leaf); word40.. = sibling[0..N-1] */
    task_write_words(32u, leaf, (uint32_t)LMS_N);
    task_write_words(40u, path, height * (uint32_t)LMS_N);
    /* Registers: I, node=leaf (includes parity bit, P1-6 q=1 fix: hardware
     * picks the concat direction per layer by leaf/node parity; node within a
     * block uses >>1), N=height */
    for (i = 0u; i < (uint32_t)LMS_I_LEN; i += 4u) {
        MMIO32(LMS_IDENTIFIER + i) = (uint32_t)I[i] | ((uint32_t)I[i + 1u] << 8) |
                                     ((uint32_t)I[i + 2u] << 16) | ((uint32_t)I[i + 3u] << 24);
    }
    MMIO32(LMS_ARG_LEAF_NODE) = node_num;
    MMIO32(LMS_ARG_STEPS) = height;
    MMIO32(LMS_COMMAND) = LMS_CMD_D_INTR_CHAIN;
    MMIO32(LMS_OUTPUT_LENGTH) = (uint32_t)LMS_N;
    (void)MMIO32(LMS_STATUS);   /* Read barrier: force all stores to commit */
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) { }
    if ((MMIO32(LMS_STATUS) & LMS_STATUS_DONE) == 0u || MMIO32(LMS_ERROR) != 0u) {
        client->last_hw_error = (uint8_t)MMIO32(LMS_ERROR);
        return LMS_ERR_INVALID;
    }
    /* D_INTR_CHAIN hardware cycles counted in the hash_once counter
     * (tree-hash hardware; keeps hw = real hardware cycles scope) */
    client->hardware_hash_once_count++;
    client->hardware_hash_once_cycles += (uint64_t)MMIO32(LMS_CYCLE_COUNT);
    for (i = 0u; i < (uint32_t)LMS_N; i += 4u) {
        uint32_t w = MMIO32(LMS_OUTPUT + i);
        root[i] = (uint8_t)w;
        root[i + 1u] = (uint8_t)(w >> 8);
        root[i + 2u] = (uint8_t)(w >> 16);
        root[i + 3u] = (uint8_t)(w >> 24);
    }
    return LMS_OK;
}

/* SIGN backend (MMIO version + bridge taskram version). sign_from_uart
 * registers the taskram variant first when bridged; lms_sign's signature y
 * stays in task RAM and is read out by the UART-bridge passthrough (saves a
 * 2144B read-back + byte-by-byte transmit transfer). */
static int hw_sign(void *context,
                   const uint8_t I[LMS_I_LEN],
                   lms_hash_alg_t hash_alg,
                   uint32_t q,
                   uint32_t lmots_type,
                   const uint8_t *coefficients,
                   uint8_t *outputs)
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {
        /* P1.5: coefficients already in hardware coefficient_words, skip
         * packing + write */
        client->coef_ready = 0;
        return lms_mmio_lmots_sign(client, client->key_handle, I, q, lmots_type,
                                   NULL, outputs, NULL)
            == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_sign(client, client->key_handle, I, q, lmots_type,
                               coefficients, outputs, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

/* SIGN bridge taskram variant: signature y stays in task RAM (skips outputs
 * read-back), read out via the UART-bridge passthrough. */
static int hw_sign_taskram(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t q,
                           uint32_t lmots_type,
                           const uint8_t *coefficients,
                           uint8_t *outputs)
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    (void)outputs;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {
        /* P1.5: coefficients already in hardware coefficient_words, skip
         * packing + write */
        client->coef_ready = 0;
        return lms_mmio_lmots_sign_taskram(client, client->key_handle, I, q, lmots_type,
                                           NULL, NULL)
            == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_sign_taskram(client, client->key_handle, I, q, lmots_type,
                                       coefficients, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

/* Switch LM-OTS hardware backend registration state by parameter-set w:
 *   - w∈{1,2,4,8}: enable (registered at main init; this function is
 *     idempotent, repeated enable hits the internal ensure_probe cache).
 *   - w∉{1,2,4,8}: disable all (chain/derive/randomizer/fused keygen/sign/
 *     verify + verify_leaf), forcing the algorithm layer to pure-software
 *     LM-OTS (REVIEW B05B06-R5). */
#if !LMS_FW_NO_HW_ACCEL
static int s_hw_lmots_enabled = 1;

static void set_hw_lmots(int enable)
{
    if (!enable) {
        /* disable **always executes** (no idempotent short-circuit):
         * sign_from_uart etc. unconditionally restore lmots_sign_backend
         * (pre-existing) after set_hw_lmots(0), leaving s_hw_lmots_enabled
         * inconsistent with the real backend state; after phase 2 (lms_mmio
         * accepts all w), a residual sign_backend makes lmots-sign of
         * unsupported w wrongly go to hardware (board W1 lmots-sign
         * cycles=5760/hits+1 regression). */
        lms_mmio_lmots_keygen_disable();
        lms_mmio_lmots_sign_disable();
        lms_mmio_lmots_verify_disable();
        lmots_verify_leaf_backend_set(NULL, NULL);
        lmots_coef_backend_set(NULL, NULL);   /* Unsupported w uses pure-software coef (status quo, zero regression) */
        s_hw_lmots_enabled = 0;
        return;
    }
    if (enable == s_hw_lmots_enabled) {
        return;
    }
    if (lms_mmio_lmots_keygen_enable_insecure(&verify_client) == LMS_MMIO_OK &&
        lms_mmio_lmots_verify_enable(&verify_client) == LMS_MMIO_OK &&
        lms_mmio_lmots_sign_enable_insecure(&verify_client) == LMS_MMIO_OK) {
        lmots_verify_leaf_backend_set(hw_verify_leaf, &verify_client);
        lmots_coef_backend_set(hw_coef_backend, &verify_client);   /* w=4 restores hardware coef */
        s_hw_lmots_enabled = 1;
    }
}
#endif /* !LMS_FW_NO_HW_ACCEL */

/* Ensure the tree cache is bound to priv (configured by h): fingerprint match
 * reuses; otherwise rebuild. Returns 1=cache usable (backend registered),
 * 0=fall back to default recursion (config failure or unsupported parameter
 * set). */
/* Tree-cache memory_target (bytes): makes configure always pick j=5
 * (sublevels: H5=1/H10=2/H15=3), matching the static-pool arena layout (see
 * s_tree_arena). H10 full (j=10) needs 64KiB, over the SoC memory budget
 * (firmware text ~48-55KB + current bss ~35KB, ~96KiB available; REVIEW
 * B05B06-R7 corrected the old 4.5KB figure), so it degrades dynamically to
 * multiple sublevels; if memory becomes ample later (or for PC/Verilator
 * verification), raise this budget and configure auto-selects the j=h full
 * tier. */
#define TREE_MEMORY_TARGET 12288u

/* Whether the tree cache hits (side-effect-free precheck; the test is the
 * same source as inside tree_cache_ensure). Level-1 bridge passthrough: on a
 * miss, ensure builds the tree (KEYGEN_LEAF overwrites the task-RAM message
 * region), so the message must be read back first. */
static int tree_cache_hit(const lms_private_key_t *priv)
{
    uint8_t fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    memcpy(fingerprint + LMS_I_LEN, priv->seed, LMS_SEED_LEN);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN + 4u, priv->lmots_type);
    return s_tree_cache_valid &&
           memcmp(s_tree_key_fingerprint, fingerprint, sizeof(fingerprint)) == 0;
}

static int tree_cache_ensure(const lms_private_key_t *priv)
{
    lms_tree_config_t cfg;
    uint8_t fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    memcpy(fingerprint + LMS_I_LEN, priv->seed, LMS_SEED_LEN);
    /* Fingerprint includes parameter-set type: different w/h with the same
     * I+seed are different key trees and must rebuild the cache. */
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN + 4u, priv->lmots_type);

    /* Fingerprint matches and cache valid: reuse directly (backend already
     * registered). */
    if (s_tree_cache_valid &&
        memcmp(s_tree_key_fingerprint, fingerprint, sizeof(fingerprint)) == 0) {
        return 1;
    }

    /* Key change / uninitialized: invalidate the old cache, re-run configure +
     * init + sign_init. Pick a tier dynamically by parameter-set h
     * (lms_tree_configure) and check the tier matches the static-pool arena
     * (subtree_size==5 and est_memory+levels ≤ arena capacity); on mismatch
     * fall back to default recursion. The tree cache works for any w
     * (auth-path table lookup O(h); K_q source goes to hardware for
     * w∈{1,2,4,8}, software otherwise). */
    tree_cache_invalidate();
    if (lms_tree_configure(priv->lms_type, TREE_MEMORY_TARGET, &cfg) != LMS_OK ||
        cfg.subtree_size != 5u ||
        cfg.est_memory +
            (uint64_t)cfg.sublevels * (uint64_t)sizeof(lms_sublevel_t) >
            (uint64_t)sizeof(s_tree_arena)) {
        return 0;
    }
    tree_pool_reset();
    if (lms_tree_ctx_init(&s_tree_ctx, &cfg, priv->I, NULL, NULL,
                          tree_pool_alloc, tree_pool_free, NULL) != LMS_OK) {
        return 0;
    }
    /* Register the leaf-direct-out callback (KEYGEN_LEAF, one MMIO yields
     * D_LEAF) when hardware is available (SHAKE256 all w; SHA-256 only W4);
     * otherwise subtree_compute_leaf uses software ots_pub + software D_LEAF
     * hash. */
    if (lmots_hw_supported(priv->lmots_type)) {
        lms_subtree_set_leaf_fn(&s_tree_ctx, hw_keygen_leaf, &verify_client);
    }
    lms_intr_backend_set(hw_intr_backend, &verify_client);
    if (lms_tree_sign_init(&s_tree_ctx, priv) != LMS_OK) {
        tree_cache_invalidate();
        return 0;
    }
    memcpy(s_tree_key_fingerprint, fingerprint, sizeof(fingerprint));
    s_tree_cache_valid = 1;
    lms_auth_path_backend_set(lms_subtree_auth_path_backend, &s_tree_ctx);
    return 1;
}

/* ===== Secure (full secure scheme) tree cache: s_sec_tree_ctx =====
 * Isolated from insecure s_tree_ctx: input carries no plaintext SEED (SEED is
 * wrapped in the SEC slot); fingerprint excludes seed and key_handle
 * (single-fixed-key scheme), using I + parameter set (key identity = I +
 * type). Tree-build KEYGEN_LEAF derives from the SEC-slot SEED (hardware,
 * lms_mmio_lmots_keygen_leaf takes no seed); software never supplies a seed.
 * Shares the static-pool arena (different paths, different sessions; each
 * runs tree_pool_reset before its own sign_init, never concurrent). The auth
 * path is not registered as a global backend (0x66 does a direct table
 * lookup). */
static lms_tree_ctx_t s_sec_tree_ctx;
static uint8_t s_sec_tree_fingerprint[LMS_I_LEN + 8u]; /* I + lms_type + lmots_type */
static int s_sec_tree_valid;

static void sec_tree_cache_invalidate(void)
{
    lms_tree_ctx_free(&s_sec_tree_ctx);
    s_sec_tree_valid = 0;
}

static int sec_tree_cache_ensure(const lms_private_key_t *priv)
{
    lms_tree_config_t cfg;
    uint8_t fingerprint[LMS_I_LEN + 8u];

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    lms_store_u32(fingerprint + LMS_I_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + 4u, priv->lmots_type);

    if (s_sec_tree_valid &&
        memcmp(s_sec_tree_fingerprint, fingerprint, sizeof(fingerprint)) == 0) {
        return 1;
    }

    sec_tree_cache_invalidate();
    if (lms_tree_configure(priv->lms_type, TREE_MEMORY_TARGET, &cfg) != LMS_OK ||
        cfg.subtree_size != 5u ||
        cfg.est_memory +
            (uint64_t)cfg.sublevels * (uint64_t)sizeof(lms_sublevel_t) >
            (uint64_t)sizeof(s_tree_arena)) {
        return 0;
    }
    tree_pool_reset();
    if (lms_tree_ctx_init(&s_sec_tree_ctx, &cfg, priv->I, NULL, NULL,
                          tree_pool_alloc, tree_pool_free, NULL) != LMS_OK) {
        return 0;
    }
    /* Register the leaf-direct-out callback (KEYGEN_LEAF, one MMIO yields
     * D_LEAF) when hardware is available (from SEC-slot SEED, no plaintext
     * seed_load); otherwise software ots_pub needs a plaintext seed,
     * unsupported on the secure path (returns 0; caller reports an error). */
    if (lmots_hw_supported(priv->lmots_type)) {
        lms_subtree_set_leaf_fn(&s_sec_tree_ctx, hw_keygen_leaf, &verify_client);
    } else {
        sec_tree_cache_invalidate();
        return 0;
    }
    lms_intr_backend_set(hw_intr_backend, &verify_client);
    if (lms_tree_sign_init(&s_sec_tree_ctx, priv) != LMS_OK) {
        sec_tree_cache_invalidate();
        return 0;
    }
    memcpy(s_sec_tree_fingerprint, fingerprint, sizeof(fingerprint));
    s_sec_tree_valid = 1;
    return 1;
}
#endif /* !LMS_FW_NO_HW_ACCEL (hardware backend + tree-cache section) */

#if LMS_FW_NO_HW_ACCEL
/* ===== Pure-software tree cache (fair baseline: auth-path cache, K_q/D_LEAF/
 * D_INTR all in software) =====
 * The cooperative version (the #if !LMS_FW_NO_HW_ACCEL section above)
 * registers hardware leaf(D_LEAF)/intr(D_INTR) backends for tree building;
 * the pure-software version **registers no hardware at all** — tree-build K_q
 * goes through the default ots_pub (lmots_public_from_private, pure
 * software), and D_LEAF/D_INTR use software hashing. Purpose: the paper's
 * "hardware vs pure-software" comparison has **hardware acceleration as the
 * only variable** (both versions enable the auth-path tree cache, eliminating
 * per-signature recursive recompute), steady-state Sign ≈ pure-software
 * LM-OTS signing (auth-path table lookup O(h)). */
#define TREE_MEMORY_TARGET 12288u
static lms_tree_ctx_t s_sw_tree_ctx;
static uint8_t s_sw_tree_fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];
static int s_sw_tree_valid;

/* Static pool: same capacity as the cooperative version (H15 j=5 sublevels=3
 * peak ~13.4KiB → 16KiB). */
static uint8_t s_sw_arena[3u * sizeof(lms_sublevel_t) + 16384u];
static uint32_t s_sw_arena_used;
static uint8_t *s_sw_pool_last_ptr;
static uint32_t s_sw_pool_last_size;

static void *sw_pool_alloc(void *context, size_t size)
{
    uint32_t aligned;
    void *ptr;
    (void)context;
    aligned = (uint32_t)((size + 3u) & ~((size_t)3u));
    if (s_sw_arena_used + aligned > (uint32_t)sizeof(s_sw_arena)) {
        return NULL;
    }
    ptr = s_sw_arena + s_sw_arena_used;
    s_sw_arena_used += aligned;
    s_sw_pool_last_ptr = (uint8_t *)ptr;
    s_sw_pool_last_size = aligned;
    return ptr;
}

static void sw_pool_free(void *context, void *ptr)
{
    (void)context;
    if (ptr != NULL && (uint8_t *)ptr == s_sw_pool_last_ptr) {
        s_sw_arena_used -= s_sw_pool_last_size;
        s_sw_pool_last_ptr = NULL;
        s_sw_pool_last_size = 0u;
    }
}

static void sw_pool_reset(void)
{
    s_sw_arena_used = 0u;
    s_sw_pool_last_ptr = NULL;
    s_sw_pool_last_size = 0u;
}

/* Pure-software tree_cache_ensure (same name as the cooperative version, #if
 * mutually exclusive): fingerprint match reuses; otherwise rebuild (configure
 * + ctx_init + sign_init + register auth-path backend). hw_keygen_leaf /
 * hw_intr_backend not registered → K_q/D_LEAF/D_INTR all in software. */
static int tree_cache_ensure(const lms_private_key_t *priv)
{
    lms_tree_config_t cfg;
    uint8_t fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    memcpy(fingerprint + LMS_I_LEN, priv->seed, LMS_SEED_LEN);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN + 4u, priv->lmots_type);

    if (s_sw_tree_valid &&
        memcmp(s_sw_tree_fingerprint, fingerprint, sizeof(fingerprint)) == 0) {
        return 1;
    }
    lms_auth_path_backend_set(NULL, NULL);
    lms_tree_ctx_free(&s_sw_tree_ctx);
    s_sw_tree_valid = 0;
    if (lms_tree_configure(priv->lms_type, TREE_MEMORY_TARGET, &cfg) != LMS_OK ||
        cfg.subtree_size != 5u ||
        cfg.est_memory +
            (uint64_t)cfg.sublevels * (uint64_t)sizeof(lms_sublevel_t) >
            (uint64_t)sizeof(s_sw_arena)) {
        return 0;
    }
    sw_pool_reset();
    if (lms_tree_ctx_init(&s_sw_tree_ctx, &cfg, priv->I, NULL, NULL,
                          sw_pool_alloc, sw_pool_free, NULL) != LMS_OK) {
        return 0;
    }
    if (lms_tree_sign_init(&s_sw_tree_ctx, priv) != LMS_OK) {
        lms_tree_ctx_free(&s_sw_tree_ctx);
        s_sw_tree_valid = 0;
        return 0;
    }
    memcpy(s_sw_tree_fingerprint, fingerprint, sizeof(fingerprint));
    s_sw_tree_valid = 1;
    lms_auth_path_backend_set(lms_subtree_auth_path_backend, &s_sw_tree_ctx);
    return 1;
}
#endif /* LMS_FW_NO_HW_ACCEL (pure-software tree cache) */

static uint32_t sign_from_uart(uint8_t signature[LMS_MAX_SIGNATURE_LEN],
                               uint32_t *signature_length,
                               uint32_t *next_q,
                               uint32_t *cycles,
                               uint32_t *total_cycles,
                               uint32_t *steady_total_cycles,
                               uint32_t *parse_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];
    /* message uses file-scope shared static (0.1.271 stack hardening G-C1). */
    lms_private_key_t private_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    uint32_t total_start;
    uint32_t steady_start;
    uint32_t parse_start;
    uint32_t expected_sig_len;
    uint32_t message_length;
    size_t written = 0u;
    int status;

    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length);
        *signature_length = 0u;
        *next_q = 0u;
        *cycles = 0u;
        *total_cycles = 0u;
        *steady_total_cycles = 0u;
        *parse_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
    s_msg_in_ram = 0;
#if !LMS_FW_NO_HW_ACCEL
    if (message_length > 74u) {
        /* Level 1: large messages go through the UART-bridge passthrough to
         * task-RAM word 582 (MQC multi-block message region, padded to 4B
         * alignment); the firmware does not take them into memory
         * (hw_coef_backend consumes s_msg_in_ram). */
        const uint32_t pad = (message_length + 3u) & ~3u;
        if (bridge_run(BRIDGE_DIR_RX, 582u, pad) == 0) {
            s_msg_in_ram = 1;
        } else {
            uart_read_bytes(s_uart_msg, message_length);
        }
    } else
#endif
    {
        uart_read_bytes(s_uart_msg, message_length);
    }

#if LMS_FW_NO_HW_ACCEL
    /* Truncated version (2026-08-21, SLotH Fig.6 replication): the
     * pure-software full Sign takes SEED from the slot (preloaded via 0x63,
     * outside the acquisition window) — the host sends all-zero in the
     * request-frame SEED segment (priv[24:56]), so the command receive/parse
     * segment carries no plaintext SEED (aligned with SLotH "without
     * plaintext key load"); the tree cache fingerprint (I+slot SEED+type)
     * matches the 0x4B warmup → hit, no rebuild. */
    if (s_seed_slot_valid) {
        memcpy(private_key_bytes + 24u, s_seed_slot, LMS_SEED_LEN);
    }
#endif

    total_start = MMIO32(SOC_CYCLE_COUNT); /* End-to-end start point (includes sign_init tree build, reference scope) */
    verify_client.last_hw_error = 0u;
    *next_q = 0u;
    parse_start = MMIO32(SOC_CYCLE_COUNT);
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    *parse_cycles = MMIO32(SOC_CYCLE_COUNT) - parse_start;
    if (status == LMS_OK) {
#if !LMS_FW_NO_HW_ACCEL
        /* Switch the hardware backend by parameter-set w (all w∈{1,2,4,8} available on both platforms, REVIEW B05B06-R5). */
        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));
        /* Bridged message and tree cache miss → ensure's tree build will
         * overwrite the task-RAM message region (KEYGEN_LEAF y region starts
         * at word 32), so read it back into memory first; same when hardware
         * is unavailable. */
        if (s_msg_in_ram &&
            (!lmots_hw_supported(private_key.lmots_type) ||
             !tree_cache_hit(&private_key))) {
            task_read_words(582u, s_uart_msg, message_length);
            s_msg_in_ram = 0;
        }
        /* First ensure the tree cache is bound to this key (configured by h;
         * h=5/10/15 registers backends). sign_init tree build uses KeyGen
         * semantics (produces public K_q, one-time): **not counted in Sign's
         * hw cycle stats** (recorded before the chain baseline), and **not in
         * steady_total** (steady single-signature scope; one key pays init
         * once for 2^h signatures, and amortizing it into one sign would
         * overstate); but **counted in total_cycles** (end-to-end scope
         * including init). */
        (void)tree_cache_ensure(&private_key);
        /* Load SEED into hardware slot 0 (sign_derive_backend usable for all
         * w; for w∉{1,2,4,8} the seed is useless but harmless). */
        (void)fw_seed_load(private_key.seed);
#else
        /* Pure-software baseline: enable the auth-path tree cache (fair scope
         * — the only variable is hardware acceleration, both versions include
         * the tree cache); disabled with LMS_FW_NO_TREE_CACHE=1 (same scope
         * as the literature: each sign recursively recomputes the auth path,
         * measuring the pure-software no-cache baseline). */
#if !LMS_FW_NO_TREE_CACHE
        (void)tree_cache_ensure(&private_key);
#endif
#endif
        expected_sig_len = (uint32_t)lms_signature_len(private_key.lms_type,
                                                       private_key.lmots_type);
        steady_start = MMIO32(SOC_CYCLE_COUNT); /* Steady single-signature start point (after init) */
        count_before = verify_client.hardware_chain_count;
        cycles_before = verify_client.hardware_chain_cycles;
        derive_count_before = verify_client.hardware_derive_count;
        derive_cycles_before = verify_client.hardware_derive_cycles;
        sign_count_before = verify_client.hardware_sign_count;
        sign_cycles_before = verify_client.hardware_sign_cycles;
        keygen_count_before = verify_client.hardware_keygen_count;
        keygen_cycles_before = verify_client.hardware_keygen_cycles;
        hash_count_before = verify_client.hardware_hash_once_count;
        hash_cycles_before = verify_client.hardware_hash_once_cycles;
        /* Bridge mode (hardware available): signature y stays in task RAM
         * (Sign uses the taskram variant, saving y read-back + transmit
         * transfer). lms_sign leaves the y segment unwritten (placeholder)
         * when assembling the signature buffer; y is output by the UART-bridge
         * passthrough; the MMIO version is restored afterwards. When
         * unavailable, the software chain is used (the full signature is
         * assembled and sent by software). */
        sign_y_in_taskram = 0u;
#if !LMS_FW_NO_HW_ACCEL
        if (lmots_hw_supported(private_key.lmots_type)) {
            /* Bridge mode: signature y stays in task RAM (Sign uses the
             * taskram variant, saving y read-back + transmit transfer). */
            lmots_sign_backend_set(hw_sign_taskram, &verify_client);
        }
#endif
#if LMS_FW_NO_HW_ACCEL
        /* Scheme-A trigger (Sign version, 2026-08-21, SLotH Fig.6
         * replication): SCA trigger calibration for the pure-software full
         * Sign — before lms_sign (steady-state signing computation), run a
         * fixed 32B zero-data HASH_ONCE; busy rising edge → SCA 512-cycle
         * pulse (start edge); the first 73k cycles (message hash ~34K + first
         * LM-OTS DERIVE ~34K, SEED-related) fall inside the acquisition
         * window. parse/tree-build precede the trigger (outside the window).
         * Fixed public data identical across both groups, no TVLA
         * pollution. */
        {
            uint32_t zi;
            MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
            MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
            MMIO32(LMS_INPUT_LENGTH) = 32u;
            MMIO32(LMS_OUTPUT_LENGTH) = 32u;
            for (zi = 0u; zi < 8u; zi++) {
                MMIO32(LMS_INPUT + 4u * zi) = 0u;   /* 32B all-zero fixed trigger data */
            }
            MMIO32(LMS_CONTROL) = LMS_CTRL_START;
            while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
            }
        }
#endif
        status = lms_sign(&private_key, s_uart_msg, message_length,
                          signature, LMS_MAX_SIGNATURE_LEN, &written);
#if !LMS_FW_NO_HW_ACCEL
        lmots_sign_backend_set(hw_sign, &verify_client);
        if (status == LMS_OK && written == (size_t)expected_sig_len &&
            lmots_hw_supported(private_key.lmots_type)) {
            /* Bridge mode: y stays in task RAM, read out via UART-bridge TX
             * passthrough (sign_y_len varies with w). */
            sign_y_in_taskram = 1u;
            sign_y_len = lmots_y_len_type(private_key.lmots_type);
        }
#endif
        *next_q = private_key.q;
        *steady_total_cycles = MMIO32(SOC_CYCLE_COUNT) - steady_start;
    } else {
        expected_sig_len = 0u;
        count_before = verify_client.hardware_chain_count;
        cycles_before = verify_client.hardware_chain_cycles;
        derive_count_before = verify_client.hardware_derive_count;
        derive_cycles_before = verify_client.hardware_derive_cycles;
        sign_count_before = verify_client.hardware_sign_count;
        sign_cycles_before = verify_client.hardware_sign_cycles;
        keygen_count_before = verify_client.hardware_keygen_count;
        keygen_cycles_before = verify_client.hardware_keygen_cycles;
        hash_count_before = verify_client.hardware_hash_once_count;
        hash_cycles_before = verify_client.hardware_hash_once_cycles;
        *steady_total_cycles = 0u;
    }
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_sign_count - sign_count_before)
                   + (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_sign_cycles - sign_cycles_before)
            + (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before)
            + (uint32_t)(verify_client.hardware_hash_once_cycles - hash_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    *signature_length = (uint32_t)written;
    return status == LMS_OK && written == (size_t)expected_sig_len ? LMS_STATUS_DONE : 0u;
}

static uint32_t keygen_from_uart(uint8_t public_key_bytes[LMS_PUBLIC_KEY_LEN],
                                 uint32_t *public_key_length,
                                 uint32_t *cycles,
                                 uint32_t *total_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];
    lms_private_key_t private_key;
    lms_public_key_t public_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    uint32_t total_start;
    int status;

    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
#if LMS_FW_NO_HW_ACCEL
    /* Truncated version (2026-08-21, SLotH Fig.6 replication): the 0x4B
     * warmup frame sends all-zero in the SEED segment; the firmware uses the
     * slot SEED (preloaded via 0x63) → tree-build fingerprint matches 0x53 →
     * 0x53 cache hit. */
    if (s_seed_slot_valid) {
        memcpy(private_key_bytes + 24u, s_seed_slot, LMS_SEED_LEN);
    }
#endif
    total_start = MMIO32(SOC_CYCLE_COUNT); /* End-to-end start point */
    count_before = verify_client.hardware_chain_count;
    cycles_before = verify_client.hardware_chain_cycles;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    verify_client.last_hw_error = 0u;
    *public_key_length = 0u;
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    if (status == LMS_OK) {
#if !LMS_FW_NO_HW_ACCEL
        /* Switch the hardware backend by parameter-set w (all w∈{1,2,4,8} available on both platforms, REVIEW B05B06-R5). */
        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));
        /* Load SEED into hardware slot 0 (KEYGEN_LEAF internally derives all
         * chains + K_q + D_LEAF from the SEED). */
        (void)fw_seed_load(private_key.seed);
        /* Prefer tree-cache build (leaf_fn=KEYGEN_LEAF, hardware yields
         * D_LEAF directly, saving software SHA-256); take the root from ctx
         * by h; on failure/unsupported parameter set fall back to
         * lms_public_key_generate. */
        if (tree_cache_ensure(&private_key)) {
            lms_sublevel_t *top = &s_tree_ctx.levels[s_tree_ctx.sublevels - 1u];
            memcpy(public_key.root,
                   top->active.nodes + (size_t)1u * LMS_N, LMS_N);
            public_key.lms_type = private_key.lms_type;
            public_key.lmots_type = private_key.lmots_type;
            memcpy(public_key.I, private_key.I, LMS_I_LEN);
            status = LMS_OK;
        } else {
            status = lms_public_key_generate(&private_key, &public_key);
        }
#else
        /* Pure-software baseline: enable the tree cache to produce the root
         * (fair scope — KeyGen cost = tree build, same as full-software tree
         * build, only the implementation path differs; also pre-builds the
         * auth-path cache for later Sign), but K_q/D_LEAF/D_INTR all in
         * software (no hardware backend registered). Disabled with
         * LMS_FW_NO_TREE_CACHE=1 (full-software tree build, same scope as the
         * literature). */
#if !LMS_FW_NO_TREE_CACHE
        if (tree_cache_ensure(&private_key)) {
            lms_sublevel_t *top = &s_sw_tree_ctx.levels[s_sw_tree_ctx.sublevels - 1u];
            memcpy(public_key.root,
                   top->active.nodes + (size_t)1u * LMS_N, LMS_N);
            public_key.lms_type = private_key.lms_type;
            public_key.lmots_type = private_key.lmots_type;
            memcpy(public_key.I, private_key.I, LMS_I_LEN);
            status = LMS_OK;
        } else {
            status = lms_public_key_generate(&private_key, &public_key);
        }
#else
        status = lms_public_key_generate(&private_key, &public_key);
#endif
#endif
    }
    if (status == LMS_OK) {
        status = lms_public_key_serialize(&public_key, public_key_bytes, LMS_PUBLIC_KEY_LEN);
    }
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before)
            + (uint32_t)(verify_client.hardware_hash_once_cycles - hash_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    if (status == LMS_OK) {
        *public_key_length = LMS_PUBLIC_KEY_LEN;
        return LMS_STATUS_DONE;
    }
    return 0u;
}

static uint32_t lmots_keygen_from_uart(uint8_t public_key[LMS_N], uint32_t *cycles,
                                       uint32_t *total_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];
    lms_private_key_t private_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint32_t total_start;
    int status;

    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
    total_start = MMIO32(SOC_CYCLE_COUNT);
    count_before = verify_client.hardware_chain_count;
    cycles_before = verify_client.hardware_chain_cycles;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    verify_client.last_hw_error = 0u;
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    if (status == LMS_OK) {
#if !LMS_FW_NO_HW_ACCEL
        /* Switch the hardware backend by parameter-set w (all w∈{1,2,4,8} available on both platforms, REVIEW B05B06-R5). */
        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));
        /* Load SEED into hardware slot 0 so keygen_backend (CMD_LMOTS_KEYGEN)
         * can complete all p chains in hardware at once and return the K_q
         * public key directly. */
        (void)fw_seed_load(private_key.seed);
#endif
        status = lmots_public_from_private(&private_key, private_key.q, public_key);
    }
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t lmots_sign_from_uart(uint8_t signature[LMS_MAX_OTS_SIG_LEN],
                                     uint32_t *cycles, uint32_t *total_cycles,
                                     uint32_t *parse_cycles, uint32_t *sign_cycles,
                                     uint32_t *steady_total_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];
    /* message uses file-scope shared static (0.1.271 stack hardening G-C1). */
#if !LMS_FW_NO_HW_ACCEL
    uint8_t C[LMS_N];
    uint8_t coefficients[LMS_MAX_OTS_P];
#endif
    lms_private_key_t private_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    uint32_t total_start;
    uint32_t steady_start;
    uint32_t parse_start;
    uint32_t sign_start;
    uint32_t message_length;
    int status;

    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length);
        *cycles = 0u;
        *total_cycles = 0u;
        *parse_cycles = 0u;
        *sign_cycles = 0u;
        *steady_total_cycles = 0u;
        sign_y_in_taskram = 0u;
        lmots_out_sig_len = 0u;
        return 0u;
    }
    uart_read_bytes(s_uart_msg, message_length);
    total_start = MMIO32(SOC_CYCLE_COUNT);
    count_before = verify_client.hardware_chain_count;
    cycles_before = verify_client.hardware_chain_cycles;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    sign_count_before = verify_client.hardware_sign_count;
    sign_cycles_before = verify_client.hardware_sign_cycles;
    verify_client.last_hw_error = 0u;
    parse_start = MMIO32(SOC_CYCLE_COUNT);
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    *parse_cycles = MMIO32(SOC_CYCLE_COUNT) - parse_start;
    if (status == LMS_OK) {
#if !LMS_FW_NO_HW_ACCEL
        /* Switch the hardware backend by parameter-set w (all w∈{1,2,4,8} available on both platforms, REVIEW B05B06-R5). */
        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));
        /* Load SEED into hardware slot 0 so sign_derive_backend
         * (CMD_DERIVE_CHAIN) can complete private-key derivation in hardware
         * (replacing software lmots_private_value SHA-256). */
        (void)fw_seed_load(private_key.seed);
#endif
        /* Steady single-signature start point (after seed_load, before
         * prepare): excludes parse/seed_load, same baseline as LMS Sign's
         * steady_total, so they are comparable (LMS steady ≥ LM-OTS steady,
         * differing by auth-path assembly). total still includes
         * parse/seed_load (reference scope). */
        steady_start = MMIO32(SOC_CYCLE_COUNT);
        sign_start = MMIO32(SOC_CYCLE_COUNT);
        sign_y_in_taskram = 0u;
        if (lmots_hw_supported(private_key.lmots_type)) {
#if !LMS_FW_NO_HW_ACCEL
            /* Step 3 bridge mode (hardware available w∈{1,2,4,8}): software
             * computes C + coefficients; signature y stays in task RAM and is
             * read out by the UART bridge (eliminates the y read-back MMIO
             * transfer). The signature buffer only fills type+C (36B). */
            status = lmots_sign_prepare(&private_key, private_key.q,
                                        s_uart_msg, message_length, C, coefficients);
            if (status == LMS_OK) {
                signature[0] = (uint8_t)(private_key.lmots_type >> 24);
                signature[1] = (uint8_t)(private_key.lmots_type >> 16);
                signature[2] = (uint8_t)(private_key.lmots_type >> 8);
                signature[3] = (uint8_t)private_key.lmots_type;
                memcpy(signature + 4, C, LMS_N);
                status = lms_mmio_lmots_sign_taskram(&verify_client, 0u,
                                                     private_key.I, private_key.q,
                                                     private_key.lmots_type,
                                                     verify_client.coef_ready ? NULL : coefficients, cycles);
                verify_client.coef_ready = 0;
                sign_y_in_taskram = (status == LMS_MMIO_OK) ? 1u : 0u;
                if (sign_y_in_taskram) {
                    sign_y_len = lmots_y_len_type(private_key.lmots_type);
                }
            }
            lmots_out_sig_len = lmots_sig_len_priv(&private_key);
#else
            lmots_out_sig_len = lmots_sig_len_priv(&private_key);
            status = lmots_sign(&private_key, private_key.q, s_uart_msg, message_length,
                                signature, lmots_out_sig_len);
#endif
        } else {
            /* Hardware unavailable: full software LM-OTS signature
             * (C/checksum/coefficients/chain values all in software); the
             * signature buffer holds the full type+C+y and is sent normally
             * over UART (no bridge passthrough). */
            lmots_out_sig_len = lmots_sig_len_priv(&private_key);
            status = lmots_sign(&private_key, private_key.q, s_uart_msg, message_length,
                                signature, lmots_out_sig_len);
        }
        *sign_cycles = MMIO32(SOC_CYCLE_COUNT) - sign_start;
        *steady_total_cycles = MMIO32(SOC_CYCLE_COUNT) - steady_start;
    } else {
        sign_y_in_taskram = 0u;
        lmots_out_sig_len = 0u;
        *sign_cycles = 0u;
        *steady_total_cycles = 0u;
    }
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_sign_count - sign_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_sign_cycles - sign_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t lmots_verify_from_uart(uint32_t *cycles, uint32_t *total_cycles)
{
    uint8_t I[LMS_I_LEN];
    uint8_t expected_public[LMS_N];
    uint8_t recovered_public[LMS_N];
    /* message uses file-scope shared static (0.1.271 stack hardening G-C1). */
    uint8_t C[LMS_N];
    /* lmots_sig uses file-scope shared static (0.1.271 stack hardening G-C1). */
#if !LMS_FW_NO_HW_ACCEL
    uint8_t coefficients[LMS_MAX_OTS_P];
    uint64_t cycles_before;
#endif
    uint64_t count_before;
    uint32_t total_start;
    uint32_t sig_len;
    uint32_t y_len;
    uint32_t q;
    uint32_t message_length;
    uint32_t signature_type;
    int y_in_taskram = 0;
    int status;

    uart_read_bytes(I, sizeof(I));
    q = uart_get_u32();
    uart_read_bytes(expected_public, sizeof(expected_public));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length + LMS_MAX_OTS_SIG_LEN);
        *cycles = 0u;
        *total_cycles = 0u;
        return 0u;
    }
    uart_read_bytes(s_uart_msg, message_length);
    /* Signature = type(4) + C(32) + y(p*n). type+C read by software (computes
     * coefficients); y written to task RAM by the UART passthrough bridge
     * (W4+hardware, Step 3) or read directly by software. Signature type is
     * 4B big-endian (00 00 00 13), so uart_get_u32 (little-endian) cannot be
     * used. */
    signature_type = ((uint32_t)uart_getc() << 24) |
                     ((uint32_t)uart_getc() << 16) |
                     ((uint32_t)uart_getc() << 8) |
                     (uint32_t)uart_getc();
    uart_read_bytes(C, sizeof(C));
    y_len = lmots_y_len_type(signature_type);
    sig_len = 36u + y_len;
    if (y_len == 0u) {
        /* Invalid ots_type: discard the remaining y, then reject. */
        uart_discard(LMS_MAX_OTS_SIG_LEN - 36u);
        *cycles = 0u;
        *total_cycles = 0u;
        return 0u;
    }
#if !LMS_FW_NO_HW_ACCEL
    /* Switch the hardware backend by signature ots_type (hardware supports
     * w∈{1,2,4,8}; otherwise pure-software LM-OTS). */
    set_hw_lmots(lmots_hw_supported(signature_type));
#endif
#if !LMS_FW_NO_HW_ACCEL
    if (lmots_hw_supported(signature_type) &&
        32u + y_len / 4u <= ((message_length <= 74u) ? mqc_msg_base(y_len) : 568u)) {
        /* Short y (y end ≤ that w's MQC base, W4=568/W2=1096/W8=304; large
         * message 568): MQC read window base = 32+y_words (outside the y
         * region), y written by the UART-bridge passthrough starting at
         * task-RAM word 32 → verify_taskram reads the real y directly
         * (msg_q_coef header word mqc_base + message word mqc_base+14 do not
         * overlap). Receive y before computing coefficients (bridge stalls on
         * missing y bytes). W1 fills the RAM → software direct read. */
        if (bridge_run(BRIDGE_DIR_RX, BRIDGE_Y_ADDR, y_len) != 0) {
            *cycles = 0u;
            *total_cycles = 0u;
            return 0u;
        }
        y_in_taskram = 1;
    } else
#endif
    {
        /* W1 (y 8480B fills task RAM) / large message / pure-software
         * baseline: y read by software into the full signature buffer
         * (type+C+y); the cooperative path writes it back to task RAM
         * starting at word 32 after prepare, then runs verify_taskram. On the
         * pure-software path the bridge-passthrough branch is unreachable (no
         * hardware), so y must be read by software. */
        s_uart_sig[0] = (uint8_t)(signature_type >> 24);
        s_uart_sig[1] = (uint8_t)(signature_type >> 16);
        s_uart_sig[2] = (uint8_t)(signature_type >> 8);
        s_uart_sig[3] = (uint8_t)signature_type;
        memcpy(s_uart_sig + 4, C, LMS_N);
        uart_read_bytes(s_uart_sig + 36u, y_len);
    }
    /* End-to-end start point: after UART input and y bridge reception (host
     * transfer, not counted) complete, before prepare. Includes
     * lmots_public_from_signature_prepare (Q/checksum/coefficient software
     * overhead) + verify orchestration + comparison, consistent with the
     * total scope of LM-OTS Sign / LMS Verify. (0.1.220 placed total_start
     * after prepare, missing the Q/checksum/coefficient overhead, giving
     * Verify total=9901 only 1.46× of hw, inconsistent with other
     * commands.) */
    total_start = MMIO32(SOC_CYCLE_COUNT);
    count_before = verify_client.hardware_verify_count;
    verify_client.last_hw_error = 0u;
#if !LMS_FW_NO_HW_ACCEL
    if (lmots_hw_supported(signature_type)) {
        cycles_before = verify_client.hardware_verify_cycles;
        status = lmots_public_from_signature_prepare(I, FW_HASH_ALG, q, signature_type,
                                                     s_uart_msg, message_length, C,
                                                     coefficients);
        if (status != LMS_OK) {
            *cycles = 0u;
            *total_cycles = 0u;
            return 0u;
        }
        /* Task-RAM resident variant (writes coefficients internally + starts
         * + waits for hardware). When y is in the software buffer (W1/large
         * message): after prepare (msg_q_coef word 568/582), write it back to
         * task RAM starting at word 32, then the taskram variant reads the
         * real y; when y was already bridged (W4/W2 short messages), task-RAM
         * y is intact and the write-back is skipped. */
        if (!y_in_taskram) {
            task_write_words(32u, s_uart_sig + 36u, y_len);
        }
        status = lms_mmio_lmots_verify_taskram(&verify_client, I, q,
                                               signature_type,
                                               verify_client.coef_ready ? NULL : coefficients,
                                               recovered_public, cycles);
        verify_client.coef_ready = 0;
        *cycles = (uint32_t)(verify_client.hardware_verify_cycles - cycles_before);
    } else
#endif
    {
        /* Hardware unavailable (w∉{1,2,4,8}) / pure software: full software
         * verify (Q/checksum/coefficients/chain values all in software). */
        status = lmots_public_from_signature(I, FW_HASH_ALG, q, signature_type,
                                             s_uart_msg, message_length,
                                             s_uart_sig, sig_len, recovered_public);
        *cycles = 0u;
    }
    if (status == LMS_OK && memcmp(recovered_public, expected_public, LMS_N) != 0) {
        status = LMS_ERR_VERIFY;
    }
    hardware_hits += (uint32_t)(verify_client.hardware_verify_count - count_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t seed_load_from_uart(uint32_t *cycles, uint32_t *total_cycles)
{
    uint8_t seed[LMS_SEED_LEN];
    uint32_t total_start;
    int status;

    uart_read_bytes(seed, sizeof(seed));
    total_start = MMIO32(SOC_CYCLE_COUNT);
    verify_client.last_hw_error = 0u;
#if !LMS_FW_NO_HW_ACCEL
    status = lms_mmio_seed_load_test(&verify_client, 0u, seed);
    if (status == LMS_MMIO_OK) {
        /* 0x63 explicit load always executes: syncs the seed fingerprint
         * (F2); later flows with the same seed can skip */
        memcpy(s_seed_slot, seed, LMS_SEED_LEN);
        s_seed_slot_valid = 1u;
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
#else
    status = LMS_MMIO_OK; /* Pure-software baseline: no hardware SEED slot;
                             store in firmware memory for software 0x6D to read */
    memcpy(s_seed_slot, seed, LMS_SEED_LEN);
    s_seed_slot_valid = 1u;
    *cycles = 0u;
#endif
    memset(seed, 0, sizeof(seed));
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    return status == LMS_MMIO_OK ? LMS_STATUS_DONE : 0u;
}

/* C_LOAD (0x6C): randomizer C load (TRNG-C scheme, finalized 2026-08-22).
 * Request: cmd(1)||C[32].
 *   - Debug (LMS_FW_SEC_TEST_MODE defined): loads a fixed 32B test vector as
 *     the LM-OTS randomizer C (deterministic signatures → reproducible
 *     KAT/TVLA).
 *   - Deploy (undefined): hard-rejects ERR_INSECURE_DISABLED(0x0a) (same gate
 *     as SEED_LOAD deploy) — in deploy, signature C can only be generated by
 *     the secure-domain TRNG; no external path injects/rewrites C.
 * Both scopes consume the 32B frame first (keeps UART alignment); deploy only
 * ignores it. Response frame [2]=rc. */
static uint32_t c_load_from_uart(uint32_t *error)
{
    uint8_t c[LMS_N];
    uint32_t index;

    uart_read_bytes(c, sizeof(c));
    *error = 0u;
#ifdef LMS_FW_SEC_TEST_MODE
    for (index = 0u; index < sizeof(c); index++) {
        s_c_slot[index] = c[index];
    }
    s_c_slot_valid = 1u;
    /* After loading, switch the C source to the C slot: from now on LM-OTS
     * Sign's randomizer C uses this fixed value (deterministic signatures,
     * reproducible TVLA/fixed-vector KAT). When not loaded, the backend falls
     * back to the deterministic DERIVE_RANDOMIZER. */
    verify_client.randomizer_c_slot = s_c_slot;
    memset(c, 0, sizeof(c));
    return LMS_STATUS_DONE;
#else
    (void)c;
    *error = 0x0au;   /* ERR_INSECURE_DISABLED */
    return 0u;
#endif
}

/* CRC16-CCITT (0xFFFF), byte-wise, RV32-friendly (tableless, constant-time). */
static uint16_t crc16_ccitt(const uint8_t *data, uint32_t length)
{
    uint16_t crc = 0xffffu;
    uint32_t index;
    uint32_t bit;
    for (index = 0u; index < length; index++) {
        crc ^= (uint16_t)data[index] << 8;
        for (bit = 0u; bit < 8u; bit++) {
            crc = (crc & 0x8000u) != 0u ? (uint16_t)((crc << 1) ^ 0x1021u)
                                        : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* NVM_SYNC: the host re-fills STATE_REC in two halves (PUSH_LO/HI, each with
 * CRC16), or reads it back (READ). Response payload in response[16..47]
 * (32B):
 *   [16]=op [17]=seq (reserved 0) [18]=status (0 ok/1 half-missing/
 *   2 crc-bad/3 unknown-op) [19]=valid_mask [20..47]=data echo (READ returns
 *   the lo-half 28B mirror).
 * Each 32B chunk's integrity is guaranteed by the CRC16 at PUSH time (UART is
 * byte-reliable; the response adds no frame CRC).
 * Never writes hardware_hits (pure-software path, accelerator untouched). */
static void nvm_sync_from_uart(uint8_t response[48])
{
    uint8_t op = uart_getc();
    uint8_t chunk[NVM_CHUNK_LEN];
    uint32_t index;
    uint32_t half;
    uint16_t got_crc;
    uint16_t calc_crc;

    response[0] = op;
    response[1] = 0u;
    response[2] = 0u;
    response[3] = (uint8_t)(nvm_valid[0] | (uint8_t)(nvm_valid[1] << 1));
    if (op == NVM_SYNC_SUB_PUSH_LO || op == NVM_SYNC_SUB_PUSH_HI) {
        half = op == NVM_SYNC_SUB_PUSH_HI ? 1u : 0u;
        uart_read_bytes(chunk, NVM_CHUNK_LEN);
        got_crc = (uint16_t)uart_getc();
        got_crc |= (uint16_t)uart_getc() << 8;
        calc_crc = crc16_ccitt(chunk, NVM_CHUNK_LEN);
        if (calc_crc != got_crc) {
            response[2] = 2u;
        } else {
            for (index = 0u; index < NVM_CHUNK_LEN; index++) {
                nvm_state[half * NVM_CHUNK_LEN + index] = chunk[index];
            }
            nvm_crc[half] = got_crc;
            nvm_valid[half] = 1u;
        }
    } else if (op == NVM_SYNC_SUB_READ) {
        /* Read the lo half, 28B (no args, backward compatible with old use
         * cases). */
        if (nvm_valid[0] == 0u || nvm_valid[1] == 0u) {
            response[2] = 1u;
        } else {
            for (index = 0u; index < 28u; index++) {
                response[4u + index] = nvm_state[index];
            }
        }
    } else if (op == NVM_SYNC_SUB_READ_HI) {
        /* Read the high segment, 28B (no args): nvm_state[36..63], includes
         * the tag's last 8B [56..63]. */
        if (nvm_valid[0] == 0u || nvm_valid[1] == 0u) {
            response[2] = 1u;
        } else {
            for (index = 0u; index < 28u; index++) {
                response[4u + index] = nvm_state[36u + index];
            }
        }
    } else if (op == NVM_SYNC_SUB_READ_MID) {
        /* Read the middle segment, 28B (no args): nvm_state[28..55], filling
         * the 28..35 gap between lo/hi. The three segments base=0/28/36
         * together cover all 64B. */
        if (nvm_valid[0] == 0u || nvm_valid[1] == 0u) {
            response[2] = 1u;
        } else {
            for (index = 0u; index < 28u; index++) {
                response[4u + index] = nvm_state[28u + index];
            }
        }
    } else {
        uart_discard(NVM_CHUNK_LEN + NVM_CRC_LEN);
        response[2] = 3u;
    }
    response[3] = (uint8_t)(nvm_valid[0] | (uint8_t)(nvm_valid[1] << 1));
}

/* SEC_STATE (0x55): secure-domain command dispatch (STATE_COMMIT/FACTORY_INIT/
 * BOOT/fault injection). Request: sub(1) + params (COMMIT 12B / READ_SLOT 1B /
 * NVM_READ 1B / NVM_LOAD 65B / MC_LOAD 4B / others 0B). Response payload
 * [16..47] filled by sec_handle_uart_cmd. */
static void sec_state_from_uart(uint8_t response[48])
{
    uint8_t sub = uart_getc();
    uint8_t params[65];
    uint32_t index;
    uint32_t plen = 0u;
    uint8_t resp32[32];

    if (sub == SEC_SUB_COMMIT) {
        plen = 12u;
    } else if (sub == SEC_SUB_READ_SLOT) {
        plen = 1u;
    } else if (sub == SEC_SUB_NVM_READ) {
        plen = 1u;
    } else if (sub == SEC_SUB_NVM_LOAD) {
        plen = 65u;
    } else if (sub == SEC_SUB_MC_LOAD) {
        plen = 4u;
    } else if (sub == SEC_SUB_WRAP_LOAD) {
        plen = 48u;
    } else if (sub == SEC_SUB_BOOT) {
        plen = 16u;   /* BOOT accepts the active key's I(16B) (used for per-key K_WRAP_i/K_STATE_i derivation) */
    } else if (sub == SEC_SUB_FACTORY_INIT) {
        plen = 16u;   /* FACTORY_INIT accepts the first key's I(16B) (KDF context; wrap consistent with BOOT unwrap) */
    }
    for (index = 0u; index < plen; index++) {
        params[index] = uart_getc();
    }
    (void)sec_handle_uart_cmd(sub, params, resp32);
    for (index = 0u; index < 32u; index++) {
        response[index] = resp32[index];
    }
    /* Host persistent-domain bridge (spec §7): after a successful COMMIT or a
     * BOOT slot selection, sync the active slot's full 64B (including tag) to
     * the NVM_SYNC channel; the host can persist it by fetching the segments
     * via the extended READs. */
    if ((sub == SEC_SUB_COMMIT && resp32[2] == 0u) || sub == SEC_SUB_BOOT) {
        sec_export_active(nvm_state);
        nvm_valid[0] = 1u;
        nvm_valid[1] = 1u;
    }
}

/* TRNG_READ (0x58) / TRNG_READ_ACK (0x5A): diagnostic direct read of the TRNG
 * peripheral RND register (tier-1 raw words). Request: cmd(1) || count(1) ||
 * [seq(1) ACK version only]. Response: response[2]=status (0 ok/1
 * health_fail, mapped to frame [18]); response[20..23]=count (mapped to frame
 * [36..39], little-endian); response[24]=seq (ACK version, mapped to frame
 * [40]). Then count*4B random words (success only); the ACK version appends
 * 1B CRC8 (over count*4B). count cap 16 words (trng_read_bytes[64]). */
/* Randomizer C's TRNG fill (deploy path, TRNG-C scheme): reads 32B from the
 * secure-domain TRNG as C. On health_fail (TRNG_STAT bit0) returns non-zero —
 * C is not output (fail-closed); the upper layer lmots_mmio_get_randomizer_c
 * returns LMS_ERR_INVALID, failing the signature. No external injection path:
 * in deploy C_LOAD is hard-rejected, so C can only come from here. Referenced
 * only by deploy + non-pure-software builds (init block). Test mode /
 * pure-software do not reference it, hence this conditional compilation to
 * avoid unused-function warnings. */
#if !defined(LMS_FW_NO_HW_ACCEL) && !defined(LMS_FW_SEC_TEST_MODE)
static int fw_trng_fill_c(void *context, uint8_t out[LMS_N])
{
    uint32_t index;
    uint32_t stat;
    (void)context;
    if ((MMIO32(TRNG_STAT) & 1u) != 0u) {
        return 1;
    }
    for (index = 0u; index < LMS_N / 4u; index++) {
        /* Before each RND read, wait for word_valid (TRNG_STAT bit8) to
         * ensure a **new** random word is fetched. word_r updates only every
         * ~4 debiased bytes (lms_trng.v word assembly); a tight read loop
         * keeps returning the same old word → C degenerates (repeated words)
         * → Q/coefficients/chains all wrong → verify fails (deploy-verify
         * q=0 status=1, root cause measured 2026-08-22). */
        stat = 0u;
        while ((stat & 0x100u) == 0u) {
            stat = MMIO32(TRNG_STAT);
            if ((stat & 1u) != 0u) {
                return 1;   /* health_fail during wait: fail-closed */
            }
        }
        {
            uint32_t word = MMIO32(TRNG_RND);
            out[index * 4u]     = (uint8_t)word;
            out[index * 4u + 1u] = (uint8_t)(word >> 8);
            out[index * 4u + 2u] = (uint8_t)(word >> 16);
            out[index * 4u + 3u] = (uint8_t)(word >> 24);
        }
    }
    return 0;
}
#endif

static uint32_t trng_read_from_uart(uint8_t response[48], uint8_t *out_words, uint8_t with_ack)
{
    uint32_t count = uart_getc();
    uint32_t index;
    uint8_t seq = 0u;

    if (with_ack != 0u) {
        seq = uart_getc();
    }
    response[2] = (MMIO32(TRNG_STAT) & 1u) != 0u ? 1u : 0u;
    if (response[2] != 0u) {
        return 0u;
    }
    if (count > 16u) {
        count = 16u;
    }
    for (index = 0u; index < count; index++) {
        uint32_t word = MMIO32(TRNG_RND);
        out_words[index * 4u] = (uint8_t)word;
        out_words[index * 4u + 1u] = (uint8_t)(word >> 8);
        out_words[index * 4u + 2u] = (uint8_t)(word >> 16);
        out_words[index * 4u + 3u] = (uint8_t)(word >> 24);
    }
    response[20] = (uint8_t)count;
    response[21] = (uint8_t)(count >> 8);
    response[22] = (uint8_t)(count >> 16);
    response[23] = (uint8_t)(count >> 24);
    response[24] = seq;
    return count * 4u;
}

/* TRNG_STATUS (0x59): diagnostic read of TRNG peripheral status/health
 * counters/control. Request: cmd(1). Only response[0..31] is returned via
 * the 48B frame ([32..47] truncated off-line), so the 5 registers are packed
 * into [16..31] (16B):
 *   [16..19]=VERSION (low 16)||CAP (low 16) (both constant 1, presence check)
 *   [20..23]=STAT [24..27]=CTRL [28..31]=APT_COUNT (little-endian). */
static void trng_status_from_uart(uint8_t response[48])
{
    uint32_t stat = MMIO32(TRNG_STAT);
    uint32_t ctrl = MMIO32(TRNG_CTRL);
    uint32_t apt = MMIO32(TRNG_APT);
    uint32_t version = MMIO32(TRNG_VERSION);
    uint32_t cap = MMIO32(TRNG_CAP);

    response[2] = 0u;
    /* [16..19]: VERSION[15:0] || CAP[15:0], presence probe (constants 1/1). */
    response[16] = (uint8_t)version;
    response[17] = (uint8_t)(version >> 8);
    response[18] = (uint8_t)cap;
    response[19] = (uint8_t)(cap >> 8);
    response[20] = (uint8_t)stat;
    response[21] = (uint8_t)(stat >> 8);
    response[22] = (uint8_t)(stat >> 16);
    response[23] = (uint8_t)(stat >> 24);
    response[24] = (uint8_t)ctrl;
    response[25] = (uint8_t)(ctrl >> 8);
    response[26] = (uint8_t)(ctrl >> 16);
    response[27] = (uint8_t)(ctrl >> 24);
    response[28] = (uint8_t)apt;
    response[29] = (uint8_t)(apt >> 8);
    response[30] = (uint8_t)(apt >> 16);
    response[31] = (uint8_t)(apt >> 24);
}

/* FLASH_PROBE (0x5B): M1 SPI flash access verification. Request: cmd(1).
 * Triggers a hardware transaction (0x9F RDID + 4B read-back × 5 MISO
 * candidates), polls done (cap 2M MMIO reads; the hardware transaction is
 * ~20us, far below). Response payload [16..31] (frame [32..47], success path
 * only):
 *   [2]=status (0 ok / 1 timeout)
 *   [16..18]=RESP0 low 3B (B4)  [19..21]=RESP1 (K12)  [22..24]=RESP2 (J14)
 *   [25..27]=RESP3 (K15)        [28..30]=RESP4 (L13)  [31]=STATUS low byte
 * Read-back bytes come byte0 first (MSB-first). Known JEDEC IDs:
 * S25FL132K=01 40 15, AT25SF321=1F 86 01, MX25L3233F=C2 5E 16; unconnected/
 * floating candidates read back random or FF. */
static void flash_probe_from_uart(uint8_t response[48])
{
    uint32_t spin = 0u;
    uint32_t stat;
    uint32_t word;
    uint8_t resp[5][4];
    uint32_t cand;
    uint32_t byte;

    MMIO32(FLASH_CTRL) = 1u;
    do {
        stat = MMIO32(FLASH_STATUS);
        spin++;
    } while ((stat & 2u) == 0u && spin < 2000000u);
    response[2] = ((stat & 2u) != 0u) ? 0u : 1u;

    word = MMIO32(FLASH_RESP0); resp[0][0] = (uint8_t)word; resp[0][1] = (uint8_t)(word >> 8); resp[0][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP1); resp[1][0] = (uint8_t)word; resp[1][1] = (uint8_t)(word >> 8); resp[1][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP2); resp[2][0] = (uint8_t)word; resp[2][1] = (uint8_t)(word >> 8); resp[2][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP3); resp[3][0] = (uint8_t)word; resp[3][1] = (uint8_t)(word >> 8); resp[3][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP4); resp[4][0] = (uint8_t)word; resp[4][1] = (uint8_t)(word >> 8); resp[4][2] = (uint8_t)(word >> 16);
    for (cand = 0u; cand < 5u; cand++) {
        for (byte = 0u; byte < 3u; byte++) {
            response[16u + cand * 3u + byte] = resp[cand][byte];
        }
    }
    response[31] = (uint8_t)stat;
}

/* FLASH_PROG (0x5C): M1b write-path verification. Request: cmd || a2 || a1 ||
 * a0 || data. Hardware executes WREN + page program (1 byte, clear-only
 * bits); the firmware waits for done, then delays (tPP) to let the flash
 * finish internal programming. Response: [2]=status (0 ok/1 timeout);
 * [16..18]=addr echo (big-endian); [19]=data; [31]=STATUS register low byte.
 * Verification: later read back and compare via the SAM3U path (shim). */
static void flash_prog_from_uart(uint8_t response[48])
{
    uint32_t addr;
    uint32_t spin = 0u;
    uint32_t stat;
    uint32_t index;
    uint8_t data;

    addr = ((uint32_t)uart_getc() << 16) | ((uint32_t)uart_getc() << 8) |
           (uint32_t)uart_getc();
    data = (uint8_t)uart_getc();
    MMIO32(FLASH_OP) = 1u;
    MMIO32(FLASH_ADDR) = addr;
    MMIO32(FLASH_BYTE) = data;
    MMIO32(FLASH_CTRL) = 1u;
    do {
        stat = MMIO32(FLASH_STATUS);
        spin++;
    } while ((stat & 2u) == 0u && spin < 2000000u);
    response[2] = ((stat & 2u) != 0u) ? 0u : 1u;
    /* tPP conservative wait (~10ms@50MHz; AT25SF321 tPP≈3ms max) */
    for (index = 0u; index < 400000u; index++) {
        (void)MMIO32(FLASH_STATUS);
    }
    response[16] = (uint8_t)(addr >> 16);
    response[17] = (uint8_t)(addr >> 8);
    response[18] = (uint8_t)addr;
    response[19] = data;
    response[31] = (uint8_t)stat;
}

/* FLASH_CMD (0x5D): M1b diagnostic — sends a raw single-byte command (OP=2,
 * e.g. WREN 0x06). Request: cmd || byte. Response: [2]=status [16]=byte echo
 * [31]=STATUS. Use: after the FPGA sends WREN, read STATUS via SAM3U to verify
 * WEL — determines whether the FPGA's SCK/CS/SI actually reach the flash. */
static void flash_cmd_from_uart(uint8_t response[48])
{
    uint32_t spin = 0u;
    uint32_t stat;
    uint8_t byte;

    byte = (uint8_t)uart_getc();
    MMIO32(FLASH_OP) = 2u;
    MMIO32(FLASH_BYTE) = byte;
    MMIO32(FLASH_CTRL) = 1u;
    do {
        stat = MMIO32(FLASH_STATUS);
        spin++;
    } while ((stat & 2u) == 0u && spin < 2000000u);
    response[2] = ((stat & 2u) != 0u) ? 0u : 1u;
    response[16] = byte;
    response[31] = (uint8_t)stat;
}

/* SEC_SIGN (0x54) signing callback context: private metadata + message +
 * output signature. */
typedef struct {
    lms_private_key_t private_key;
    const uint8_t *message;
    uint32_t message_length;
    uint8_t *signature;
    int sign_rc;   /* lmots_sign specific return code (diagnostic, placed in response [3]) */
} sec_sign_ctx_t;

/* SEC_SIGN reuses global buffers (avoids new hot-path statics inflating
 * .bss): the message reuses the verify message buffer, the signature reuses
 * the global s_uart_sig. */
static uint8_t sec_sign_message[VERIFY_MESSAGE_MAX];

/* do_sign callback: v5 fused derive+sign (SEED never leaves hardware), q
 * passed in by sec_sign. Signature length derived from lmots_type (SEC_SIGN
 * supports all w; W1/W2 signatures > W4). */
static int sec_sign_do(uint32_t q, void *vctx)
{
    sec_sign_ctx_t *ctx = (sec_sign_ctx_t *)vctx;
    ctx->private_key.q = q;
    ctx->sign_rc = lmots_sign(&ctx->private_key, q, ctx->message, ctx->message_length,
                              ctx->signature, lmots_sig_len_priv(&ctx->private_key));
    return ctx->sign_rc;
}

/* SEC_SIGN (0x54): atomic signing (spec §9.4, step 6).
 * Request: I(16) || lms_type(4) || lmots_type(4) || msg_len(2, big-endian) ||
 * message(msg_len). Single-fixed-key scheme, no key_handle.
 * Response: frame [2]=rc (sec_sign error code) [3]=0; [4..7]=hw cycles
 * (derive+sign); [8..11]=hardware_hits; [12..15]=0; [16..19]=nvm_response
 * [0..3] ([18]=rc [19]=sign_rc diagnostic); [20..23]=total_cycles (end-to-end
 * SOC_CYCLE_COUNT, same offset as normal commands); [24..35]=0; [36..39]=signed
 * q (big-endian). Signature follows (success only). */
static void sec_sign_from_uart(uint8_t response[48],
                               uint8_t signature[LMS_MAX_OTS_SIG_LEN], /* REVIEW B05B06-R9: supports all w (W1=8516B); the former W4 size (2180B) scope was misleading */
                               uint32_t *signature_length,
                               uint32_t *cycles,
                               uint32_t *total_cycles)
{
    sec_sign_ctx_t ctx;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    uint32_t total_start;
    uint32_t q_out;
    int rc;

    uart_read_bytes(ctx.private_key.I, LMS_I_LEN);
    ctx.private_key.lms_type = uart_get_u32();
    ctx.private_key.lmots_type = uart_get_u32();
    ctx.message_length = uart_get_u16();
    if (ctx.message_length > VERIFY_MESSAGE_MAX) {
        uart_discard(ctx.message_length);
        *signature_length = 0u;
        *cycles = 0u;
        *total_cycles = 0u;
        response[2] = (uint8_t)SEC_ERR_PATH;
        return;
    }
    /* Reuse global buffers: message in sec_sign_message, signature directly
     * in the caller's global s_uart_sig (avoids new statics inflating
     * .bss). */
    uart_read_bytes(sec_sign_message, ctx.message_length);
    ctx.message = sec_sign_message;
    ctx.signature = signature;

    total_start = MMIO32(SOC_CYCLE_COUNT);
    count_before = verify_client.hardware_derive_count;
    cycles_before = verify_client.hardware_derive_cycles;
    sign_count_before = verify_client.hardware_sign_count;
    sign_cycles_before = verify_client.hardware_sign_cycles;
    verify_client.last_hw_error = 0u;

    /* max_ctr = 2^h (h parsed from lms_type): the SEC state machine's ctr cap
     * varies with the key's parameter set (H5=32/H10=1024/H15=32768, 0.1.243
     * all parameter sets). */
    {
        lms_param_t lparam;
        uint32_t max_ctr = 32u; /* conservative H5 when lms_type is invalid */
        if (lms_get_lms_param(ctx.private_key.lms_type, &lparam) == LMS_OK) {
            max_ctr = 1u << lparam.height;
        }
        rc = lms_mmio_lmots_sign_enable(&verify_client, 0u);
        if (rc == LMS_MMIO_OK) {
            rc = sec_sign(max_ctr, sec_sign_do, &ctx, &q_out);
        } else {
            rc = SEC_ERR_AUTH;
        }
    }
    lms_mmio_lmots_sign_disable();
    (void)lms_mmio_lmots_sign_enable_insecure(&verify_client);

    hardware_hits += (uint32_t)(verify_client.hardware_derive_count - count_before);
    hardware_hits += (uint32_t)(verify_client.hardware_sign_count - sign_count_before);
    *cycles = (uint32_t)(verify_client.hardware_derive_cycles - cycles_before +
                         verify_client.hardware_sign_cycles - sign_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;

    response[2] = (uint8_t)rc;
    response[3] = (uint8_t)(ctx.sign_rc & 0xffu);  /* Diagnostic: lmots_sign specific return code */
    /* total_cycles (end-to-end SOC_CYCLE_COUNT delta) written little-endian
     * into nvm_response[4..7]; serve_uart reassembles little-endian into
     * response frame [20..23] — same offset as normal commands' total_cycles,
     * so board tests can read it uniformly (secure-domain signing performance
     * vs insecure signing). */
    response[4] = (uint8_t)(*total_cycles);
    response[5] = (uint8_t)(*total_cycles >> 8);
    response[6] = (uint8_t)(*total_cycles >> 16);
    response[7] = (uint8_t)(*total_cycles >> 24);
    response[20] = (uint8_t)(q_out >> 24);
    response[21] = (uint8_t)(q_out >> 16);
    response[22] = (uint8_t)(q_out >> 8);
    response[23] = (uint8_t)q_out;
    /* Readability note (REVIEW B05B06-R12): q_out is written big-endian into
     * response[20..23] here; the serve_uart 0x54 branch re-assembles
     * nvm_response[index] little-endian, so the on-wire frame [36..39] is
     * still big-endian (the two reversals cancel; consistent with board test
     * ">I at 36" scope). */
    *signature_length = (rc == SEC_OK) ? lmots_sig_len_priv(&ctx.private_key) : 0u;
    /* Host persistent-domain bridge (spec §7): sec_sign's internal
     * state_commit does not go through sec_handle_uart_cmd, so the active
     * slot must be synced to the NVM_SYNC mirror here, letting the host fetch
     * the full 64B (including tag) via the three READs. */
    if (sec_key_ready() != 0u) {
        sec_export_active(nvm_state);
        nvm_valid[0] = 1u;
        nvm_valid[1] = 1u;
    }
}

#if !LMS_FW_NO_HW_ACCEL
/* ===== Secure LMS trio (0x66/0x67): full secure-scheme scope =====
 * 0x66 SEC_LMS_SIGN: the LM-OTS part runs through the sec_sign state machine
 * (SEED from the SEC slot, Release→Commit, monotonic ctr, Release⇒Committed
 * invariant); the auth path runs through the SEC tree cache (KEYGEN_LEAF
 * builds the tree from the SEC-slot SEED, no plaintext seed_load). Outputs a
 * full LMS signature (RFC 8554: q||σ_q||lms_type||path, σ_q =
 * lmots_type||C||y). q is set by the SEC ctr.
 * 0x67 SEC_LMS_KEYGEN: builds the tree from the SEC-slot SEED and produces
 * the public key (KeyGen semantics, consumes no signing state). */

/* sec_lms_sign core: sec_sign + SEC tree-cache auth path + assembly.
 * Single-fixed-key scheme: the SEC tree-cache key_handle is fixed at 0 (the
 * fingerprint includes lms_type, so it auto-rebuilds across parameter
 * sets). */
static int sec_lms_sign_impl(const lms_private_key_t *private_key,
                             const uint8_t *message,
                             uint32_t message_length,
                             uint8_t *signature,
                             size_t signature_len,
                             size_t *written,
                             uint32_t *q_out,
                             uint32_t *steady_total_cycles)
{
    lms_param_t lparam;
    lmots_param_t oparam;
    sec_sign_ctx_t ctx;
    uint32_t qo;
    size_t needed;
    size_t sig_len;
    uint8_t *path;
    int rc;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0;
    uint32_t prof_t1;
    uint32_t prof_t2;
#endif

    if (lms_get_lms_param(private_key->lms_type, &lparam) != LMS_OK ||
        lms_get_lmots_param(private_key->lmots_type, &oparam) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    needed = lms_signature_len(private_key->lms_type, private_key->lmots_type);
    if (signature_len < needed) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }
    /* 1. SEC tree-cache build (auth path; KEYGEN_LEAF from SEC-slot SEED).
     *    init counted in total_cycles, not in steady_total_cycles. */
    if (sec_tree_cache_ensure(private_key) == 0) {
        return LMS_ERR_INVALID;
    }
    if (steady_total_cycles != NULL) {
        *steady_total_cycles = MMIO32(SOC_CYCLE_COUNT); /* Steady single-signature start point (after init) */
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_t0 = MMIO32(SOC_CYCLE_COUNT);
#endif
    /* 2. sec_sign atomic signing: σ_q (lmots_type||C||y) written directly to
     *    signature+4. */
    ctx.private_key = *private_key;
    ctx.message = message;
    ctx.message_length = message_length;
    ctx.signature = signature + 4u;
    ctx.sign_rc = 0;
    if (lms_mmio_lmots_sign_enable(&verify_client, 0u) != LMS_MMIO_OK) {
        return LMS_ERR_INVALID;
    }
    /* Bridge passthrough (0.1.245 optimization): σ_q's y segment stays in
     * task RAM (taskram variant, saving y read-back + software assembly
     * transfer, same scope as insecure 0x53); read out via the UART bridge in
     * the serve_uart 0x66 branch. SHAKE256 hardware available for all w;
     * sign_y_len varies with w. */
    lmots_sign_backend_set(hw_sign_taskram, &verify_client);
    sign_y_in_taskram = 1u;
    sign_y_len = lmots_y_len_type(private_key->lmots_type);
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_t1 = MMIO32(SOC_CYCLE_COUNT);
#endif
    /* max_ctr = 2^h: the SEC state machine's ctr cap varies with the key's
     * parameter set (H5/H10/H15). */
    rc = sec_sign(1u << lparam.height, sec_sign_do, &ctx, &qo);
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_t2 = MMIO32(SOC_CYCLE_COUNT);
#endif
    lms_mmio_lmots_sign_disable();
    (void)lms_mmio_lmots_sign_enable_insecure(&verify_client);
    if (rc != SEC_OK) {
        return LMS_ERR_INVALID;
    }
    /* 3. Assemble: q || σ_q || lms_type || path. */
    sig_len = 4u + oparam.n + oparam.p * oparam.n;
    lms_store_u32(signature, qo);
    lms_store_u32(signature + 4u + sig_len, private_key->lms_type);
    path = signature + 4u + sig_len + 4u;
    if (lms_subtree_auth_path_backend(&s_sec_tree_ctx, private_key, qo, path) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_sec_enable_cycles = prof_t1 - prof_t0;
    prof_sec_sign_cycles = prof_t2 - prof_t1;
    prof_sec_tail_cycles = MMIO32(SOC_CYCLE_COUNT) - prof_t2;
#endif
    if (steady_total_cycles != NULL) {
        *steady_total_cycles = MMIO32(SOC_CYCLE_COUNT) - *steady_total_cycles;
    }
    if (q_out) {
        *q_out = qo;
    }
    if (written) {
        *written = needed;
    }
    return LMS_OK;
}

/* sec_lms_keygen core: builds the tree from the SEC-slot SEED and produces
 * the root (KeyGen semantics, consumes no signing state). */
static int sec_lms_keygen_impl(const lms_private_key_t *private_key,
                               uint8_t public_key_bytes[LMS_PUBLIC_KEY_LEN])
{
    lms_public_key_t public_key;

    if (sec_tree_cache_ensure(private_key) == 0) {
        return LMS_ERR_INVALID;
    }
    {
        lms_sublevel_t *top = &s_sec_tree_ctx.levels[s_sec_tree_ctx.sublevels - 1u];
        memcpy(public_key.root, top->active.nodes + (size_t)1u * LMS_N, LMS_N);
    }
    public_key.lms_type = private_key->lms_type;
    public_key.lmots_type = private_key->lmots_type;
    memcpy(public_key.I, private_key->I, LMS_I_LEN);
    return lms_public_key_serialize(&public_key, public_key_bytes, LMS_PUBLIC_KEY_LEN);
}

/* SEC_LMS_SIGN (0x66) UART wrapper.
 * Request: I(16) || lms_type(4) || lmots_type(4) || msg_len(2, big-endian) ||
 * message. Single-fixed-key scheme, no key_handle.
 * Response: frame [2]=rc; [4..7]=hw (derive+sign); [16..19]=signed q;
 * [20..23]=total_cycles; [24..27]=steady_total_cycles. Signature follows. */
static uint32_t sec_lms_sign_from_uart(uint8_t signature[LMS_MAX_SIGNATURE_LEN],
                                       uint32_t *signature_length,
                                       uint32_t *next_q,
                                       uint32_t *cycles,
                                       uint32_t *total_cycles,
                                       uint32_t *steady_total_cycles)
{
    lms_private_key_t private_key;
    /* message uses file-scope shared static (0.1.271 stack hardening G-C1). */
    uint32_t message_length;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    uint32_t total_start;
    size_t written = 0u;
    int status;

    memset(&private_key, 0, sizeof(private_key));
    uart_read_bytes(private_key.I, LMS_I_LEN);
    private_key.lms_type = uart_get_u32();
    private_key.lmots_type = uart_get_u32();
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length);
        *signature_length = 0u;
        *next_q = 0u;
        *cycles = 0u;
        *total_cycles = 0u;
        *steady_total_cycles = 0u;
        return 0u;
    }
    uart_read_bytes(s_uart_msg, message_length);

    total_start = MMIO32(SOC_CYCLE_COUNT); /* End-to-end start point (includes init tree build) */
    verify_client.last_hw_error = 0u;
    *next_q = 0u;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    sign_count_before = verify_client.hardware_sign_count;
    sign_cycles_before = verify_client.hardware_sign_cycles;
    status = sec_lms_sign_impl(&private_key, s_uart_msg, message_length,
                               signature, LMS_MAX_SIGNATURE_LEN, &written, next_q,
                               steady_total_cycles);
    hardware_hits += (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_sign_count - sign_count_before);
    *cycles = (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before +
                         verify_client.hardware_sign_cycles - sign_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    *signature_length = (status == LMS_OK) ? (uint32_t)written : 0u;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

/* SEC_LMS_KEYGEN (0x67) UART wrapper.
 * Request: I(16) || lms_type(4) || lmots_type(4). Single-fixed-key scheme, no
 * key_handle. Response: frame [2]=rc; [4..7]=hw (keygen+hash_once);
 * [20..23]=total. Public key follows. */
static uint32_t sec_lms_keygen_from_uart(uint8_t public_key[LMS_PUBLIC_KEY_LEN],
                                         uint32_t *public_key_length,
                                         uint32_t *cycles,
                                         uint32_t *total_cycles)
{
    lms_private_key_t private_key;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    uint32_t total_start;
    int status;

    memset(&private_key, 0, sizeof(private_key));
    /* The device generates I_i/SEED_i (multi-key: the device generates a new
     * key on-chip as needed; I is no longer host-provided). sec_keygen_key
     * does: generate → derive K_WRAP_i/K_STATE_i → load SEED_i → wrap. */
    private_key.lms_type = uart_get_u32();
    private_key.lmots_type = uart_get_u32();

    total_start = MMIO32(SOC_CYCLE_COUNT); /* End-to-end start point */
    verify_client.last_hw_error = 0u;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    status = sec_keygen_key(private_key.I);
    if (status == SEC_OK) {
        status = sec_lms_keygen_impl(&private_key, public_key);
    }
    hardware_hits += (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before +
                         verify_client.hardware_hash_once_cycles - hash_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    *public_key_length = (status == LMS_OK) ? LMS_PUBLIC_KEY_LEN : 0u;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

/* SEC_LMS_KEYGEN_NEW (0x68) UART wrapper: multi-key rotation — generates and
 * activates **one new key**. Request: I(16) || lms_type(4) || lmots_type(4).
 * (Test scope: I = host-provided new-key vector I; SEED preloaded by the host
 * into slot 0 via 0x63. Deploy scope (0.1.281 model B): sec_keygen_new
 * generates a fresh SEED+I on-device via TRNG (controlled load into slot 0);
 * the I argument is ignored and private_key.I is back-filled with the
 * generated value.)
 * Response: frame [2]=rc; [4..7]=hw (keygen+hash_once); [20..23]=total;
 * public key (56B) follows. */
static uint32_t sec_lms_keygen_new_from_uart(uint8_t public_key[LMS_PUBLIC_KEY_LEN],
                                             uint32_t *public_key_length,
                                             uint32_t *cycles,
                                             uint32_t *total_cycles)
{
    lms_private_key_t private_key;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    uint32_t total_start;
    int status;

    memset(&private_key, 0, sizeof(private_key));
    uart_read_bytes(private_key.I, LMS_I_LEN);   /* I = host-provided (external test input; rejected in deploy) */
    private_key.lms_type = uart_get_u32();
    private_key.lmots_type = uart_get_u32();

    total_start = MMIO32(SOC_CYCLE_COUNT); /* End-to-end start point */
    verify_client.last_hw_error = 0u;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    status = sec_keygen_new(private_key.I);
    if (status == SEC_OK) {
        status = sec_lms_keygen_impl(&private_key, public_key);
    }
    hardware_hits += (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before +
                         verify_client.hardware_hash_once_cycles - hash_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    *public_key_length = (status == LMS_OK) ? LMS_PUBLIC_KEY_LEN : 0u;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}
#endif /* !LMS_FW_NO_HW_ACCEL (secure LMS trio) */

static void serve_uart(void)
{
    uint32_t cycles;
    uint32_t total_cycles;
    uint32_t steady_total_cycles;
    uint32_t parse_cycles;
    uint32_t sign_cycles;
    uint32_t index;
    uint32_t status;
    uint32_t error;
    uint32_t input_length;
    uint32_t request;
    uint32_t return_digest;
    uint32_t response_value;
    uint32_t signature_length;
    uint32_t public_key_length;
    uint8_t keygen_public_key[LMS_PUBLIC_KEY_LEN];
    uint8_t lmots_public_key[LMS_N];
    /* s_uart_sig uses file-scope shared static s_uart_sig (0.1.271 stack
     * hardening G-C1). */
    uint8_t nvm_response[48];
    uint8_t trng_read_bytes[64];
    uint32_t trng_read_len = 0u;

    for (;;) {
        request = uart_getc();
        return_digest = 1u;
        response_value = 0u;
        signature_length = 0u;
        public_key_length = 0u;
        cycles = 0u; /* Each command branch overwrites explicitly; cycle-less commands such as NVM/secure-domain keep 0 */
        total_cycles = 0u;
        steady_total_cycles = 0u;
        parse_cycles = 0u;
        sign_cycles = 0u;
        if (request == 0x7fu) {
            /* DEBUG 2026-08-25: read back the LMS_INPUT window (128B) and
             * send it over UART to diagnose 50MHz input corruption */
            for (index = 0; index < 128u; index++) {
                uint32_t w = MMIO32(LMS_INPUT + (index & ~3u));
                uart_putc((uint8_t)(w >> ((index & 3u) * 8u)));
            }
            continue;
        }
        if (request == 0x7eu) {
            /* DEBUG 2026-08-25: read back the LMS_OUTPUT window (48B) and
             * send it over UART to diagnose digest output capture. Note: must
             * be called immediately after HASH_ONCE; LMS_OUTPUT still holds
             * the digest last written by the engine. */
            for (index = 0; index < 48u; index++) {
                uint32_t w = MMIO32(LMS_OUTPUT + (index & ~3u));
                uart_putc((uint8_t)(w >> ((index & 3u) * 8u)));
            }
            continue;
        }
        if (request == UART_REQUEST_HASH) {
            input_length = uart_getc();
            status = hash_once_from_uart(input_length, &cycles);
            error = input_length > 128u ? 3u : MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_DERIVE_RANDOMIZER) {
            /* TVLA single-PRF isolation (0x6D): exactly one DERIVE_RANDOMIZER,
             * no SEED load. SEED must be preloaded to the hardware slot via
             * 0x63 first. Response return_digest reads back C. */
            status = derive_randomizer_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_PRF_CHAIN) {
            /* Multi-PRF chain (0x6E, 2026-08-21): M consecutive software PRFs,
             * trigger at the head. SEED must be preloaded to s_seed_slot via
             * 0x63 first. Response return_digest reads back the last C. */
            status = prf_chain_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_DERIVE_XQ) {
            /* TVLA isolated single x_q[i] (0x6F, 2026-08-25): exactly one
             * DERIVE_CHAIN (steps=0), no SEED load. SEED must be preloaded to
             * the hardware slot via 0x63; requires ALLOW_XQ_DERIVE=1 build.
             * **x_q[i] is never read back** (private-key element) →
             * return_digest=0 + response_value=0; verification uses an
             * independent oracle. */
            status = derive_xq_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
            return_digest = 0u;
            response_value = 0u;
        } else if (request == UART_REQUEST_CHAIN) {
            status = chain_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_VERIFY) {
            status = verify_from_uart(&cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_SIGN_TEST) {
            status = sign_from_uart(s_uart_sig, &signature_length,
                                    &response_value, &cycles, &total_cycles,
                                    &steady_total_cycles, &parse_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_KEYGEN_TEST) {
            status = keygen_from_uart(keygen_public_key, &public_key_length, &cycles,
                                      &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_LMOTS_KEYGEN_TEST) {
            status = lmots_keygen_from_uart(lmots_public_key, &cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
            status = lmots_sign_from_uart(s_uart_sig, &cycles, &total_cycles,
                                          &parse_cycles, &sign_cycles,
                                          &steady_total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_LMOTS_VERIFY_TEST) {
            status = lmots_verify_from_uart(&cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEED_LOAD_TEST) {
            status = seed_load_from_uart(&cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_C_LOAD) {
            status = c_load_from_uart(&error);
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEC_SIGN) {
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP)) { continue; }
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            sec_sign_from_uart(nvm_response, s_uart_sig, &signature_length,
                               &cycles, &total_cycles);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
#if !LMS_FW_NO_HW_ACCEL
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP) ||
                sec_key_ready() == 0u) { continue; }
            status = sec_lms_sign_from_uart(s_uart_sig, &signature_length,
                                            &response_value, &cycles, &total_cycles,
                                            &steady_total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
            /* On failure: y is not output; clear the bridge-passthrough flag
             * (the serve_uart 0x66 output branch consumes it only on
             * success). */
            if (status != LMS_STATUS_DONE || error != 0u) {
                sign_y_in_taskram = 0u;
            }
#else
            continue;
#endif
        } else if (request == UART_REQUEST_SEC_LMS_KEYGEN) {
#if !LMS_FW_NO_HW_ACCEL
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP) ||
                sec_key_ready() == 0u) { continue; }
            status = sec_lms_keygen_from_uart(keygen_public_key, &public_key_length,
                                              &cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
#else
            continue;
#endif
        } else if (request == UART_REQUEST_SEC_LMS_KEYGEN_NEW) {
#if !LMS_FW_NO_HW_ACCEL
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP) ||
                sec_key_ready() == 0u) { continue; }
            status = sec_lms_keygen_new_from_uart(keygen_public_key, &public_key_length,
                                                  &cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
#else
            continue;
#endif
        } else if (request == UART_REQUEST_NVM_SYNC) {
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP)) { continue; }
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            nvm_sync_from_uart(nvm_response);
            status = LMS_STATUS_DONE;
            error = 0u;
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEC_STATE) {
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP)) { continue; }
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            sec_state_from_uart(nvm_response);
            status = LMS_STATUS_DONE;
            error = 0u;
            return_digest = 0u;
        } else if (request == UART_REQUEST_TRNG_READ) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            trng_read_len = trng_read_from_uart(nvm_response, trng_read_bytes, 0u);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_TRNG_READ_ACK) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            trng_read_len = trng_read_from_uart(nvm_response, trng_read_bytes, 1u);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_TRNG_STATUS) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            trng_status_from_uart(nvm_response);
            status = LMS_STATUS_DONE;
            error = 0u;
            return_digest = 0u;
        } else if (request == UART_REQUEST_FLASH_PROBE) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            flash_probe_from_uart(nvm_response);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_FLASH_PROG) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            flash_prog_from_uart(nvm_response);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_FLASH_CMD) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            flash_cmd_from_uart(nvm_response);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else {
            continue;
        }

        uart_putc(UART_RESPONSE);
        uart_putc(status == LMS_STATUS_DONE && error == 0u ? 0u : 1u);
        uart_putc((uint8_t)error);
        uart_putc(0u);
        uart_put_u32(cycles);
        uart_put_u32(hardware_hits);
        uart_put_u32(0u);
        for (index = 0; index < 32u; index += 4u) {
            uint32_t word;
            if (return_digest && error == 0u) {
#if LMS_FW_NO_HW_ACCEL
                if (request == UART_REQUEST_DERIVE_RANDOMIZER ||
                    request == UART_REQUEST_PRF_CHAIN) {
                    /* Pure-software baseline: 0x6D/0x6E's C is computed in
                     * software and stored in s_uart_msg (no hardware
                     * LMS_OUTPUT write-back; reading the MMIO window returns a
                     * stale value — for 0x6E the stale value is the trigger
                     * HASH_ONCE (32B all-zero) output). The response-frame
                     * digest region is taken from s_uart_msg instead
                     * (2026-08-21 fix; same for 0x6D). */
                    word = (uint32_t)s_uart_msg[index] |
                           ((uint32_t)s_uart_msg[index + 1u] << 8) |
                           ((uint32_t)s_uart_msg[index + 2u] << 16) |
                           ((uint32_t)s_uart_msg[index + 3u] << 24);
                } else
#endif
                {
                    word = MMIO32(LMS_OUTPUT + index);
                }
            } else if (request == UART_REQUEST_NVM_SYNC ||
                       request == UART_REQUEST_SEC_STATE ||
                       request == UART_REQUEST_SEC_SIGN ||
                       request == UART_REQUEST_TRNG_READ ||
                       request == UART_REQUEST_TRNG_READ_ACK ||
                       request == UART_REQUEST_TRNG_STATUS ||
                       request == UART_REQUEST_FLASH_PROBE ||
                       request == UART_REQUEST_FLASH_PROG ||
                       request == UART_REQUEST_FLASH_CMD) {
                word = (uint32_t)nvm_response[index] |
                       ((uint32_t)nvm_response[index + 1u] << 8) |
                       ((uint32_t)nvm_response[index + 2u] << 16) |
                       ((uint32_t)nvm_response[index + 3u] << 24);
            } else if (index == 0u) {
                word = response_value;
            } else if (index == 4u) {
                word = total_cycles;
            } else if (index == 8u) {
                if (request == UART_REQUEST_SIGN_TEST ||
                    request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = steady_total_cycles;
                } else if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
                    word = parse_cycles;
                } else {
                    word = 0u;
                }
            } else if (index == 12u) {
                if (request == UART_REQUEST_SIGN_TEST) {
                    word = parse_cycles;
                } else if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
                    word = sign_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
#if defined(LMS_MMIO_SOC_PROFILE)
                    word = sec_prof_stc_cycles;
#else
                    word = 0u;
#endif
                } else {
                    word = 0u;
                }
            } else if (index == 16u) {
                /* Frame [32..35]: LM-OTS Sign's steady_total (steady single
                 * signature after seed_load, same baseline as LMS Sign steady,
                 * comparable). For 0x66 = secure enable segment (PROFILE). */
                if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
                    word = steady_total_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
#if defined(LMS_MMIO_SOC_PROFILE)
                    word = prof_sec_enable_cycles;
#else
                    word = 0u;
#endif
                } else {
                    word = 0u;
                }
            } else if (index == 20u) {
#if defined(LMS_MMIO_SOC_PROFILE)
                if (request == UART_REQUEST_LMOTS_SIGN_TEST ||
                    request == UART_REQUEST_LMOTS_VERIFY_TEST) {
                    word = verify_client.prof_write_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = prof_sec_sign_cycles;
                } else {
                    word = 0u;
                }
#else
                word = 0u;
#endif
            } else if (index == 24u) {
#if defined(LMS_MMIO_SOC_PROFILE)
                if (request == UART_REQUEST_LMOTS_SIGN_TEST ||
                    request == UART_REQUEST_LMOTS_VERIFY_TEST) {
                    word = verify_client.prof_wait_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = prof_sec_tail_cycles;
                } else {
                    word = 0u;
                }
#else
                word = 0u;
#endif
            } else if (index == 28u) {
#if defined(LMS_MMIO_SOC_PROFILE)
                if (request == UART_REQUEST_LMOTS_SIGN_TEST ||
                    request == UART_REQUEST_LMOTS_VERIFY_TEST) {
                    word = verify_client.prof_read_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = sec_prof_enc_cycles;
                } else {
                    word = 0u;
                }
#else
                word = 0u;
#endif
            } else {
                word = 0u;
            }
            uart_put_u32(word);
        }
        if (request == UART_REQUEST_SEC_SIGN && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < signature_length; index++) {
                uart_putc(s_uart_sig[index]);
            }
        }
        if (request == UART_REQUEST_TRNG_READ && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < trng_read_len; index++) {
                uart_putc(trng_read_bytes[index]);
            }
        }
        /* TRNG_READ_ACK: append 1B CRC8 after the random words (over the
         * count*4B data, CRC-8/SMBUS). */
        if (request == UART_REQUEST_TRNG_READ_ACK && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < trng_read_len; index++) {
                uart_putc(trng_read_bytes[index]);
            }
            uart_putc(crc8_block(trng_read_bytes, trng_read_len));
        }
        if (request == UART_REQUEST_SIGN_TEST && status == LMS_STATUS_DONE && error == 0u) {
#if LMS_FW_NO_HW_ACCEL
            /* Pure-software baseline: the full signature buffer
             * (q|type|C|y|lms_type|path) is sent by software (no bridge
             * passthrough). */
            for (index = 0; index < signature_length; index++) {
                uart_putc(s_uart_sig[index]);
            }
#else
            if (sign_y_in_taskram) {
                /* Step 3 bridge mode (hardware available): q+type+C (40B) sent
                 * by software; y (length varies with w) read out by the UART
                 * bridge passthrough from task RAM; lms_type+auth path sent by
                 * software. Signature frame order unchanged. */
                for (index = 0; index < 40u && index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
                (void)bridge_run(BRIDGE_DIR_TX, BRIDGE_Y_ADDR, sign_y_len);
                for (index = 40u + sign_y_len; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            } else {
                /* Hardware unavailable (w∉{1,2,4,8}) / pure software: the
                 * full signature buffer (q|type|C|y|lms_type|path) is sent by
                 * software. */
                for (index = 0; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            }
            sign_y_in_taskram = 0u;
#endif
        }
        /* 0x66 secure LMS Sign: σ_q is in the buffer (sec_sign output).
         * q+type+C sent by software; y (length varies with w) read out by the
         * UART bridge passthrough from task RAM; lms_type+auth path sent by
         * software (0.1.245 bridge passthrough, same scope as 0x53). On
         * failure no signature is output (flag already cleared in the
         * branch). */
        if (request == UART_REQUEST_SEC_LMS_SIGN && status == LMS_STATUS_DONE && error == 0u) {
            if (sign_y_in_taskram) {
                for (index = 0; index < 40u && index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
                (void)bridge_run(BRIDGE_DIR_TX, BRIDGE_Y_ADDR, sign_y_len);
                for (index = 40u + sign_y_len; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            } else {
                for (index = 0; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            }
            sign_y_in_taskram = 0u;
        }
        /* 0x67 secure LMS KeyGen: public key sent by software. */
        if (request == UART_REQUEST_SEC_LMS_KEYGEN && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < public_key_length; index++) {
                uart_putc(keygen_public_key[index]);
            }
        }
        /* 0x68 secure LMS KeyGen_NEW (multi-key rotation): public key sent by
         * software. */
        if (request == UART_REQUEST_SEC_LMS_KEYGEN_NEW && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < public_key_length; index++) {
                uart_putc(keygen_public_key[index]);
            }
        }
        if (request == UART_REQUEST_KEYGEN_TEST && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < public_key_length; index++) {
                uart_putc(keygen_public_key[index]);
            }
        }
        if (request == UART_REQUEST_LMOTS_KEYGEN_TEST && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < LMS_N; index++) {
                uart_putc(lmots_public_key[index]);
            }
        }
        if (request == UART_REQUEST_LMOTS_SIGN_TEST && status == LMS_STATUS_DONE && error == 0u) {
#if LMS_FW_NO_HW_ACCEL
            /* Pure-software baseline: the full signature type+C+y is sent by
             * software (no bridge passthrough). */
            for (index = 0; index < lmots_out_sig_len; index++) {
                uart_putc(s_uart_sig[index]);
            }
#else
            if (sign_y_in_taskram) {
                /* Step 3 bridge mode (hardware available): type+C (36B) sent
                 * by software; y (length varies with w) read out via the UART
                 * bridge passthrough */
                for (index = 0; index < lmots_out_sig_len - sign_y_len; index++) {
                    uart_putc(s_uart_sig[index]);
                }
                (void)bridge_run(BRIDGE_DIR_TX, BRIDGE_Y_ADDR, sign_y_len);
            } else {
                /* Hardware unavailable (w∉{1,2,4,8}) / pure software: the
                 * full signature type+C+y is sent by software. */
                for (index = 0; index < lmots_out_sig_len; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            }
            sign_y_in_taskram = 0u;
#endif
        }
    }
}

static void fail(uint32_t code)
{
    MMIO32(GPIO_OUT) = code;
    for (;;) {
    }
}

int main(void)
{
#if defined(FW_HASH_SHA256)
    static const uint32_t expected[8] = {
        0xbf1678bau, 0xeacf018fu, 0xde404141u, 0x2322ae5du,
        0xa36103b0u, 0x9c7a1796u, 0x61ff10b4u, 0xad1500f2u
    };
    static const uint32_t expected_cycles = 68u;
#else
    static const uint32_t expected[8] = {
        0x60663348u, 0x77a86013u, 0x0863681cu, 0x4d11c40cu,
        0x3045b48du, 0xeee1f1f8u, 0x37ea944fu, 0x39578be7u
    };
    static const uint32_t expected_cycles = 12u;
#endif
    uint32_t poll;
    uint32_t index;
#if !LMS_FW_NO_HW_ACCEL
    lms_mmio_bus_t verify_bus;
#endif

    MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
    MMIO32(LMS_INPUT_LENGTH) = 3u;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    MMIO32(LMS_INPUT) = 0x00636261u;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;

    for (poll = 0; poll < 1024u; poll++) {
        if ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) == 0u) {
            break;
        }
    }
    if (poll == 1024u) {
        fail(0xe1u);
    }
    if (MMIO32(LMS_STATUS) != LMS_STATUS_DONE || MMIO32(LMS_ERROR) != 0u) {
        fail(0xe2u);
    }
    if (MMIO32(LMS_CYCLE_COUNT) != expected_cycles) {
        fail(0xe3u);
    }
#if defined(FW_HASH_SHA256)
    for (index = 0; index < 8u; index++) {
        if (MMIO32(LMS_OUTPUT + index * 4u) != expected[index]) {
            fail(0xe4u + index);
        }
    }
#else
    (void)index;
    (void)expected;
#endif

    hardware_hits = 1u;

    /* Reset clears the NVM volatile state: .bss was already zeroed by the
     * startup code (lms_soc_start.S); the explicit initialization here is
     * only semantic self-documentation (REVIEW B05B06-R13). */
    for (index = 0u; index < NVM_STATE_LEN; index++) {
        nvm_state[index] = 0u;
    }
    for (index = 0u; index < NVM_STATE_LEN / NVM_CHUNK_LEN; index++) {
        nvm_crc[index] = 0u;
        nvm_valid[index] = 0u;
    }

#if !LMS_FW_NO_HW_ACCEL
    lms_mmio_bus_init_direct(&verify_bus, (volatile void *)(uintptr_t)LMS_BASE);
    if (lms_mmio_client_init(&verify_client, &verify_bus, 100000u, 0) != LMS_MMIO_OK ||
        lms_mmio_lmots_keygen_enable_insecure(&verify_client) != LMS_MMIO_OK ||
        lms_mmio_lmots_verify_enable(&verify_client) != LMS_MMIO_OK ||
        lms_mmio_lmots_sign_enable_insecure(&verify_client) != LMS_MMIO_OK) {
        fail(0xecu);
    }
    /* Randomizer C source (TRNG-C scheme, finalized 2026-08-22): configured
     * by INSECURE_TEST_MODE.
     *   - Debug (LMS_FW_SEC_TEST_MODE defined): default randomizer_c_slot=NULL
     *     → the backend falls back to the hardware deterministic
     *     DERIVE_RANDOMIZER (existing KAT golden values unchanged, migration
     *     period). Once C_LOAD(0x6C) loads a fixed test vector,
     *     c_load_from_uart sets verify_client.randomizer_c_slot=s_c_slot →
     *     the backend switches to the C slot (deterministic signatures,
     *     reproducible TVLA/fixed-vector KAT, and the fixed C introduces no
     *     between-group variance). */
    verify_client.randomizer_c_slot = NULL;
    verify_client.trng_fill_c = NULL;
    verify_client.trng_context = NULL;
#ifdef LMS_FW_SEC_TEST_MODE
    /* Debug: see above; the C source is switched on the fly by C_LOAD */
#else
    /* Deploy: C can only come from the secure-domain TRNG (fw_trng_fill_c,
     * health-gated fail-closed); C_LOAD is hard-rejected
     * (ERR_INSECURE_DISABLED), no external C injection path. */
    verify_client.trng_fill_c = fw_trng_fill_c;
#endif
    /* Global D_INTR backend: all lms_internal_node calls go through HASH_ONCE
     * (full KeyGen/Sign/Verify coverage) */
    lms_intr_backend_set(hw_intr_backend, &verify_client);
    /* VERIFY_LEAF backend: one MMIO yields the leaf (chain verify→K_q→D_LEAF),
     * uniform across SHA256/SHAKE256 */
    lmots_verify_leaf_backend_set(hw_verify_leaf, &verify_client);
    /* Verify auth-path chained D_INTR primitive (CMD_D_INTR_CHAIN): one MMIO
     * completes the auth path (VERIFY_LEAF handles OTS→leaf; this backend
     * handles the LMS tree hash; root comparison in software). Both platforms
     * implement it since S6; on failure automatically falls back to
     * per-level HASH_ONCE. */
    lms_verify_authpath_backend_set(hw_dintr_authpath, &verify_client);
    /* Message-hash backend: short messages (≤74B) use HASH_ONCE; long
     * messages fall back to software SHA-256 */
    lmots_message_hash_backend_set(hw_message_hash_backend, &verify_client);
    /* coef backend: CMD_MSG_Q_COEF yields Q+checksum+coefficients at once
     * (superset includes the message hash, P1 single block L≤128); on
     * failure/over-limit falls back to hw_message_hash_backend + software
     * coef. */
    lmots_coef_backend_set(hw_coef_backend, &verify_client);

    /* Load the prototype SEED (INSECURE staging) so existing LMOTS/KAT use
     * cases do not depend on FACTORY_INIT/BOOT; in phase 3, the secure
     * domain's K_WRAP/K_STATE are loaded via FACTORY_INIT (FE_GEN/KDF) and
     * BOOT (FE_REP/KDF) instead, no longer preset here. P1-6 (0.1.274): deploy
     * builds skip this preset — SEED is only restored via BOOT wrapped→UNWRAP
     * (plaintext never lands), and 0x63 loads are rejected by the RTL gate. */
#if defined(LMS_FW_SEC_TEST_MODE)
    {
        uint8_t seed[LMS_SEED_LEN];
        for (index = 0u; index < LMS_SEED_LEN; index++) {
            seed[index] = (uint8_t)index;
        }
        if (fw_seed_load(seed) != LMS_MMIO_OK) {
            fail(0xedu);
        }
    }
#endif
#endif /* !LMS_FW_NO_HW_ACCEL */

    /* Random source (implementation A) bound to a fixed prototype context:
     * the determinism of FACTORY_INIT's device_epoch and BOOT rebuild is
     * guaranteed by this binding (under implementation C/TRNG there is no
     * seed concept; skipped). */
#ifndef LMS_RND_IMPL_TRNG
    {
        uint8_t rnd_ctx[16];
        for (index = 0u; index < sizeof(rnd_ctx); index++) {
            rnd_ctx[index] = (uint8_t)(0x70u + index);
        }
        lms_rnd_det_seed(rnd_ctx, sizeof(rnd_ctx));
    }
#endif
    if (verify_client.capabilities & LMS_MMIO_CAP_WRAP) {
        sec_init(&verify_client);
    }

    MMIO32(GPIO_OUT) = 0xa5u;
    serve_uart();
}
