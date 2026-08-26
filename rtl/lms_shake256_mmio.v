`default_nettype none

// SHAKE256 LMS MMIO wrapper (single-core single-chain primitive, SHAKE256 hardware step 2).
//
// State prefix convention (REVIEW X-04): the engine-layer single-chain state machine uses
// ST_* (ST_IDLE/ST_DONE/ST_WAIT_CORE/ST_MODE/ST_ABSORB, from the lms_hash_engine skeleton);
// this wrapper's batch-task FSM uses STATE_* (STATE_TASK_*/STATE_DUAL_*/STATE_PBLC_* etc.) --
// the two layers each have their own scheme; do not mix prefixes.
//
// Register layout aligned with rtl/lms_sha256_mmio.v (VERSION/CAPABILITY identify SHAKE256).
// This round implements single-chain primitives (batch tasks / KEYGEN_LEAF / top-level
// thin-shell selector later):
//   CMD_HASH_ONCE          message hash (<=128B, INPUT area; single block this round)
//   CMD_SEED_LOAD          INSECURE_TEST_MODE gated SEED load (sets seed_valid)
//   CMD_CHAIN              chain: v_{j+1} = SHAKE256(I||q||i||j||v_j), start+steps steps
//   CMD_DERIVE_CHAIN       x_q[i] = SHAKE256(I||q||i||0xff||SEED) followed by chain
//   CMD_DERIVE_RANDOMIZER  C = SHAKE256(I||q||0x8585||SEED)
//
// LM-OTS semantics (aligned with src/lm_ots.c + src/lms_internal.h):
//   x_q[i] = H(I||u32(q)||u16(i)||0xff||SEED)  55B
//   C      = H(I||u32(q)||u16(0x8585)||SEED)   54B
//   chain step = H(I||u32(q)||u16(i)||j||value) 55B
// Each step is an independent complete SHAKE256 (absorb 1 rate block + permute + squeeze
// 32B); the core takes 12 cycles per block (unroll-2), no state continuation (unlike
// SHA-256 Merkle-Damgård).
// rate block padding: data || 0x1F || 0x00... || 0x80 (0x80 fixed at byte 135).
//
// Byte convention (all big-endian): register word byte0 is in [31:24]; rate block byte i is
// in rate_block_w[i*8 +: 8]; byte k of chain_value/seed is in [255-k*8 +: 8].
// Result is written to the OUTPUT area (0x200, 8 words); cycle_count accumulates core
// permute cycles (12/block; REVIEW B09B10-R2: system-level batch task ~15 cycles/block
// including scheduling, so the count is not wall-clock).

(* keep_hierarchy = "yes" *)
module lms_shake256_mmio #(
    parameter [31:0] SHAKE_BASE = 32'h1600_0000,
    parameter INSECURE_TEST_MODE = 0,
    parameter HAS_SECURITY = 1,    /* 1=compile security domain (SEC: MC/WRAP/HMAC/key slots, borrows core); 0=pure algorithm hardware (saves area, SEED stored locally) */
    parameter RANDOM_DELAY = 0     /* TVLA lightweight mitigation (option B-RTL, 2026-08-19): insert LFSR random cycle delay (0..1023) before 0x6D DERIVE,
                                    * breaking per-PRF phase alignment to the trigger edge -> diluted per-point t. Enabled only in TVLA builds
                                    * (SCA_TEST=1); off (0) in normal builds */
    ,parameter DERIVE_SHUFFLE = 0  /* DERIVE phase shuffle (tier 1, 2026-08-21): batch-task block parameter i gets a per-trace random
                                    * start offset i_act = (i + b) mod p (b latched per trace from the free-running LFSR, [1,p-1]).
                                    * DERIVE and CHAIN phases share the same i_act (chain starts from x_q[i_act]); chain result is
                                    * written back to slot i_act -> slot k holds exactly y_k -> output read order unchanged (zero
                                    * external change). verify has no DERIVE phase, keeps order. Zero performance cost (1-level
                                    * combinational add + 2 conditional subtracts, ~30 LUT). Only TVLA builds (SCA_TEST=1) enable it;
                                    * off (0) in normal builds */
    ,parameter ALLOW_XQ_DERIVE = 0 /* TVLA isolates a single x_q[i] (side-channel SEED leak characterization): only this build
                                    * allows DERIVE_CHAIN steps=0. deploy (default 0) keeps M3 */
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        bus_valid,
    input  wire        bus_write,
    input  wire [31:0] bus_addr,
    input  wire [31:0] bus_wdata,
    output reg  [31:0] bus_rdata,
    output wire        mem_hit,
    /* Task RAM stream port (Step 2, in front of UART bridge; usable when core idle !stream_busy).
     * Mutually exclusive mux with the MMIO task RAM port (stream port has priority), for the
     * SoC-layer UART pass-through bridge. Write: stream_wr_en single-cycle write of 1 word;
     * read: stream_rd_en single-cycle request, next cycle stream_rd_valid/stream_rd_data valid
     * (synchronous read, same as task RAM). */
    input  wire        stream_wr_en,
    input  wire [11:0] stream_wr_addr,
    input  wire [31:0] stream_wr_data,
    input  wire        stream_rd_en,
    input  wire [11:0] stream_rd_addr,
    output wire        stream_rd_valid,
    output wire [31:0] stream_rd_data,
    output wire        stream_busy
);
    /* Register/error-code sections retained for alignment with the SHA-256 wrapper are unused;
     * lint is turned off for harmless items. */
    /* verilator lint_off WIDTHTRUNC */
    /* verilator lint_off WIDTHEXPAND */
    /* verilator lint_off UNUSEDPARAM */
    /* verilator lint_off UNUSEDSIGNAL */
    localparam [31:0] VERSION = 32'h00000001;
    /* bit0=SHAKE256 support; bit1=HASH_ONCE; bit2=CHAIN; bit3=DERIVE_CHAIN;
     * bit5=LMOTS_KEYGEN; bit6=LMOTS_SIGN; bit7=LMOTS_VERIFY;
     * bit8=INSECURE_TEST_MODE gated SEED load; bit11=KEYGEN_LEAF.
     * Bit order aligned with the LMS_MMIO_CAP_* definitions in lms_mmio.h. */
    localparam [31:0] CAPABILITY =
        32'h00000001 |                                  /* bit0:  SHAKE256 */
        32'h00000002 |                                  /* bit1:  HASH_ONCE */
        32'h00000004 |                                  /* bit2:  CHAIN */
        32'h00000008 |                                  /* bit3:  DERIVE_CHAIN */
        32'h00000010 |                                  /* bit4:  INSECURE_TEST_MODE (always advertised) */
        32'h00000020 |                                  /* bit5:  LMOTS_KEYGEN */
        32'h00000040 |                                  /* bit6:  LMOTS_SIGN */
        32'h00000080 |                                  /* bit7:  LMOTS_VERIFY */
        (HAS_SECURITY ? 32'h00000100 : 32'h00000000) | /* bit8:  SIM_MC (security-domain monotonic counter, HAS_SECURITY only) */
        (HAS_SECURITY ? 32'h00000200 : 32'h00000000) | /* bit9:  WRAP (security-domain wrap/unwrap, HAS_SECURITY only) */
        (HAS_SECURITY ? 32'h00000400 : 32'h00000000) | /* bit10: HMAC_KSTATE (security-domain HMAC, HAS_SECURITY only) */
        32'h00000800 |                                  /* bit11: LMOTS_KEYGEN_LEAF */
        32'h00001000 |                                  /* bit12: SHAKE256 marker (distinguishes from SHA-256) */
        32'h00002000 |                                  /* bit13: D_INTR_CHAIN (chained D_INTR primitive) */
        32'h00004000 |                                  /* bit14: MSG_Q_COEF (message hash -> Q -> checksum -> coefficients) */
        (HAS_SECURITY ? 32'h00008000 : 32'h00000000);   /* bit15: STATE_COMMIT (fused command; aligned with CAP_STATE_COMMIT in lms_mmio.h) */

    localparam [9:0] REG_VERSION       = 10'h000;
    localparam [9:0] REG_CAPABILITY    = 10'h004;
    localparam [9:0] REG_COMMAND       = 10'h008;
    localparam [9:0] REG_CONTROL       = 10'h00c;
    localparam [9:0] REG_STATUS        = 10'h010;
    localparam [9:0] REG_ERROR         = 10'h014;
    localparam [9:0] REG_INPUT_LENGTH  = 10'h018;
    localparam [9:0] REG_OUTPUT_LENGTH = 10'h01c;
    localparam [9:0] REG_CYCLE_COUNT   = 10'h020;
    localparam [9:0] REG_ARG_Q         = 10'h024;
    localparam [9:0] REG_ARG_I         = 10'h028;
    localparam [9:0] REG_ARG_START     = 10'h02c;
    localparam [9:0] REG_ARG_STEPS     = 10'h030;
    localparam [9:0] REG_ARG_KEY       = 10'h034;
    localparam [9:0] REG_IDENTIFIER    = 10'h040;  /* 16B */
    localparam [9:0] REG_SIM_MC        = 10'h060;  /* security-domain monotonic counter (SEC slot, step 2) */
    localparam [9:0] REG_SEED_BASE     = 10'h080;  /* 32B */
    localparam [9:0] REG_WRAPPED_BASE  = 10'h0a0;  /* 48B (SEC slot, wrap output) */
    localparam [9:0] REG_KWRAP_BASE    = 10'h0e0;  /* 32B (SEC slot, K_WRAP/K_STATE) */
    localparam [9:0] REG_INPUT_BASE    = 10'h100;  /* 32 words = 128B */
    localparam [9:0] REG_OUTPUT_BASE   = 10'h200;  /* 8 words = 32B */

    localparam [31:0] CMD_HASH_ONCE = 32'h00000001;
    localparam [31:0] CMD_CHAIN = 32'h00000002;
    localparam [31:0] CMD_SEED_LOAD = 32'h00000003;
    localparam [31:0] CMD_DERIVE_CHAIN = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER = 32'h00000005;
    localparam [31:0] CMD_LMOTS_KEYGEN = 32'h00000006;
    localparam [31:0] CMD_LMOTS_SIGN = 32'h00000007;
    localparam [31:0] CMD_LMOTS_VERIFY = 32'h00000008;
    localparam [31:0] CMD_LMOTS_KEYGEN_LEAF = 32'h0000000e;
    localparam [31:0] CMD_LMOTS_VERIFY_LEAF = 32'h0000000f;
    localparam [31:0] CMD_MC_STEP       = 32'h00000010;
    localparam [31:0] CMD_MC_LOAD       = 32'h00000011;
    localparam [31:0] CMD_WRAP_SEED     = 32'h00000012;
    localparam [31:0] CMD_UNWRAP_SEED   = 32'h00000013;
    localparam [31:0] CMD_HMAC_KSTATE   = 32'h00000014;
    localparam [31:0] CMD_STATE_COMMIT  = 32'h00000015;  /* mc_step+HMAC fused (SEC state commit) */
    localparam [31:0] CMD_D_INTR_CHAIN = 32'h00000018;
    localparam [31:0] CMD_HASH_ONCE_RAM = 32'h00000019;
    localparam [31:0] CMD_MSG_Q_COEF = 32'h0000001a;   /* message hash -> Q -> checksum -> coefficients (P1 single block) */
    localparam [31:0] CTRL_START = 32'h00000001;
    localparam [31:0] CTRL_CLEAR = 32'h00000002;

    /* Batch-task state constants (aligned with lms_sha256_mmio; single core: no DUAL_*) */
    localparam [3:0] STATE_IDLE          = 4'd0;
    localparam [3:0] STATE_START_CORE    = 4'd1;
    localparam [3:0] STATE_WAIT_CORE     = 4'd2;
    localparam [3:0] STATE_TASK_WRITE    = 4'd3;
    localparam [3:0] STATE_TASK_LOAD     = 4'd4;
    localparam [3:0] STATE_TASK_PREFETCH = 4'd6;
    localparam [3:0] STATE_DUAL_SETUP1   = 4'd8;
    localparam [3:0] STATE_DUAL_WAIT     = 4'd9;
    localparam [3:0] STATE_PBLC_FINAL    = 4'd10;
    /* Chained D_INTR primitive states (CMD_D_INTR_CHAIN, Verify authentication path batching) */
    localparam [3:0] STATE_DINTR_PREFETCH    = 4'd11;
    localparam [3:0] STATE_DINTR_LOAD_START  = 4'd12;
    localparam [3:0] STATE_DINTR_LOAD_SIB    = 4'd13;
    localparam [3:0] STATE_DINTR_CORE        = 4'd14;
    localparam [3:0] STATE_DINTR_KICK        = 4'd15;
    /* HASH_ONCE_RAM multi-block absorb states (level 0, task RAM input) */
    localparam [3:0] STATE_HASH_RAM_LOAD     = 4'd5;
    localparam [3:0] STATE_HASH_RAM_KICK     = 4'd7;
    /* HASH_ONCE_RAM multi-block absorb states (level 0, task RAM input);
     * P3 MQC reuses the same state machine: 54B header word 32 + message word 46 written to
     * task RAM by firmware (layout same as HASH_ONCE_RAM, block construction +2 offset),
     * after the last block finishes it enters STATE_MQC_COEF. */
    localparam [4:0] STATE_MQC_COEF          = 5'd17;
    localparam [1:0] BATCH_DERIVE = 2'd0;
    localparam [1:0] BATCH_CHAIN  = 2'd1;
    localparam [1:0] BATCH_PBLC   = 2'd2;

    localparam [9:0] REG_TASK_ADDR     = 10'h038;
    localparam [9:0] REG_TASK_DATA     = 10'h03c;
    localparam [9:0] REG_ARG_LEAF_NODE = 10'h050;
    localparam [9:0] REG_ARG_W         = 10'h054;

    /* Unified command validation (lms_hash_cmd_check) returned action classes (aligned with
     * SHA-256: includes security-domain actions) */
    localparam [3:0] ACT_START       = 4'd0;
    localparam [3:0] ACT_DONE_SEED   = 4'd1;
    localparam [3:0] ACT_DONE_CHAIN0 = 4'd2;
    localparam [3:0] ACT_DONE_KWRAP  = 4'd3;
    localparam [3:0] ACT_DONE_KSTATE = 4'd4;
    localparam [3:0] ACT_DONE_MC     = 4'd5;
    localparam [3:0] ACT_START_HMAC  = 4'd6;
    localparam [3:0] ACT_START_WRAP  = 4'd7;
    localparam [3:0] ACT_START_STC   = 4'd8;

    localparam [31:0] STATUS_BUSY  = 32'h00000001;
    localparam [31:0] STATUS_DONE  = 32'h00000002;
    localparam [31:0] STATUS_ERROR = 32'h00000004;

    localparam [31:0] ERR_UNSUPPORTED_COMMAND = 32'h00000001;
    localparam [31:0] ERR_BUSY                = 32'h00000002;
    localparam [31:0] ERR_INPUT_LENGTH        = 32'h00000003;
    localparam [31:0] ERR_CONTROL             = 32'h00000007;
    localparam [31:0] ERR_SEED_NOT_LOADED     = 32'h00000009;
    localparam [31:0] ERR_INSECURE_DISABLED   = 32'h0000000a;
    /* REVIEW X-03: compared with the 10-code table of lms_sha256_mmio, this wrapper only
     * declares the 6 codes it generates locally; ERR_OUTPUT_LENGTH(4)/ERR_CHAIN_INDEX(5)/
     * ERR_CHAIN_RANGE(6)/ERR_KEY_HANDLE(8) are validated and output by the shared
     * lms_hash_cmd_check.v (the single source of truth for the full error-code set is
     * cmd_check), so the wrapper does not redeclare them. */

    localparam [1:0] TASK_NONE  = 2'd0;
    localparam [1:0] TASK_CHAIN = 2'd1;
    localparam [1:0] TASK_DERIVE = 2'd2;
    localparam [1:0] TASK_RANDOMIZER = 2'd3;

    localparam [3:0] ST_IDLE       = 4'd0;
    localparam [3:0] ST_ABSORB     = 4'd1;  /* issue start (incl. init) */
    localparam [3:0] ST_WAIT_CORE  = 4'd2;  /* wait 12 cycles */
    localparam [3:0] ST_DONE       = 4'd3;

    reg [31:0] command_r;
    reg [31:0] input_length_r;
    reg [31:0] output_length_r;   /* unified command validation (lms_hash_cmd_check) requires == 32 */
    reg [31:0] arg_q_r;
    reg [15:0] arg_i_r;
    reg [7:0]  arg_start_r;
    reg [31:0] arg_steps_r;
    reg [31:0] identifier_words [0:3];
    /* SEED/K_WRAP/K_STATE secret slots moved into the SEC submodule (step 2); the wrapper
     * no longer holds the seed. */
    reg [31:0] input_words [0:31];
    reg [31:0] output_words [0:7];
    reg [31:0] error_r;
    reg        done_r;              /* completion latch (STATUS_DONE) */
    reg        engine_start_r;      /* engine start pulse (ACT_START) */
    /* Batch-task registers (aligned with the lms_sha256_mmio single-core subset) */
    reg [31:0] arg_key_r;
    reg [31:0] arg_leaf_node_r;
    reg [3:0]  arg_w_r;               /* Winternitz w (1/2/4/8), batch-task parameter; default 4 */
    reg [4:0]  state_r;               /* 5-bit: new MQC states 16/17 added (4-bit values 0..15 kept) */
    reg [1:0]  block_index_r;
    reg [1:0]  block_count_r;
    reg [31:0] cycle_count_r;
    reg        error_status_r;
    reg        busy_error_pending_r;
    reg        keygen_dleaf_r;
    /* ---------- Winternitz w parameters (batch tasks: chain count / coefficient width / max step / PBLc last block) ---------- */
    /* arg_w_r in {1,2,4,8} (default 4=W4 keeps zero regression); PBLc last-block parameters
     * derived from w_p: block 0 = header 22B + 114B; full block = 136B; last block data =
     * y_len - 114 - nfull*136; last block number = 1 + nfull; last block read window =
     * (last_bytes + 2)/4. */
    reg  [8:0]  w_p;               /* chain count 265/133/67/34 */
    reg  [3:0]  w_coef_bits;       /* coefficient width 1/2/4/8 */
    reg  [7:0]  w_max_step;        /* max chain step 2^w-1 = 1/3/15/255 */
    reg  [6:0]  w_pblc_last_block; /* last block number (0-based) */
    reg  [7:0]  w_pblc_last_bytes; /* last block data byte count */
    reg  [5:0]  w_pblc_last_rd;    /* last block read window words (W4=32 needs 6-bit) */
    always @* begin
        case (arg_w_r)
            4'd1: begin w_p = 9'd265; w_coef_bits = 4'd1; w_max_step = 8'd1;
                        w_pblc_last_block = 7'd62; w_pblc_last_bytes = 8'd70; w_pblc_last_rd = 6'd18; end
            4'd2: begin w_p = 9'd133; w_coef_bits = 4'd2; w_max_step = 8'd3;
                        w_pblc_last_block = 7'd31; w_pblc_last_bytes = 8'd62; w_pblc_last_rd = 6'd16; end
            4'd8: begin w_p = 9'd34;  w_coef_bits = 4'd8; w_max_step = 8'd255;
                        w_pblc_last_block = 7'd8;  w_pblc_last_bytes = 8'd22; w_pblc_last_rd = 6'd6;  end
            default: begin w_p = 9'd67; w_coef_bits = 4'd4; w_max_step = 8'd15;
                        w_pblc_last_block = 7'd15; w_pblc_last_bytes = 8'd126; w_pblc_last_rd = 6'd32; end
        endcase
    end

    /* Dual-core chain state (aligned with the lms_sha256_mmio dual core): core0 = chain batch_i,
     * core1 = chain batch_i+1 */
    reg [255:0] chain_value0_r;
    reg [255:0] chain_value1_r;
    reg [7:0]  chain_j_r;           /* blockgen core0 view (batch tasks changed to chain_j0_r) */
    reg [7:0]  chain_j0_r;
    reg [7:0]  chain_j1_r;
    reg [7:0]  chain_steps_left0_r;
    reg [7:0]  chain_steps_left1_r;
    reg [1:0]  batch_phase_r;
    reg [8:0]  batch_i_r;
    reg [2:0]  task_write_word_r;   /* single-core compatible */
    reg [2:0]  task_write_word0_r;
    reg [2:0]  task_write_word1_r;
    reg [255:0] task_digest0_r;
    reg [255:0] task_digest1_r;
    /* Dual-core gating: done latch (done single-cycle pulse). REVIEW B09B10-R7: the original
     * core0/1_run_r "run enable" was never set 1 / never read; actual behavior is carried by
     * the kick pulse + done latch, so it was removed. */
    reg        core0_done_latched_r;
    reg        core1_done_latched_r;
    reg        dual_write_sel_r;    /* Sign dual-core task RAM write select: 0=core0, 1=core1 */
    reg        verify_dual_load_r;  /* Verify dual-core task RAM load chain1 flag */
    reg [1087:0] batch_block1_r;    /* core1's block latch (derived from core0 block at DUAL_SETUP1 cycle) */
    /* Dual-core PBLc/load helper flags */
    reg        dual_core1_active_r;   /* this batch core1 participates (batch_i+1 < 67 and has steps) */
    reg        chain0_zero_r;         /* core0 chain is a 0-step chain (digest keeps chain_value0) */
    reg        chain1_zero_r;         /* core1 chain is a 0-step chain */
    reg [11:0] task_addr_r;
    reg [31:0] task_ram_read_r;
    reg        stream_read_r;
    reg        stream_rd_pending_r;  /* stream read request latch: set 1 on request cycle, next cycle stream_rd_valid */
    reg        task_prefetch_pending_r;
    (* ram_style = "block" *) reg [31:0] task_words [0:2151];   /* W1 max tier: 8p+31=2151 */
    /* Coefficient area compact packing: each word holds 32/w coefficients (W1: 32 1-bit per
     * word, W2: 16 2-bit, W4: 8 4-bit, W8: 4 8-bit). Max W1 265 coefficients = 9 words;
     * the 32-word array is roomy (words 0..31 are the MMIO coefficient area; the task RAM y
     * area starts at word 32, no conflict). */
    reg [31:0] coefficient_words [0:31];
    /* Final PBLc unified absorb (option 1 revised): after all 67 chain tails are double-written
     * to task RAM, core0 serially absorbs 16 blocks -- block 0 = header registers 22B + RAM
     * words 32..60 114B (29 words aligned); blocks 1..15 = 35-word read window + fixed 2-byte
     * lane rearrangement (pure wiring, 22==2 mod 4, 136==0 mod 4); last block (block 15)
     * reads 32 words taking 126B + SHAKE256 padding. */
    reg [6:0]    pblc_final_block_r;   /* final absorb block number (W4 0..15 / W1 0..62) */
    reg [5:0]    pblc_final_word_r;    /* read window word index (0..RD_WORDS-1; == RD_WORDS means read full) */
    reg [1119:0] pblc_final_window_r;  /* 35-word read window = 140B (block=15 fills only 32 words) */
    /* Chained D_INTR primitive (CMD_D_INTR_CHAIN): consecutive N-layer D_INTR authentication
     * path hash chain (for Verify; OTS/LMS semantics layered: VERIFY_LEAF handles OTS->leaf,
     * this primitive handles LMS tree hashing, root comparison still in software).
     * Input: task RAM words 32..39 = starting left, word 40 + layer*8 = sibling[layer] (8
     * words each); I = identifier, starting node_num = arg_leaf_node, N = arg_steps. Output
     * root to output_words. */
    reg [255:0] dintr_left_r;      /* current layer left (continuous big-endian, byte0 most significant; initially = start node) */
    reg [255:0] dintr_right_r;     /* current layer right/sibling (same as left) */
    reg [31:0]  dintr_node_r;      /* current layer node_num (>>1 per layer) */
    reg [4:0]   dintr_layer_r;     /* current layer number (0..N-1) */
    reg [3:0]   dintr_load_word_r; /* task RAM read word (0..7) */
    wire dintr_cmd_w = command_r == CMD_D_INTR_CHAIN;
    /* Block 0 header 22B (I||q||0x8080) register concatenation; byte k in [k*8 +: 8], same as blockgen */
    wire [175:0] pblc_head_w = {
        8'h80,                          /* byte21 */
        8'h80,                          /* byte20 */
        arg_q_r[7:0],                   /* byte19 */
        arg_q_r[15:8],                  /* byte18 */
        arg_q_r[23:16],                 /* byte17 */
        arg_q_r[31:24],                 /* byte16 */
        identifier_flat_w[15*8 +: 8], identifier_flat_w[14*8 +: 8],
        identifier_flat_w[13*8 +: 8], identifier_flat_w[12*8 +: 8],
        identifier_flat_w[11*8 +: 8], identifier_flat_w[10*8 +: 8],
        identifier_flat_w[9*8 +: 8],  identifier_flat_w[8*8 +: 8],
        identifier_flat_w[7*8 +: 8],  identifier_flat_w[6*8 +: 8],
        identifier_flat_w[5*8 +: 8],  identifier_flat_w[4*8 +: 8],
        identifier_flat_w[3*8 +: 8],  identifier_flat_w[2*8 +: 8],
        identifier_flat_w[1*8 +: 8],  identifier_flat_w[0*8 +: 8]};
    /* Final absorb read window base: block 0 = word 32 (chain value area start); block N>=1 =
     * 26 + 34N (byte offset stays 2 mod 4, 34-word full-block window). Last block
     * (N=w_pblc_last_block) reads only w_pblc_last_rd words. */
    wire [11:0] pblc_final_base_w =
        (pblc_final_block_r == 7'd0) ? 12'd32 :
        (12'd26 + {5'b0, pblc_final_block_r} * 12'd34);
    wire [5:0] pblc_final_rd_words =
        (pblc_final_block_r == w_pblc_last_block) ? w_pblc_last_rd : 6'd35;
    /* Final PBLc last block (constructed by w data length): byte0..last-1 = data (read window
     * byte 2 onward, skipping the 2B lane), byte last = 0x1F, byte 135 = 0x80 (padding to rate). */
    reg [1087:0] pblc_last_block_w;
    integer pblc_lb;     /* last-block construction loop (module level; Vivado does not allow declarations inside begin-end) */
    always @* begin
        pblc_last_block_w = 1088'b0;
        for (pblc_lb = 0; pblc_lb < 136; pblc_lb = pblc_lb + 1) begin
            if (pblc_lb < w_pblc_last_bytes)
                pblc_last_block_w[pblc_lb * 8 +: 8] = pblc_final_window_r[16 + pblc_lb * 8 +: 8];
            else if (pblc_lb == w_pblc_last_bytes)
                pblc_last_block_w[pblc_lb * 8 +: 8] = 8'h1f;
            else if (pblc_lb == 135)
                pblc_last_block_w[pblc_lb * 8 +: 8] = 8'h80;
        end
    end
    /* ---------- HASH_ONCE_RAM (task RAM multi-block absorb, level 0) ----------
     * Input = 54B prefix + message placed consecutively in task RAM from word 32, total length
     * L = input_length (<=2048). Block count = L/136 + 1 (when L%136==0 the last block is a
     * pure padding block); full block 136B, last block rem bytes carry padding (rem==135 ->
     * byte135 = 0x1F^0x80 = 0x9F, don't miss the sponge boundary). Read window reuses
     * pblc_final_window_r (HASH_ONCE_RAM and the batch-task PBLc command are mutually exclusive). */
    wire hash_ram_cmd_w = command_r == CMD_HASH_ONCE_RAM;
    /* P3: MQC (all lengths) reuses the HASH_ONCE_RAM read-window state machine (paths merged,
     * single-block construction removed). Layout: words 32..45 = 54B header (word 45 high 2B
     * unused), word 46 onward = message (4B aligned, bridge pass-through/firmware writes).
     * Block 0 constructs the header window byte0..53 + message window byte56.. (skips 2B
     * padding); blocks k>=1 window offset 0 (message tiled from byte 136k, word aligned). */
    wire mqc_multi_w = mqc_cmd_w;
    wire hash_ram_path_w = hash_ram_cmd_w || mqc_multi_w;
    wire mqc_block0_w = mqc_multi_w && (hash_ram_block_r == 4'd0);
    reg  [3:0] hash_ram_block_r;      /* current block number (0..L/136) */
    reg  [5:0] hash_ram_word_r;       /* read window word count (0..rd_words) */
    reg  [3:0] hash_ram_full_r;       /* full block count = L/136 (latched at ACT_START) */
    reg  [7:0] hash_ram_rem_r;        /* L%136 (latched at ACT_START) */
    reg        hash_ram_kicked_r;     /* KICK first-cycle flag (latch block+kick, then wait for done) */
    wire hash_ram_is_last_w = (hash_ram_block_r == hash_ram_full_r);
    wire [7:0] hash_ram_data_bytes_w = hash_ram_is_last_w ?
        (hash_ram_rem_r == 8'd0 ? 8'd0 : hash_ram_rem_r) : 8'd136;
    wire [5:0] hash_ram_rd_words_w =
        hash_ram_is_last_w ?
            (hash_ram_rem_r == 8'd0 ? 6'd0 :
             (mqc_multi_w ? (({1'b0, hash_ram_rem_r} + 7'd5) >> 2)
                          : ({1'b0, hash_ram_rem_r[7:2]} +
                             (|hash_ram_rem_r[1:0] ? 6'd1 : 6'd0))))
        : ((mqc_multi_w && (hash_ram_block_r != 4'd0)) ? 6'd35
           : (mqc_block0_w ? 6'd35 : 6'd34));
    /* P3.2: MQC read-window base by short/large message -- short message (L<=128, y-bridge
     * pass-through scenario) base = 32+y_words (by w: W4=568/W2=1096/W8=304; W1 y 8480B fills
     * the whole task RAM so there is no separate area -> 568, y read directly by software);
     * large message (L>128, message area 582 fixed) -> 568. HASH_ONCE_RAM still base 32. */
    wire mqc_short_w = mqc_multi_w && (input_length_r <= 12'd128);
    wire [11:0] mqc_base_w = mqc_short_w ?
        ((w_p == 9'd265) ? 12'd568 : (12'd32 + {w_p, 3'b0})) : 12'd568;
    wire [11:0] hash_ram_base_w =
        (mqc_multi_w ? mqc_base_w : 12'd32) + {8'b0, hash_ram_block_r} * 12'd34;
    /* Current block combined construction: byte<data_bytes = data (window tiled byte hrb,
     * word0 at the lowest bits); byte==data_bytes = 0x1F (data_bytes==135 -> 0x9F); byte135 =
     * 0x80. Full block (136) has no padding. (Measured 2026-08-11: full-block pass-through
     * optimization does not save LUTs, +264 instead -- the last-block construction must be
     * fully kept, comparators unchanged, Vivado boundary reassignment cancels it out. Keep
     * unified construction.) */
    reg [1087:0] hash_ram_block_w;
    integer hram_lb;     /* HASH_ONCE_RAM block construction loop (module level) */
    always @* begin
        hash_ram_block_w = 1088'b0;
        for (hram_lb = 0; hram_lb < 136; hram_lb = hram_lb + 1) begin
            if (hram_lb[7:0] < hash_ram_data_bytes_w)
                hash_ram_block_w[hram_lb * 8 +: 8] =
                    /* MQC multi-block: message tiled from byte 56 (+2 offset, block 0 header section excepted) */
                    (mqc_multi_w && (mqc_block0_w ? (hram_lb >= 54) : 1'b1)) ?
                        pblc_final_window_r[(hram_lb + 2) * 8 +: 8] :
                        pblc_final_window_r[hram_lb * 8 +: 8];
            else if (hram_lb[7:0] == hash_ram_data_bytes_w)
                hash_ram_block_w[hram_lb * 8 +: 8] =
                    (hash_ram_data_bytes_w == 8'd135) ? 8'h9f : 8'h1f;
            else if (hram_lb == 135)
                hash_ram_block_w[hram_lb * 8 +: 8] = 8'h80;
        end
    end
    /* ---------- CMD_MSG_Q_COEF (message hash -> Q -> checksum -> coefficients, P3 unified
     * task RAM path) ----------
     * Input = 54B header (I||q little-endian||0x8181||C) written to task RAM word 32, message
     * to word 46 (4B aligned, layout same as HASH_ONCE_RAM, block construction +2 offset);
     * I/q/D_MESG also come from registers (identifier_flat_w/arg_q_r/0x8181). Completion ->
     * kec_digest_be_w (big-endian Q) latched to mqc_q_be_r + output_words; STATE_MQC_COEF
     * produces 1 coefficient per cycle: first u cycles accumulate checksum (max_digit-digit)
     * writing the Q-segment coefficients, then p-u cycles slice the remaining coefficients
     * from the checksum16 big-endian view, all compact-packed into coefficient_words. */
    wire mqc_cmd_w = command_r == CMD_MSG_Q_COEF;
    reg  [255:0] mqc_q_be_r;          /* Q big-endian (byte0=MSB, = kec_digest_be_w) */
    reg  [15:0] mqc_cs_be_r;          /* checksum big-endian view (byte0=MSB), used in phase B */
    reg  [15:0] mqc_checksum_r;       /* checksum accumulation (not yet shifted) */
    reg  [8:0]  mqc_idx_r;            /* coefficient index 0..p-1 */
    reg  [4:0]  mqc_shift_r;          /* bit offset within word (0..31) */
    reg  [8:0]  mqc_word_idx_r;       /* coefficient_words word index */
    wire [15:0] mqc_cs_final_w =        /* checksum final value (after left shift by ls), combinational */
        (mqc_checksum_r + (w_max_step - mqc_digit_w)) << mqc_ls_w;
    reg  [8:0]  mqc_u_w;              /* u = 256/w (Q-segment coefficient count, always combinational assignment) */
    reg  [3:0]  mqc_ls_w;             /* checksum left shift amount (W1=7/W2=6/W4=4/W8=0) */
    reg  [3:0]  mqc_log2w_w;          /* log2(w): 0/1/2/3 */
    reg  [2:0]  mqc_bp3w_w;           /* 3-log2(w): 3/2/1/0 (byte_idx = i >> (3-log2w)) */
    reg  [2:0]  mqc_dib_mask_w;       /* digit mask within byte 8/w-1: 7/3/1/0 */
    wire        mqc_last_w = (mqc_idx_r == w_p - 9'd1);
    always @* begin
        case (arg_w_r)
            4'd1: begin mqc_u_w = 9'd256; mqc_ls_w = 4'd7; mqc_log2w_w = 4'd0; mqc_bp3w_w = 3'd3; mqc_dib_mask_w = 3'd7; end
            4'd2: begin mqc_u_w = 9'd128; mqc_ls_w = 4'd6; mqc_log2w_w = 4'd1; mqc_bp3w_w = 3'd2; mqc_dib_mask_w = 3'd3; end
            4'd8: begin mqc_u_w = 9'd32;  mqc_ls_w = 4'd0; mqc_log2w_w = 4'd3; mqc_bp3w_w = 3'd0; mqc_dib_mask_w = 3'd0; end
            default: begin mqc_u_w = 9'd64; mqc_ls_w = 4'd4; mqc_log2w_w = 4'd2; mqc_bp3w_w = 3'd1; mqc_dib_mask_w = 3'd1; end
        endcase
    end
    /* Coefficient slicing (byte level, avoiding a 256:1 bit barrel selector; Q big-endian byte k
     * in [255-8k -: 8]):
     *   Q segment (i<u): byte_idx = i>>log2w; shift within byte (from MSB) = ((~i)&mask)<<log2w
     *   checksum segment (i>=u): same framework applied to the 2-byte cs_be_r (byte0=high byte) */
    wire [8:0]  mqc_q_byte_idx_w = mqc_idx_r >> mqc_bp3w_w;
    wire [7:0]  mqc_q_byte_w = mqc_q_be_r[255 - {4'b0, mqc_q_byte_idx_w} * 8'd8 -: 8];
    wire [3:0]  mqc_q_shift_w = ((~mqc_idx_r[2:0]) & mqc_dib_mask_w) << mqc_log2w_w;
    wire [7:0]  mqc_digit_q_w = mqc_q_byte_w >> mqc_q_shift_w;
    wire [8:0]  mqc_cs_j_w = mqc_idx_r - mqc_u_w;
    wire [7:0]  mqc_cs_byte_idx_w = mqc_cs_j_w >> mqc_bp3w_w;
    wire [7:0]  mqc_cs_byte_w = mqc_cs_be_r[15 - {6'b0, mqc_cs_byte_idx_w} * 8'd8 -: 8];
    wire [3:0]  mqc_cs_shift_w = ((~mqc_cs_j_w[2:0]) & mqc_dib_mask_w) << mqc_log2w_w;
    wire [7:0]  mqc_digit_cs_w = mqc_cs_byte_w >> mqc_cs_shift_w;
    /* Coefficient value = shift result & mask (takes the low w bits); checksum accumulation and
     * writes both use this value */
    wire [7:0] mqc_mask_w =
        (w_coef_bits == 4'd8) ? 8'hff : (8'h01 << w_coef_bits) - 8'h01;
    reg [7:0] mqc_digit_w;
    always @* begin
        if (mqc_idx_r < mqc_u_w)
            mqc_digit_w = mqc_digit_q_w & mqc_mask_w;
        else
            mqc_digit_w = mqc_digit_cs_w & mqc_mask_w;
    end
    /* Batch-task block construction (SHAKE256 rate=136B).
     * batch_rate_block_w/init_w are only blockgen outputs + combinational reads, so use wire
     * (Vivado Synth 8-685: reg cannot be connected to a submodule output port, but Verilator
     * allows it). */
    wire [1087:0] batch_rate_block_w;
    wire          batch_rate_init_w;
    /* D_LEAF K_q flattening (word7..word0 big-endian concatenation; byte k = word[k/4] bit
     * (k%4)*8) */
    wire [255:0] dleaf_kq_w = {output_words[7], output_words[6], output_words[5], output_words[4],
                               output_words[3], output_words[2], output_words[1], output_words[0]};
    /* Batch-task block task type (blockgen is the only block source, eliminating the wide mux
     * into the core): 4=D_LEAF (core0), 5=PBLc full/last block (core0), 1/2=CHAIN/DERIVE
     * (core1) */
    reg [2:0] batch_task_type_w;
    /* Thesis-style dedicated 1088-bit block input register: latched from blockgen output at
     * START_CORE/TASK_ENDPOINT cycles; the core absorbs from the register on the next cycle,
     * cutting the combinational mux into the core (Vivado once folded block construction into
     * the two Keccaks, inflating each by ~5.4K/9.8K LUT). */
    reg [1087:0] batch_block_r;
    reg          core0_kick_r;   /* core0 start pulse (latched, next cycle, 1 cycle) */
    reg          core1_kick_r;   /* core1 start pulse */
    reg          core0_init_r;   /* core0 latched init */
    reg          core1_init_r;   /* core1 latched init */
    /* VERIFY and VERIFY_LEAF share the whole batch-task path (differ only in whether D_LEAF is
     * continued at the chain tail) */
    wire verify_cmd_w = (command_r == CMD_LMOTS_VERIFY ||
                         command_r == CMD_LMOTS_VERIFY_LEAF);
    wire         batch_cmd_w = command_r == CMD_LMOTS_KEYGEN ||
        command_r == CMD_LMOTS_SIGN || verify_cmd_w ||
        command_r == CMD_LMOTS_KEYGEN_LEAF;
    wire [8:0] batch_i1_w = batch_i_r + 9'd1;   /* batch index for core1 */

    /* ===== DERIVE phase shuffle (tier 1, 2026-08-21) =====
     * Batch-task block parameter i gets a per-trace random start offset: i_act = (i + b) mod p.
     * DERIVE/CHAIN phases share the same i_act (chain starts from x_q[i_act]); chain result is
     * written back to slot i_act -> slot k holds exactly y_k -> output read order unchanged
     * (zero external change). verify has no DERIVE phase (chain starts from signature y), keeps
     * order. Zero performance cost: 1-level combinational 9-bit add + 2 conditional subtracts
     * p (b in [1,p-1] => sum <= 2p-2). b is latched per trace at the batch-task start cycle
     * from the free-running LFSR (no data dependency on SEED, introduces no new leakage). */
    reg  [15:0] der_lfsr_r;              /* free-running LFSR (XOR feedback, non-zero seed prevents lock at 0) */
    reg  [8:0]  der_b_r;                 /* this batch's offset (blocking latch at start cycle, [1,p-1]) */
    wire [8:0]  der_b_w = ((der_lfsr_r[7:0] % (w_p - 9'd1)) + 9'd1);   /* b in [1,p-1] */
    /* Batch-task start cycle (= CTRL_START decoded OK and action=ACT_START and batch command):
     * der_b_r blocking assignment -> new value combinationally visible in the same cycle (P2
     * folds the first block, latching block parameters in the same cycle as the start). */
    wire batch_start_w = bus_valid && bus_write &&
        bus_addr[9:0] == REG_CONTROL && (bus_wdata & CTRL_START) &&
        cmd_check_valid_w && cmd_check_action_w == ACT_START && batch_cmd_w;
    function automatic [8:0] der_perm(input [8:0] der_x);
        reg [9:0] der_s, der_s1, der_s2;
        begin
            if (!DERIVE_SHUFFLE || verify_cmd_w) begin
                der_perm = der_x;
            end else begin
                der_s  = {1'b0, der_x} + der_b_r;                    /* <= 2p-2 */
                der_s1 = (der_s >= {1'b0, w_p}) ? der_s - {1'b0, w_p} : der_s;
                der_s2 = (der_s1 >= {1'b0, w_p}) ? der_s1 - {1'b0, w_p} : der_s1;
                der_perm = der_s2[8:0];
            end
        end
    endfunction
    /* Combinational wire views (referenced uniformly by sequential/combinational blocks, to
     * avoid evaluation differences of the function on the RHS of procedural assignments) */
    wire [8:0] der_perm_bi_w   = der_perm(batch_i_r);
    wire [8:0] der_perm_bi1_w  = der_perm(batch_i1_w);
    wire [8:0] der_perm_fold_w = der_perm(fold_next_i_w);
    always @(posedge clk) begin
        if (rst) der_lfsr_r <= 16'hACE1;
        else     der_lfsr_r <= {der_lfsr_r[14:0],
                                der_lfsr_r[15] ^ der_lfsr_r[13] ^
                                der_lfsr_r[12] ^ der_lfsr_r[10]};
    end
    /* der_b_r: blocking assignment (visible combinationally in the same cycle) -- P2 folds the
     * first block, latching block parameters in the same cycle as the start, so this task's new
     * offset must be used; a non-blocking assignment would take effect one cycle later (first
     * block uses the old value -> bijection broken). This is the only write site; the BLKSEQ
     * warning is expected (intentional; synthesis semantics = same-cycle-visible latch). */
    /* verilator lint_off BLKSEQ */
    always @(posedge clk) begin
        if (rst) der_b_r <= 9'd1;
        else if (batch_start_w) der_b_r = der_b_w;
    end
    /* verilator lint_on BLKSEQ */
    /* Coefficient extraction (compact packed, sliced by w width):
     *   W1: 32 1-bit per word, index = batch_i>>5 / [batch_i&31]
     *   W2: 16 2-bit per word, index = batch_i>>4 / [batch_i&15]*2
     *   W4: 8 4-bit per word, index = batch_i>>3 / [batch_i&7]*4
     *   W8: 4 8-bit per word, index = batch_i>>2 / [batch_i&3]*8 */
    reg [7:0] batch_coefficient_w;
    reg [7:0] batch_coefficient1_w;
    always @* begin
        case (w_coef_bits)
            4'd1: begin
                batch_coefficient_w = {7'b0, coefficient_words[der_perm_bi_w[8:5]][der_perm_bi_w[4:0]]};
                batch_coefficient1_w = {7'b0, coefficient_words[der_perm_bi1_w[8:5]][der_perm_bi1_w[4:0]]};
            end
            4'd2: begin
                batch_coefficient_w = {6'b0, coefficient_words[der_perm_bi_w[8:4]][der_perm_bi_w[3:0] * 2 +: 2]};
                batch_coefficient1_w = {6'b0, coefficient_words[der_perm_bi1_w[8:4]][der_perm_bi1_w[3:0] * 2 +: 2]};
            end
            4'd4: begin
                batch_coefficient_w = {4'b0, coefficient_words[der_perm_bi_w[8:3]][der_perm_bi_w[2:0] * 4 +: 4]};
                batch_coefficient1_w = {4'b0, coefficient_words[der_perm_bi1_w[8:3]][der_perm_bi1_w[2:0] * 4 +: 4]};
            end
            default: begin   /* W8: 4 8-bit per word */
                batch_coefficient_w = coefficient_words[der_perm_bi_w[8:2]][der_perm_bi_w[1:0] * 8 +: 8];
                batch_coefficient1_w = coefficient_words[der_perm_bi1_w[8:2]][der_perm_bi1_w[1:0] * 8 +: 8];
            end
        endcase
    end
    /* Whether core1 participates in this batch (combinational; judged directly at START_CORE
     * cycle for kick, avoiding dependence on the stale dual_core1_active_r) */
    wire core1_should_run = (batch_i1_w < w_p) &&
        (batch_phase_r == BATCH_DERIVE || chain_steps_left1_r != 8'd0);

    /* ---------- Hash-independent command validation (unified refactor step 1) ---------- */
    wire        cmd_check_valid_w;
    wire [31:0] cmd_check_error_w;
    wire [3:0]  cmd_check_action_w;
    lms_hash_cmd_check #(
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE), /* P1-6: connected to top-level parameter (no longer hardcoded 1; test config=1, deploy=0 rejects plaintext SEED_LOAD) */
        .HAS_SECURITY(HAS_SECURITY), /* compile-time security-domain switch: 1=includes MC/WRAP/HMAC/K-slot commands; 0=pure algorithm */
        .MAX_ONCE_BYTES(8'd128),   /* SHAKE256 HASH_ONCE upper limit 128B (unified with SHA-256; input_words_flat 1024 bits) */
        .HAS_HASH_ONCE_RAM(1'b1),  /* SHAKE256 enables HASH_ONCE_RAM (task RAM multi-block, <=2048B) */
        .MAX_ONCE_BYTES_RAM(12'd2048),
        .HAS_STATE_COMMIT(1'b1),    /* SHAKE256 enables CMD_STATE_COMMIT (SEC state commit fusion) */
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE) /* TVLA isolated single x_q[i] allowance (see plan) */
    ) u_cmd_check (
        .command(command_r),
        .input_length(input_length_r),
        .output_length(output_length_r),
        .arg_i({16'b0, arg_i_r}),
        .arg_start({24'b0, arg_start_r}),
        .arg_steps(arg_steps_r),
        .arg_key(arg_key_r),          /* SEED_LOAD arg_key=1/2 -> K_WRAP/K_STATE (SEC slots) */
        .seed_valid(sec_seed_valid_w),
        .k_wrap_valid(sec_k_wrap_valid_w),
        .k_state_valid(sec_k_state_valid_w),
        .lmots_sign_y_len(w_p * 32),   /* SIGN y length by w (W4=2144 zero regression) */
        .valid(cmd_check_valid_w),
        .error_code(cmd_check_error_w),
        .action(cmd_check_action_w)
    );

    /* ---------- Security domain (SEC, step 2: SHAKE256 wired into lms_sha256_sec HASH_TYPE=1) ----------
     * SEC is a hash-independent template (lms_sha256_sec.v): secret slots (SEED/K_WRAP/K_STATE)/
     * sim_mc counter/WRAP/UNWRAP/HMAC multi-machine + core-borrowing handshake + construction
     * parameter outputs. Block construction is implemented by this wrapper per SHAKE256 rate=136B
     * (HMAC-SHAKE256 / WRAP 1088-bit blocks). SEC borrows Keccak core0 (via the kec_ext_* channel,
     * sec_core_mode mutually exclusive with batch tasks / single chain). */
    wire        sec_busy_w;
    wire        sec_done_w;
    wire        sec_error_valid_w;
    wire [31:0] sec_error_code_w;
    wire [31:0] sec_cycles_w;
    wire [255:0] sec_result_data_w;
    wire [7:0]   sec_result_wmask_w;
    wire        sec_result_valid_w;
    wire [31:0] sec_mc_next_value_w;
    wire [255:0] sec_seed_data_w;
    wire        sec_seed_valid_w;
    wire        sec_k_wrap_valid_w;
    wire        sec_k_state_valid_w;
    wire        sec_core_start_w;
    wire        sec_core_init_w;
    wire        sec_core_state_load_w;
    wire [255:0] sec_core_state_in_w;
    wire        sec_is_hmac_w;
    wire [1:0]  sec_wrap_phase_w;
    wire [1:0]  sec_block_index_w;
    wire [1:0]  sec_block_count_w;
    wire        sec_stc_w;
    wire [31:0] sec_stc_tx_w;
    wire [255:0] sec_k_wrap_w;
    wire [255:0] sec_k_state_w;
    wire [255:0] sec_wrap_ct_w;
    wire [255:0] sec_wrap_tag_w;
    wire [31:0]  sec_bus_rdata_w;

    /* SEC bus access: address areas = SIM_MC(0x060)/SEED(0x080)/WRAPPED(0x0a0)/KWRAP(0x0e0).
     * SEC's bus_addr expects [9:0]; write gating reg_write_ok=!wrapper_busy (rejects writes
     * while SEC runs / bus busy). */
    wire sec_bus_hit_w =
        (bus_addr[9:0] == 10'h060) ||
        (bus_addr[9:0] >= 10'h080 && bus_addr[9:0] < 10'h080 + 32) ||
        (bus_addr[9:0] >= 10'h0a0 && bus_addr[9:0] < 10'h0a0 + 48) ||
        (bus_addr[9:0] >= 10'h0e0 && bus_addr[9:0] < 10'h0e0 + 32);
    wire sec_bus_valid_w = bus_valid && sec_bus_hit_w;

    /* Command start (shell drives combinationally on the CTRL_START cycle, SEC latches on the
     * same posedge; aligned with the lms_sha256_mmio "shell pulls *_latch_en/mc_*_en high
     * combinationally on the CTRL_START cycle" convention). */
    wire ctrl_start_w = !wrapper_busy_w && bus_valid && bus_write &&
        bus_addr[9:0] == REG_CONTROL && (bus_wdata & CTRL_START) != 32'b0;
    wire seed_latch_en_w   = ctrl_start_w && cmd_check_action_w == ACT_DONE_SEED;
    wire kwrap_latch_en_w  = ctrl_start_w && cmd_check_action_w == ACT_DONE_KWRAP;
    wire kstate_latch_en_w = ctrl_start_w && cmd_check_action_w == ACT_DONE_KSTATE;
    wire mc_step_en_w = ctrl_start_w && cmd_check_action_w == ACT_DONE_MC &&
                        command_r == CMD_MC_STEP;
    wire mc_load_en_w = ctrl_start_w && cmd_check_action_w == ACT_DONE_MC &&
                        command_r != CMD_MC_STEP;
    wire wrap_start_w = ctrl_start_w && cmd_check_action_w == ACT_START_WRAP;
    wire wrap_is_unwrap_w = command_r == CMD_UNWRAP_SEED;
    wire hmac_start_w = ctrl_start_w && cmd_check_action_w == ACT_START_HMAC;
    /* STATE_COMMIT: on the start cycle feed ARG_I=state, ARG_Q=ctr, ARG_KEY=aad to SEC
     * (combinational). */
    wire stc_start_w = ctrl_start_w && cmd_check_action_w == ACT_START_STC;
    /* Whether the current command is security-domain/immediate (used in CYCLE_COUNT read
     * decode: SEC cycles latch cycle_count_r; includes CMD_SEED_LOAD -- SEC slot immediate
     * latch, goes through cycle_count_r rather than the engine value) */
    wire sec_cmd_pending_w = (command_r == CMD_MC_STEP || command_r == CMD_MC_LOAD ||
                              command_r == CMD_WRAP_SEED || command_r == CMD_UNWRAP_SEED ||
                              command_r == CMD_HMAC_KSTATE || command_r == CMD_STATE_COMMIT ||
                              command_r == CMD_SEED_LOAD);

    /* SEED layout conversion: SEC seed_data is big-endian (byte k in [255-k*8+:8], designed
     * for the SHA-256 blockgen); the SHAKE256 blockgen expects "little-endian within word"
     * (byte k in word[k/4] bits (k%4)*8, i.e. the old seed_flat_w layout). Conversion = byte
     * reversal within each 32-bit word (word0 still at MSB):
     * sec_seed_flat_w[255:224] = {sec[231:224],sec[239:232],sec[247:240],sec[255:248]}
     * = {byte3,byte2,byte1,byte0} little-endian word0. */
    wire [255:0] sec_seed_flat_w;
    /* SEC block construction buffer (declared outside generate: driven by the always inside
     * g_sec_on, referenced by the external SEC core-borrowing always). */
    reg  [1087:0] sec_block0_w;
    reg  [1087:0] sec_block1_w;
    wire [1087:0] sec_block_w;
    integer sec_b0_i;
    integer sec_b1_i;

    /* Security-domain compile switch: HAS_SECURITY=1 instantiates lms_sha256_sec + HMAC/WRAP
     * block construction (SEC slots/core borrowing, step 2); HAS_SECURITY=0 does not
     * instantiate the security core (saves ~3.7K LUT + 4 DSP), SEED instead carried by the
     * local sec_seed_words registers (reproduces the 0.1.235 path), SEC outputs fixed 0. */
    generate
        if (HAS_SECURITY) begin : g_sec_on
            assign sec_block_w = (sec_block_index_w == 2'd0) ? sec_block0_w : sec_block1_w;
            assign sec_seed_flat_w = {
                sec_seed_data_w[231:224], sec_seed_data_w[239:232], sec_seed_data_w[247:240], sec_seed_data_w[255:248],
                sec_seed_data_w[199:192], sec_seed_data_w[207:200], sec_seed_data_w[215:208], sec_seed_data_w[223:216],
                sec_seed_data_w[167:160], sec_seed_data_w[175:168], sec_seed_data_w[183:176], sec_seed_data_w[191:184],
                sec_seed_data_w[135:128], sec_seed_data_w[143:136], sec_seed_data_w[151:144], sec_seed_data_w[159:152],
                sec_seed_data_w[103:96],  sec_seed_data_w[111:104], sec_seed_data_w[119:112], sec_seed_data_w[127:120],
                sec_seed_data_w[71:64],   sec_seed_data_w[79:72],   sec_seed_data_w[87:80],   sec_seed_data_w[95:88],
                sec_seed_data_w[39:32],   sec_seed_data_w[47:40],   sec_seed_data_w[55:48],   sec_seed_data_w[63:56],
                sec_seed_data_w[7:0],     sec_seed_data_w[15:8],    sec_seed_data_w[23:16],   sec_seed_data_w[31:24]};

    /* SEC instantiation (HASH_TYPE=1: SHAKE256 HMAC-SHAKE256, inner always 2 blocks).
     * Core borrowing: SEC requests drive Keccak core0 via the kec_ext_* channel; core_digest is
     * connected to the big-endian flip (kec_digest_be_w, byte0 at the most significant bit --
     * SEC semantics same as SHA-256, first 16B in [255:128]). */
    lms_sha256_sec #(
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .HASH_TYPE(1)
    ) u_sec (
        .clk(clk),
        .rst(rst),
        .bus_valid(sec_bus_valid_w),
        .bus_write(bus_write),
        .bus_addr(bus_addr[9:0]),
        .bus_wdata(bus_wdata),
        .bus_rdata(sec_bus_rdata_w),
        .reg_write_ok(!wrapper_busy_w),
        .seed_latch_en(seed_latch_en_w),
        .kwrap_latch_en(kwrap_latch_en_w),
        .kstate_latch_en(kstate_latch_en_w),
        .mc_step_en(mc_step_en_w),
        .mc_load_en(mc_load_en_w),
        .mc_load_value(arg_q_r),
        .wrap_start(wrap_start_w),
        .wrap_is_unwrap(wrap_is_unwrap_w),
        .hmac_start(hmac_start_w),
        .input_length(input_length_r[7:0]),
        .stc_start(stc_start_w),
        .stc_state(arg_i_r),
        .stc_ctr(arg_q_r),
        .stc_aad(arg_key_r[7:0]),
        .busy(sec_busy_w),
        .done(sec_done_w),
        .error_valid(sec_error_valid_w),
        .error_code(sec_error_code_w),
        .cycles(sec_cycles_w),
        .result_data(sec_result_data_w),
        .result_wmask(sec_result_wmask_w),
        .result_valid(sec_result_valid_w),
        .mc_next_value(sec_mc_next_value_w),
        .seed_data(sec_seed_data_w),
        .seed_valid(sec_seed_valid_w),
        .k_wrap_valid(sec_k_wrap_valid_w),
        .k_state_valid(sec_k_state_valid_w),
        .core_start(sec_core_start_w),
        .core_init(sec_core_init_w),
        .core_state_load(sec_core_state_load_w),
        .core_state_in(sec_core_state_in_w),
        .sec_is_hmac(sec_is_hmac_w),
        .wrap_phase(sec_wrap_phase_w),
        .block_index(sec_block_index_w),
        .block_count(sec_block_count_w),
        .stc_active(sec_stc_w),
        .stc_tx(sec_stc_tx_w),
        .k_wrap(sec_k_wrap_w),
        .k_state(sec_k_state_w),
        .wrap_ct(sec_wrap_ct_w),
        .wrap_tag(sec_wrap_tag_w),
        .core_busy(kec_ext_busy_w),
        .core_done(kec_ext_done_w),
        .core_digest(kec_digest_be_w)
    );

    /* ---------- SEC block construction (SHAKE256 HMAC-SHAKE256 / WRAP 1088-bit blocks) ----------
     * rate=136B, padding = 0x1F @ data end || 0x00.. || 0x80 @ byte135. Message length
     * <=119B/32B/43B, never triggers the rem==135->0x9F boundary (sponge padding: don't miss
     * byte135=0x80). K/byte sequence consistent with the SHA-256 production line (K first):
     *   mask  = SHAKE256(k_wrap[32B] || "LMSWRAP-ENC"[11B])  -> 1 block (HMAC block length=43)
     *   inner = SHAKE256((K^0x36)[136B] || msg[<=119B])      -> 2 blocks (K=HMAC->k_state,
     *                                                          WRAP->k_wrap; msg=HMAC->input,
     *                                                          WRAP->wrap_ct)
     *   outer = SHAKE256((K^0x5c)[136B] || inner[32B])       -> 2 blocks (inner=wrap_tag)
     * core_init=(block_index==0): each phase is an independent sponge, block 0 init=1, later
     * blocks continue (aligned with HASH_ONCE_RAM). */
    /* SEC block construction (refactor: block0/block1 separated + 4-scenario mux merged, lower
     * LUT). Area optimization: block0 (K^pad area) and block1 (data+padding area) constructed
     * separately, top-level 2:1 select by block_index -- each byte index is constant (removes
     * the old per-byte dynamic part-select `key[255-sec_gi*8-:8]` with runtime block_index and
     * the 5-scenario deep nesting); the 4 HMAC-like scenarios (HMAC/WRAP x inner/outer) merge
     * into one unified template (differing only in key source/pad constant/message source and
     * length), mask is a special case (1 block). */
    wire         sec_is_mask_w = !sec_is_hmac_w && (sec_wrap_phase_w == 2'd0);
    wire         sec_inner_w   = (sec_wrap_phase_w == 2'd1);
    wire [255:0] sec_key_w     = sec_is_hmac_w ? sec_k_state_w : sec_k_wrap_w;
    wire [7:0]   sec_pad_w     = sec_inner_w ? 8'h36 : 8'h5c;
    wire [7:0]   sec_msg_len_w = (sec_is_hmac_w && sec_inner_w) ?
                                 (sec_stc_w ? 8'd49 : input_length_r[7:0]) : 8'd32;
    /* STATE_COMMIT body 49B forward view: magic(4,"LMSS")||state(2,BE)||ctr(4,BE)||tx(4,BE)
     * ||reserved(34,0)||aad(1). genvar constant indices (no negative indices, safe for Vivado
     * static checks). stc fields come from ARG registers stable during the command
     * (arg_i_r/arg_q_r/arg_key_r) and SEC's latched tx (sec_stc_tx_w). */
    wire [1087:0] sec_body_be_w;
    genvar sec_bd_i;
    for (sec_bd_i = 0; sec_bd_i < 4; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_magic
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            (sec_bd_i == 0) ? 8'h4c : (sec_bd_i == 1) ? 8'h4d :
            (sec_bd_i == 2) ? 8'h53 : 8'h53;   /* "LMSS" */
    end
    for (sec_bd_i = 4; sec_bd_i < 6; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_state
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            (sec_bd_i == 4) ? arg_i_r[15:8] : arg_i_r[7:0];   /* state BE */
    end
    for (sec_bd_i = 6; sec_bd_i < 10; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_ctr
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            arg_q_r[(9 - sec_bd_i) * 8 +: 8];   /* ctr BE (forward index 24..0) */
    end
    for (sec_bd_i = 10; sec_bd_i < 14; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_tx
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            sec_stc_tx_w[(13 - sec_bd_i) * 8 +: 8];   /* tx BE (forward index 24..0) */
    end
    for (sec_bd_i = 14; sec_bd_i < 48; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_rsv
        assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;   /* reserved */
    end
    for (sec_bd_i = 48; sec_bd_i < 49; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_aad
        assign sec_body_be_w[sec_bd_i * 8 +: 8] = arg_key_r[7:0];   /* aad=slot_id */
    end
    for (sec_bd_i = 49; sec_bd_i < 136; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_z
        assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;
    end
    /* block1 message source forward byte layout view (block byte b in [b*8 +: 8]): wrap_ct/tag
     * are big-endian (byte0 at most significant), input is little-endian within word. genvar
     * generates only legal indices, avoiding Vivado static-check errors on negative/out-of-range
     * part selects in loop unrolling (Synth 8-524); b>=32 (wrap)/b>=128 (input, HMAC message
     * <=119B) zero-fill is not needed. */
    wire [1087:0] sec_input_be_w;
    wire [1087:0] sec_wrap_ct_be_w;
    wire [1087:0] sec_wrap_tag_be_w;
    genvar sec_be_i;
    for (sec_be_i = 0; sec_be_i < 32; sec_be_i = sec_be_i + 1) begin : g_sec_be
            assign sec_wrap_ct_be_w[sec_be_i * 8 +: 8]  = sec_wrap_ct_w[255 - sec_be_i * 8 -: 8];
            assign sec_wrap_tag_be_w[sec_be_i * 8 +: 8] = sec_wrap_tag_w[255 - sec_be_i * 8 -: 8];
        end
        for (sec_be_i = 32; sec_be_i < 136; sec_be_i = sec_be_i + 1) begin : g_sec_be_z
            assign sec_wrap_ct_be_w[sec_be_i * 8 +: 8]  = 8'b0;
            assign sec_wrap_tag_be_w[sec_be_i * 8 +: 8] = 8'b0;
        end
        for (sec_be_i = 0; sec_be_i < 128; sec_be_i = sec_be_i + 1) begin : g_sec_in_be
            assign sec_input_be_w[sec_be_i * 8 +: 8] =
                input_flat_w[(sec_be_i / 4) * 32 + (sec_be_i % 4) * 8 +: 8];
        end
        for (sec_be_i = 128; sec_be_i < 136; sec_be_i = sec_be_i + 1) begin : g_sec_in_be_z
            assign sec_input_be_w[sec_be_i * 8 +: 8] = 8'b0;
        end
    /* HMAC inner message source: when stc = body (49B valid, rest 0), otherwise = input.
     * Pre-mux into two-level 2:1 (body/input merged, then selected against wrap_ct), replacing
     * the three-source nested mux inside block1 -- behaviorally equivalent, gives the synthesizer
     * a cleaner mapping (LUT reduction candidate). */
    wire [1087:0] sec_inner_msg_be_w;
    assign sec_inner_msg_be_w = sec_stc_w ? sec_body_be_w : sec_input_be_w;
    /* block0 (block_index==0): non-mask = K^pad(32B) || pad(104B); mask =
     * k_wrap(32B) || "LMSWRAP-ENC"(11B) || 0x1f || 0x00.. || 0x80 (1 block). */
    always @* begin
        sec_block0_w = 1088'b0;
        if (sec_is_mask_w) begin
            for (sec_b0_i = 0; sec_b0_i < 136; sec_b0_i = sec_b0_i + 1) begin
                if (sec_b0_i < 32) begin
                    sec_block0_w[sec_b0_i * 8 +: 8] = sec_k_wrap_w[255 - sec_b0_i * 8 -: 8];
                end else if (sec_b0_i < 43) begin
                    /* "LMSWRAP-ENC": 4c 4d 53 57 52 41 50 2d 45 4e 43 */
                    case (sec_b0_i - 32)
                        8'd0:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h4c;  /* L */
                        8'd1:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h4d;  /* M */
                        8'd2:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h53;  /* S */
                        8'd3:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h57;  /* W */
                        8'd4:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h52;  /* R */
                        8'd5:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h41;  /* A */
                        8'd6:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h50;  /* P */
                        8'd7:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h2d;  /* - */
                        8'd8:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h45;  /* E */
                        8'd9:  sec_block0_w[sec_b0_i * 8 +: 8] = 8'h4e;  /* N */
                        default: sec_block0_w[sec_b0_i * 8 +: 8] = 8'h43;  /* C */
                    endcase
                end else if (sec_b0_i == 43) begin
                    sec_block0_w[sec_b0_i * 8 +: 8] = 8'h1f;
                end else if (sec_b0_i == 135) begin
                    sec_block0_w[sec_b0_i * 8 +: 8] = 8'h80;
                end
            end
        end else begin
            for (sec_b0_i = 0; sec_b0_i < 136; sec_b0_i = sec_b0_i + 1) begin
                if (sec_b0_i < 32)
                    sec_block0_w[sec_b0_i * 8 +: 8] =
                        sec_key_w[255 - sec_b0_i * 8 -: 8] ^ sec_pad_w;
                else
                    sec_block0_w[sec_b0_i * 8 +: 8] = sec_pad_w;
            end
        end
    end
    /* block1 (block_index==1): message || 0x1f || 0x00.. || 0x80.
     * Message = inner->(HMAC->input_words little-endian / WRAP->wrap_ct big-endian),
     * outer->wrap_tag (big-endian); message length = HMAC inner->input_length, others->32B.
     * Message source read via the sec_*_be_w forward views. */
    always @* begin
        sec_block1_w = 1088'b0;
        for (sec_b1_i = 0; sec_b1_i < 136; sec_b1_i = sec_b1_i + 1) begin
            if (sec_b1_i < sec_msg_len_w) begin
                if (sec_inner_w)
                    sec_block1_w[sec_b1_i * 8 +: 8] = sec_is_hmac_w ?
                        sec_inner_msg_be_w[sec_b1_i * 8 +: 8] :
                        sec_wrap_ct_be_w[sec_b1_i * 8 +: 8];
                else
                    sec_block1_w[sec_b1_i * 8 +: 8] = sec_wrap_tag_be_w[sec_b1_i * 8 +: 8];
            end else if (sec_b1_i == sec_msg_len_w) begin
                sec_block1_w[sec_b1_i * 8 +: 8] = 8'h1f;
            end else if (sec_b1_i == 135) begin
                sec_block1_w[sec_b1_i * 8 +: 8] = 8'h80;
            end
        end
    end
        end else begin : g_sec_off
            /* ---- No security domain: local SEED storage (reproduces the 0.1.235 seed_words path) ----
             * SEED_LOAD (8 word writes to the 0x080 area) -> sec_seed_words; CMD_SEED_LOAD sets
             * sec_seed_valid_r. SEC instantiation/block construction not generated, other SEC
             * outputs fixed 0. */
            reg [31:0] sec_seed_words [0:7];
            reg        sec_seed_valid_r;
            integer    sec_wi;
            always @(posedge clk) begin
                if (rst) begin
                    sec_seed_valid_r <= 1'b0;
                    for (sec_wi = 0; sec_wi < 8; sec_wi = sec_wi + 1) begin
                        sec_seed_words[sec_wi] <= 32'b0;
                    end
                end else begin
                    if (bus_valid && bus_write &&
                        bus_addr[9:0] >= 10'h080 && bus_addr[9:0] < 10'h080 + 32) begin
                        sec_seed_words[(bus_addr[9:0] - 10'h080) >> 2] <= bus_wdata;
                    end
                    if (ctrl_start_w && cmd_check_action_w == ACT_DONE_SEED) begin
                        sec_seed_valid_r <= 1'b1;
                    end
                end
            end
            assign sec_seed_data_w = {sec_seed_words[0], sec_seed_words[1], sec_seed_words[2],
                                      sec_seed_words[3], sec_seed_words[4], sec_seed_words[5],
                                      sec_seed_words[6], sec_seed_words[7]};
            assign sec_seed_valid_w = sec_seed_valid_r;
            assign sec_seed_flat_w = sec_seed_data_w;   /* already the final little-endian-within-word layout */
            assign sec_busy_w = 1'b0;
            assign sec_done_w = 1'b0;
            assign sec_error_valid_w = 1'b0;
            assign sec_error_code_w = 32'b0;
            assign sec_cycles_w = 32'b0;
            assign sec_result_data_w = 256'b0;
            assign sec_result_wmask_w = 8'b0;
            assign sec_result_valid_w = 1'b0;
            assign sec_mc_next_value_w = 32'b0;
            assign sec_k_wrap_valid_w = 1'b0;
            assign sec_k_state_valid_w = 1'b0;
            assign sec_core_start_w = 1'b0;
            assign sec_core_init_w = 1'b0;
            assign sec_core_state_load_w = 1'b0;
            assign sec_core_state_in_w = 256'b0;
            assign sec_is_hmac_w = 1'b0;
            assign sec_wrap_phase_w = 2'b0;
            assign sec_block_index_w = 2'b0;
            assign sec_block_count_w = 2'b0;
            assign sec_stc_w = 1'b0;
            assign sec_stc_tx_w = 32'b0;
            assign sec_k_wrap_w = 256'b0;
            assign sec_k_state_w = 256'b0;
            assign sec_wrap_ct_w = 256'b0;
            assign sec_wrap_tag_w = 256'b0;
            assign sec_bus_rdata_w = 32'b0;
            assign sec_block_w = 1088'b0;
        end
    endgenerate

    /* SEC core-borrowing mode: while SEC is busy, core0 belongs to SEC (mutually exclusive
     * with batch tasks / single chain); kec_ext_mode is also set 1 while SEC is busy (the
     * engine hands core0 control to the external party). */
    wire sec_core_mode_w = sec_busy_w;
    wire kec_ext_mode_w =
        ((batch_cmd_w || dintr_cmd_w || hash_ram_cmd_w || mqc_cmd_w) && state_r != STATE_IDLE) ||
        sec_core_mode_w;

    /* ---------- Hash-independent single-chain engine (unified refactor step 2) ---------- */
    wire         engine_busy_w;
    wire         engine_done_w;
    wire [255:0] engine_digest_w;
    wire [31:0]  engine_cycle_w;
    wire         unused_sha_ext_busy_w;
    wire         unused_sha_ext_done_w;
    wire [255:0] unused_sha_ext_digest_w;
    wire         unused_sha_ext1_busy_w;
    wire         unused_sha_ext1_done_w;
    wire [255:0] unused_sha_ext1_digest_w;
    wire         unused_kec_ext_busy_w;
    wire         unused_kec_ext_done_w;
    wire [255:0] unused_kec_ext_digest_w;
    /* CHAIN start initial value: byte-reversed concatenation of each input_words word -> continuous
     * big-endian (byte0 at most significant), consistent with the iterative digest_be_w layout
     * (aligned with the SHA-256 engine_chain_input_w). */
    wire [255:0] chain_value_in_w = {
        input_words[0][7:0], input_words[0][15:8], input_words[0][23:16], input_words[0][31:24],
        input_words[1][7:0], input_words[1][15:8], input_words[1][23:16], input_words[1][31:24],
        input_words[2][7:0], input_words[2][15:8], input_words[2][23:16], input_words[2][31:24],
        input_words[3][7:0], input_words[3][15:8], input_words[3][23:16], input_words[3][31:24],
        input_words[4][7:0], input_words[4][15:8], input_words[4][23:16], input_words[4][31:24],
        input_words[5][7:0], input_words[5][15:8], input_words[5][23:16], input_words[5][31:24],
        input_words[6][7:0], input_words[6][15:8], input_words[6][23:16], input_words[6][31:24],
        input_words[7][7:0], input_words[7][15:8], input_words[7][23:16], input_words[7][31:24]
    };
    /* SEED flattening: SEED moved into the SEC slot (step 2); DERIVE/batch tasks read from
     * SEC's seed_data (layout converted via sec_seed_flat_w to align with the SHAKE256
     * blockgen, see the SEC declaration area). */
    wire [127:0] identifier_flat_w;
    wire [1023:0] input_flat_w;
    genvar flat_index;
    generate
        for (flat_index = 0; flat_index < 4; flat_index = flat_index + 1) begin : g_identifier_flat
            assign identifier_flat_w[flat_index * 32 +: 32] = identifier_words[flat_index];
        end
        for (flat_index = 0; flat_index < 32; flat_index = flat_index + 1) begin : g_input_flat
            assign input_flat_w[flat_index * 32 +: 32] = input_words[flat_index];
        end
    endgenerate

    lms_hash_engine #(
        .HASH_TYPE(2'd1),              /* SHAKE256 (step 2) */
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .RANDOM_DELAY(RANDOM_DELAY)    /* TVLA lightweight mitigation: random delay inside 0x6D engine */
    ) u_engine (
        .clk(clk),
        .rst(rst),
        .start(engine_start_r),
        .command(command_r),
        .input_length(input_length_r[7:0]),
        .arg_q(arg_q_r),
        .arg_i(arg_i_r),
        .arg_start(arg_start_r),
        .arg_steps(arg_steps_r),
        .identifier_flat(identifier_flat_w),
        .chain_value_in(chain_value_in_w),
        .seed_flat(sec_seed_flat_w),   /* SEED via SEC slot + layout conversion (step 2) */
        .input_words_flat(input_flat_w),
        .sha_ext_mode(1'b0),
        .sha_ext_start(1'b0),
        .sha_ext_init(1'b0),
        .sha_ext_state_load(1'b0),
        .sha_ext_state_in(256'b0),
        .sha_ext_block(512'b0),
        .sha_ext_busy(unused_sha_ext_busy_w),
        .sha_ext_done(unused_sha_ext_done_w),
        .sha_ext_digest(unused_sha_ext_digest_w),
        .sha_ext1_start(1'b0),
        .sha_ext1_init(1'b0),
        .sha_ext1_state_load(1'b0),
        .sha_ext1_state_in(256'b0),
        .sha_ext1_block(512'b0),
        .sha_ext1_busy(unused_sha_ext1_busy_w),
        .sha_ext1_done(unused_sha_ext1_done_w),
        .sha_ext1_digest(unused_sha_ext1_digest_w),
        .kec_ext_mode(kec_ext_mode_w),   /* includes SEC core-borrowing mode (step 2: while SEC busy, core0 belongs to SEC) */
        .kec_ext_start(kec_start_w),
        .kec_ext_init(kec_init_w),
        .kec_ext_block(kec_block_w),
        .kec_ext_busy(kec_ext_busy_w),
        .kec_ext_done(kec_ext_done_w),
        .kec_ext_digest(kec_ext_digest_w),
        .kec_ext1_start(kec1_start_w),
        .kec_ext1_init(kec1_init_w),
        .kec_ext1_block(kec1_block_w),
        .kec_ext1_busy(kec_ext1_busy_w),
        .kec_ext1_done(kec_ext1_done_w),
        .kec_ext1_digest(kec_ext1_digest_w),
        .busy(engine_busy_w),
        .done(engine_done_w),
        .digest_out(engine_digest_w),
        .cycle_count(engine_cycle_w)
    );

    wire wrapper_busy_w = engine_busy_w || (state_r != STATE_IDLE) || sec_busy_w;
    /* Batch-task external core control signals: core0 = PBLc sponge/D_LEAF, core1 = chain computation */
    wire kec_ext_busy_w;
    wire kec_ext_done_w;
    wire [255:0] kec_ext_digest_w;
    reg  kec_start_w;
    reg  kec_init_w;
    reg [1087:0] kec_block_w;
    wire kec_ext1_busy_w;
    wire kec_ext1_done_w;
    wire [255:0] kec_ext1_digest_w;
    reg  kec1_start_w;
    reg  kec1_init_w;
    reg [1087:0] kec1_block_w;
    /* Keccak core digest little-endian-first -> big-endian flip (core0 = PBLc/D_LEAF result) */
    wire [255:0] kec_digest_be_w = {
        kec_ext_digest_w[7:0],   kec_ext_digest_w[15:8],  kec_ext_digest_w[23:16], kec_ext_digest_w[31:24],
        kec_ext_digest_w[39:32], kec_ext_digest_w[47:40], kec_ext_digest_w[55:48], kec_ext_digest_w[63:56],
        kec_ext_digest_w[71:64], kec_ext_digest_w[79:72], kec_ext_digest_w[87:80], kec_ext_digest_w[95:88],
        kec_ext_digest_w[103:96], kec_ext_digest_w[111:104], kec_ext_digest_w[119:112], kec_ext_digest_w[127:120],
        kec_ext_digest_w[135:128], kec_ext_digest_w[143:136], kec_ext_digest_w[151:144], kec_ext_digest_w[159:152],
        kec_ext_digest_w[167:160], kec_ext_digest_w[175:168], kec_ext_digest_w[183:176], kec_ext_digest_w[191:184],
        kec_ext_digest_w[199:192], kec_ext_digest_w[207:200], kec_ext_digest_w[215:208], kec_ext_digest_w[223:216],
        kec_ext_digest_w[231:224], kec_ext_digest_w[239:232], kec_ext_digest_w[247:240], kec_ext_digest_w[255:248]};
    wire address_hit = bus_valid && bus_addr[31:10] == SHAKE_BASE[31:10];
    assign mem_hit = address_hit;

    /* ---------- Batch-task block construction ---------- */
    /* Batch DERIVE/CHAIN blocks: reuse lms_shake256_blockgen (byte order same as single chain).
     * Chain computation runs on core1, digest taken from core1 (isolated from the PBLc sponge
     * on core0). */
    wire [255:0] chain_digest_be_w;
    /* Batch-task block task type (combinational, derived by kick state; value irrelevant on
     * non-kick cycles). P2: fold-cycle override -- on the fold_dc cycle phase_r is still DERIVE
     * but the next block is CHAIN; on fold_derive/fold_first cycles the next block is DERIVE
     * (phase_r still the old value). */
    always @* begin
        if (dintr_cmd_w && state_r == STATE_DINTR_LOAD_SIB)
            batch_task_type_w = 3'd6;                  /* D_INTR (block latched on last-word cycle) */
        else if (keygen_dleaf_r || fold_dleaf_w)
            batch_task_type_w = 3'd4;                  /* D_LEAF (folded on PBLc last-block completion cycle) */
        else if (fold_dc_w)
            batch_task_type_w = 3'd1;                  /* CHAIN (folded on DERIVE completion cycle) */
        else if (fold_derive_any_w || fold_first_w)
            batch_task_type_w = 3'd2;                  /* DERIVE (folded on next-pair/first-cycle) */
        else if (batch_phase_r == BATCH_CHAIN)
            batch_task_type_w = 3'd1;                  /* CHAIN */
        else
            batch_task_type_w = 3'd2;                  /* DERIVE (initial/KEYGEN/SIGN) */
    end
    /* D_INTR node updated per layer (dintr_node_r, >>1 per layer from the leaf node); D_LEAF
     * uses the MMIO register arg_leaf_node_r. P1-6 q=1 fix: command arg = leaf node (including
     * parity bit) -- layer k concatenation direction determined by current node parity (odd ->
     * sibling||cur), in-block node = current node>>1 (parent node). Old convention arg=leaf>>1
     * lost leaf parity -> layer 0 direction wrong when q is odd. */
    wire        dintr_swap_w       = dintr_node_r[0];
    wire [31:0] dintr_block_node_w = dintr_node_r >> 1;
    wire [31:0] dleaf_node_w = dintr_cmd_w ? dintr_block_node_w : arg_leaf_node_r;

    /* ---------- P2: START_CORE merge (step A=CHAIN->CHAIN; step B=DERIVE->CHAIN,
     * TASK_WRITE->next-pair DERIVE, ACT_START->first DERIVE) ----------
     * Completion cycle gives digest combinationally to blockgen (next view) + latches
     * block/kick in the same cycle, saving 1 cycle per fold point. Block still latched via
     * batch_block_r/batch_block1_r into the core (prevents Vivado from folding block
     * construction into the core and inflating LUTs). */
    wire cores_done_w = (core0_done_latched_r || kec_ext_done_w) &&
                        (!dual_core1_active_r || core1_done_latched_r || kec_ext1_done_w);
    wire chain_more_w = (chain_steps_left0_r > 8'd1) || (chain_steps_left1_r > 8'd1);
    wire fold_step_w = (state_r == STATE_WAIT_CORE) && batch_cmd_w && !keygen_dleaf_r &&
                       (batch_phase_r == BATCH_CHAIN) && chain_more_w && cores_done_w;
    /* DERIVE completion cycle -> first CHAIN block (j=0, value=derived digest) */
    wire fold_dc_w = (state_r == STATE_WAIT_CORE) && batch_cmd_w && !keygen_dleaf_r &&
                     (batch_phase_r == BATCH_DERIVE) && cores_done_w;
    /* TASK_WRITE wrap-up cycle -> next-pair first DERIVE (not verify; verify goes through LOAD
     * prefetch); P3: SIGN chain completion cycle (not chain_more) -> next-pair first DERIVE
     * (write already backgrounded). */
    /* P3 background-write FIFO backpressure: when both bg_q slots are full, the two-chain
     * completion cycle does not push (batch FSM parks this cycle), waiting for drain to free a
     * slot -- DERIVE shuffling can group 0-step chains together, so push spacing can be <16
     * cycles (P3's original "spacing >=16 cycles" assumption broken); without backpressure the
     * "overwrite slot1" fallback would lose data. */
    wire bg_q_full_w = bg_q_valid[0] && bg_q_valid[1];
    /* P3 backpressure park: refined conditions for SIGN two-chain completion (pair done)
     * advance/push. sign_next_pair_done_w excludes backpressure; sign_next_pair_stall_w = both
     * bg_q slots full (push would lose data/overwrite here, batch FSM must park and wait for
     * drain to free a slot); sign_next_pair_w (push+advance) holds only with backpressure headroom. */
    wire sign_next_pair_done_w = (state_r == STATE_WAIT_CORE) && (command_r == CMD_LMOTS_SIGN) &&
                                 !keygen_dleaf_r && (batch_phase_r == BATCH_CHAIN) &&
                                 !chain_more_w && cores_done_w;
    wire sign_next_pair_stall_w = sign_next_pair_done_w && bg_q_full_w;
    wire sign_next_pair_w = sign_next_pair_done_w && !bg_q_full_w;
    /* P3: SIGN two-chain completion cycle -> y background-write push (digest combinational
     * select; single always drives to prevent multi-driver) */
    wire bg_push_w = sign_next_pair_w;
    wire [255:0] bg_digest0_sel_w = chain0_zero_r ? chain_value0_r : kec_digest_be_w;
    wire [255:0] bg_digest1_sel_w = chain1_zero_r ? chain_value1_r : chain_digest_be_w;
    wire fold_derive_w = (state_r == STATE_TASK_WRITE) && !verify_cmd_w &&
        ((!dual_write_sel_r && task_write_word0_r == 3'd7 && !dual_core1_active_r &&
          batch_i_r != (w_p - 9'd1)) ||
         (dual_write_sel_r && task_write_word1_r == 3'd7 && batch_i1_w != (w_p - 9'd1)));
    wire fold_derive_any_w = fold_derive_w || sign_next_pair_w;
    wire [8:0] fold_next_i_w = (batch_i_r >= (w_p - 9'd3)) ? (w_p - 9'd1)
                                                          : (batch_i_r + 9'd2);
    /* ACT_START batch-task first cycle -> first DERIVE (i=0) */
    wire fold_first_w = (state_r == STATE_IDLE) && batch_cmd_w && !verify_cmd_w;
    /* P2 step C: PBLc last-block completion cycle -> D_LEAF block (K_q combinational view,
     * saves TASK_PREFETCH+START_CORE) */
    wire fold_dleaf_w = (state_r == STATE_WAIT_CORE) && (batch_phase_r == BATCH_PBLC) &&
                        kec_ext_done_w && (pblc_final_block_r == w_pblc_last_block) &&
                        (command_r == CMD_LMOTS_KEYGEN_LEAF ||
                         command_r == CMD_LMOTS_VERIFY_LEAF);
    /* Combinational K_q view isomorphic to the output_words latch + dleaf_kq_w flattening
     * (fold-cycle digest fed directly) */
    wire [255:0] dleaf_kq_fold_w = {
        kec_digest_be_w[255 - (7*32+24) -: 8], kec_digest_be_w[255 - (7*32+16) -: 8],
        kec_digest_be_w[255 - (7*32+8)  -: 8], kec_digest_be_w[255 - 7*32      -: 8],
        kec_digest_be_w[255 - (6*32+24) -: 8], kec_digest_be_w[255 - (6*32+16) -: 8],
        kec_digest_be_w[255 - (6*32+8)  -: 8], kec_digest_be_w[255 - 6*32      -: 8],
        kec_digest_be_w[255 - (5*32+24) -: 8], kec_digest_be_w[255 - (5*32+16) -: 8],
        kec_digest_be_w[255 - (5*32+8)  -: 8], kec_digest_be_w[255 - 5*32      -: 8],
        kec_digest_be_w[255 - (4*32+24) -: 8], kec_digest_be_w[255 - (4*32+16) -: 8],
        kec_digest_be_w[255 - (4*32+8)  -: 8], kec_digest_be_w[255 - 4*32      -: 8],
        kec_digest_be_w[255 - (3*32+24) -: 8], kec_digest_be_w[255 - (3*32+16) -: 8],
        kec_digest_be_w[255 - (3*32+8)  -: 8], kec_digest_be_w[255 - 3*32      -: 8],
        kec_digest_be_w[255 - (2*32+24) -: 8], kec_digest_be_w[255 - (2*32+16) -: 8],
        kec_digest_be_w[255 - (2*32+8)  -: 8], kec_digest_be_w[255 - 2*32      -: 8],
        kec_digest_be_w[255 - (1*32+24) -: 8], kec_digest_be_w[255 - (1*32+16) -: 8],
        kec_digest_be_w[255 - (1*32+8)  -: 8], kec_digest_be_w[255 - 1*32      -: 8],
        kec_digest_be_w[255 - (0*32+24) -: 8], kec_digest_be_w[255 - (0*32+16) -: 8],
        kec_digest_be_w[255 - (0*32+8)  -: 8], kec_digest_be_w[255 - 0*32      -: 8]};
    /* D_INTR KICK fold: on LOAD_SIB last-word cycle right is already complete (last word
     * combined combinationally), in-block left/right include parity swap (q=1 fix convention). */
    wire [255:0] dintr_right_bg_w = (state_r == STATE_DINTR_LOAD_SIB && dintr_load_word_r == 4'd7)
        ? {dintr_right_r[255:32],
           task_ram_read_r[7:0], task_ram_read_r[15:8],
           task_ram_read_r[23:16], task_ram_read_r[31:24]}
        : dintr_right_r;

    /* P2 step C: VERIFY LOAD completion cycle (chain1 last word) -> first CHAIN block
     * (j=coefficient, value=loaded y). chain1 last word combined combinationally (NBA not yet
     * visible in the same cycle). */
    wire fold_load_w = (state_r == STATE_TASK_LOAD) && verify_dual_load_r &&
                       (task_write_word_r == 3'd7);
    wire [255:0] chain_value1_full_w = fold_load_w
        ? {chain_value1_r[255:32],
           task_ram_read_r[7:0], task_ram_read_r[15:8],
           task_ram_read_r[23:16], task_ram_read_r[31:24]}
        : chain_value1_r;

    wire [255:0] bg_chain_value0_w = (fold_step_w || fold_dc_w) ? kec_digest_be_w
                                                                 : chain_value0_r;
    wire [7:0]   bg_chain_j0_w     = fold_step_w ? (chain_j0_r + 8'd1) :
                                     (fold_dc_w ? 8'd0 :
                                      (fold_load_w ? batch_coefficient_w : chain_j0_r));
    wire [255:0] bg_chain_value1_w = (fold_step_w || fold_dc_w) ? chain_digest_be_w
                                                                 : chain_value1_full_w;
    wire [7:0]   bg_chain_j1_w     = fold_step_w ? (chain_j1_r + 8'd1) :
                                     (fold_dc_w ? 8'd0 :
                                      (fold_load_w ? batch_coefficient1_w : chain_j1_r));
    wire [8:0]   bg_batch_i_w      = fold_derive_any_w ? der_perm_fold_w :
                                     (fold_first_w ? (DERIVE_SHUFFLE ? der_b_w : 9'd0)
                                                   : der_perm_bi_w);
    /* core1 block parameters = next real i (under shuffle = i_act+1; mod p prevents i_act=p-1
     * overflow. With DERIVE_SHUFFLE=0 i_act=batch_i_r, this expression is equivalent to the
     * old no-mod +1 at the unused tail clamp). */
    wire [8:0]   bg_batch_i1_w     = (bg_batch_i_w == (w_p - 9'd1)) ? 9'd0 : bg_batch_i_w + 9'd1;
    /* First cycle after a fold re-kick: the previous completion's done level has not yet
     * fallen (the core only clears done on the start edge); that cycle must silently skip
     * completion detection, otherwise a false completion cascades the advance. */
    reg fold_settle_r;
    /* P3: SIGN background write -- dual-entry FIFO (each entry = one chain pair's 16/8 words),
     * push and drain decoupled: with dense 0-step chains push spacing is ~17 cycles, a single
     * buffer would be overwritten by the new push before the old pair finishes draining; FIFO
     * capacity 2 pairs (32 words) covers a 32-cycle window. slot0 = draining/awaiting drain,
     * slot1 = queued. */
    reg [255:0] bg_q_d0 [0:1];
    reg [255:0] bg_q_d1 [0:1];
    reg [11:0]  bg_q_addr [0:1];   /* this pair's y start address (word) */
    reg [4:0]   bg_q_words [0:1];  /* this pair's total word count (16 dual-chain / 8 tail single-chain; 5-bit prevents 16 truncation) */
    reg         bg_q_valid [0:1];
    /* DERIVE shuffle wrap flag: when the dual core hits the tail slot on core0 (perm(j)=p-1),
     * core1=perm(j+1)=0, so the drained core1 segment (idx8-15) must wrap to slot 0 instead of
     * writing contiguously out of range. Never wraps in sequential order. */
    reg         bg_q_wrap [0:1];
    reg         bg_drain_active_r;
    reg [3:0]   bg_drain_idx_r;    /* current word index (0..15) */
    /* P3: background write busy (draining or queue non-empty) -- gates bridge/MMIO task RAM reads. */
    wire bg_busy_w = bg_drain_active_r || bg_q_valid[0] || bg_q_valid[1];

    lms_shake256_blockgen u_batch_blockgen (
        .task_type(batch_task_type_w),
        .input_words_flat(input_flat_w),
        .identifier_flat(identifier_flat_w),
        .arg_q(arg_q_r),
        .arg_i({7'b0, bg_batch_i_w}),
        .chain_j(bg_chain_j0_w),
        .chain_value(bg_chain_value0_w),
        .derive_phase(batch_phase_r == BATCH_DERIVE || fold_derive_any_w || fold_first_w),
        .input_length(input_length_r[7:0]),
        .seed_flat(sec_seed_flat_w),   /* SEED via SEC slot + layout conversion (step 2) */
        .arg_leaf_node(dleaf_node_w),
        .dleaf_kq(fold_dleaf_w ? dleaf_kq_fold_w : dleaf_kq_w),
        .pblc_buffer(1088'b0),   /* PBLc block constructed combinationally by wrapper (option 1 revised), not via blockgen */
        .pblc_fill(8'b0),
        .pblc_phase(1'b0),
        .dintr_left(dintr_cmd_w && dintr_swap_w ? dintr_right_bg_w : dintr_left_r),
        .dintr_right(dintr_cmd_w && dintr_swap_w ? dintr_left_r : dintr_right_bg_w),
        .rate_block(batch_rate_block_w),
        .rate_init(batch_rate_init_w),
        .core_digest(kec_ext1_digest_w),
        .digest_bigendian(chain_digest_be_w)
    );

    /* core1 block (combinationally derived from the blockgen core0 view: i=batch_i+1, CHAIN
     * changes j/value). Used only on chain-step (DERIVE/CHAIN) START_CORE cycles; core1 does
     * not participate in D_LEAF/PBLc phases. */
    reg [1087:0] core1_block_w;
    always @* begin
        core1_block_w = batch_rate_block_w;
        /* i field (byte20=high byte, byte21=low byte, aligned with blockgen's {arg_i[7:0],
         * arg_i[15:8]} layout where byte20=arg_i high part... actually per the W4 original code
         * byte20=0/byte21=batch_i1: i.e. byte20=i high byte, byte21=i low byte (big-endian).
         * P2: fold cycles use the bg view's i+1. */
        core1_block_w[20 * 8 +: 8] = {7'b0, bg_batch_i1_w[8]};
        core1_block_w[21 * 8 +: 8] = bg_batch_i1_w[7:0];
        if ((batch_phase_r != BATCH_DERIVE && !fold_derive_any_w && !fold_first_w) || fold_dc_w) begin
            /* Only overwrite core1's value/j when the next block is CHAIN:
             * on the fold_dc cycle phase_r is still DERIVE (pre-edge) but the next block is the
             * first CHAIN; on fold_derive/fold_first cycles the next block is DERIVE (seed
             * block, never overwritten). */
            core1_block_w[22 * 8 +: 8] = bg_chain_j1_w;
            for (bj = 0; bj < 32; bj = bj + 1) begin
                core1_block_w[(23 + bj) * 8 +: 8] = bg_chain_value1_w[255 - bj * 8 -: 8];
            end
        end
    end

    /* Block select: uniformly from batch_block_r (thesis-style dedicated input register,
     * latched at START_CORE/TASK_ENDPOINT cycles); the core absorbs from the register on the
     * kick cycle. Combinational output reduced to only the kick pulse and latched init, zero
     * combinational into the core (eliminates Vivado folding block construction into the
     * core's inflated area). */
    always @* begin
        if (sec_core_mode_w) begin
            /* SEC core borrowing: core0 belongs to SEC (block/start from SEC construction
             * params), core1 stopped. */
            kec_start_w  = sec_core_start_w;
            kec_init_w   = sec_core_init_w;
            kec_block_w  = sec_block_w;
            kec1_start_w = 1'b0;
            kec1_init_w  = 1'b0;
            kec1_block_w = 1088'b0;
        end else begin
            kec_start_w  = core0_kick_r;
            kec_init_w   = core0_init_r;
            kec_block_w  = batch_block_r;
            kec1_start_w = core1_kick_r;
            kec1_init_w  = core1_init_r;
            kec1_block_w = batch_block1_r;
        end
    end

    /* Block construction and digest byte order: single chain inside the engine
     * (lms_shake256_blockgen); batch DERIVE/CHAIN reuse u_batch_blockgen; D_LEAF/PBLc
     * constructed combinationally by the wrapper. */

    /* ---------- Main state machine ---------- */
    integer dl_k;     /* PBLc header/buffer construction loop (module level, Vivado does not allow declarations inside begin-end) */
    integer out_oi;
    integer pblc_i;
    integer bj;       /* core1 block derivation: chain_value1 byte loop */
    always @(posedge clk) begin
        if (rst) begin
            command_r <= 32'b0;
            input_length_r <= 32'b0;
            output_length_r <= 32'b0;
            arg_q_r <= 32'b0;
            arg_i_r <= 16'b0;
            arg_start_r <= 8'b0;
            arg_steps_r <= 32'b0;
            error_r <= 32'b0;
            done_r <= 1'b0;
            engine_start_r <= 1'b0;
            arg_key_r <= 32'b0;
            arg_leaf_node_r <= 32'b0;
            arg_w_r <= 4'd4;   /* default W4, zero regression */
            state_r <= STATE_IDLE;
            block_index_r <= 2'b0;
            block_count_r <= 2'b0;
            cycle_count_r <= 32'b0;
            error_status_r <= 1'b0;
            busy_error_pending_r <= 1'b0;
            keygen_dleaf_r <= 1'b0;
            chain_value0_r <= 256'b0;
            chain_value1_r <= 256'b0;
            chain_j_r <= 8'b0;
            chain_j0_r <= 8'b0;
            chain_j1_r <= 8'b0;
            chain_steps_left0_r <= 8'b0;
            chain_steps_left1_r <= 8'b0;
            batch_phase_r <= BATCH_DERIVE;
            batch_i_r <= 9'b0;
            task_write_word_r <= 3'b0;
            task_write_word0_r <= 3'b0;
            task_write_word1_r <= 3'b0;
            task_digest0_r <= 256'b0;
            task_digest1_r <= 256'b0;
            batch_block_r <= 1088'b0;
            batch_block1_r <= 1088'b0;
            core0_kick_r <= 1'b0;
            core1_kick_r <= 1'b0;
            core0_init_r <= 1'b0;
            core1_init_r <= 1'b0;
            core0_done_latched_r <= 1'b0;
            core1_done_latched_r <= 1'b0;
            dual_write_sel_r <= 1'b0;
            verify_dual_load_r <= 1'b0;
            dual_core1_active_r <= 1'b0;
            chain0_zero_r <= 1'b0;
            chain1_zero_r <= 1'b0;
            fold_settle_r <= 1'b0;
            task_prefetch_pending_r <= 1'b0;
            pblc_final_block_r <= 7'd0;
            pblc_final_word_r <= 6'd0;
            pblc_final_window_r <= 1120'b0;
            dintr_left_r <= 256'b0;
            dintr_right_r <= 256'b0;
            dintr_node_r <= 32'b0;
            dintr_layer_r <= 5'b0;
            dintr_load_word_r <= 4'b0;
        end else begin
            engine_start_r <= 1'b0;
            task_prefetch_pending_r <= 1'b0;

            /* Engine (single chain) completion -> latch result (little-endian words: bytes
             * reversed, aligned with SHA-256/firmware) */
            if (engine_done_w) begin
                for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                    output_words[out_oi[2:0]] <= {
                        engine_digest_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                        engine_digest_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                        engine_digest_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                        engine_digest_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                end
                done_r <= 1'b1;
            end

            /* SEC completion (HMAC/WRAP/UNWRAP multi-cycle commands) -> latch
             * done/error/cycle/result. HMAC result (sec_result_data) is little-endian words
             * (aligned with output_words), written directly to OUTPUT; WRAP/UNWRAP's
             * wrapped_seed is maintained inside SEC (read via the WRAPPED window). */
            if (sec_done_w) begin
                /* REVIEW B08-R5: concurrent START's busy_error_pending_r also reports
                 * ERR_BUSY (aligned with the SHA-256 platform; the original implementation
                 * silently swallowed it on the SEC path). */
                if (busy_error_pending_r) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b1;
                    error_r <= ERR_BUSY;
                end else begin
                    done_r <= 1'b1;
                end
                cycle_count_r <= sec_cycles_w;
                if (busy_error_pending_r) begin
                    /* error already locked above, skip SEC's own error overwrite */
                end else if (sec_error_valid_w) begin
                    error_status_r <= 1'b1;
                    error_r <= sec_error_code_w;
                end else begin
                    error_status_r <= 1'b0;
                    error_r <= 32'b0;
                end
                if (sec_result_valid_w) begin
                    if (sec_stc_w) begin
                        /* STATE_COMMIT: word0=tx, word1..4=tag (first 16B), rest 0 */
                        output_words[0] <= sec_stc_tx_w;
                        output_words[1] <= sec_result_data_w[255:224];
                        output_words[2] <= sec_result_data_w[223:192];
                        output_words[3] <= sec_result_data_w[191:160];
                        output_words[4] <= sec_result_data_w[159:128];
                        output_words[5] <= 32'b0;
                        output_words[6] <= 32'b0;
                        output_words[7] <= 32'b0;
                    end else begin
                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                            output_words[out_oi] <= sec_result_data_w[255 - out_oi * 32 -: 32];
                        end
                    end
                end
            end

            /* Register writes (when IDLE) */
            if (!wrapper_busy_w && bus_valid && bus_write) begin
                case (bus_addr[9:0])
                    REG_COMMAND: command_r <= bus_wdata;
                    REG_INPUT_LENGTH: input_length_r <= bus_wdata;
                    REG_OUTPUT_LENGTH: output_length_r <= bus_wdata;
                    REG_ARG_Q: arg_q_r <= bus_wdata;
                    REG_ARG_I: arg_i_r <= bus_wdata[15:0];
                    REG_ARG_START: arg_start_r <= bus_wdata[7:0];
                    REG_ARG_STEPS: arg_steps_r <= bus_wdata;
                    REG_ARG_KEY: arg_key_r <= bus_wdata;
                    REG_ARG_LEAF_NODE: arg_leaf_node_r <= bus_wdata;
                    REG_ARG_W: arg_w_r <= bus_wdata[3:0]; /* REVIEW B09B10-R11: illegal w (0/3/5-7/9-15) silently executes as W4 (case default); firmware only writes 1/2/4/8, no error code added for now, strict validation to be closed later in cmd_check */
                    REG_TASK_ADDR: begin
                        /* task_addr_r writes are uniformly handled by the auto-increment read
                         * always below (single owner, eliminates Vivado multi-driven); here only
                         * the prefetch flag is set synchronously. Yields during stream-port
                         * activity (mutual exclusion). */
                        if (!stream_wr_en && !stream_rd_en &&
                            bus_wdata >= 32 && bus_wdata < 2152) begin
                            task_prefetch_pending_r <= 1'b1;
                        end
                    end
                    REG_TASK_DATA: begin
                        if (!stream_wr_en && !stream_rd_en &&
                            task_addr_r < 32) coefficient_words[task_addr_r[4:0]] <= bus_wdata;
                    end
                    REG_IDENTIFIER: identifier_words[0] <= bus_wdata;
                    REG_IDENTIFIER + 4: identifier_words[1] <= bus_wdata;
                    REG_IDENTIFIER + 8: identifier_words[2] <= bus_wdata;
                    REG_IDENTIFIER + 12: identifier_words[3] <= bus_wdata;
                    /* SEED/KWRAP/KSTATE/WRAPPED/SIM_MC handled by the SEC submodule
                     * (sec_bus_valid_w), not duplicated here (SEC's reg_write_ok gating rejects
                     * writes while busy). */
                    default: begin
                        if (bus_addr[9:0] >= REG_INPUT_BASE &&
                            bus_addr[9:0] < REG_INPUT_BASE + 128) begin
                            input_words[(bus_addr[9:0] - REG_INPUT_BASE) >> 2] <= bus_wdata;
                        end
                    end
                endcase
            end

            /* MQC coefficient writes (STATE_MQC_COEF produces 1 coefficient per cycle): case
             * expands fixed words, avoiding the barrel write-enable network of dynamic word
             * indexed array writes (area-heavy). Shares coefficient_words with the bus write in
             * the same always (single driver). Words 0..8 = max W1 9 words. */
            if (mqc_cmd_w && state_r == STATE_MQC_COEF) begin
                case (mqc_word_idx_r)
                    9'd0: case (w_coef_bits)
                        4'd1: coefficient_words[0][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[0][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[0][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[0][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd1: case (w_coef_bits)
                        4'd1: coefficient_words[1][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[1][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[1][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[1][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd2: case (w_coef_bits)
                        4'd1: coefficient_words[2][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[2][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[2][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[2][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd3: case (w_coef_bits)
                        4'd1: coefficient_words[3][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[3][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[3][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[3][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd4: case (w_coef_bits)
                        4'd1: coefficient_words[4][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[4][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[4][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[4][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd5: case (w_coef_bits)
                        4'd1: coefficient_words[5][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[5][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[5][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[5][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd6: case (w_coef_bits)
                        4'd1: coefficient_words[6][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[6][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[6][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[6][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd7: case (w_coef_bits)
                        4'd1: coefficient_words[7][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[7][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[7][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[7][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd8: case (w_coef_bits)
                        4'd1: coefficient_words[8][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[8][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[8][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[8][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    default: ;
                endcase
            end

            /* CONTROL: CTRL_CLEAR clears state; CTRL_START unified command validation + execute
             * by action (aligned with lms_sha256_mmio: CTRL_CLEAR must clear
             * done/error/cycle_count, otherwise prepare_command's CTRL_CLEAR->STATUS==0 check
             * would read a residual DONE) */
            if (!wrapper_busy_w && bus_valid && bus_write &&
                bus_addr[9:0] == REG_CONTROL) begin
                if (bus_wdata == CTRL_CLEAR) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b0;
                    error_r <= 32'b0;
                    cycle_count_r <= 32'b0;
                    busy_error_pending_r <= 1'b0;
                end else if (bus_wdata & CTRL_START) begin
                    done_r <= 1'b0;
                    error_r <= 32'b0;
                    if (!cmd_check_valid_w) begin
                        /* Aligned with the SHA-256 wrapper (1338-1340): reject by setting
                         * STATUS_ERROR, otherwise STATUS stays 0 -> MMIO side times out and the
                         * error code is lost. (Pre-existing asymmetry exposed by the P1-6
                         * deployment gate.) */
                        error_status_r <= 1'b1;
                        error_r <= cmd_check_error_w;
                    end else begin
                        case (cmd_check_action_w)
                        ACT_START: begin
                            if (dintr_cmd_w) begin
                                /* Chained D_INTR start: read starting left (task RAM words
                                 * 32..39) -> absorb sibling per layer (word 40 + layer*8).
                                 * arg_leaf_node = leaf node (including parity bit, P1-6 q=1
                                 * fix). */
                                cycle_count_r <= 32'd1;
                                dintr_layer_r <= 5'd0;
                                dintr_load_word_r <= 4'd0;
                                dintr_node_r <= arg_leaf_node_r;
                                state_r <= STATE_DINTR_PREFETCH;
                            end else if (batch_cmd_w) begin
                                /* Batch-task start: chain tails uniformly double-written to task
                                 * RAM, then core0 uniformly absorbs the final block (header 22B
                                 * via register concatenation, not filling pblc_buffer). */
                                batch_i_r <= 9'd0;
                                pblc_final_block_r <= 7'd0;
                                pblc_final_word_r <= 6'd0;
                                pblc_final_window_r <= 1120'b0;
                                keygen_dleaf_r <= 1'b0;
                                cycle_count_r <= 32'd1;
                                chain_value0_r <= 256'b0;
                                chain_value1_r <= 256'b0;
                                chain_j0_r <= 8'b0;
                                chain_j1_r <= 8'b0;
                                chain_steps_left0_r <= 8'b0;
                                chain_steps_left1_r <= 8'b0;
                                core0_done_latched_r <= 1'b0;
                                core1_done_latched_r <= 1'b0;
                                dual_write_sel_r <= 1'b0;
                                verify_dual_load_r <= 1'b0;
                                if (verify_cmd_w) begin
                                    batch_phase_r <= BATCH_CHAIN;
                                    task_write_word_r <= 3'd0;
                                    state_r <= STATE_TASK_PREFETCH;
                                end else begin
                                    batch_phase_r <= BATCH_DERIVE;
                                    /* P2 step B: first DERIVE folded into this cycle (i=0 via
                                     * bg view) */
                                    if (fold_first_w) begin
                                        batch_block_r  <= batch_rate_block_w;
                                        batch_block1_r <= core1_block_w;
                                        core0_init_r  <= batch_rate_init_w;
                                        core1_init_r  <= batch_rate_init_w;
                                        core0_kick_r <= 1'b1;
                                        core0_done_latched_r <= 1'b0;
                                        dual_core1_active_r <= (9'd1 < w_p);
                                        if (9'd1 < w_p) begin
                                            core1_kick_r <= 1'b1;
                                            core1_done_latched_r <= 1'b0;
                                        end else begin
                                            core1_kick_r <= 1'b0;
                                            core1_done_latched_r <= 1'b1;
                                        end
                                        state_r <= STATE_WAIT_CORE;
                                    end else begin
                                        state_r <= STATE_START_CORE;
                                    end
                                end
                            end else if (hash_ram_path_w) begin
                                /* HASH_ONCE_RAM / MQC multi-block start: multi-block absorb
                                 * from task RAM word 32. Latch block count/remainder; enter
                                 * TASK_PREFETCH to prefetch block 0 first word. MQC multi-block
                                 * also initializes the coefficient-generation state (enters COEF
                                 * after the last block). */
                                hash_ram_block_r <= 4'd0;
                                hash_ram_word_r <= 6'd0;
                                hash_ram_kicked_r <= 1'b0;
                                hash_ram_full_r <= input_length_r[11:0] / 12'd136;
                                hash_ram_rem_r  <= input_length_r[11:0] % 12'd136;
                                pblc_final_window_r <= 1120'b0;
                                mqc_q_be_r <= 256'b0;
                                mqc_cs_be_r <= 16'b0;
                                mqc_checksum_r <= 16'd0;
                                mqc_idx_r <= 9'd0;
                                mqc_shift_r <= 5'd0;
                                mqc_word_idx_r <= 9'd0;
                                cycle_count_r <= 32'd1;
                                state_r <= STATE_TASK_PREFETCH;
                            end else begin
                                /* Single-chain primitive: engine start (command/params already
                                 * connected combinationally). TVLA random delay
                                 * (RANDOM_DELAY=1) implemented inside the engine's ST_ABSORB
                                 * (delays core_start_r, busy asserted early as normal). */
                                engine_start_r <= 1'b1;
                            end
                        end
                        ACT_DONE_SEED: begin
                            /* SEED latched into the SEC slot (combinational seed_latch_en_w
                             * driven on the CTRL_START cycle) */
                            cycle_count_r <= 32'd1;   /* immediate command, 1 cycle */
                            done_r <= 1'b1;
                        end
                        ACT_DONE_CHAIN0: begin
                            output_words[0] <= input_words[0];
                            output_words[1] <= input_words[1];
                            output_words[2] <= input_words[2];
                            output_words[3] <= input_words[3];
                            output_words[4] <= input_words[4];
                            output_words[5] <= input_words[5];
                            output_words[6] <= input_words[6];
                            output_words[7] <= input_words[7];
                            done_r <= 1'b1;
                        end
                        ACT_DONE_KWRAP: begin
                            /* K_WRAP latched into the SEC slot (combinational kwrap_latch_en_w
                             * driven on the CTRL_START cycle) */
                            cycle_count_r <= 32'd1;   /* immediate command, 1 cycle */
                            done_r <= 1'b1;
                        end
                        ACT_DONE_KSTATE: begin
                            /* K_STATE latched into the SEC slot (combinational kstate_latch_en_w
                             * driven on the CTRL_START cycle) */
                            cycle_count_r <= 32'd1;   /* immediate command, 1 cycle */
                            done_r <= 1'b1;
                        end
                        ACT_DONE_MC: begin
                            /* sim_mc update (SEC combinational mc_step_en/mc_load_en driven on
                             * the CTRL_START cycle); new value read back via output_words[0]
                             * (aligned with SHA-256 inline: reads sim_mc+1 before update). */
                            cycle_count_r <= 32'd1;   /* immediate command, 1 cycle */
                            if (command_r == CMD_MC_STEP) begin
                                output_words[0] <= sec_mc_next_value_w;
                            end else begin
                                output_words[0] <= arg_q_r;
                            end
                            done_r <= 1'b1;
                        end
                        ACT_START_HMAC: begin
                            /* SEC independent FSM executes (combinational hmac_start_w driven on
                             * the CTRL_START cycle); done/error/cycle/result latched by the
                             * sec_done event. */
                        end
                        ACT_START_WRAP: begin
                            /* SEC independent FSM executes (combinational wrap_start_w +
                             * wrap_is_unwrap_w driven); done/error/cycle/result latched by the
                             * sec_done event. */
                        end
                        default: error_r <= ERR_UNSUPPORTED_COMMAND;
                    endcase
                end
            end
            end

            /* ---------- Batch task / D_INTR / HASH_ONCE_RAM / MQC state machine ---------- */
            if (batch_cmd_w || dintr_cmd_w || hash_ram_cmd_w || mqc_cmd_w) begin
                case (state_r)
                    STATE_MQC_COEF: begin
                        /* Produces 1 coefficient per cycle: for i<u accumulate checksum
                         * (max_digit-digit) (the i==u-1 cycle latches the final checksum
                         * big-endian view); for i>=u use the checksum segment. Coefficient
                         * writes done by the g_mqc_coef_write generate (fixed words). */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (mqc_idx_r < mqc_u_w) begin
                            mqc_checksum_r <= mqc_checksum_r + (w_max_step - mqc_digit_w);
                            if (mqc_idx_r == mqc_u_w - 9'd1) begin
                                /* checksum big-endian 2-byte view (byte0=most significant byte):
                                 * {hi,lo} */
                                mqc_cs_be_r <= {mqc_cs_final_w[15:8], mqc_cs_final_w[7:0]};
                            end
                        end
                        /* REVIEW proactive scan (2026-08-17): the original 5'd32 was truncated
                         * to 0, relying on the coincidence "0 - w_coef_bits == 32 - w_coef_bits
                         * (mod 32)" holding (with wcb in {1,2,4,8} the values 31/30/28/24
                         * happen to match intent, same truncation trap class as B09B10-R5);
                         * changed to explicit 6-bit subtraction to eliminate the trap, behavior
                         * unchanged. */
                        if ({1'b0, mqc_shift_r} == 6'd32 - {1'b0, w_coef_bits}) begin
                            mqc_shift_r <= 5'd0;
                            mqc_word_idx_r <= mqc_word_idx_r + 9'd1;
                        end else begin
                            mqc_shift_r <= mqc_shift_r + {1'b0, w_coef_bits};
                        end
                        if (mqc_idx_r == w_p - 9'd1) begin
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end else begin
                            mqc_idx_r <= mqc_idx_r + 9'd1;
                        end
                    end
                    STATE_START_CORE: begin
                        /* Dual-core batch step: latch core0 block (blockgen core0 view) +
                         * combinationally derived core1 block (i=batch_i+1, CHAIN changes
                         * j/value), kick both cores in the same cycle (each latches
                         * independently). D_LEAF single-core phase uses only core0 (final PBLc
                         * absorb goes through STATE_PBLC_FINAL). */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        batch_block_r  <= batch_rate_block_w;
                        batch_block1_r <= core1_block_w;
                        if (keygen_dleaf_r) begin
                            core0_kick_r  <= 1'b1;
                            core1_kick_r  <= 1'b0;
                            core0_init_r  <= 1'b1;
                            core1_init_r  <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                        end else begin
                            /* Chain step: core0 (+ core1 if batch_i+1 < w_p and has steps) */
                            core0_init_r  <= batch_rate_init_w;
                            core1_init_r  <= batch_rate_init_w;
                            /* dual_core1_active = this batch has a core1 chain (whether or not
                             * a 0-step chain), used for WAIT_CORE completion detection and
                             * TASK_WRITE/PBLc dual writes; whether core1 kicks is decided
                             * separately by core1_should_run (0-step chain does not kick). */
                            dual_core1_active_r <= (batch_i1_w < w_p);
                            if (batch_phase_r == BATCH_DERIVE || chain_steps_left0_r != 8'd0) begin
                                core0_kick_r <= 1'b1;
                                core0_done_latched_r <= 1'b0;
                            end else begin
                                /* 0-step chain: core0 not started, digest keeps chain_value0 */
                                core0_kick_r <= 1'b0;
                                core0_done_latched_r <= 1'b1;
                            end
                            if (core1_should_run) begin
                                core1_kick_r <= 1'b1;
                                core1_done_latched_r <= 1'b0;
                            end else begin
                                core1_kick_r <= 1'b0;
                                if (batch_i1_w < w_p && batch_phase_r != BATCH_DERIVE &&
                                    chain_steps_left1_r == 8'd0) begin
                                    core1_done_latched_r <= 1'b1;   /* core1 0-step chain */
                                end
                            end
                        end
                        state_r <= STATE_WAIT_CORE;
                    end
                    STATE_WAIT_CORE: begin
                        cycle_count_r <= cycle_count_r + 32'd1;
                        core0_kick_r <= 1'b0;
                        core1_kick_r <= 1'b0;
                        if (fold_settle_r) begin
                            /* P2: first cycle after a fold re-kick, the previous completion's
                             * done level has not fallen; silently skip one cycle (completion
                             * detection resumes next cycle). */
                            fold_settle_r <= 1'b0;
                        end else if (keygen_dleaf_r) begin
                            /* D_LEAF (core0) completion: output leaf digest (little-endian
                             * words, aligned with single chain) */
                            if (kec_ext_done_w) begin
                                keygen_dleaf_r <= 1'b0;
                                for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                    output_words[out_oi[2:0]] <= {
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                        kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                end
                                state_r <= STATE_IDLE;
                                done_r <= 1'b1;
                            end
                        end else if (batch_phase_r == BATCH_PBLC) begin
                            /* Final PBLc block (core0) absorb completion: non-last block
                             * continues reading the next block's window */
                            if (kec_ext_done_w) begin
                                if (pblc_final_block_r == w_pblc_last_block) begin
                                    /* Last block complete: K_q already latched as core0 digest
                                     * (little-endian words, aligned with single chain) */
                                    if (command_r == CMD_LMOTS_KEYGEN_LEAF ||
                                        command_r == CMD_LMOTS_VERIFY_LEAF) begin
                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        keygen_dleaf_r <= 1'b1;
                                        block_count_r <= 2'd1;
                                        block_index_r <= 2'd0;
                                        /* P2 step C: D_LEAF block folded into this cycle (K_q
                                         * combinational view), saves TASK_PREFETCH + START_CORE. */
                                        batch_block_r  <= batch_rate_block_w;
                                        batch_block1_r <= core1_block_w;
                                        core0_init_r  <= batch_rate_init_w;
                                        core1_init_r  <= 1'b0;
                                        core0_kick_r <= 1'b1;
                                        core1_kick_r <= 1'b0;
                                        core0_done_latched_r <= 1'b0;
                                        core1_done_latched_r <= 1'b0;
                                        dual_core1_active_r <= 1'b0;
                                        fold_settle_r <= 1'b1;
                                        state_r <= STATE_WAIT_CORE;
                                    end else begin
                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end
                                end else begin
                                    /* Next block read window: TASK_PREFETCH prefetches first word */
                                    pblc_final_block_r <= pblc_final_block_r + 1'b1;
                                    state_r <= STATE_TASK_PREFETCH;
                                end
                            end
                        end else begin
                            /* Chain step (dual core): wait for core0 and core1 (if participating) */
                            if (kec_ext_done_w) begin
                                core0_done_latched_r <= 1'b1;
                            end
                            if (dual_core1_active_r) begin
                                if (kec_ext1_done_w) begin
                                    core1_done_latched_r <= 1'b1;
                                end
                            end
                            if (core0_done_latched_r || kec_ext_done_w) begin
                                if (!dual_core1_active_r || core1_done_latched_r || kec_ext1_done_w) begin
                                    if (!sign_next_pair_stall_w) begin
                                    core0_done_latched_r <= 1'b0;
                                    core1_done_latched_r <= 1'b0;
                                    end
                                    if (command_r == CMD_LMOTS_SIGN) begin
                                        /* SIGN dual core: DERIVE->CHAIN (per-coefficient steps)
                                         * -> dual-write task RAM */
                                        if (batch_phase_r == BATCH_DERIVE) begin
                                            chain_value0_r <= kec_digest_be_w;
                                            chain_value1_r <= chain_digest_be_w;
                                            chain_j0_r <= 8'd0;
                                            chain_j1_r <= 8'd0;
                                            chain_steps_left0_r <= batch_coefficient_w;
                                            chain_steps_left1_r <= batch_coefficient1_w;
                                            chain0_zero_r <= (batch_coefficient_w == 0);
                                            chain1_zero_r <= (batch_coefficient1_w == 0);
                                            batch_phase_r <= BATCH_CHAIN;
                                            /* P2 step B: first CHAIN block folded into this
                                             * cycle (j=0/value=digest via bg view); 0-step chain
                                             * does not kick, keeps completion state. */
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            if (batch_coefficient_w != 0) begin
                                                core0_kick_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                            end else begin
                                                core0_kick_r <= 1'b0;
                                                core0_done_latched_r <= 1'b1;
                                            end
                                            if (batch_i1_w < w_p && batch_coefficient1_w != 0) begin
                                                core1_kick_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                if (batch_i1_w < w_p) begin
                                                    core1_done_latched_r <= 1'b1;
                                                end
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else if (chain_steps_left0_r > 8'd1 ||
                                                     chain_steps_left1_r > 8'd1) begin
                                            if (chain_steps_left0_r > 8'd0) begin
                                                chain_value0_r <= kec_digest_be_w;
                                                chain_j0_r <= chain_j0_r + 1'b1;
                                                chain_steps_left0_r <= chain_steps_left0_r - 1'b1;
                                            end
                                            if (chain_steps_left1_r > 8'd0) begin
                                                chain_value1_r <= chain_digest_be_w;
                                                chain_j1_r <= chain_j1_r + 1'b1;
                                                chain_steps_left1_r <= chain_steps_left1_r - 1'b1;
                                            end
                                            /* P2 step A: fold the next START_CORE -- latch the
                                             * next block (bg next view) + kick in this same
                                             * cycle, do not return to START_CORE. */
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            if (chain_steps_left0_r > 8'd1) begin
                                                core0_kick_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                            end else begin
                                                core0_kick_r <= 1'b0;
                                                core0_done_latched_r <= 1'b1;
                                            end
                                            if (batch_i1_w < w_p && chain_steps_left1_r > 8'd1) begin
                                                core1_kick_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                if (batch_i1_w < w_p && chain_steps_left1_r <= 8'd1) begin
                                                    /* 0-step/current-step wrap-up: core1 keeps
                                                     * completion state (line 1619 unconditionally
                                                     * cleared the latch, must be re-set) */
                                                    core1_done_latched_r <= 1'b1;
                                                end
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            if (!sign_next_pair_stall_w) begin
                                            /* P3: two chains complete -> y dual-write to task RAM
                                             * backgrounded (bg push executed by the dedicated
                                             * always); chain advance does not stall 16 cycles.
                                             * Tail single chain (odd p): done early (drain
                                             * continues 8 words). */
                                            if (batch_i1_w >= w_p) begin
                                                state_r <= STATE_IDLE;
                                                done_r <= 1'b1;
                                            end else begin
                                                /* Next-pair first DERIVE folded into this cycle
                                                 * (settle prevents false completion) */
                                                batch_i_r <= fold_next_i_w;
                                                batch_phase_r <= BATCH_DERIVE;
                                                batch_block_r  <= batch_rate_block_w;
                                                batch_block1_r <= core1_block_w;
                                                core0_init_r  <= batch_rate_init_w;
                                                core1_init_r  <= batch_rate_init_w;
                                                core0_kick_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                                dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p);
                                                if ((fold_next_i_w + 9'd1) < w_p) begin
                                                    core1_kick_r <= 1'b1;
                                                    core1_done_latched_r <= 1'b0;
                                                end else begin
                                                    core1_kick_r <= 1'b0;
                                                    core1_done_latched_r <= 1'b1;
                                                end
                                                fold_settle_r <= 1'b1;
                                                state_r <= STATE_WAIT_CORE;
                                            end
                                            end
                                        end
                                    end else begin
                                        /* KEYGEN / KEYGEN_LEAF / VERIFY dual core */
                                        if (batch_phase_r == BATCH_DERIVE) begin
                                            chain_value0_r <= kec_digest_be_w;
                                            chain_value1_r <= chain_digest_be_w;
                                            chain_j0_r <= 8'd0;
                                            chain_j1_r <= 8'd0;
                                            chain_steps_left0_r <= w_max_step;
                                            chain_steps_left1_r <= w_max_step;
                                            chain0_zero_r <= 1'b0;
                                            chain1_zero_r <= 1'b0;
                                            batch_phase_r <= BATCH_CHAIN;
                                            /* P2 step B: KEYGEN/VERIFY first CHAIN fold
                                             * (w_max_step always >0, both cores must kick). */
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            if (batch_i1_w < w_p) begin
                                                core1_kick_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else if (batch_phase_r == BATCH_CHAIN &&
                                                     (chain_steps_left0_r > 8'd1 ||
                                                      chain_steps_left1_r > 8'd1)) begin
                                            if (chain_steps_left0_r > 8'd0) begin
                                                chain_value0_r <= kec_digest_be_w;
                                                chain_j0_r <= chain_j0_r + 1'b1;
                                                chain_steps_left0_r <= chain_steps_left0_r - 1'b1;
                                            end
                                            if (chain_steps_left1_r > 8'd0) begin
                                                chain_value1_r <= chain_digest_be_w;
                                                chain_j1_r <= chain_j1_r + 1'b1;
                                                chain_steps_left1_r <= chain_steps_left1_r - 1'b1;
                                            end
                                            /* P2 step A: fold the next START_CORE (KEYGEN/VERIFY
                                             * same as SIGN). */
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            if (chain_steps_left0_r > 8'd1) begin
                                                core0_kick_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                            end else begin
                                                core0_kick_r <= 1'b0;
                                                core0_done_latched_r <= 1'b1;
                                            end
                                            if (batch_i1_w < w_p && chain_steps_left1_r > 8'd1) begin
                                                core1_kick_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                if (batch_i1_w < w_p && chain_steps_left1_r <= 8'd1) begin
                                                    /* 0-step/current-step wrap-up: core1 keeps
                                                     * completion state (same as above) */
                                                    core1_done_latched_r <= 1'b1;
                                                end
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else if (batch_phase_r == BATCH_CHAIN) begin
                                            /* Two chains complete: dual-write task RAM (unified
                                             * with SIGN; 0-step chain uses preserved
                                             * chain_value) */
                                            task_digest0_r <= chain0_zero_r ? chain_value0_r : kec_digest_be_w;
                                            task_digest1_r <= chain1_zero_r ? chain_value1_r : chain_digest_be_w;
                                            task_write_word0_r <= 3'd0;
                                            task_write_word1_r <= 3'd0;
                                            dual_write_sel_r <= 1'b0;
                                            state_r <= STATE_TASK_WRITE;
                                        end
                                    end
                                end
                            end
                        end
                    end
                    STATE_TASK_WRITE: begin
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (!dual_write_sel_r) begin
                            /* Write core0 chain (batch_i) 8 words */
                            if (task_write_word0_r == 3'd7) begin
                                if (dual_core1_active_r) begin
                                    dual_write_sel_r <= 1'b1;
                                    state_r <= STATE_TASK_WRITE;
                                end else if (batch_i_r == (w_p - 9'd1)) begin
                                    /* Last single chain (batch_i == p-1, odd p) written */
                                    if (command_r == CMD_LMOTS_SIGN) begin
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end else begin
                                        /* Final PBLc unified absorb: prefetch block 0 read
                                         * window */
                                        batch_phase_r <= BATCH_PBLC;
                                        pblc_final_block_r <= 7'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end
                                end else begin
                                    batch_i_r <= batch_i_r + 9'd2;
                                    if (verify_cmd_w) begin
                                        batch_phase_r <= BATCH_CHAIN;
                                        task_write_word_r <= 3'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end else begin
                                        batch_phase_r <= BATCH_DERIVE;
                                        /* P2 step B: next-pair first DERIVE folded into this
                                         * cycle (i=fold_next_i via bg view); core1 keeps
                                         * completion state on tail single chain. */
                                        if (fold_derive_w) begin
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p);
                                            if ((fold_next_i_w + 9'd1) < w_p) begin
                                                core1_kick_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            state_r <= STATE_START_CORE;
                                        end
                                    end
                                end
                            end else begin
                                task_write_word0_r <= task_write_word0_r + 1'b1;
                            end
                        end else begin
                            /* Write core1 chain (batch_i+1) 8 words */
                            if (task_write_word1_r == 3'd7) begin
                                dual_write_sel_r <= 1'b0;
                                if (batch_i1_w == (w_p - 9'd1)) begin
                                    /* core1 wrote the last chain (p-1): even p means this batch
                                     * is final, wrap up directly */
                                    if (command_r == CMD_LMOTS_SIGN) begin
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end else begin
                                        batch_phase_r <= BATCH_PBLC;
                                        pblc_final_block_r <= 7'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end
                                end else if (batch_i_r >= (w_p - 9'd3)) begin
                                    batch_i_r <= (w_p - 9'd1);
                                    if (verify_cmd_w) begin
                                        batch_phase_r <= BATCH_CHAIN;
                                        task_write_word_r <= 3'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end else begin
                                        batch_phase_r <= BATCH_DERIVE;
                                        /* P2 step B: next-pair first DERIVE folded into this
                                         * cycle (i=fold_next_i via bg view); core1 keeps
                                         * completion state on tail single chain. */
                                        if (fold_derive_w) begin
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p);
                                            if ((fold_next_i_w + 9'd1) < w_p) begin
                                                core1_kick_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            state_r <= STATE_START_CORE;
                                        end
                                    end
                                end else begin
                                    batch_i_r <= batch_i_r + 9'd2;
                                    if (verify_cmd_w) begin
                                        batch_phase_r <= BATCH_CHAIN;
                                        task_write_word_r <= 3'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end else begin
                                        batch_phase_r <= BATCH_DERIVE;
                                        /* P2 step B: next-pair first DERIVE folded into this
                                         * cycle (i=fold_next_i via bg view); core1 keeps
                                         * completion state on tail single chain. */
                                        if (fold_derive_w) begin
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p);
                                            if ((fold_next_i_w + 9'd1) < w_p) begin
                                                core1_kick_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            state_r <= STATE_START_CORE;
                                        end
                                    end
                                end
                            end else begin
                                task_write_word1_r <= task_write_word1_r + 1'b1;
                            end
                        end
                    end
                    STATE_TASK_PREFETCH: begin
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (hash_ram_path_w) begin
                            /* HASH_ONCE_RAM/MQC multi-block: block first word already prefetched
                             * (task RAM control), switch to read window */
                            state_r <= STATE_HASH_RAM_LOAD;
                        end else if (keygen_dleaf_r) begin
                            /* D_LEAF message already read combinationally by block construction
                             * (output_words holds K_q) */
                            state_r <= STATE_START_CORE;
                        end else if (batch_phase_r == BATCH_PBLC) begin
                            /* Final PBLc read-window prefetch: base+0 already read this cycle
                             * (task RAM control), consumed next cycle */
                            pblc_final_word_r <= 6'd0;
                            state_r <= STATE_PBLC_FINAL;
                        end else begin
                            /* Prefetch VERIFY chain input first word */
                            state_r <= STATE_TASK_LOAD;
                        end
                    end
                    STATE_TASK_LOAD: begin
                        cycle_count_r <= cycle_count_r + 32'd1;
                        /* Dual read: !verify_dual_load_r loads chain0 (batch_i), otherwise chain1
                         * (batch_i+1) */
                        if (!verify_dual_load_r) begin
                            chain_value0_r[255 - task_write_word_r * 32 -: 32] <= {
                                task_ram_read_r[7:0], task_ram_read_r[15:8],
                                task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        end else begin
                            chain_value1_r[255 - task_write_word_r * 32 -: 32] <= {
                                task_ram_read_r[7:0], task_ram_read_r[15:8],
                                task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        end
                        if (task_write_word_r == 3'd7) begin
                            if (!verify_dual_load_r) begin
                                /* chain0 load complete -> prefetch chain1 first word */
                                verify_dual_load_r <= 1'b1;
                                task_write_word_r <= 3'd0;
                                state_r <= STATE_TASK_PREFETCH;
                            end else begin
                                /* Both chains loaded -> first CHAIN block folded into this cycle
                                 * (P2 step C): j=coefficient, value=loaded y (chain1 last word
                                 * combined combinationally); 0-step chain (coefficient==
                                 * w_max_step) does not kick, keeps completion state. */
                                verify_dual_load_r <= 1'b0;
                                chain_j0_r <= batch_coefficient_w;
                                chain_j1_r <= batch_coefficient1_w;
                                chain_steps_left0_r <= w_max_step - batch_coefficient_w;
                                chain_steps_left1_r <= w_max_step - batch_coefficient1_w;
                                chain0_zero_r <= (batch_coefficient_w == w_max_step);
                                chain1_zero_r <= (batch_coefficient1_w == w_max_step);
                                batch_phase_r <= BATCH_CHAIN;
                                batch_block_r  <= batch_rate_block_w;
                                batch_block1_r <= core1_block_w;
                                core0_init_r  <= batch_rate_init_w;
                                core1_init_r  <= batch_rate_init_w;
                                dual_core1_active_r <= (batch_i1_w < w_p);
                                if (batch_coefficient_w != w_max_step) begin
                                    core0_kick_r <= 1'b1;
                                    core0_done_latched_r <= 1'b0;
                                end else begin
                                    core0_kick_r <= 1'b0;
                                    core0_done_latched_r <= 1'b1;
                                end
                                if (batch_i1_w < w_p && batch_coefficient1_w != w_max_step) begin
                                    core1_kick_r <= 1'b1;
                                    core1_done_latched_r <= 1'b0;
                                end else begin
                                    core1_kick_r <= 1'b0;
                                    if (batch_i1_w < w_p) begin
                                        core1_done_latched_r <= 1'b1;
                                    end
                                end
                                state_r <= STATE_WAIT_CORE;
                            end
                        end else begin
                            task_write_word_r <= task_write_word_r + 1'b1;
                        end
                    end
                    STATE_PBLC_FINAL: begin
                        /* Final PBLc read window: consumes task_ram_read_r each cycle
                         * (TASK_PREFETCH already prefetched the first word). word==RD_WORDS
                         * read full -> combinationally construct the block (block 0 header
                         * registers + 29 words aligned; blocks 1..14 full-block lane
                         * rearrangement; block 15 last block 126B + padding) -> kick core0
                         * absorb. */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (pblc_final_word_r == pblc_final_rd_words) begin
                            core0_kick_r  <= 1'b1;
                            core1_kick_r  <= 1'b0;
                            core0_init_r  <= (pblc_final_block_r == 7'd0);
                            core1_init_r  <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                            if (pblc_final_block_r == 7'd0) begin
                                /* Block 0: header 22B + window[byte0..113] (114B) */
                                batch_block_r <= {pblc_final_window_r[911:0], pblc_head_w};
                            end else if (pblc_final_block_r == w_pblc_last_block) begin
                                /* Last block: data (by w length) + 0x1F + 0x00.. + 0x80@135 */
                                batch_block_r <= pblc_last_block_w;
                            end else begin
                                /* Full block: window[byte2..137] (136B, fixed 2-byte lane
                                 * rearrangement) */
                                batch_block_r <= pblc_final_window_r[1103:16];
                            end
                            state_r <= STATE_WAIT_CORE;
                        end else begin
                            pblc_final_window_r[pblc_final_word_r * 32 +: 32] <= task_ram_read_r;
                            pblc_final_word_r <= pblc_final_word_r + 6'd1;
                        end
                    end
                    STATE_DINTR_PREFETCH: begin
                        /* Starting left first word (word32) already prefetched (task RAM
                         * control), consumed next cycle */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        state_r <= STATE_DINTR_LOAD_START;
                    end
                    STATE_DINTR_LOAD_START: begin
                        /* Read starting left 8 words (continuous big-endian, bytes reversed) */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        dintr_left_r[255 - dintr_load_word_r * 8'd32 -: 32] <= {
                            task_ram_read_r[7:0], task_ram_read_r[15:8],
                            task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        if (dintr_load_word_r == 4'd7) begin
                            dintr_load_word_r <= 4'd0;
                            state_r <= STATE_DINTR_LOAD_SIB;  /* sibling[0] first word already prefetched */
                        end else begin
                            dintr_load_word_r <= dintr_load_word_r + 1'b1;
                        end
                    end
                    STATE_DINTR_LOAD_SIB: begin
                        /* Read sibling[layer] 8 words; read full -> latch block + kick this
                         * cycle (P2 step C: KICK state folded, right last word combined
                         * combinationally via dintr_right_bg_w) */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        dintr_right_r[255 - dintr_load_word_r * 8'd32 -: 32] <= {
                            task_ram_read_r[7:0], task_ram_read_r[15:8],
                            task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        if (dintr_load_word_r == 4'd7) begin
                            dintr_load_word_r <= 4'd0;
                            batch_block_r <= batch_rate_block_w;
                            core0_kick_r <= 1'b1;
                            core1_kick_r <= 1'b0;
                            core0_init_r <= 1'b1;
                            core1_init_r <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                            state_r <= STATE_DINTR_CORE;
                        end else begin
                            dintr_load_word_r <= dintr_load_word_r + 1'b1;
                        end
                    end
                    STATE_DINTR_CORE: begin
                        /* Wait for core0 D_INTR absorb completion; per layer left=digest,
                         * node>>=1 */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        core0_kick_r <= 1'b0;
                        core1_kick_r <= 1'b0;
                        if (kec_ext_done_w) begin
                            if (dintr_layer_r + 1'b1 < {1'b0, arg_steps_r[4:0]}) begin
                                /* Next layer: left=digest, prefetch next sibling first word (task
                                 * RAM control) */
                                dintr_left_r <= kec_digest_be_w;
                                dintr_node_r <= dintr_node_r >> 1;
                                dintr_layer_r <= dintr_layer_r + 1'b1;
                                state_r <= STATE_DINTR_LOAD_SIB;
                            end else begin
                                /* N layers complete: output root (= this layer's digest,
                                 * big-endian -> little-endian words) to output_words */
                                for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                    output_words[out_oi[2:0]] <= {
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                        kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                end
                                state_r <= STATE_IDLE;
                                done_r <= 1'b1;
                            end
                        end
                    end
                    STATE_HASH_RAM_LOAD: begin
                        /* HASH_ONCE_RAM read window: consumes task_ram_read_r each cycle
                         * (TASK_PREFETCH already prefetched the block first word), read full
                         * hash_ram_rd_words_w -> switch to KICK (construct block). Padding block
                         * (rd_words=0) triggers construction on the first cycle, window stays all 0. */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (hash_ram_word_r == hash_ram_rd_words_w) begin
                            state_r <= STATE_HASH_RAM_KICK;
                        end else begin
                            pblc_final_window_r[hash_ram_word_r * 32 +: 32] <= task_ram_read_r;
                            hash_ram_word_r <= hash_ram_word_r + 1'b1;
                        end
                    end
                    STATE_HASH_RAM_KICK: begin
                        /* First cycle latches block + kicks core0 (block 0 init=1, later blocks
                         * continue the sponge); then wait for done. Last block complete ->
                         * output digest (big-endian -> little-endian words) to output_words. */
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (!hash_ram_kicked_r) begin
                            batch_block_r <= hash_ram_block_w;
                            core0_kick_r <= 1'b1;
                            core1_kick_r <= 1'b0;
                            core0_init_r <= (hash_ram_block_r == 4'd0);
                            core1_init_r <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                            hash_ram_kicked_r <= 1'b1;
                        end else begin
                            core0_kick_r <= 1'b0;
                            if (kec_ext_done_w) begin
                                hash_ram_kicked_r <= 1'b0;
                                if (hash_ram_block_r == hash_ram_full_r) begin
                                    if (mqc_multi_w) begin
                                        /* MQC multi-block last block: latch big-endian Q
                                         * (mqc_q_be_r + output_words little-endian words) ->
                                         * coefficient generation */
                                        mqc_q_be_r <= kec_digest_be_w;
                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        state_r <= STATE_MQC_COEF;
                                    end else begin
                                        /* Last block (incl. padding) complete: output digest */
                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end
                                end else begin
                                    hash_ram_block_r <= hash_ram_block_r + 1'b1;
                                    hash_ram_word_r <= 6'd0;
                                    state_r <= STATE_TASK_PREFETCH;
                                end
                            end
                        end
                    end
                    default: ;
                endcase
            end
        end
    end

    /* ---------- Task RAM control ---------- */
    reg task_ram_enable_w;
    reg task_ram_write_w;
    reg [11:0] task_ram_addr_w;
    reg [31:0] task_ram_wdata_w;
    always @* begin
        task_ram_enable_w = 1'b0;
        task_ram_write_w = 1'b0;
        task_ram_addr_w = 12'b0;
        task_ram_wdata_w = 32'b0;
        /* Stream port first (mutually exclusive with the MMIO task RAM port; usable when the
         * core is idle). */
        if (stream_wr_en && !wrapper_busy_w && stream_wr_addr < 2152) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = stream_wr_addr;
            task_ram_wdata_w = stream_wr_data;
        end else if (stream_rd_en && !wrapper_busy_w && stream_rd_addr < 2152) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = stream_rd_addr;
        end else if (!wrapper_busy_w && bus_valid && bus_write &&
            bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = task_addr_r;
            task_ram_wdata_w = bus_wdata;
        end else if (bg_drain_active_r) begin
            /* P3: SIGN background-write drain (1 word/cycle). First 8 words take core0 digest,
             * last 8 words take core1 digest (byte order same as the STATE_TASK_WRITE write
             * path). */
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = (bg_q_wrap[0] && bg_drain_idx_r[3]) ?
                              (12'd32 + {9'b0, bg_drain_idx_r[2:0]}) :
                              (bg_q_addr[0] + {8'b0, bg_drain_idx_r});
            if (bg_drain_idx_r[3]) begin
                task_ram_wdata_w = {
                    bg_q_d1[0][255 - (bg_drain_idx_r[2:0] * 32 + 24) -: 8],
                    bg_q_d1[0][255 - (bg_drain_idx_r[2:0] * 32 + 16) -: 8],
                    bg_q_d1[0][255 - (bg_drain_idx_r[2:0] * 32 + 8) -: 8],
                    bg_q_d1[0][255 - bg_drain_idx_r[2:0] * 32 -: 8]};
            end else begin
                task_ram_wdata_w = {
                    bg_q_d0[0][255 - (bg_drain_idx_r[2:0] * 32 + 24) -: 8],
                    bg_q_d0[0][255 - (bg_drain_idx_r[2:0] * 32 + 16) -: 8],
                    bg_q_d0[0][255 - (bg_drain_idx_r[2:0] * 32 + 8) -: 8],
                    bg_q_d0[0][255 - bg_drain_idx_r[2:0] * 32 -: 8]};
            end
        end else if (task_prefetch_pending_r) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
        end else if (state_r == STATE_TASK_WRITE) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            if (dual_write_sel_r) begin
                /* core1 write: address base = 32 + (batch_i+1)*8 */
                task_ram_addr_w = 12'd32 + {der_perm_bi1_w, 3'b0} + {9'b0, task_write_word1_r};
                task_ram_wdata_w = {
                    task_digest1_r[255 - (task_write_word1_r * 32 + 24) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 16) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 8) -: 8],
                    task_digest1_r[255 - task_write_word1_r * 32 -: 8]};
            end else begin
                /* core0 write: address base = 32 + batch_i*8 */
                task_ram_addr_w = 12'd32 + {der_perm_bi_w, 3'b0} + {9'b0, task_write_word0_r};
                task_ram_wdata_w = {
                    task_digest0_r[255 - (task_write_word0_r * 32 + 24) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 16) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 8) -: 8],
                    task_digest0_r[255 - task_write_word0_r * 32 -: 8]};
            end
        end else if (state_r == STATE_TASK_LOAD) begin
            task_ram_enable_w = 1'b1;
            if (verify_dual_load_r) begin
                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0} +
                    (task_write_word_r == 3'd7 ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end else begin
                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    (task_write_word_r == 3'd7 ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end
        end else if (state_r == STATE_TASK_PREFETCH && !keygen_dleaf_r) begin
            task_ram_enable_w = 1'b1;
            if (hash_ram_path_w)
                task_ram_addr_w = hash_ram_base_w;   /* HASH_ONCE_RAM/MQC multi-block block first word */
            else if (batch_phase_r == BATCH_PBLC)
                task_ram_addr_w = pblc_final_base_w;   /* final PBLc read-window first word */
            else
                task_ram_addr_w = 12'd32 +
                    (verify_dual_load_r ? {batch_i1_w, 3'b0} : {batch_i_r, 3'b0});
        end else if (state_r == STATE_PBLC_FINAL) begin
            /* Final PBLc read window: prefetch next word (last word not +1 to prevent
             * overflow; construction cycle address stays rd-1) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = pblc_final_base_w +
                (pblc_final_word_r >= pblc_final_rd_words - 6'd1 ?
                    (pblc_final_rd_words - 6'd1) : pblc_final_word_r + 6'd1);
        end else if (state_r == STATE_HASH_RAM_LOAD && hash_ram_rd_words_w != 6'd0) begin
            /* HASH_ONCE_RAM/MQC multi-block read window: prefetch next word (last word not +1
             * to prevent overflow; padding block reads no data) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = hash_ram_base_w +
                (hash_ram_word_r >= hash_ram_rd_words_w - 6'd1 ?
                    (hash_ram_rd_words_w - 6'd1) : hash_ram_word_r + 6'd1);
        end else if (state_r == STATE_DINTR_PREFETCH) begin
            /* Chained D_INTR: prefetch starting left first word (word32) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd32;
        end else if (state_r == STATE_DINTR_LOAD_START) begin
            /* Read starting left: words 0..6 prefetch next word (33..39); word7 prefetches
             * sibling[0] first word (40) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = (dintr_load_word_r == 4'd7) ? 12'd40 :
                               (12'd33 + dintr_load_word_r);
        end else if (state_r == STATE_DINTR_LOAD_SIB) begin
            /* Read sibling[layer]: words 0..6 prefetch next word; word7 does not prefetch */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r, 3'b0} +
                (dintr_load_word_r == 4'd7 ? 4'd7 : dintr_load_word_r + 1'b1);
        end else if (state_r == STATE_DINTR_CORE) begin
            /* During absorb, prefetch next layer's sibling first word (= word40 + (layer+1)*8) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r + 1'b1, 3'b0};
        end else if (!wrapper_busy_w && done_r && bus_valid && !bus_write &&
                     bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32 && !stream_read_r &&
                     !bg_busy_w) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
        end
    end
    /* P3: SIGN background write (push enqueue + drain in a single always; 1 word/cycle, not
     * counted in cycle_count). 2026-08-17 fixes (root causes of the FIFO-version batch FAIL,
     * four pitfalls in a row):
     * 1) bg_q_words was 4-bit, push writing 4'd16 truncated to 0 -> only 1 word drained per
     *    pair (root cause of all w1/2/4/8 SIGN wrong values) -> widened to 5 bits (5'd16);
     * 2) completion compare idx+1 used 4-bit add, idx=15 wraps -> 16-word pair never completes
     *    (potential deadlock) -> changed to {1'b0,idx}+5'd1 5-bit compare;
     * 3) push and drain completion in the same cycle: old code shifted reading the old empty
     *    slot1 and later wrote valid[1]=0, clobbering the new push (whole pair lost) ->
     *    when there is a push on the completion cycle, it lands directly in the freed slot0
     *    (no shifting, slot1 untouched);
     * 4) tail-pair detection used batch_i1_w (already the next-pair view on the push cycle) ->
     *    the penultimate pair was misjudged as 8 words -> changed to batch_i_r (this pair's
     *    index): batch_i_r >= w_p-1 is the true tail single-chain pair. */
    always @(posedge clk) begin
        if (rst) begin
            bg_drain_active_r <= 1'b0;
            bg_drain_idx_r    <= 4'd0;
            bg_q_valid[0]     <= 1'b0;
            bg_q_valid[1]     <= 1'b0;
            bg_q_addr[0]      <= 12'd0;
            bg_q_addr[1]      <= 12'd0;
            bg_q_words[0]     <= 5'd0;
            bg_q_words[1]     <= 5'd0;
            bg_q_wrap[0]      <= 1'b0;
            bg_q_wrap[1]      <= 1'b0;
        end else begin
            if (bg_drain_active_r) begin
                if ({1'b0, bg_drain_idx_r} + 5'd1 >= bg_q_words[0]) begin
                    /* Completion cycle: slot0 freed; a same-cycle push lands directly in slot0
                     * (no shifting, slot1 untouched) */
                    bg_drain_active_r <= 1'b0;
                    bg_drain_idx_r    <= 4'd0;
                    if (bg_push_w) begin
                        bg_q_d0[0]    <= bg_digest0_sel_w;
                        bg_q_d1[0]    <= bg_digest1_sel_w;
                        bg_q_addr[0]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[0] <= (batch_i_r >= (w_p - 9'd1)) ? 5'd8 : 5'd16;
                        bg_q_valid[0] <= 1'b1;
                        bg_q_wrap[0]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end else begin
                        bg_q_valid[0] <= bg_q_valid[1];
                        bg_q_d0[0]    <= bg_q_d0[1];
                        bg_q_d1[0]    <= bg_q_d1[1];
                        bg_q_addr[0]  <= bg_q_addr[1];
                        bg_q_words[0] <= bg_q_words[1];
                        bg_q_wrap[0]  <= bg_q_wrap[1];
                        bg_q_valid[1] <= 1'b0;
                    end
                end else begin
                    bg_drain_idx_r <= bg_drain_idx_r + 4'd1;
                    /* Same-cycle push: slot0 busy (draining) -> enter slot1.
                     * Double-full overwriting slot1 theoretically unreachable: push spacing
                     * >=16 cycles = one pair's drain duration, slot1 only holds data 1 cycle
                     * before slot0 completes; still keep the overwrite fallback (keeps new
                     * data). */
                    if (bg_push_w) begin
                        bg_q_d0[1]    <= bg_digest0_sel_w;
                        bg_q_d1[1]    <= bg_digest1_sel_w;
                        bg_q_addr[1]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[1] <= (batch_i_r >= (w_p - 9'd1)) ? 5'd8 : 5'd16;
                        bg_q_valid[1] <= 1'b1;
                        bg_q_wrap[1]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end
                end
            end else begin
                if (bg_push_w) begin
                    if (!bg_q_valid[0]) begin
                        bg_q_d0[0]    <= bg_digest0_sel_w;
                        bg_q_d1[0]    <= bg_digest1_sel_w;
                        bg_q_addr[0]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[0] <= (batch_i_r >= (w_p - 9'd1)) ? 5'd8 : 5'd16;
                        bg_q_valid[0] <= 1'b1;
                        bg_q_wrap[0]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end else if (!bg_q_valid[1]) begin
                        bg_q_d0[1]    <= bg_digest0_sel_w;
                        bg_q_d1[1]    <= bg_digest1_sel_w;
                        bg_q_addr[1]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[1] <= (batch_i_r >= (w_p - 9'd1)) ? 5'd8 : 5'd16;
                        bg_q_valid[1] <= 1'b1;
                        bg_q_wrap[1]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end else begin
                        /* Double-full fallback (unreachable, see above): overwrite slot1 to keep
                         * new data */
                        bg_q_d0[1]    <= bg_digest0_sel_w;
                        bg_q_d1[1]    <= bg_digest1_sel_w;
                        bg_q_addr[1]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[1] <= (batch_i_r >= (w_p - 9'd1)) ? 5'd8 : 5'd16;
                        bg_q_valid[1] <= 1'b1;
                        bg_q_wrap[1]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end
                end
                if (bg_q_valid[0]) begin
                    bg_drain_active_r <= 1'b1;
                    bg_drain_idx_r    <= 4'd0;
                end
            end
        end
    end
    always @(posedge clk) begin
        if (task_ram_enable_w) begin
            if (task_ram_write_w) begin
                task_words[task_ram_addr_w] <= task_ram_wdata_w;
            end else begin
                task_ram_read_r <= task_words[task_ram_addr_w];
            end
        end
        if (rst) begin
            task_ram_read_r <= 32'b0;
        end
    end

    /* Auto-increment read/write: address increments (read side consistent with SHA-256; write
     * side added 2026-08-07). task_addr_r's only owner: bus write (REG_TASK_ADDR), reset,
     * write auto-increment, read auto-increment all collected in this always, avoiding
     * cross-always multi-driven (Vivado Synth 8-6859). Write auto-increment (REG_TASK_DATA
     * write and address >=17): write transaction bus_valid is a single cycle, no gating flag
     * needed; read auto-increment needs stream_read_r gating (read transaction bus_valid high
     * for 2 cycles). */
    always @(posedge clk) begin
        if (rst) begin
            task_addr_r <= 12'b0;
            stream_read_r <= 1'b0;
            stream_rd_pending_r <= 1'b0;
        end else begin
            /* Stream read request latch: set 1 on request cycle, output next cycle
             * (task_ram_read_r already updated). */
            if (stream_rd_en && !wrapper_busy_w) begin
                stream_rd_pending_r <= 1'b1;
            end else begin
                stream_rd_pending_r <= 1'b0;
            end
            /* MMIO task RAM access yields during stream-port activity (mutual exclusion,
             * prevents address auto-increment from being triggered by mistake) */
            if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && bus_valid && bus_write &&
                bus_addr[9:0] == REG_TASK_ADDR && bus_wdata < 2152) begin
                task_addr_r <= bus_wdata[11:0];
            end else if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && bus_valid && bus_write &&
                bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32) begin
                /* Write-side auto-increment: firmware does one ADDR + consecutive DATA,
                 * saving hundreds of address writes */
                task_addr_r <= task_addr_r + 12'd1;
            end else if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && done_r && bus_valid && !bus_write &&
                bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32 && !stream_read_r && !bg_busy_w) begin
                task_addr_r <= task_addr_r + 12'd1;
                stream_read_r <= 1'b1;
            end else if (!bus_valid) begin
                stream_read_r <= 1'b0;
            end
        end
    end

    /* ---------- Stream port output ---------- */
    assign stream_busy      = wrapper_busy_w || bg_busy_w;
    assign stream_rd_valid  = stream_rd_pending_r;
    assign stream_rd_data   = stream_rd_pending_r ? task_ram_read_r : 32'b0;

    /* ---------- Read ---------- */
    always @* begin
        bus_rdata = 32'b0;
        case (bus_addr[9:0])
            REG_VERSION: bus_rdata = VERSION;
            REG_CAPABILITY: bus_rdata = CAPABILITY;
            REG_STATUS: bus_rdata = (wrapper_busy_w || bg_busy_w) ? STATUS_BUSY :
                                     (done_r ? STATUS_DONE : 32'b0) |
                                     (error_status_r ? STATUS_ERROR : 32'b0);
            REG_ERROR: bus_rdata = error_r;
            REG_OUTPUT_LENGTH: bus_rdata = output_length_r;
            REG_CYCLE_COUNT: bus_rdata = (batch_cmd_w || dintr_cmd_w || hash_ram_cmd_w ||
                                          sec_cmd_pending_w) ? cycle_count_r : engine_cycle_w;
            REG_SIM_MC: bus_rdata = sec_bus_rdata_w;   /* security-domain monotonic counter (SEC slot) */
            REG_ARG_LEAF_NODE: bus_rdata = arg_leaf_node_r;
            REG_ARG_W: bus_rdata = {28'b0, arg_w_r};
            REG_TASK_ADDR: bus_rdata = {20'b0, task_addr_r};
            REG_TASK_DATA: begin
                if (task_addr_r < 32) begin
                    bus_rdata = coefficient_words[task_addr_r[4:0]];
                end else begin
                    bus_rdata = task_ram_read_r;
                end
            end
            default: begin
                if (bus_addr[9:0] >= REG_IDENTIFIER &&
                    bus_addr[9:0] < REG_IDENTIFIER + 16) begin
                    bus_rdata = identifier_words[(bus_addr[9:0] - REG_IDENTIFIER) >> 2];
                end else if (bus_addr[9:0] >= REG_SEED_BASE &&
                             bus_addr[9:0] < REG_SEED_BASE + 32) begin
                    bus_rdata = sec_bus_rdata_w;   /* SEED not readable (SEC returns 0) */
                end else if (bus_addr[9:0] >= REG_WRAPPED_BASE &&
                             bus_addr[9:0] < REG_WRAPPED_BASE + 48) begin
                    bus_rdata = sec_bus_rdata_w;   /* WRAPPED 48B (SEC slot, wrap output) */
                end else if (bus_addr[9:0] >= REG_KWRAP_BASE &&
                             bus_addr[9:0] < REG_KWRAP_BASE + 32) begin
                    bus_rdata = sec_bus_rdata_w;   /* K_WRAP/K_STATE not readable (SEC returns 0) */
                end else if (bus_addr[9:0] >= REG_INPUT_BASE &&
                             bus_addr[9:0] < REG_INPUT_BASE + 128) begin
                    bus_rdata = input_words[(bus_addr[9:0] - REG_INPUT_BASE) >> 2];
                end else if (bus_addr[9:0] >= REG_OUTPUT_BASE &&
                             bus_addr[9:0] < REG_OUTPUT_BASE + 32) begin
                    bus_rdata = output_words[(bus_addr[9:0] - REG_OUTPUT_BASE) >> 2];
                end
            end
        endcase
    end

endmodule

`default_nettype wire
