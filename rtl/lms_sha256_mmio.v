`default_nettype none

/* Command validation has been moved to lms_hash_cmd_check.v; some CMD_xx / ERR_xx constants
 * of this module are no longer used directly inside the wrapper (-Wall reports UNUSEDPARAM). */
/* verilator lint_off WIDTHTRUNC */
/* verilator lint_off WIDTHEXPAND */
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */

module lms_sha256_mmio #(
    parameter INSECURE_TEST_MODE = 0,
    parameter HAS_SECURITY = 1      // 1=include WRAP/UNWRAP/HMAC/MC; 0=pure LMS algorithm
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        bus_valid,
    input  wire        bus_write,
    input  wire [9:0]  bus_addr,
    input  wire [31:0] bus_wdata,
    output reg  [31:0] bus_rdata,
    /* Task RAM stream port (UART bridge passthrough; same semantics as the SHAKE256 wrapper).
     * Write: stream_wr_en writes 1 word in a single cycle; read: stream_rd_en requests in one
     *    cycle, stream_rd_valid/stream_rd_data valid on the next. Usable while core idle (!stream_busy). */
    input  wire        stream_wr_en,
    input  wire [11:0] stream_wr_addr,
    input  wire [31:0] stream_wr_data,
    input  wire        stream_rd_en,
    input  wire [11:0] stream_rd_addr,
    output wire        stream_rd_valid,
    output wire [31:0] stream_rd_data,
    output wire        stream_busy
);
    localparam [31:0] VERSION = 32'h00000007;
    localparam [31:0] CAPABILITY = 32'h000000ef |
        (INSECURE_TEST_MODE ? 32'h00000010 : 32'h00000000) |
        32'h00000300 | 32'h00000400 |
        32'h00002000 |                                  /* bit13: D_INTR_CHAIN (S6 chained primitive) */
        32'h00004000 |                                  /* bit14: MSG_Q_COEF (S8 message hash -> Q -> checksum -> coefficients) */
        (HAS_SECURITY ? 32'h00000800 : 32'h00000000) |
        (HAS_SECURITY ? 32'h00008000 : 32'h00000000);  /* bit15: STATE_COMMIT (S9 fused command) */

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
    localparam [9:0] REG_TASK_ADDR     = 10'h038;
    localparam [9:0] REG_TASK_DATA     = 10'h03c;
    localparam [9:0] REG_IDENTIFIER    = 10'h040;
    localparam [9:0] REG_SIM_MC        = 10'h060;  /* Space fixed: moved here from 0x044 (permanently resolves overlap with IDENTIFIER) */
    localparam [9:0] REG_ARG_LEAF_NODE = 10'h050;
    localparam [9:0] REG_ARG_W         = 10'h054;  /* Winternitz w (1/2/4/8), batch task parameter; default 4 */
    localparam [9:0] REG_SEED_BASE     = 10'h080;
    localparam [9:0] REG_WRAPPED_BASE  = 10'h0a0;  /* 48B: 0x0a0..0x0cf */
    localparam [9:0] REG_KWRAP_BASE    = 10'h0e0;  /* 32B: 0x0e0..0x0ff, 32-aligned (no overlap with WRAPPED) */
    localparam [9:0] REG_INPUT_BASE    = 10'h100;
    localparam [9:0] REG_OUTPUT_BASE   = 10'h200;

    localparam [31:0] CMD_HASH_ONCE = 32'h00000001;
    localparam [31:0] CMD_HASH_ONCE_RAM = 32'h00000019;  /* S7: multi-block absorb from task RAM (<=2048B) */
    localparam [31:0] CMD_MSG_Q_COEF = 32'h0000001a;     /* S8: message hash -> Q -> checksum -> coefficients */
    localparam [31:0] CMD_CHAIN = 32'h00000002;
    localparam [31:0] CMD_SEED_LOAD = 32'h00000003;
    localparam [31:0] CMD_DERIVE_CHAIN = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER = 32'h00000005;
    localparam [31:0] CMD_LMOTS_KEYGEN = 32'h00000006;
    localparam [31:0] CMD_LMOTS_SIGN = 32'h00000007;
    localparam [31:0] CMD_LMOTS_VERIFY = 32'h00000008;
    localparam [31:0] CMD_MC_STEP = 32'h00000010;
    localparam [31:0] CMD_MC_LOAD = 32'h00000011;
    localparam [31:0] CMD_WRAP_SEED = 32'h00000012;
    localparam [31:0] CMD_UNWRAP_SEED = 32'h00000013;
    localparam [31:0] CMD_HMAC_KSTATE = 32'h00000014;
    localparam [31:0] CMD_D_INTR_CHAIN = 32'h00000018;  /* S6: chained D_INTR auth path (single MMIO yields root) */
    localparam [31:0] CMD_LMOTS_KEYGEN_LEAF = 32'h0000000e;
    localparam [31:0] CMD_LMOTS_VERIFY_LEAF = 32'h0000000f;
    localparam [31:0] CTRL_START = 32'h00000001;
    localparam [31:0] CTRL_CLEAR = 32'h00000002;

    localparam [31:0] STATUS_BUSY  = 32'h00000001;
    localparam [31:0] STATUS_DONE  = 32'h00000002;
    localparam [31:0] STATUS_ERROR = 32'h00000004;

    /* Error codes are bit-for-bit synonymous with the same-named localparams in lms_hash_cmd_check.v (REVIEW X-03):
     * the unified command check outputs a 32-bit error_code written straight to error_r; this table
     * remains only for local error sources (ERR_BUSY/ERR_CONTROL etc.). Keep both sides in sync. */
    localparam [31:0] ERR_UNSUPPORTED_COMMAND = 32'h00000001;
    localparam [31:0] ERR_BUSY                = 32'h00000002;
    localparam [31:0] ERR_INPUT_LENGTH        = 32'h00000003;
    localparam [31:0] ERR_OUTPUT_LENGTH       = 32'h00000004;
    localparam [31:0] ERR_CHAIN_INDEX         = 32'h00000005;
    localparam [31:0] ERR_CHAIN_RANGE         = 32'h00000006;
    localparam [31:0] ERR_CONTROL             = 32'h00000007;
    localparam [31:0] ERR_KEY_HANDLE          = 32'h00000008;
    localparam [31:0] ERR_SEED_NOT_LOADED     = 32'h00000009;
    localparam [31:0] ERR_INSECURE_DISABLED   = 32'h0000000a;

    localparam [3:0] STATE_IDLE          = 4'd0;
    localparam [3:0] STATE_START_CORE    = 4'd1;
    localparam [3:0] STATE_WAIT_CORE     = 4'd2;
    localparam [3:0] STATE_TASK_WRITE    = 4'd3;
    localparam [3:0] STATE_TASK_LOAD     = 4'd4;
    localparam [3:0] STATE_TASK_ENDPOINT = 4'd5;
    localparam [3:0] STATE_TASK_PREFETCH = 4'd6;
    /* Dual-core parallel states (used only by LMOTS_KEYGEN/SIGN/VERIFY) */
    localparam [3:0] STATE_DUAL_WAIT     = 4'd7;  /* Wait for both cores to finish */
    localparam [3:0] STATE_DUAL_SETUP1   = 4'd8;  /* Set up core1 (core0 running) */
    /* Chained D_INTR primitive states (CMD_D_INTR_CHAIN, Verify auth-path batching, S6) */
    localparam [3:0] STATE_DINTR_PREFETCH    = 4'd9;
    localparam [3:0] STATE_DINTR_LOAD_START  = 4'd10;
    localparam [3:0] STATE_DINTR_LOAD_SIB    = 4'd11;
    localparam [3:0] STATE_DINTR_KICK        = 4'd12;
    localparam [3:0] STATE_DINTR_CORE        = 4'd13; /* REVIEW B08-R2: no state_r<=STATE_DINTR_CORE assignment exists (dead state); only referenced in a combinational condition around line 870, which never holds; definition kept pending dead-path cleanup */
    /* HASH_ONCE_RAM multi-block absorb states (CMD_HASH_ONCE_RAM, task RAM input, S7).
     * First-block prefetch reuses STATE_TASK_PREFETCH (combinational read branches on hash_ram_cmd_w). */
    localparam [3:0] STATE_HASH_RAM_LOAD     = 4'd14;  /* Read window (consume + prefetch next word each cycle) */
    localparam [3:0] STATE_HASH_RAM_KICK     = 4'd15;  /* Window full -> build block + kick core0 */
    /* MQC coefficient generation state (CMD_MSG_Q_COEF, S8): after last-block digest latched, produce 1 coefficient per cycle */
    localparam [4:0] STATE_MQC_COEF         = 5'd16;

    /* Action class returned by the unified command check (lms_hash_cmd_check) */
    localparam [3:0] ACT_START       = 4'd0;
    localparam [3:0] ACT_DONE_SEED   = 4'd1;
    localparam [3:0] ACT_DONE_CHAIN0 = 4'd2;
    localparam [3:0] ACT_DONE_KWRAP  = 4'd3;
    localparam [3:0] ACT_DONE_KSTATE = 4'd4;
    localparam [3:0] ACT_DONE_MC     = 4'd5;
    localparam [3:0] ACT_START_HMAC  = 4'd6;
    localparam [3:0] ACT_START_WRAP  = 4'd7;
    localparam [3:0] ACT_START_STC   = 4'd8;  /* Enabled by S9 (unreachable when cmd_check HAS_STATE_COMMIT=0) */

    reg [31:0] command_r;
    reg [31:0] input_length_r;
    reg [31:0] output_length_r;
    reg [31:0] arg_q_r;
    reg [31:0] arg_i_r;
    reg [31:0] arg_start_r;
    reg [31:0] arg_steps_r;
    reg [31:0] arg_key_r;
    reg [31:0] identifier_words [0:3];
    /* input/output/identifier window registers are intentionally not reset (REVIEW B08-R9):
     * they rely on protocol ordering "write before read"; reset semantics gated by the xprop
     * regression (run_soc_xprop --x-initial unique); a "read before write" path must add reset. */
    /* Local SEED slot (reproduces the 0.1.235 plaintext path when HAS_SECURITY=0; when
     * HAS_SECURITY=1, lms_sha256_sec takes over and this slot is unused). */
    reg [31:0] local_seed_staging [0:7];
    reg [255:0] local_seed_r;
    reg local_seed_valid_r;
    reg [31:0] error_r;
    reg [31:0] cycle_count_r;
    reg [31:0] input_words [0:31];
    reg [31:0] output_words [0:7];
    (* ram_style = "block" *) reg [31:0] task_words [0:2151];
    reg [31:0] coefficient_words [0:31];
    reg [11:0] task_addr_r;
    reg [31:0] task_ram_read_r;
    reg task_prefetch_pending_r;
    reg [2:0] task_write_word_r;
    reg [255:0] task_digest_r;
    reg [4:0] state_r;
    reg [1:0] block_index_r;
    reg [1:0] block_count_r;
    reg done_r;
    reg error_status_r;
    reg stream_read_r;         /* Auto-increment read active flag, prevents multi-cycle repeats */
    reg stream_rd_pending_r;   /* Stream read request latch: set on request cycle, stream_rd_valid next cycle */
    reg busy_error_pending_r;
    reg core_start_r;
    reg engine_start_r;
    reg [255:0] chain_value_r;
    reg [7:0] chain_j_r;
    reg [7:0] chain_steps_left_r;
    /* Dual-core parallel: batch_i increments by 2 for LMOTS_KEYGEN/SIGN/VERIFY, each core processes one chain */
    /* verilator lint_off UNUSEDSIGNAL */
    reg core_start0_r;
    reg core_start1_r;
    reg core0_done_latched_r;  /* Latch core0 done (done is a single-cycle pulse) */
    reg core1_done_latched_r;  /* Latch core1 done */
    reg dual_pblc_delay_r;     /* Delay PBLc one cycle for pblc_buffer to settle */
    reg [255:0] chain_value0_r;
    reg [255:0] chain_value1_r;
    reg [7:0] chain_j0_r;
    reg [7:0] chain_j1_r;
    reg [7:0] chain_steps_left0_r;
    reg [7:0] chain_steps_left1_r;
    reg [255:0] task_digest0_r;
    reg [255:0] task_digest1_r;
    reg [2:0] task_write_word0_r;
    reg [2:0] task_write_word1_r;
    reg dual_write_sel_r;      /* Dual-core Task RAM write select: 0=core0, 1=core1 */
    reg verify_dual_load_r;     /* Verify dual-core Task RAM load of chain i+1 flag */
    reg verify_dc_mode_r;       /* Verify: current batch uses dual-core CHAIN+PBLc */
    reg core0_run_r;            /* core0 start enable: prevents auto-restart of a core that finished early on an asymmetric chain */
    reg core1_run_r;            /* core1 start enable: same as above */
    /* verilator lint_on UNUSEDSIGNAL */
    localparam [1:0] BATCH_DERIVE = 2'd0;
    localparam [1:0] BATCH_CHAIN  = 2'd1;
    localparam [1:0] BATCH_PBLC   = 2'd2;
    reg [1:0] batch_phase_r;
    reg [8:0] batch_i_r;
    reg [3:0]  arg_w_r;               /* Winternitz w (1/2/4/8), batch task parameter; default 4 */
    /* arg_w_r is in {1,2,4,8} (default 4=W4 keeps zero regression). SHA-256 PBLc is a 64B-block
     * sliding window (22B header + 32B per chain concatenated, one block per 64B), independent of
     * w; w only affects chain count p and the last-block tail (p odd: 54B+pad; p even: 22B+pad final). */
    reg  [8:0]  w_p;               /* Chain count 265/133/67/34 */
    reg  [3:0]  w_coef_bits;       /* Coefficient width 1/2/4/8 */
    reg  [7:0]  w_max_step;        /* Max chain steps 2^w-1 = 1/3/15/255 */
    wire [8:0]  w_p_last = w_p - 9'd1;   /* Last chain index (p-1) */
    wire        w_p_even = !w_p[0];      /* p even (W8=34): PBLc needs residual-window final block */
    always @* begin
        /* Winternitz chain count p = ceil(256/w)+checksum (RFC 8554 section 5, REVIEW B08-R7):
         * w=1->265, w=2->133, w=4->67, w=8->34; default (including illegal w) collapses to W4. */
        case (arg_w_r)
            4'd1: begin w_p = 9'd265; w_coef_bits = 4'd1; w_max_step = 8'd1;   end
            4'd2: begin w_p = 9'd133; w_coef_bits = 4'd2; w_max_step = 8'd3;   end
            4'd8: begin w_p = 9'd34;  w_coef_bits = 4'd8; w_max_step = 8'd255; end
            default: begin w_p = 9'd67; w_coef_bits = 4'd4; w_max_step = 8'd15; end
        endcase
    end
    /* VERIFY and VERIFY_LEAF share the whole batch task path (they differ only in whether D_LEAF is computed at the chain tail) */
    wire verify_cmd_w = (command_r == CMD_LMOTS_VERIFY ||
                         command_r == CMD_LMOTS_VERIFY_LEAF);
    wire dual_batch_w = (command_r == CMD_LMOTS_KEYGEN ||
                         command_r == CMD_LMOTS_KEYGEN_LEAF ||
                         command_r == CMD_LMOTS_SIGN ||
                         verify_cmd_w);
    wire [8:0] batch_i1_w = batch_i_r + 9'd1;  /* batch index for core1 */
    wire dual_active_w = dual_batch_w && (batch_phase_r != BATCH_PBLC) &&
        (!verify_cmd_w || verify_dc_mode_r) &&
        (command_r != CMD_LMOTS_SIGN || batch_i1_w < w_p);
    /* Winternitz coefficient extraction (packed, sliced by w-bit width; same layout as SHAKE256):
     *   W1: 32 1-bit per word, index = batch_i>>5 / [batch_i&31]
     *   W2: 16 2-bit per word, index = batch_i>>4 / [batch_i&15]*2
     *   W4: 8 4-bit per word, index = batch_i>>3 / [batch_i&7]*4
     *   W8: 4 8-bit per word, index = batch_i>>2 / [batch_i&3]*8 */
    reg [7:0] batch_coefficient_w;
    reg [7:0] batch_coefficient1_w;
    always @* begin
        case (w_coef_bits)
            4'd1: begin
                batch_coefficient_w = {7'b0, coefficient_words[batch_i_r[8:5]][batch_i_r[4:0]]};
                batch_coefficient1_w = {7'b0, coefficient_words[batch_i1_w[8:5]][batch_i1_w[4:0]]};
            end
            4'd2: begin
                batch_coefficient_w = {6'b0, coefficient_words[batch_i_r[8:4]][batch_i_r[3:0] * 2 +: 2]};
                batch_coefficient1_w = {6'b0, coefficient_words[batch_i1_w[8:4]][batch_i1_w[3:0] * 2 +: 2]};
            end
            4'd4: begin
                batch_coefficient_w = {4'b0, coefficient_words[batch_i_r[8:3]][batch_i_r[2:0] * 4 +: 4]};
                batch_coefficient1_w = {4'b0, coefficient_words[batch_i1_w[8:3]][batch_i1_w[2:0] * 4 +: 4]};
            end
            default: begin   /* W8: 4 8-bit per word */
                batch_coefficient_w = coefficient_words[batch_i_r[8:2]][batch_i_r[1:0] * 8 +: 8];
                batch_coefficient1_w = coefficient_words[batch_i1_w[8:2]][batch_i1_w[1:0] * 8 +: 8];
            end
        endcase
    end
    reg pblc_final_due_r;      /* p-even (W8) residual-window final block pending absorb flag */
    reg keygen_dleaf_r;        /* D_LEAF hash phase of KEYGEN_LEAF */
    reg [31:0] arg_leaf_node_r; /* node_num for D_LEAF = 2^h + q */
    reg [7:0] pblc_block_count_r;
    reg [255:0] pblc_state_r;
    reg [511:0] pblc_buffer_r;
    reg [511:0] pblc_block_r;
    /* Chained D_INTR primitive (CMD_D_INTR_CHAIN, S6): N consecutive D_INTR auth-path hash chain
     * layers (used by Verify; OTS/LMS layering: VERIFY_LEAF handles OTS->leaf, this primitive
     * handles LMS tree hashing; root comparison stays in software). Input: task RAM word32..39=
     * starting left, word40+layer*8=sibling[layer] (8 words each); I=identifier, node=arg_leaf_node, N=arg_steps. */
    reg [255:0] dintr_left_r;      /* Current-layer left (contiguous big-endian, byte0 is MSB; initially the leaf) */
    reg [255:0] dintr_right_r;     /* Current-layer right/sibling (same layout as left) */
    reg [31:0]  dintr_node_r;      /* Current-layer node_num (starting at the leaf, >>1 per layer) */
    /* P1-6 q=1 fix: command arg is the leaf node (incl. parity bit). Layer-k concatenation
     * direction by current node parity (odd -> sibling||cur, RFC 8554 lms_root_from_signature
     * semantics); in-block node = current node>>1 (parent); old arg=leaf>>1 lost leaf parity -> wrong layer-0 direction when q odd. */
    wire [31:0] dintr_block_node_w = dintr_node_r >> 1;
    wire        dintr_swap_w       = dintr_node_r[0];
    reg [4:0]   dintr_layer_r;     /* Current layer number (0..N-1) */
    reg [3:0]   dintr_load_word_r; /* Task RAM read word (0..7) */
    wire dintr_cmd_w = command_r == CMD_D_INTR_CHAIN;

    /* HASH_ONCE_RAM multi-block absorb (CMD_HASH_ONCE_RAM, S7): message hash H(I||q||0x8181||C||M)
     * for large messages (54+len > 128B, <=2048B). Input written to task RAM starting at word32
     * (54+len bytes, firmware uses one ADDR + consecutive DATA); hardware absorbs in 64B blocks
     * (block0 init, state continues), SHA-256 padding on last block (0x80@total + 8B length). */
    reg [5:0]   hash_ram_block_r;  /* Current block number (0..32; init=(block==0)) */
    reg [5:0]   hash_ram_word_r;   /* Words read so far in current block (0..17) */
    reg [575:0] hash_ram_window_r; /* Current block read window (word w at [575-w*32-:32], loaded byte-reversed;
                                     * 18 words: MQC block0 header 14w+message 4w, others use first 16w) */
    wire hash_ram_cmd_w = command_r == CMD_HASH_ONCE_RAM;
    wire [11:0] hash_ram_total_w = input_length_r[11:0];   /* Total bytes (incl. 54B prefix; firmware passes full length <=2048) */
    wire [11:0] hash_ram_block_base_w = {hash_ram_block_r, 6'b0};   /* Block start byte */
    wire [11:0] hash_ram_rem_w = (hash_ram_block_base_w < hash_ram_total_w)
        ? (hash_ram_total_w - hash_ram_block_base_w) : 12'd0;      /* Remaining bytes in this block */
    wire [5:0]  hash_ram_blocks_w =
        (hash_ram_total_w + 12'd9 + 12'd63) >> 6;                  /* Total blocks (+9=0x80+8B length) */
    /* MQC block k>=1 remaining message bytes = L - 64k (saturating 0; block0 always reads full
     * 18 words: header 14w + message 4w). Blocks k>=1 have a +2 window offset (message starts at
     * window byte2) -> words to read = min(18, ceil((d+2)/4)) */
    wire [11:0] mqc_block_data_w = (hash_ram_block_r == 6'd0) ? 12'd64 :
        ((hash_ram_total_w > hash_ram_block_base_w)
         ? (hash_ram_total_w - hash_ram_block_base_w) : 12'd0);
    wire [5:0]  hash_ram_rd_words_w =
        mqc_cmd_w ?
            ((hash_ram_block_r == 6'd0) ? 6'd18 :
             ((mqc_block_data_w == 12'd0) ? 6'd0 :
              ((mqc_block_data_w + 12'd5 >= 12'd72) ? 6'd18 :
               ((mqc_block_data_w + 12'd5) >> 2))))
        : ((hash_ram_rem_w >= 12'd64) ? 6'd16
            : ((hash_ram_rem_w + 12'd3) >> 2));                    /* Words to read in this block (0 = pure padding block) */
    wire [63:0] hash_ram_bitlen_w = {52'b0, hash_ram_total_w} << 3; /* Total bit count (last-block length field) */

    /* MSG_Q_COEF (S8): message hash (multi-block read window, same FSM as HASH_ONCE_RAM) ->
     * latch Q -> checksum -> p coefficients packed into coefficient_words. Input layout
     * (aligned with lms_mmio.c P3): header 54B (I||q little-endian||0x8181||C) written to task
     * RAM mqc_base, message at mqc_base+14 words (+56B); block0 = header 54B + message 8B
     * (byte54/55 hole=0) + padding, blocks k>=1 = message 64B flat. mqc_base: short messages
     * (L<=128) use w=32+p*8 words (W4=568/W2=1096/W8=304; W1 y fills task RAM -> 568), large (L>128) fixed 568. */
    reg [271:0] mqc_q_be_r;      /* Q(256) || checksum(16) forward view (byte0=MSB) */
    reg [15:0]  mqc_checksum_r;  /* checksum accumulation (not shifted) */
    reg [8:0]   mqc_idx_r;       /* Coefficient index 0..p-1 */
    wire mqc_cmd_w = command_r == CMD_MSG_Q_COEF;
    wire [2:0]   mqc_ls_w = (arg_w_r == 4'd1) ? 3'd7 : (arg_w_r == 4'd2) ? 3'd6 :
                             (arg_w_r == 4'd4) ? 3'd4 : 3'd0;
    wire [8:0]   mqc_u_w = (arg_w_r == 4'd1) ? 9'd256 :
                            (arg_w_r == 4'd2) ? 9'd128 :
                            (arg_w_r == 4'd4) ? 9'd64 : 9'd32;  /* u=256/w (number of Q coefficients) */
    wire [7:0]   mqc_mask_w = (w_coef_bits == 4'd8) ? 8'hff :
                              ((8'd1 << w_coef_bits) - 8'd1);
    wire [4:0]   mqc_shift_w = (mqc_idx_r * w_coef_bits) & 5'd31; /* Bit offset within word */
    wire [4:0]   mqc_word_idx_w = (mqc_idx_r * w_coef_bits) >> 5; /* Coefficient word index */
    wire [8:0]   mqc_cs_j_w = mqc_idx_r - mqc_u_w;          /* Valid only for i>=u */
    /* w-bit slice of coefficient idx: Q 256 bits at q34[271:16] (bit271=MSB); byte base =
     * 271-(idx*w>>3)*8, in-byte offset = 8-w-((idx*w)&7) (MSB-first, same as lms_lmots_coef) */
    wire [3:0]   mqc_q_shift_w = 8 - w_coef_bits - ((mqc_idx_r * w_coef_bits) & 7);
    wire [7:0]   mqc_digit_q_w = (mqc_q_be_r[271 - ((mqc_idx_r * w_coef_bits) >> 3) * 8 -: 8] >>
                                  mqc_q_shift_w);
    /* cs 16 bits at q34[15:0] (bit15=MSB), sliced byte-aligned the same way */
    wire [3:0]   mqc_cs_shift_w = 8 - w_coef_bits - ((mqc_cs_j_w * w_coef_bits) & 7);
    wire [7:0]   mqc_digit_cs_w = (mqc_q_be_r[15 - ((mqc_cs_j_w * w_coef_bits) >> 3) * 8 -: 8] >>
                                   mqc_cs_shift_w);
    wire [11:0]  mqc_base_w = ((input_length_r[11:0] <= 12'd128) &&
                               (w_p != 9'd265)) ? (12'd32 + {w_p, 3'b0}) : 12'd568;
    wire hash_ram_path_w = hash_ram_cmd_w || mqc_cmd_w;   /* HASH_ONCE_RAM/MQC share the read window */
    wire [11:0] hash_ram_read_base_w =
        (mqc_cmd_w ? mqc_base_w : 12'd32) + {hash_ram_block_r, 4'b0};
    reg [7:0] mqc_digit_w;
    always @* begin
        if (mqc_idx_r < mqc_u_w) begin
            mqc_digit_w = mqc_digit_q_w & mqc_mask_w;
        end else begin
            mqc_digit_w = mqc_digit_cs_w & mqc_mask_w;
        end
    end

    reg [511:0] block_w;
    integer byte_index;
    /* REVIEW B08-R8: the following three combinational temporaries keep their old names without
     * the _w suffix (local intermediates inside the block-construction always @*); inconsistent
     * with the _w convention of bit_length_w/block_w here, but renaming yields little benefit, so kept. */
    integer global_index;
    integer length_byte_index;
    reg [7:0] selected_byte;
    reg [63:0] bit_length_w;
    reg [63:0] pblc_bitlen_w;   /* PBLc message total length (bits): (22 + p*32)*8, last/final block length field */
    reg [511:0] pblc_initial_w;
    reg [511:0] pblc_next_block_w;

    wire core0_busy_w;
    wire core0_done_w;
    wire [255:0] core0_digest_w;
    wire core1_busy_w;
    wire core1_done_w;
    wire [255:0] core1_digest_w;
    reg [511:0] block0_latched_r;  /* Latched block for core0 */
    reg [511:0] block1_latched_r;  /* Latched block for core1 (derived from block0) */
    /* Single-core compatibility: for non-batch commands core_done_w = core0_done_w */
    wire core_busy_w = dual_active_w ? (core0_busy_w | core1_busy_w) : core0_busy_w;
    wire core_done_w = dual_active_w ? (core0_done_w & core1_done_w) : core0_done_w;
    wire [255:0] core_digest_w = core0_digest_w;
    wire batch_pblc_w = (command_r == CMD_LMOTS_KEYGEN ||
                         command_r == CMD_LMOTS_KEYGEN_LEAF ||
                         verify_cmd_w) &&
                        batch_phase_r == BATCH_PBLC && !keygen_dleaf_r;
    wire [255:0] batch_endpoint_w = state_r == STATE_TASK_ENDPOINT
        ? chain_value_r : core_digest_w;
    wire single_engine_command_w = command_r == CMD_HASH_ONCE ||
        command_r == CMD_CHAIN || command_r == CMD_DERIVE_CHAIN ||
        command_r == CMD_DERIVE_RANDOMIZER;
    wire engine_busy_w;
    wire engine_done_w;
    wire [255:0] engine_digest_w;
    wire [31:0] engine_cycle_count_w;
    wire unused_kec_ext_busy_w;
    wire unused_kec_ext_done_w;
    wire [255:0] unused_kec_ext_digest_w;
    wire unused_kec_ext1_busy_w;
    wire unused_kec_ext1_done_w;
    wire [255:0] unused_kec_ext1_digest_w;
    wire [255:0] engine_chain_input_w = {
        input_words[0][7:0], input_words[0][15:8], input_words[0][23:16], input_words[0][31:24],
        input_words[1][7:0], input_words[1][15:8], input_words[1][23:16], input_words[1][31:24],
        input_words[2][7:0], input_words[2][15:8], input_words[2][23:16], input_words[2][31:24],
        input_words[3][7:0], input_words[3][15:8], input_words[3][23:16], input_words[3][31:24],
        input_words[4][7:0], input_words[4][15:8], input_words[4][23:16], input_words[4][31:24],
        input_words[5][7:0], input_words[5][15:8], input_words[5][23:16], input_words[5][31:24],
        input_words[6][7:0], input_words[6][15:8], input_words[6][23:16], input_words[6][31:24],
        input_words[7][7:0], input_words[7][15:8], input_words[7][23:16], input_words[7][31:24]
    };
    wire [127:0] engine_identifier_flat_w;
    wire [1023:0] engine_input_flat_w;
    genvar engine_flat_index;
    generate
        for (engine_flat_index = 0; engine_flat_index < 4;
             engine_flat_index = engine_flat_index + 1) begin : g_engine_identifier_flat
            assign engine_identifier_flat_w[engine_flat_index * 32 +: 32] =
                identifier_words[engine_flat_index];
        end
        for (engine_flat_index = 0; engine_flat_index < 32;
             engine_flat_index = engine_flat_index + 1) begin : g_engine_input_flat
            assign engine_input_flat_w[engine_flat_index * 32 +: 32] =
                input_words[engine_flat_index];
        end
    endgenerate
    wire wrapper_busy_w = state_r != STATE_IDLE || engine_busy_w || engine_start_r ||
        sec_busy_w;
    wire [31:0] status_w = (wrapper_busy_w ? STATUS_BUSY : 32'b0) |
                           (done_r ? STATUS_DONE : 32'b0) |
                           (error_status_r ? STATUS_ERROR : 32'b0);

    /* ---------- Hash-independent command check (unified refactor step 1) ---------- */
    wire        cmd_check_valid_w;
    wire [31:0] cmd_check_error_w;
    wire [3:0]  cmd_check_action_w;
    lms_hash_cmd_check #(
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .HAS_SECURITY(HAS_SECURITY),
        .MAX_ONCE_BYTES(8'd128),
        .HAS_HASH_ONCE_RAM(1'b1),   /* S7: enable HASH_ONCE_RAM (task RAM multi-block, <=2048B) */
        .HAS_STATE_COMMIT(1'b1)  /* S9: enable CMD_STATE_COMMIT (mc_step+HMAC fusion) */
    ) u_cmd_check (
        .command(command_r),
        .input_length(input_length_r),
        .output_length(output_length_r),
        .arg_i(arg_i_r),
        .arg_start(arg_start_r),
        .arg_steps(arg_steps_r),
        .arg_key(arg_key_r),
        .seed_valid(seed_valid_merged_w),
        .k_wrap_valid(k_wrap_valid_merged_w),
        .k_state_valid(k_state_valid_merged_w),
        .lmots_sign_y_len(w_p * 32),   /* SIGN y length per w (W4=2144 zero regression) */
        .valid(cmd_check_valid_w),
        .error_code(cmd_check_error_w),
        .action(cmd_check_action_w)
    );

    lms_hash_engine #(
        .HASH_TYPE(0),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE)
    ) u_single_engine (
        .clk(clk),
        .rst(rst),
        .start(engine_start_r),
        .command(command_r),
        .input_length(input_length_r[7:0]),
        .arg_q(arg_q_r),
        .arg_i(arg_i_r[15:0]),
        .arg_start(arg_start_r[7:0]),
        .arg_steps(arg_steps_r),
        .identifier_flat(engine_identifier_flat_w),
        .chain_value_in(engine_chain_input_w),
        .seed_flat(engine_seed_flat_w),
        .input_words_flat(engine_input_flat_w),
        .sha_ext_mode(!single_engine_command_w || sec_core_mode_w),
        .sha_ext_start(sec_core_mode_w ? sec_core_start_w :
            (dual_active_w ? (core_start0_r && core0_run_r) : core_start_r)),
        .sha_ext_init(sec_core_mode_w ? sec_core_init_w :
            (batch_pblc_w ? pblc_block_count_r == 0 :
            command_r == CMD_CHAIN || command_r == CMD_DERIVE_CHAIN ||
            command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
            command_r == CMD_LMOTS_SIGN || verify_cmd_w ||
            block_index_r == 0)),
        .sha_ext_state_load(sec_core_mode_w ? sec_core_state_load_w :
            (batch_pblc_w && pblc_block_count_r != 0)),
        .sha_ext_state_in(sec_core_mode_w ? sec_core_state_in_w : pblc_state_r),
        .sha_ext_block(sec_core_mode_w ? block_w :
            (dual_active_w ? block0_latched_r : block_w)),
        .sha_ext_busy(core0_busy_w),
        .sha_ext_done(core0_done_w),
        .sha_ext_digest(core0_digest_w),
        .sha_ext1_start(core_start1_r && core1_run_r),
        .sha_ext1_init(batch_pblc_w ? pblc_block_count_r == 0 :
            command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
            command_r == CMD_LMOTS_SIGN || verify_cmd_w ||
            block_index_r == 0),
        .sha_ext1_state_load(batch_pblc_w && pblc_block_count_r != 0),
        .sha_ext1_state_in(pblc_state_r),
        .sha_ext1_block(block1_latched_r),
        .sha_ext1_busy(core1_busy_w),
        .sha_ext1_done(core1_done_w),
        .sha_ext1_digest(core1_digest_w),
        .kec_ext_mode(1'b0),
        .kec_ext_start(1'b0),
        .kec_ext_init(1'b0),
        .kec_ext_block(1088'b0),
        .kec_ext_busy(unused_kec_ext_busy_w),
        .kec_ext_done(unused_kec_ext_done_w),
        .kec_ext_digest(unused_kec_ext_digest_w),
        .kec_ext1_start(1'b0),
        .kec_ext1_init(1'b0),
        .kec_ext1_block(1088'b0),
        .kec_ext1_busy(unused_kec_ext1_busy_w),
        .kec_ext1_done(unused_kec_ext1_done_w),
        .kec_ext1_digest(unused_kec_ext1_digest_w),
        .busy(engine_busy_w),
        .done(engine_done_w),
        .digest_out(engine_digest_w),
        .cycle_count(engine_cycle_count_w)
    );

    /* ---------- Security domain (SEC production wiring: instantiate lms_sha256_sec HASH_TYPE=0, borrow core0) ----------
     * SEC is a hash-independent template (shared with the SHAKE256 platform): secret slots
     * (SEED/K_WRAP/K_STATE) / sim_mc counter / WRAP/UNWRAP/HMAC state machines + core-borrowing
     * handshake + construction-parameter outputs. SHA-256 block construction (64B blocks) is done
     * by this wrapper (sec_core_mode: block_w takes the HMAC/WRAP branch); SEC borrows core0 via sha_ext, mutually exclusive with batch/single-chain. */
    wire        sec_busy_w;
    wire        sec_done_w;
    wire        sec_error_valid_w;
    wire [31:0] sec_error_code_w;
    wire [31:0] sec_cycles_w;
    wire [255:0] sec_result_data_w;
    /* verilator lint_off UNUSEDSIGNAL */
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
    /* verilator lint_off UNUSEDSIGNAL */
    wire        sec_stc_w;
    wire [31:0] sec_stc_tx_w;
    /* verilator lint_on UNUSEDSIGNAL */
    wire [255:0] sec_k_wrap_w;
    wire [255:0] sec_k_state_w;
    wire [255:0] sec_wrap_ct_w;
    wire [255:0] sec_wrap_tag_w;
    wire [31:0] sec_bus_rdata_w;

    /* SEC bus access: address regions = SIM_MC(0x060)/SEED(0x080)/WRAPPED(0x0a0)/KWRAP(0x0e0).
     * SEC expects bus_addr [9:0]; write gated by reg_write_ok=!wrapper_busy. */
    wire sec_bus_hit_w =
        (bus_addr == 10'h060) ||
        (bus_addr >= 10'h080 && bus_addr < 10'h080 + 32) ||
        (bus_addr >= 10'h0a0 && bus_addr < 10'h0a0 + 48) ||
        (bus_addr >= 10'h0e0 && bus_addr < 10'h0e0 + 32);
    wire sec_bus_valid_w = bus_valid && sec_bus_hit_w;
    wire sec_core_mode_w = sec_busy_w;

    /* Command start (shell drives these combinationally on the CTRL_START cycle; SEC latches on
     * the same posedge; SHAKE256 wrapper convention). Not consumed when HAS_SECURITY=0 except seed_latch. */
    /* verilator lint_off UNUSEDSIGNAL */
    wire ctrl_start_w = !wrapper_busy_w && bus_valid && bus_write &&
        bus_addr == REG_CONTROL && (bus_wdata & CTRL_START) != 32'b0;
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
    /* STATE_COMMIT: enabled by S9 (constant 0 when cmd_check HAS_STATE_COMMIT=0; wiring ready). */
    wire stc_start_w = ctrl_start_w && cmd_check_action_w == ACT_START_STC;
    /* verilator lint_on UNUSEDSIGNAL */

    /* Merged outputs (fall back to the local SEED path when HAS_SECURITY=0). */
    wire [255:0] engine_seed_flat_w;
    wire        seed_valid_merged_w;
    wire        k_wrap_valid_merged_w;
    wire        k_state_valid_merged_w;

    /* Security-domain compile switch: HAS_SECURITY=1 instantiates lms_sha256_sec (SEC slots/borrowed
     * core); HAS_SECURITY=0 does not instantiate it, SEED is carried by the local local_seed
     * register (reproducing the 0.1.235 path), and SEC outputs are tied to 0. */
    /* verilator lint_off UNUSEDSIGNAL */
    integer sec_latch_index;
    /* verilator lint_on UNUSEDSIGNAL */
    generate
        if (HAS_SECURITY) begin : g_sec_on
            lms_sha256_sec #(
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HASH_TYPE(0)
            ) u_sec (
                .clk(clk),
                .rst(rst),
                .bus_valid(sec_bus_valid_w),
                .bus_write(bus_write),
                .bus_addr(bus_addr),
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
                .input_length(stc_start_w ? 8'd49 : input_length_r[7:0]),  /* stc body fixed 49B (S9) */
                .stc_start(stc_start_w),
                .stc_state(arg_i_r[15:0]),
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
                .core_busy(core0_busy_w),
                .core_done(core0_done_w),
                .core_digest(core0_digest_w)
            );
            assign engine_seed_flat_w = sec_seed_data_w;
            assign seed_valid_merged_w = sec_seed_valid_w;
            assign k_wrap_valid_merged_w = sec_k_wrap_valid_w;
            assign k_state_valid_merged_w = sec_k_state_valid_w;
        end else begin : g_sec_off
            /* Local SEED slot (reproduces the 0.1.235 plaintext path; SEC outputs tied to 0). */
            always @(posedge clk) begin
                if (seed_latch_en_w) begin
                    for (sec_latch_index = 0; sec_latch_index < 8;
                         sec_latch_index = sec_latch_index + 1) begin
                        local_seed_r[255 - sec_latch_index * 32 -: 32] <= {
                            local_seed_staging[sec_latch_index][7:0],
                            local_seed_staging[sec_latch_index][15:8],
                            local_seed_staging[sec_latch_index][23:16],
                            local_seed_staging[sec_latch_index][31:24]
                        };
                        local_seed_staging[sec_latch_index] <= 32'b0;
                    end
                    local_seed_valid_r <= 1'b1;
                end
                if (rst) begin
                    local_seed_r <= 256'b0;
                    local_seed_valid_r <= 1'b0;
                    for (sec_latch_index = 0; sec_latch_index < 8;
                         sec_latch_index = sec_latch_index + 1) begin
                        local_seed_staging[sec_latch_index] <= 32'b0;
                    end
                end
            end
            assign sec_busy_w = 1'b0;
            assign sec_done_w = 1'b0;
            assign sec_error_valid_w = 1'b0;
            assign sec_error_code_w = 32'b0;
            assign sec_cycles_w = 32'b0;
            assign sec_result_data_w = 256'b0;
            assign sec_result_wmask_w = 8'b0;
            assign sec_result_valid_w = 1'b0;
            assign sec_mc_next_value_w = 32'b0;
            assign sec_seed_data_w = 256'b0;
            assign sec_seed_valid_w = 1'b0;
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
            assign engine_seed_flat_w = local_seed_r;
            assign seed_valid_merged_w = local_seed_valid_r;
            assign k_wrap_valid_merged_w = 1'b0;
            assign k_state_valid_merged_w = 1'b0;
        end
    endgenerate

    /* STATE_COMMIT body 49B view (S9): magic(4,"LMSS")||state(2,BE)||ctr(4,BE)||tx(4,BE)
     * ||reserved(34,0)||aad(1), zero-padded to 64B (in-block byte indices 0..63 all valid).
     * stc fields come from ARG registers, stable during the command, and SEC-latched tx. The
     * HMAC inner branch selects by dynamic index (global_index-64) (runtime variable, no static
     * out-of-bounds). REVIEW B07-R7: naming/order aligned to the SHAKE mirror (sec_body_be_w) --
     * old vec name and reversed triples (3->0) disagreed with this file's BE byte-order; cosmetic only. */
    wire [511:0] sec_body_be_w;
    genvar sec_bd_i;
    generate
        for (sec_bd_i = 0; sec_bd_i < 4; sec_bd_i = sec_bd_i + 1) begin : g_stc_magic
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                (sec_bd_i == 0) ? 8'h4c :
                (sec_bd_i == 1) ? 8'h4d :
                (sec_bd_i == 2) ? 8'h53 : 8'h53;   /* "LMSS" */
        end
        for (sec_bd_i = 4; sec_bd_i < 6; sec_bd_i = sec_bd_i + 1) begin : g_stc_state
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                (sec_bd_i == 4) ? arg_i_r[15:8] : arg_i_r[7:0];   /* state BE */
        end
        for (sec_bd_i = 6; sec_bd_i < 10; sec_bd_i = sec_bd_i + 1) begin : g_stc_ctr
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                arg_q_r[(9 - sec_bd_i) * 8 +: 8];   /* ctr BE */
        end
        for (sec_bd_i = 10; sec_bd_i < 14; sec_bd_i = sec_bd_i + 1) begin : g_stc_tx
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                sec_stc_tx_w[(13 - sec_bd_i) * 8 +: 8];   /* tx BE */
        end
        for (sec_bd_i = 14; sec_bd_i < 48; sec_bd_i = sec_bd_i + 1) begin : g_stc_rsv
            assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;   /* reserved */
        end
        for (sec_bd_i = 48; sec_bd_i < 49; sec_bd_i = sec_bd_i + 1) begin : g_stc_aad
            assign sec_body_be_w[sec_bd_i * 8 +: 8] = arg_key_r[7:0];   /* aad=slot_id */
        end
        for (sec_bd_i = 49; sec_bd_i < 64; sec_bd_i = sec_bd_i + 1) begin : g_stc_z
            assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;
        end
    endgenerate
    /* HMAC inner message length: stc=49 (body), otherwise input_length_r. */
    wire [7:0] sec_inner_len_w = sec_stc_w ? 8'd49 : input_length_r[7:0];

    /* wrap/unwrap ct/tag assembly moved into lms_sha256_sec with the SEC production wiring
     * (sec_wrap_ct_w/sec_wrap_tag_w outputs); this wrapper no longer keeps inline copies. */

    reg task_ram_enable_w;
    reg task_ram_write_w;
    reg [11:0] task_ram_addr_w;
    reg [31:0] task_ram_wdata_w;

    always @* begin
        task_ram_enable_w = 1'b0;
        task_ram_write_w = 1'b0;
        task_ram_addr_w = 12'b0;
        task_ram_wdata_w = 32'b0;
        /* Stream port takes priority (mutually exclusive with the MMIO task RAM port; usable while core idle). */
        if (stream_wr_en && !wrapper_busy_w && stream_wr_addr < 2152) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = stream_wr_addr;
            task_ram_wdata_w = stream_wr_data;
        end else if (stream_rd_en && !wrapper_busy_w && stream_rd_addr < 2152) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = stream_rd_addr;
        end else if (!wrapper_busy_w && bus_valid && bus_write &&
            bus_addr == REG_TASK_DATA && task_addr_r >= 32) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = task_addr_r;
            task_ram_wdata_w = bus_wdata;
        end else if (task_prefetch_pending_r) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
        end else if (state_r == STATE_TASK_WRITE) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            if (dual_batch_w && dual_write_sel_r &&
                batch_phase_r != BATCH_CHAIN) begin
                /* Dual-core core1 write: address base = 32 + (batch_i+1)*8 */
                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0} +
                    {9'b0, task_write_word1_r};
                task_ram_wdata_w = {
                    task_digest1_r[255 - (task_write_word1_r * 32 + 24) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 16) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 8) -: 8],
                    task_digest1_r[255 - task_write_word1_r * 32 -: 8]
                };
            end else if (dual_batch_w &&
                batch_phase_r != BATCH_CHAIN) begin
                /* Dual-core core0 write */
                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    {9'b0, task_write_word0_r};
                task_ram_wdata_w = {
                    task_digest0_r[255 - (task_write_word0_r * 32 + 24) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 16) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 8) -: 8],
                    task_digest0_r[255 - task_write_word0_r * 32 -: 8]
                };
            end else begin
                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    {9'b0, task_write_word_r};
                task_ram_wdata_w = {
                    task_digest_r[255 - (task_write_word_r * 32 + 24) -: 8],
                    task_digest_r[255 - (task_write_word_r * 32 + 16) -: 8],
                    task_digest_r[255 - (task_write_word_r * 32 + 8) -: 8],
                    task_digest_r[255 - task_write_word_r * 32 -: 8]
                };
            end
        end else if (state_r == STATE_TASK_PREFETCH && hash_ram_path_w) begin
            /* HASH_ONCE_RAM/MQC: prefetch current block's first word (word32 or mqc_base + block*16) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = hash_ram_read_base_w;
        end else if (state_r == STATE_HASH_RAM_LOAD) begin
            /* HASH_ONCE_RAM/MQC read window: prefetch next word (no +1 on last word to avoid overflow; padding blocks read no data) */
            task_ram_enable_w = 1'b1;
            if (hash_ram_word_r + 1'b1 < hash_ram_rd_words_w) begin
                task_ram_addr_w = hash_ram_read_base_w + {5'b0, hash_ram_word_r} + 12'd1;
            end else begin
                task_ram_addr_w = hash_ram_read_base_w + {5'b0, hash_ram_word_r};
            end
        end else if (state_r == STATE_TASK_PREFETCH) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0};
        end else if (state_r == STATE_TASK_LOAD) begin
            task_ram_enable_w = 1'b1;
            if (verify_dual_load_r) begin
                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0} +
                    (task_write_word_r == 3'd7
                        ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end else if (!verify_dual_load_r && task_write_word_r == 3'd7 &&
                         dual_batch_w && verify_cmd_w &&
                         batch_i1_w < w_p) begin
                /* Prefetch chain1's first word before the first load round finishes, avoiding a stale prefetch */
                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0};
            end else begin
                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    (task_write_word_r == 3'd7
                        ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end
        end else if (state_r == STATE_DINTR_PREFETCH) begin
            /* Chained D_INTR: prefetch starting left's first word (word32) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd32;
        end else if (state_r == STATE_DINTR_LOAD_START) begin
            /* Read starting left: word0..6 prefetch next word (33..39); word7 prefetches sibling[0]'s first word */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = (dintr_load_word_r == 4'd7) ? 12'd40 :
                               (12'd33 + {8'b0, dintr_load_word_r});
        end else if (state_r == STATE_DINTR_LOAD_SIB) begin
            /* Read sibling[layer]: word0..6 prefetch next word; word7 does not prefetch */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r, 3'b0} +
                (dintr_load_word_r == 4'd7 ? 4'd7 : {1'b0, dintr_load_word_r} + 4'd1);
        end else if (state_r == STATE_DINTR_CORE ||
                     (state_r == STATE_WAIT_CORE && dintr_cmd_w)) begin
            /* Prefetch next layer's sibling first word during absorb (word40+(layer+1)*8; when
             * block1 finishes it is already the next layer's first word, consumed on first LOAD_SIB cycle) */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r + 1'b1, 3'b0};
        end else if (!wrapper_busy_w && done_r && bus_valid &&
                     !bus_write && bus_addr == REG_TASK_DATA &&
                     task_addr_r >= 32 && !stream_read_r) begin
            /* Auto-increment read: each new read transaction triggers one on-demand read + address
             * increment. stream_read_r prevents multi-cycle bus_valid repeats from the mmio bridge. */
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
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
    end

    /* Stream read request latch: set on the request cycle, output next cycle (after task_ram_read_r updates). */
    always @(posedge clk) begin
        if (rst) begin
            stream_rd_pending_r <= 1'b0;
        end else if (stream_rd_en && !wrapper_busy_w) begin
            stream_rd_pending_r <= 1'b1;
        end else begin
            stream_rd_pending_r <= 1'b0;
        end
    end

    /* ---------- Stream port outputs ---------- */
    assign stream_busy     = wrapper_busy_w;
    assign stream_rd_valid = stream_rd_pending_r;
    assign stream_rd_data  = stream_rd_pending_r ? task_ram_read_r : 32'b0;

    always @* begin
        /* HMAC inner message total length = 64 + message length (stc=49); outer = 96. Otherwise use input_length_r. */
        if (sec_is_hmac_w && sec_wrap_phase_w == 2'd1) begin
            bit_length_w = {29'b0, (32'd64 + {24'b0, sec_inner_len_w})} << 3;
        end else if (sec_is_hmac_w) begin
            bit_length_w = 64'd96 << 3;
        end else begin
            bit_length_w = {29'b0, input_length_r[31:0]} << 3;
        end
        block_w = 512'b0;
        selected_byte = 8'b0;
        global_index = 0;
        length_byte_index = 0;
        pblc_initial_w = 512'b0;
        pblc_next_block_w = pblc_buffer_r;
        /* PBLc message total length (bits): W1=8502B/W2=4278B/W4=2166B/W8=1110B */
        pblc_bitlen_w = (64'd22 + ({55'b0, w_p} << 5)) << 3;
        for (byte_index = 0; byte_index < 16; byte_index = byte_index + 1) begin
            pblc_initial_w[511 - byte_index * 8 -: 8] =
                identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
        end
        pblc_initial_w[511 - 16 * 8 -: 8] = arg_q_r[31:24];
        pblc_initial_w[511 - 17 * 8 -: 8] = arg_q_r[23:16];
        pblc_initial_w[511 - 18 * 8 -: 8] = arg_q_r[15:8];
        pblc_initial_w[511 - 19 * 8 -: 8] = arg_q_r[7:0];
        pblc_initial_w[511 - 20 * 8 -: 8] = 8'h80;
        pblc_initial_w[511 - 21 * 8 -: 8] = 8'h80;
        if (pblc_final_due_r) begin
            /* p-even (W8) residual-window final block: sliding window 22B + 0x80 + total length */
            pblc_next_block_w = 512'b0;
            for (byte_index = 0; byte_index < 22; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - byte_index * 8 -: 8] =
                    pblc_buffer_r[511 - byte_index * 8 -: 8];
            end
            pblc_next_block_w[511 - 22 * 8 -: 8] = 8'h80;
            for (byte_index = 0; byte_index < 8; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (56 + byte_index) * 8 -: 8] =
                    pblc_bitlen_w[(7 - byte_index) * 8 +: 8];
            end
        end else if (dual_batch_w && batch_i_r != w_p_last &&
            (!verify_cmd_w || verify_dc_mode_r)) begin
            for (byte_index = 0; byte_index < 10; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (54 + byte_index) * 8 -: 8] =
                    core1_digest_w[255 - byte_index * 8 -: 8];
            end
        end else if (batch_i_r[0]) begin
            for (byte_index = 0; byte_index < 10; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (54 + byte_index) * 8 -: 8] =
                    batch_endpoint_w[255 - byte_index * 8 -: 8];
            end
        end else if (batch_i_r == w_p_last) begin
            pblc_next_block_w = 512'b0;
            for (byte_index = 0; byte_index < 22; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - byte_index * 8 -: 8] =
                    pblc_buffer_r[511 - byte_index * 8 -: 8];
            end
            for (byte_index = 0; byte_index < 32; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (22 + byte_index) * 8 -: 8] =
                    batch_endpoint_w[255 - byte_index * 8 -: 8];
            end
            pblc_next_block_w[511 - 54 * 8 -: 8] = 8'h80;
            for (byte_index = 0; byte_index < 8; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (56 + byte_index) * 8 -: 8] =
                    pblc_bitlen_w[(7 - byte_index) * 8 +: 8];
            end
        end
        for (byte_index = 0; byte_index < 64; byte_index = byte_index + 1) begin
            if (dintr_cmd_w) begin
                /* D_INTR: I(16)||node(4BE)||0x8383||left(32)||right(32) = 86B, 2 blocks.
                 * Block0 = header 22B + left 32B + right first 10B; block1 = right tail 22B + 0x80@22
                 * + length 0x2b0 (86*8) @62..63. Block1 core state continues automatically (init=0).
                 * Type byte 0x8383=D_INTR (hash-independent in RFC 8554; do not use 0x8181=D_MESG). */                if (block_index_r == 2'd0) begin
                    if (byte_index < 16) begin
                        selected_byte = identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
                    end else if (byte_index < 20) begin
                        selected_byte = dintr_block_node_w[(19 - byte_index) * 8 +: 8];
                    end else if (byte_index < 22) begin
                        selected_byte = 8'h83;
                    end else if (byte_index < 54) begin
                        selected_byte = dintr_swap_w ?
                            dintr_right_r[255 - (byte_index - 22) * 8 -: 8] :
                            dintr_left_r[255 - (byte_index - 22) * 8 -: 8];
                    end else begin
                        selected_byte = dintr_swap_w ?
                            dintr_left_r[255 - (byte_index - 54) * 8 -: 8] :
                            dintr_right_r[255 - (byte_index - 54) * 8 -: 8];
                    end
                end else begin
                    if (byte_index < 22) begin
                        selected_byte = dintr_swap_w ?
                            dintr_left_r[255 - (10 + byte_index) * 8 -: 8] :
                            dintr_right_r[255 - (10 + byte_index) * 8 -: 8];
                    end else if (byte_index == 22) begin
                        selected_byte = 8'h80;
                    end else if (byte_index == 62) begin
                        selected_byte = 8'h02;
                    end else if (byte_index == 63) begin
                        selected_byte = 8'hb0;
                    end else begin
                        selected_byte = 8'h00;
                    end
                end
            end else if (hash_ram_cmd_w) begin
                /* HASH_ONCE_RAM (S7): multi-block absorb, block = 64B straight layout of the read
                 * window (window word0..15 at [575:64]); last-block SHA-256 padding: 0x80@total,
                 * 8B length at block tail (bitlen=total*8 big-endian). Block0 uses
                 * block_index_r==0 -> core init=1, later blocks init=0 continuing state. */
                global_index = hash_ram_block_base_w + byte_index;
                if (global_index < hash_ram_total_w) begin
                    selected_byte = hash_ram_window_r[575 - byte_index * 8 -: 8];
                end else if (global_index == hash_ram_total_w) begin
                    selected_byte = 8'h80;
                end else if (global_index >= hash_ram_blocks_w * 64 - 8) begin
                    length_byte_index = global_index - (hash_ram_blocks_w * 64 - 8);
                    selected_byte = hash_ram_bitlen_w[(7 - length_byte_index) * 8 +: 8];
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (mqc_cmd_w) begin
                /* MSG_Q_COEF (S8): hashed byte stream = header 54B + message (contiguous, no holes,
                 * global = b+64k). Window layout: header 54B at byte0..53, message starts at window
                 * byte56 (+2 gap, block0); block k>=1 window = message 8+64(k-1).. (message data
                 * segment offset +2 vs window). Unified construction: b<54 (block0) takes window b,
                 * otherwise window b+2 (block0 b>=54=message, block k>=1 b+2=message 10+64(k-1)+b); padding same as HASH_ONCE_RAM. */
                global_index = hash_ram_block_base_w + byte_index;
                if (global_index < hash_ram_total_w) begin
                    if (hash_ram_block_r == 6'd0 && byte_index < 54) begin
                        selected_byte = hash_ram_window_r[575 - byte_index * 8 -: 8];
                    end else begin
                        selected_byte = hash_ram_window_r[575 - (byte_index + 2) * 8 -: 8];
                    end
                end else if (global_index == hash_ram_total_w) begin
                    selected_byte = 8'h80;
                end else if (global_index >= hash_ram_blocks_w * 64 - 8) begin
                    length_byte_index = global_index - (hash_ram_blocks_w * 64 - 8);
                    selected_byte = hash_ram_bitlen_w[(7 - length_byte_index) * 8 +: 8];
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (((command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                  command_r == CMD_LMOTS_SIGN || verify_cmd_w) &&
                 batch_phase_r == BATCH_CHAIN)) begin
                if (byte_index < 16) begin
                    selected_byte = identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
                end else if (byte_index < 20) begin
                    selected_byte = arg_q_r[(19 - byte_index) * 8 +: 8];
                end else if (byte_index < 22) begin
                    selected_byte = arg_i_r[(21 - byte_index) * 8 +: 8];
                end else if (byte_index == 22) begin
                    selected_byte = chain_j_r;
                end else if (byte_index < 55) begin
                    selected_byte = chain_value_r[255 - (byte_index - 23) * 8 -: 8];
                end else if (byte_index == 55) begin
                    selected_byte = 8'h80;
                end else if (byte_index == 62) begin
                    selected_byte = 8'h01;
                end else if (byte_index == 63) begin
                    selected_byte = 8'hb8;
                end else begin
                    selected_byte = 8'h00;
                end
                        end else if (((command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                           command_r == CMD_LMOTS_SIGN) &&
                          batch_phase_r == BATCH_DERIVE)) begin
                if (byte_index < 16) begin
                    selected_byte = identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
                end else if (byte_index < 20) begin
                    selected_byte = arg_q_r[(19 - byte_index) * 8 +: 8];
                end else if (byte_index < 22) begin
                    selected_byte = arg_i_r[(21 - byte_index) * 8 +: 8];
                end else if (byte_index == 22) begin
                    selected_byte = 8'hff;
                end else if (byte_index < 55) begin
                    selected_byte = engine_seed_flat_w[255 - (byte_index - 23) * 8 -: 8];
                end else if (byte_index == 55) begin
                    selected_byte = 8'h80;
                end else if (byte_index == 62) begin
                    selected_byte = 8'h01;
                end else if (byte_index == 63) begin
                    selected_byte = 8'hb8;
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (HAS_SECURITY && sec_core_mode_w && sec_is_hmac_w) begin
                /* Generic HMAC-SHA256(K_STATE, input_words[0..input_length_r]).
                 * phase1 inner: message = (K_STATE XOR ipad 64B) || input(len B), len<=119, <=3 blocks.
                 * phase2 outer: message = (K_STATE XOR opad 64B) || inner_digest(32B) = 96B, 2 blocks.
                 * global_index addresses continuously across blocks, padding at the tail of the last block. */
                global_index = sec_block_index_w * 64 + byte_index;
                if (sec_wrap_phase_w == 2'd1) begin
                    if (global_index < 64) begin
                        selected_byte = (global_index < 32)
                            ? (sec_k_state_w[255 - global_index * 8 -: 8] ^ 8'h36)
                            : 8'h36;
                    end else if (global_index < 64 + {24'b0, sec_inner_len_w}) begin
                        if (sec_stc_w) begin
                            /* STATE_COMMIT: message = body 49B (S9) */
                            selected_byte = sec_body_be_w[(global_index - 64) * 8 +: 8];
                        end else begin
                            selected_byte = input_words[(global_index - 64) / 4]
                                                     [((global_index - 64) % 4) * 8 +: 8];
                        end
                    end else if (global_index == 64 + {24'b0, sec_inner_len_w}) begin
                        selected_byte = 8'h80;
                    end else if (global_index >= sec_block_count_w * 64 - 8) begin
                        length_byte_index = global_index - (sec_block_count_w * 64 - 8);
                        selected_byte = bit_length_w[(7 - length_byte_index) * 8 +: 8];
                    end else begin
                        selected_byte = 8'h00;
                    end
                end else begin
                    if (global_index < 64) begin
                        selected_byte = (global_index < 32)
                            ? (sec_k_state_w[255 - global_index * 8 -: 8] ^ 8'h5c)
                            : 8'h5c;
                    end else if (global_index < 96) begin
                        selected_byte = sec_wrap_tag_w[255 - (global_index - 64) * 8 -: 8];
                    end else if (global_index == 96) begin
                        selected_byte = 8'h80;
                    end else if (global_index >= sec_block_count_w * 64 - 8) begin
                        length_byte_index = global_index - (sec_block_count_w * 64 - 8);
                        selected_byte = bit_length_w[(7 - length_byte_index) * 8 +: 8];
                    end else begin
                        selected_byte = 8'h00;
                    end
                end
            end else if (HAS_SECURITY && sec_core_mode_w && !sec_is_hmac_w) begin
                /* phase 0: mask = H(k_wrap || "LMSWRAP-ENC")  len=43 */
                if (sec_wrap_phase_w == 2'd0) begin
                    if (byte_index < 32) begin
                        selected_byte = sec_k_wrap_w[255 - byte_index * 8 -: 8];
                    end else if (byte_index == 32) begin
                        selected_byte = 8'h4c;  /* L */
                    end else if (byte_index == 33) begin
                        selected_byte = 8'h4d;  /* M */
                    end else if (byte_index == 34) begin
                        selected_byte = 8'h53;  /* S */
                    end else if (byte_index == 35) begin
                        selected_byte = 8'h57;  /* W */
                    end else if (byte_index == 36) begin
                        selected_byte = 8'h52;  /* R */
                    end else if (byte_index == 37) begin
                        selected_byte = 8'h41;  /* A */
                    end else if (byte_index == 38) begin
                        selected_byte = 8'h50;  /* P */
                    end else if (byte_index == 39) begin
                        selected_byte = 8'h2d;  /* - */
                    end else if (byte_index == 40) begin
                        selected_byte = 8'h45;  /* E */
                    end else if (byte_index == 41) begin
                        selected_byte = 8'h4e;  /* N */
                    end else if (byte_index == 42) begin
                        selected_byte = 8'h43;  /* C */
                    end else if (byte_index == 43) begin
                        selected_byte = 8'h80;
                    end else if (byte_index == 62) begin
                        selected_byte = 8'h01;
                    end else if (byte_index == 63) begin
                        selected_byte = 8'h58;  /* 43*8=344=0x158 */
                    end else begin
                        selected_byte = 8'h00;
                    end
                /* phase 1: HMAC inner = H((k_wrap||0^32)⊕ipad || ct)  len=96, 2 block.
                 * block 0 = k_wrap⊕ipad(32B) || ipad(32B=0x36); block 1 = ct(32B) || padding. */
                end else if (sec_wrap_phase_w == 2'd1) begin
                    if (sec_block_index_w == 2'd0) begin
                        if (byte_index < 32) begin
                            selected_byte = sec_k_wrap_w[255 - byte_index * 8 -: 8] ^ 8'h36;
                        end else begin
                            selected_byte = 8'h36;  /* key zero-padded part XOR ipad = ipad */
                        end
                    end else begin
                        if (byte_index < 32) begin
                            selected_byte = sec_wrap_ct_w[255 - byte_index * 8 -: 8];
                        end else if (byte_index == 32) begin
                            selected_byte = 8'h80;
                        end else if (byte_index == 62) begin
                            selected_byte = 8'h03;
                        end else if (byte_index == 63) begin
                            selected_byte = 8'h00;  /* 96*8=768=0x300 */
                        end else begin
                            selected_byte = 8'h00;
                        end
                    end
                /* phase 2: HMAC outer = H((k_wrap||0^32)⊕opad || inner)  len=96, 2 block.
                 * block 0 = k_wrap⊕opad(32B) || opad(32B=0x5c); block 1 = inner(32B) || padding. */
                end else begin
                    if (sec_block_index_w == 2'd0) begin
                        if (byte_index < 32) begin
                            selected_byte = sec_k_wrap_w[255 - byte_index * 8 -: 8] ^ 8'h5c;
                        end else begin
                            selected_byte = 8'h5c;  /* key zero-padded part XOR opad = opad */
                        end
                    end else begin
                        if (byte_index < 32) begin
                            selected_byte = sec_wrap_tag_w[255 - byte_index * 8 -: 8];
                        end else if (byte_index == 32) begin
                            selected_byte = 8'h80;
                        end else if (byte_index == 62) begin
                            selected_byte = 8'h03;
                        end else if (byte_index == 63) begin
                            selected_byte = 8'h00;  /* 96*8=768 */
                        end else begin
                            selected_byte = 8'h00;
                        end
                    end
                end
            end else if (command_r == CMD_LMOTS_KEYGEN ||
                         (command_r == CMD_LMOTS_KEYGEN_LEAF && !keygen_dleaf_r) ||
                         (verify_cmd_w && !keygen_dleaf_r)) begin
                selected_byte = pblc_block_r[511 - byte_index * 8 -: 8];
            end else if (keygen_dleaf_r) begin
                /* D_LEAF message already filled into input_words by STATE_TASK_PREFETCH */
                global_index = block_index_r * 64 + byte_index;
                if (global_index < 54) begin
                    selected_byte = input_words[global_index / 4][(global_index % 4) * 8 +: 8];
                end else if (global_index == 54) begin
                    selected_byte = 8'h80;
                end else if (global_index >= 64 - 8) begin
                    length_byte_index = global_index - (64 - 8);
                    if (length_byte_index == 6) selected_byte = 8'h01;
                    else if (length_byte_index == 7) selected_byte = 8'hb0;
                    else selected_byte = 8'h00;
                end else begin
                    selected_byte = 8'h00;
                end
            end else begin
                global_index = block_index_r * 64 + byte_index;
                if (global_index < input_length_r) begin
                    selected_byte = input_words[global_index / 4][(global_index % 4) * 8 +: 8];
                end else if (global_index == input_length_r) begin
                    selected_byte = 8'h80;
                end else if (global_index >= block_count_r * 64 - 8) begin
                    length_byte_index = global_index - (block_count_r * 64 - 8);
                    selected_byte = bit_length_w[(7 - length_byte_index) * 8 +: 8];
                end else begin
                    selected_byte = 8'h00;
                end
            end
            block_w[511 - byte_index * 8 -: 8] = selected_byte;
        end
    end

    integer output_index;
    integer bj;
    always @(posedge clk) begin
        core_start_r <= 1'b0;
        core_start0_r <= 1'b0;
        core_start1_r <= 1'b0;
        engine_start_r <= 1'b0;
        task_prefetch_pending_r <= 1'b0;

        if (sec_done_w) begin
            /* SEC multi-cycle command (WRAP/UNWRAP/HMAC) done: latch cycle/error/result.
             * REVIEW B08-R5: busy_error_pending_r from a concurrent START is also reported here
             * as ERR_BUSY (consistent with the engine done path; the old code swallowed it on SEC). */
            cycle_count_r <= sec_cycles_w;
            if (busy_error_pending_r) begin
                done_r <= 1'b0;
                error_status_r <= 1'b1;
                error_r <= ERR_BUSY;
            end else if (sec_error_valid_w) begin
                done_r <= 1'b0;
                error_status_r <= 1'b1;
                error_r <= sec_error_code_w;
            end else begin
                done_r <= 1'b1;
                error_status_r <= 1'b0;
                error_r <= 32'b0;
            end
            if (sec_result_valid_w) begin
                if (sec_stc_w) begin
                    /* STATE_COMMIT: word0=tx, word1..4=tag (first 16B), rest 0 (S9) */
                    output_words[0] <= sec_stc_tx_w;
                    output_words[1] <= sec_result_data_w[255:224];
                    output_words[2] <= sec_result_data_w[223:192];
                    output_words[3] <= sec_result_data_w[191:160];
                    output_words[4] <= sec_result_data_w[159:128];
                    output_words[5] <= 32'b0;
                    output_words[6] <= 32'b0;
                    output_words[7] <= 32'b0;
                end else begin
                    for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                        output_words[output_index] <=
                            sec_result_data_w[255 - output_index * 32 -: 32];
                    end
                end
            end
        end

        if (engine_done_w) begin
            cycle_count_r <= engine_cycle_count_w;
            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                output_words[output_index] <= {
                    engine_digest_w[255 - (output_index * 32 + 24) -: 8],
                    engine_digest_w[255 - (output_index * 32 + 16) -: 8],
                    engine_digest_w[255 - (output_index * 32 + 8) -: 8],
                    engine_digest_w[255 - output_index * 32 -: 8]
                };
            end
            if (busy_error_pending_r) begin
                done_r <= 1'b0;
                error_status_r <= 1'b1;
                error_r <= ERR_BUSY;
            end else begin
                done_r <= 1'b1;
                error_status_r <= 1'b0;
                error_r <= 32'b0;
            end
        end

        if (bus_valid && bus_write) begin
            if (bus_addr == REG_CONTROL) begin
                if (wrapper_busy_w) begin
                    if ((bus_wdata & CTRL_START) != 0) begin
                        busy_error_pending_r <= 1'b1;
                    end
                end else if (bus_wdata == CTRL_CLEAR) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b0;
                    error_r <= 32'b0;
                    cycle_count_r <= 32'b0;
                    busy_error_pending_r <= 1'b0;
                end else if (bus_wdata == CTRL_START) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b0;
                    error_r <= 32'b0;
                    cycle_count_r <= 32'd1;
                    busy_error_pending_r <= 1'b0;
                    /* Unified command check (lms_hash_cmd_check): valid -> execute per action */
                    if (!cmd_check_valid_w) begin
                        error_status_r <= 1'b1;
                        error_r <= cmd_check_error_w;
                    end else begin
                        case (cmd_check_action_w)
                            ACT_START: begin
                                block_index_r <= 2'd0;
                                keygen_dleaf_r <= 1'b0;
                                if (dintr_cmd_w) begin
                                    /* D_INTR_CHAIN: read-window init (left first-word prefetch).
                                     * arg_leaf_node = leaf node (incl. parity bit, P1-6 q=1 fix). */
                                    dintr_left_r <= 256'b0;
                                    dintr_right_r <= 256'b0;
                                    dintr_node_r <= arg_leaf_node_r;
                                    dintr_layer_r <= 5'd0;
                                    dintr_load_word_r <= 4'd0;
                                    block_count_r <= 2'd2;  /* 86B = 2 blocks */
                                    state_r <= STATE_DINTR_PREFETCH;
                                end else if (hash_ram_path_w) begin
                                    /* HASH_ONCE_RAM/MQC: multi-block read-window init (block0
                                     * first-word prefetch, reuses TASK_PREFETCH; block0 index=0 -> init=1) */
                                    hash_ram_block_r <= 6'd0;
                                    hash_ram_word_r <= 6'd0;
                                    hash_ram_window_r <= 576'b0;
                                    if (mqc_cmd_w) begin
                                        mqc_q_be_r <= 272'b0;
                                        mqc_checksum_r <= 16'd0;
                                        mqc_idx_r <= 9'd0;
                                    end
                                    state_r <= STATE_TASK_PREFETCH;
                                end else if (single_engine_command_w) begin
                                    engine_start_r <= 1'b1;
                                end else if (command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                                    command_r == CMD_LMOTS_SIGN) begin
                                    batch_phase_r <= BATCH_DERIVE;
                                    batch_i_r <= 9'd0;
                                    arg_i_r <= 32'd0;
                                    pblc_block_count_r <= 8'd0;
                                    pblc_state_r <= 256'b0;
                                    pblc_buffer_r <= pblc_initial_w;
                                    block_count_r <= 2'd1;
                                end else if (verify_cmd_w) begin
                                    batch_phase_r <= BATCH_CHAIN;
                                    batch_i_r <= 9'd0;
                                    arg_i_r <= 32'd0;
                                    task_write_word_r <= 3'd0;
                                    pblc_block_count_r <= 8'd0;
                                    pblc_state_r <= 256'b0;
                                    pblc_buffer_r <= pblc_initial_w;
                                    block_count_r <= 2'd1;
                                    state_r <= STATE_TASK_PREFETCH;
                                end
                                if (!single_engine_command_w &&
                                    !verify_cmd_w && !dintr_cmd_w && !hash_ram_path_w) begin
                                    state_r <= STATE_START_CORE;
                                end
                            end
                            ACT_DONE_SEED: begin
                                /* SEED slot latched by SEC on the CTRL_START cycle (seed_latch_en
                                 * combinational); when HAS_SECURITY=0 latched locally (g_sec_off). */
                                done_r <= 1'b1;
                            end
                            ACT_DONE_CHAIN0: begin
                                for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                    output_words[output_index] <= input_words[output_index];
                                end
                                done_r <= 1'b1;
                            end
                            ACT_DONE_KWRAP: begin
                                /* K_WRAP slot latched by SEC (kwrap_latch_en combinational). */
                                done_r <= 1'b1;
                            end
                            ACT_DONE_KSTATE: begin
                                /* K_STATE slot latched by SEC (kstate_latch_en combinational). */
                                done_r <= 1'b1;
                            end
                            ACT_DONE_MC: begin
                                /* sim_mc updated by SEC (mc_step/mc_load combinational), new value
                                 * read back via mc_next_value. */
                                output_words[0] <= sec_mc_next_value_w;
                                done_r <= 1'b1;
                            end
                            ACT_START_HMAC: begin
                                /* HMAC executed by SEC's own FSM (hmac_start combinational already driven). */
                            end
                            ACT_START_WRAP: begin
                                /* WRAP/UNWRAP executed by SEC's own FSM (wrap_start combinational already driven). */
                            end
                            ACT_START_STC: begin
                                /* STATE_COMMIT executed by SEC's own FSM (stc_start combinational already driven, S9). */
                            end
                            default: begin
                                error_status_r <= 1'b1;
                                error_r <= ERR_UNSUPPORTED_COMMAND;
                            end
                        endcase
                    end
                end else if (bus_wdata != 0) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b1;
                    error_r <= ERR_CONTROL;
                    cycle_count_r <= 32'd1;
                end
            end else if (!wrapper_busy_w) begin
                if (bus_addr == REG_COMMAND) begin
                    command_r <= bus_wdata;
                end else if (bus_addr == REG_INPUT_LENGTH) begin
                    input_length_r <= bus_wdata;
                end else if (bus_addr == REG_OUTPUT_LENGTH) begin
                    output_length_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_Q) begin
                    arg_q_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_I) begin
                    arg_i_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_START) begin
                    arg_start_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_STEPS) begin
                    arg_steps_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_KEY) begin
                    arg_key_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_LEAF_NODE) begin
                    arg_leaf_node_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_W) begin
                    arg_w_r <= bus_wdata[3:0];
                end else if (!stream_wr_en && !stream_rd_en &&
                             bus_addr == REG_TASK_ADDR && bus_wdata < 2152) begin
                    task_addr_r <= bus_wdata[11:0];
                    if (bus_wdata >= 32) begin
                        task_prefetch_pending_r <= 1'b1;
                    end
                end else if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w &&
                             bus_valid && bus_write && bus_addr == REG_TASK_DATA &&
                             task_addr_r >= 32) begin
                    /* Write-side auto-increment (S6, aligned with the SHAKE wrapper):
                     * hw_dintr_authpath batch-writes leaf/path relying on one ADDR + consecutive
                     * DATA; without it all 8 writes collapse onto the first address (SoC root mismatch, 0.1.264). */
                    task_addr_r <= task_addr_r + 12'd1;
                end else if (!stream_wr_en && !stream_rd_en &&
                             bus_addr == REG_TASK_DATA) begin
                    if (task_addr_r < 32) begin
                        coefficient_words[task_addr_r[4:0]] <= bus_wdata;
                    end
                end else if (bus_addr >= REG_IDENTIFIER && bus_addr < REG_IDENTIFIER + 16 &&
                             bus_addr[1:0] == 2'b00) begin
                    identifier_words[bus_addr[3:2]] <= bus_wdata;
                end else if (bus_addr >= REG_INPUT_BASE && bus_addr < REG_INPUT_BASE + 128 &&
                             bus_addr[1:0] == 2'b00) begin
                    input_words[bus_addr[6:2]] <= bus_wdata;
                end else if (!HAS_SECURITY && INSECURE_TEST_MODE && bus_addr >= REG_SEED_BASE &&
                             bus_addr < REG_SEED_BASE + 32 && bus_addr[1:0] == 2'b00) begin
                    /* Local SEED staging (only HAS_SECURITY=0; SEC mode handled by lms_sha256_sec). */
                    local_seed_staging[bus_addr[4:2]] <= bus_wdata;
                end
            end
        end

        /* MQC coefficient write (STATE_MQC_COEF produces 1 coefficient per cycle, S8): case-expanded
         * fixed words, avoiding the barrel write-enable network of dynamic word-indexed array writes
         * (a major area cost). Shares coefficient_words with bus writes in the same always block
         * (single driver). word 0..8 = max W1 9 words; must sit outside !wrapper_busy_w (busy during MQC_COEF). */
        if (mqc_cmd_w && state_r == STATE_MQC_COEF) begin
            case (mqc_word_idx_w)
                    5'd0: case (w_coef_bits)
                        4'd1: coefficient_words[0][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[0][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[0][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[0][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd1: case (w_coef_bits)
                        4'd1: coefficient_words[1][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[1][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[1][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[1][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd2: case (w_coef_bits)
                        4'd1: coefficient_words[2][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[2][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[2][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[2][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd3: case (w_coef_bits)
                        4'd1: coefficient_words[3][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[3][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[3][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[3][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd4: case (w_coef_bits)
                        4'd1: coefficient_words[4][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[4][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[4][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[4][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd5: case (w_coef_bits)
                        4'd1: coefficient_words[5][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[5][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[5][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[5][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd6: case (w_coef_bits)
                        4'd1: coefficient_words[6][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[6][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[6][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[6][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd7: case (w_coef_bits)
                        4'd1: coefficient_words[7][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[7][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[7][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[7][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    default: case (w_coef_bits)
                        4'd1: coefficient_words[8][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[8][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[8][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[8][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                endcase
        end

        if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && done_r && bus_valid &&
            !bus_write && bus_addr == REG_TASK_DATA &&
            task_addr_r >= 32 && !stream_read_r) begin
            /* Auto-increment read: address increments when bus_valid first asserts, preventing multi-cycle repeats */
            task_addr_r <= task_addr_r + 12'd1;
            stream_read_r <= 1'b1;
        end else if (!bus_valid) begin
            stream_read_r <= 1'b0;
        end

        if (state_r == STATE_START_CORE) begin
            core_start_r <= 1'b1;
            cycle_count_r <= cycle_count_r + 1'b1;
            if (dual_active_w) begin
                /* Dual-core mode: latch block after starting core0, then set up core1 */
                if (chain_steps_left0_r != 0 || batch_phase_r == BATCH_DERIVE) begin
                    core_start0_r <= 1'b1;
                    core0_run_r <= 1'b1;
                end else begin
                    /* Core already finished (asymmetric chain ended early); skip start and mark done directly */
                    core0_done_latched_r <= 1'b1;
                end
                block0_latched_r <= block_w;
                state_r <= STATE_DUAL_SETUP1;
            end else begin
                state_r <= STATE_WAIT_CORE;
            end
        end else if (state_r == STATE_DUAL_SETUP1) begin
            /* core0 running; set up core1 */
            block1_latched_r <= block0_latched_r;
            block1_latched_r[511 - 20*8 -: 8] <= {7'b0, batch_i1_w[8]};
            block1_latched_r[511 - 21*8 -: 8] <= batch_i1_w[7:0];
            if (batch_phase_r != BATCH_DERIVE && chain_steps_left1_r != 0) begin
                /* BATCH_CHAIN and chain 1 still has steps: replace j and chain_value */
                block1_latched_r[511 - 22*8 -: 8] <= chain_j1_r;
                for (bj = 23; bj < 55; bj = bj + 1) begin
                    block1_latched_r[511 - bj*8 -: 8] <=
                        chain_value1_r[255 - (bj - 23)*8 -: 8];
                end
            end
            core_start1_r <= 1'b1;
            if (chain_steps_left1_r != 0 || batch_phase_r == BATCH_DERIVE) begin
                core1_run_r <= 1'b1;
            end else begin
                /* Core already finished (asymmetric chain ended early); skip start and mark done directly */
                core1_done_latched_r <= 1'b1;
            end
            state_r <= STATE_DUAL_WAIT;
        end else if (state_r == STATE_DUAL_WAIT) begin
            /* Dual-core wait: latch done pulses (single-cycle), process once both cores finish */
            cycle_count_r <= cycle_count_r + 1'b1;
            if (core0_done_w) core0_done_latched_r <= 1'b1;
            if (core1_done_w) core1_done_latched_r <= 1'b1;
            /* Prevent an early-finished core from auto-restarting and overwriting the digest.
             * In asymmetric chains (e.g. Verify) one core may finish hundreds of cycles early.
             * Gated by the coreX_run_r enable; once cleared, start=0 blocks restart. */
            if (core0_done_w) core0_run_r <= 1'b0;
            if (core1_done_w) core1_run_r <= 1'b0;
            if ((core0_done_latched_r || core0_done_w) &&
                (core1_done_latched_r || core1_done_w)) begin
                core0_done_latched_r <= 1'b0;
                core1_done_latched_r <= 1'b0;
                /* Save both cores' results */
                if (command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                    command_r == CMD_LMOTS_SIGN || verify_cmd_w) begin
                    if (batch_phase_r == BATCH_DERIVE) begin
                        chain_value0_r <= core0_digest_w;
                        chain_value1_r <= core1_digest_w;
                        if (command_r == CMD_LMOTS_SIGN) begin
                            /* Sign: DERIVE dual-core done, set up dual-core CHAIN.
                             * chain_value0_r/chain_value1_r already set in shared code.
                             * chain_value_r is used for block_w assembly (same as KeyGen). */
                            chain_value_r <= core0_digest_w;
                            chain_j0_r <= 8'd0;
                            chain_j1_r <= 8'd0;
                            chain_j_r   <= 8'd0;
                            chain_steps_left0_r <= batch_coefficient_w;
                            chain_steps_left1_r <= batch_coefficient1_w;
                            batch_phase_r <= BATCH_CHAIN;
                            state_r <= STATE_START_CORE;
                        end else begin
                            chain_value_r <= core0_digest_w;
                            chain_j0_r <= 8'd0;
                            chain_j1_r <= 8'd0;
                            chain_j_r   <= 8'd0;
                            chain_steps_left0_r <= w_max_step;
                            chain_steps_left1_r <= w_max_step;
                            batch_phase_r <= BATCH_CHAIN;
                            state_r <= STATE_START_CORE;
                        end
                    end else if (chain_steps_left0_r > 1 || chain_steps_left1_r > 1) begin
                        /* Asymmetric CHAIN: update only chains that still have steps */
                        if (chain_steps_left0_r > 0) begin
                            chain_value0_r <= core0_digest_w;
                            chain_value_r   <= core0_digest_w;
                            chain_j0_r <= chain_j0_r + 1'b1;
                            chain_j_r   <= chain_j0_r + 1'b1;
                            chain_steps_left0_r <= chain_steps_left0_r - 1'b1;
                        end
                        if (chain_steps_left1_r > 0) begin
                            chain_value1_r <= core1_digest_w;
                            chain_j1_r <= chain_j1_r + 1'b1;
                            chain_steps_left1_r <= chain_steps_left1_r - 1'b1;
                        end
                        state_r <= STATE_START_CORE;
                    end else if (command_r == CMD_LMOTS_SIGN) begin
                        /* Sign dual-core CHAIN done: core0/1_digest_w are the final results this cycle.
                         * When coeff==0 core0 was not restarted; digest keeps the DERIVE output. */
                        task_digest0_r <= core0_digest_w;
                        task_digest1_r <= core1_digest_w;
                        task_write_word0_r <= 3'd0;
                        task_write_word1_r <= 3'd0;
                        dual_write_sel_r <= 1'b0;
                        batch_phase_r <= BATCH_DERIVE;
                        state_r <= STATE_TASK_WRITE;
                    end else begin
                        /* Both chains done: PBLc two phases.
                         * Phase 1: core0 -> pblc_buffer[22:53]
                         * Phase 2: pblc_block=pblc_buffer (incl. core0),
                         *   core1 -> pblc_buffer[0:21] (left for the next PBLc block) */
                        for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                            pblc_buffer_r[511 - (22 + output_index)*8 -: 8] <=
                                core0_digest_w[255 - output_index*8 -: 8];
                        end
                        task_digest0_r <= core0_digest_w;
                        task_digest1_r <= core1_digest_w;
                        task_write_word0_r <= 3'd0;
                        task_write_word1_r <= 3'd0;
                        dual_write_sel_r <= 1'b0;
                        dual_pblc_delay_r <= 1'b1;
                    end
                end
            end
            if (dual_pblc_delay_r) begin
                /* Phase 2: pblc_buffer already holds core0_digest; capture pblc_block,
                 * then write the core1 prefix to prepare the next PBLc block.
                 * Uses pblc_next_block_w (with padding fix). */
                pblc_block_r <= pblc_next_block_w;
                for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                    pblc_buffer_r[511 - output_index*8 -: 8] <=
                        core1_digest_w[255 - (10 + output_index)*8 -: 8];
                end
                dual_pblc_delay_r <= 1'b0;
                batch_phase_r <= BATCH_PBLC;
                state_r <= STATE_START_CORE;
            end
        end else if (state_r == STATE_WAIT_CORE) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (core_done_w) begin
                if (dintr_cmd_w) begin
                    /* D_INTR chain (S6): block0 done -> continue block1 (core state continues
                     * automatically); block1 done -> next layer (left=digest, node>>=1) or output root. */
                    if (block_index_r == 2'd0) begin
                        block_index_r <= 2'd1;
                        state_r <= STATE_DINTR_KICK;
                    end else if (dintr_layer_r + 1'b1 < {1'b0, arg_steps_r[4:0]}) begin
                        dintr_left_r <= core_digest_w;
                        dintr_node_r <= dintr_node_r >> 1;
                        dintr_layer_r <= dintr_layer_r + 1'b1;
                        dintr_load_word_r <= 4'd0;
                        block_index_r <= 2'd0;
                        state_r <= STATE_DINTR_LOAD_SIB;
                    end else begin
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        state_r <= STATE_IDLE;
                        done_r <= 1'b1;
                    end
                end else if (hash_ram_path_w) begin
                    /* HASH_ONCE_RAM/MQC (S7/S8): block done -> next block (prefetch first word) /
                     * last block output (MQC last block latches Q, switches to coefficient generation) */
                    if (hash_ram_block_r + 1'b1 < hash_ram_blocks_w) begin
                        hash_ram_block_r <= hash_ram_block_r + 1'b1;
                        hash_ram_word_r <= 6'd0;
                        block_index_r <= 2'd1;   /* Later blocks init=0 (core state continues) */
                        state_r <= STATE_TASK_PREFETCH;
                    end else if (mqc_cmd_w) begin
                        /* MQC last block: latch big-endian Q (mqc_q_be_r[271:16]) + output_words
                         * little-endian words (Q readable back) -> coefficient generation */
                        mqc_q_be_r[271:16] <= core_digest_w;
                        mqc_checksum_r <= 16'd0;
                        mqc_idx_r <= 9'd0;
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        state_r <= STATE_MQC_COEF;
                    end else begin
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        state_r <= STATE_IDLE;
                        done_r <= 1'b1;
                    end
                end else if (keygen_dleaf_r) begin
                    /* D_LEAF done: output leaf node digest */
                    keygen_dleaf_r <= 1'b0;
                    for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                        output_words[output_index] <= {
                            core_digest_w[255 - (output_index * 32 + 24) -: 8],
                            core_digest_w[255 - (output_index * 32 + 16) -: 8],
                            core_digest_w[255 - (output_index * 32 + 8) -: 8],
                            core_digest_w[255 - output_index * 32 -: 8]
                        };
                    end
                    state_r <= STATE_IDLE;
                    done_r <= 1'b1;
                end else if (verify_cmd_w) begin
                    if (batch_phase_r == BATCH_CHAIN && chain_steps_left_r > 1) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= chain_j_r + 1'b1;
                        chain_steps_left_r <= chain_steps_left_r - 1'b1;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN &&
                                 (batch_i_r[0] || batch_i_r == w_p_last)) begin
                        pblc_block_r <= pblc_next_block_w;
                        if (batch_i_r[0]) begin
                            pblc_buffer_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_buffer_r[511 - output_index * 8 -: 8] <=
                                    core_digest_w[255 - (10 + output_index) * 8 -: 8];
                            end
                        end
                        batch_phase_r <= BATCH_PBLC;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN) begin
                        for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                            pblc_buffer_r[511 - (22 + output_index) * 8 -: 8] <=
                                core_digest_w[255 - output_index * 8 -: 8];
                        end
                        batch_i_r <= batch_i_r + 1'b1;
                        arg_i_r <= arg_i_r + 1'b1;
                        task_write_word_r <= 3'd0;
                        state_r <= STATE_TASK_PREFETCH;
                    end else if (batch_i_r == w_p_last || pblc_final_due_r) begin
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        pblc_final_due_r <= 1'b0;
                        if (command_r == CMD_LMOTS_VERIFY_LEAF) begin
                            /* VERIFY_LEAF: K_q already in output_words; set the D_LEAF flag and
                             * continue computing D_LEAF. Distinguish via keygen_dleaf_r, not batch_i==66:
                             * the batch-task PREFETCH (chain 66 input) also has batch_i==66. */
                            keygen_dleaf_r <= 1'b1;
                            state_r <= STATE_TASK_PREFETCH;
                        end else begin
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end
                    end else begin
                        pblc_state_r <= core_digest_w;
                        pblc_block_count_r <= pblc_block_count_r + 1'b1;
                        if (w_p_even && batch_i_r ==
                            (verify_dc_mode_r ? w_p - 9'd2 : w_p - 9'd1)) begin
                            /* W8 (p even) after last full-block absorb: residual window 22B + padding final block */
                            pblc_final_due_r <= 1'b1;
                            pblc_block_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_block_r[511 - output_index * 8 -: 8] <=
                                    pblc_buffer_r[511 - output_index * 8 -: 8];
                            end
                            pblc_block_r[511 - 22 * 8 -: 8] <= 8'h80;
                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                pblc_block_r[511 - (56 + output_index) * 8 -: 8] <=
                                    pblc_bitlen_w[(7 - output_index) * 8 +: 8];
                            end
                            state_r <= STATE_START_CORE;
                        end else begin
                            batch_i_r <= batch_i_r + (verify_dc_mode_r ? 9'd2 : 9'd1);
                            arg_i_r <= arg_i_r + (verify_dc_mode_r ? 32'd2 : 32'd1);
                            task_write_word_r <= 3'd0;
                            batch_phase_r <= BATCH_CHAIN;
                            state_r <= STATE_TASK_PREFETCH;
                        end
                    end
                end else if (command_r == CMD_LMOTS_SIGN) begin
                    if (batch_phase_r == BATCH_DERIVE && batch_coefficient_w == 0) begin
                        /* 0-step chain (y=x output directly). Must set BATCH_CHAIN simultaneously:
                         * TASK_WRITE selects the dual-core write branch by phase!=BATCH_CHAIN; keeping
                         * DERIVE would wrongly write stale task_digest0_r (odd-p last-chain single-core
                         * case, root cause of wrong W1 tail-chain y[264], 0.1.266->0.1.267). */
                        task_digest_r <= core_digest_w;
                        task_write_word_r <= 3'd0;
                        batch_phase_r <= BATCH_CHAIN;
                        state_r <= STATE_TASK_WRITE;
                    end else if (batch_phase_r == BATCH_DERIVE) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= 8'd0;
                        chain_steps_left_r <= batch_coefficient_w;
                        batch_phase_r <= BATCH_CHAIN;
                        state_r <= STATE_START_CORE;
                    end else if (chain_steps_left_r > 1) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= chain_j_r + 1'b1;
                        chain_steps_left_r <= chain_steps_left_r - 1'b1;
                        state_r <= STATE_START_CORE;
                    end else begin
                        task_digest_r <= core_digest_w;
                        task_write_word_r <= 3'd0;
                        state_r <= STATE_TASK_WRITE;
                    end
                end else if (command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF) begin
                    if (batch_phase_r == BATCH_DERIVE) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= 8'd0;
                        chain_steps_left_r <= w_max_step;
                        batch_phase_r <= BATCH_CHAIN;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN && chain_steps_left_r > 1) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= chain_j_r + 1'b1;
                        chain_steps_left_r <= chain_steps_left_r - 1'b1;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN &&
                                 (batch_i_r[0] || batch_i_r == w_p_last)) begin
                        pblc_block_r <= pblc_next_block_w;
                        if (batch_i_r[0]) begin
                            pblc_buffer_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_buffer_r[511 - output_index * 8 -: 8] <=
                                    core_digest_w[255 - (10 + output_index) * 8 -: 8];
                            end
                        end
                        batch_phase_r <= BATCH_PBLC;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN) begin
                        for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                            pblc_buffer_r[511 - (22 + output_index) * 8 -: 8] <=
                                core_digest_w[255 - output_index * 8 -: 8];
                        end
                        batch_i_r <= batch_i_r + 1'b1;
                        arg_i_r <= arg_i_r + 1'b1;
                        batch_phase_r <= BATCH_DERIVE;
                        state_r <= STATE_START_CORE;
                    end else if (batch_i_r == w_p_last || pblc_final_due_r) begin
                        pblc_final_due_r <= 1'b0;
                        if (command_r == CMD_LMOTS_KEYGEN_LEAF) begin
                            /* K_q -> output_words; fill input_words one cycle later */
                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                output_words[output_index] <= {
                                    core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                    core_digest_w[255 - output_index * 32 -: 8]
                                };
                            end
                            state_r <= STATE_TASK_PREFETCH;
                        end else begin
                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                output_words[output_index] <= {
                                    core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                    core_digest_w[255 - output_index * 32 -: 8]
                                };
                            end
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end
                    end else begin
                        pblc_state_r <= core_digest_w;
                        pblc_block_count_r <= pblc_block_count_r + 1'b1;
                        if (w_p_even && batch_i_r == w_p - 9'd2) begin
                            /* W8 (p even) after the last full-block pair absorb: residual window 22B + padding final block */
                            pblc_final_due_r <= 1'b1;
                            pblc_block_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_block_r[511 - output_index * 8 -: 8] <=
                                    pblc_buffer_r[511 - output_index * 8 -: 8];
                            end
                            pblc_block_r[511 - 22 * 8 -: 8] <= 8'h80;
                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                pblc_block_r[511 - (56 + output_index) * 8 -: 8] <=
                                    pblc_bitlen_w[(7 - output_index) * 8 +: 8];
                            end
                            state_r <= STATE_START_CORE;
                        end else begin
                            batch_i_r <= batch_i_r + (dual_batch_w ? 9'd2 : 9'd1);
                            arg_i_r <= arg_i_r + (dual_batch_w ? 32'd2 : 32'd1);
                            batch_phase_r <= BATCH_DERIVE;
                            state_r <= STATE_START_CORE;
                        end
                    end
                end else if (block_index_r + 1'b1 < block_count_r) begin
                    block_index_r <= block_index_r + 1'b1;
                    state_r <= STATE_START_CORE;
                end else begin
                    for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                        output_words[output_index] <= {
                            core_digest_w[255 - (output_index * 32 + 24) -: 8],
                            core_digest_w[255 - (output_index * 32 + 16) -: 8],
                            core_digest_w[255 - (output_index * 32 + 8) -: 8],
                            core_digest_w[255 - output_index * 32 -: 8]
                        };
                    end
                    state_r <= STATE_IDLE;
                    if (busy_error_pending_r) begin
                        done_r <= 1'b0;
                        error_status_r <= 1'b1;
                        error_r <= ERR_BUSY;
                    end else begin
                        done_r <= 1'b1;
                        error_status_r <= 1'b0;
                        error_r <= 32'b0;
                    end
                end
            end
        end else if (state_r == STATE_TASK_WRITE) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (dual_batch_w && batch_phase_r != BATCH_CHAIN) begin
                /* Dual-core write: write core0's 8 words first.
                 * If already at the last pair (batch_i == last chain index), write only core0.
                 * During Sign's DERIVE->CHAIN transition batch_phase_r=BATCH_CHAIN,
                 * so the single-core write path (task_write_word_r) is used. */
                if (!dual_write_sel_r) begin
                    if (task_write_word0_r == 3'd7) begin
                        task_write_word0_r <= 3'd0;
                        if (batch_i_r == w_p_last) begin
                            /* Last pair: core1 is dummy, finish directly */
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end else begin
                            dual_write_sel_r <= 1'b1;
                        end
                    end else begin
                        task_write_word0_r <= task_write_word0_r + 1'b1;
                    end
                end else begin
                    if (task_write_word1_r == 3'd7) begin
                        task_write_word1_r <= 3'd0;
                        dual_write_sel_r <= 1'b0;
                        if (w_p_even && batch_i_r == w_p - 9'd2) begin
                            /* W8 (p even) last pair dual write done; no dummy single chain, finish directly */
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end else begin
                            /* Dual-core write done: batch_i += 2 */
                            batch_i_r <= batch_i_r + 9'd2;
                            arg_i_r <= arg_i_r + 32'd2;
                            batch_phase_r <= BATCH_DERIVE;
                            state_r <= STATE_START_CORE;
                        end
                    end else begin
                        task_write_word1_r <= task_write_word1_r + 1'b1;
                    end
                end
            end else if (task_write_word_r == 3'd7) begin
                if (batch_i_r == w_p_last) begin
                    state_r <= STATE_IDLE;
                    done_r <= 1'b1;
                end else begin
                    batch_i_r <= batch_i_r + 1'b1;
                    arg_i_r <= arg_i_r + 1'b1;
                    batch_phase_r <= BATCH_DERIVE;
                    state_r <= STATE_START_CORE;
                end
            end else begin
                task_write_word_r <= task_write_word_r + 1'b1;
            end
        end else if (state_r == STATE_TASK_PREFETCH) begin
            if (hash_ram_path_w) begin
                /* HASH_ONCE_RAM/MQC: block first word already prefetched (combinational read), switch to read-window consumption */
                cycle_count_r <= cycle_count_r + 1'b1;
                state_r <= STATE_HASH_RAM_LOAD;
            end else if (command_r == CMD_LMOTS_KEYGEN_LEAF ||
                (command_r == CMD_LMOTS_VERIFY_LEAF && keygen_dleaf_r)) begin
                /* Build the D_LEAF message from internal registers into input_words.
                 * VERIFY_LEAF builds it only on a PREFETCH where K_q is already computed
                 * (keygen_dleaf_r flag); batch-task PREFETCH (prefetching chain input, flag=0) must
                 * go through TASK_LOAD. output_words already holds K_q (prev cycle's NBA in effect) */
                input_words[0] <= identifier_words[0];
                input_words[1] <= identifier_words[1];
                input_words[2] <= identifier_words[2];
                input_words[3] <= identifier_words[3];
                input_words[4] <= {arg_leaf_node_r[7:0], arg_leaf_node_r[15:8],
                                   arg_leaf_node_r[23:16], arg_leaf_node_r[31:24]};
                /* K_q bytes packed into LE words: input_words[n]={Kq[4n+3],Kq[4n+2],Kq[4n+1],Kq[4n+0]}.
                 * output_words store K_q big-endian bytes: ow[i]={Kq[4i],Kq[4i+1],Kq[4i+2],Kq[4i+3]}.
                 * input_words[5]={Kq[1],Kq[0],0x82,0x82}={ow[0][23:16],ow[0][31:24],...}
                 * input_words[n]={ow[n-5][23:16],ow[n-5][31:24],ow[n-6][7:0],ow[n-6][15:8]} (n>=6) */
                input_words[5] <= {output_words[0][15:8], output_words[0][7:0], 8'h82, 8'h82};
                input_words[6]  <= {output_words[1][15:8], output_words[1][7:0],
                                    output_words[0][31:24], output_words[0][23:16]};
                input_words[7]  <= {output_words[2][15:8], output_words[2][7:0],
                                    output_words[1][31:24], output_words[1][23:16]};
                input_words[8]  <= {output_words[3][15:8], output_words[3][7:0],
                                    output_words[2][31:24], output_words[2][23:16]};
                input_words[9]  <= {output_words[4][15:8], output_words[4][7:0],
                                    output_words[3][31:24], output_words[3][23:16]};
                input_words[10] <= {output_words[5][15:8], output_words[5][7:0],
                                    output_words[4][31:24], output_words[4][23:16]};
                input_words[11] <= {output_words[6][15:8], output_words[6][7:0],
                                    output_words[5][31:24], output_words[5][23:16]};
                input_words[12] <= {output_words[7][15:8], output_words[7][7:0],
                                    output_words[6][31:24], output_words[6][23:16]};
                input_words[13] <= {16'b0, output_words[7][31:24], output_words[7][23:16]};
                keygen_dleaf_r <= 1'b1;
                block_count_r <= 2'd1;
                block_index_r <= 2'd0;
                state_r <= STATE_START_CORE;
            end else begin
                cycle_count_r <= cycle_count_r + 1'b1;
                state_r <= STATE_TASK_LOAD;
            end
        end else if (state_r == STATE_TASK_LOAD) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (verify_dual_load_r) begin
                chain_value1_r[255 - task_write_word_r * 32 -: 32] <= {
                    task_ram_read_r[7:0], task_ram_read_r[15:8],
                    task_ram_read_r[23:16], task_ram_read_r[31:24] };
            end else begin
                chain_value_r[255 - task_write_word_r * 32 -: 32] <= {
                    task_ram_read_r[7:0], task_ram_read_r[15:8],
                    task_ram_read_r[23:16], task_ram_read_r[31:24] };
            end
            if (task_write_word_r == 3'd7) begin
                if (dual_batch_w && verify_cmd_w && !verify_dual_load_r &&
                    !batch_i_r[0] &&
                    batch_i1_w < w_p &&
                    batch_coefficient_w != w_max_step && batch_coefficient1_w != w_max_step) begin
                    verify_dual_load_r <= 1'b1;
                    task_write_word_r <= 3'd0;
                end else if (dual_batch_w && verify_cmd_w && verify_dual_load_r) begin
                    chain_j0_r <= batch_coefficient_w;
                    chain_j1_r <= batch_coefficient1_w;
                    chain_j_r   <= batch_coefficient_w;
                    chain_steps_left0_r <= w_max_step - batch_coefficient_w;
                    chain_steps_left1_r <= w_max_step - batch_coefficient1_w;
                    verify_dual_load_r <= 1'b0;
                    verify_dc_mode_r <= 1'b1;
                    batch_phase_r <= BATCH_CHAIN;
                    state_r <= STATE_START_CORE;
                end else begin
                    if (dual_batch_w && verify_cmd_w) begin
                        verify_dual_load_r <= 1'b0;
                        verify_dc_mode_r <= 1'b0;
                    end
                    chain_j_r <= batch_coefficient_w;
                    chain_steps_left_r <= w_max_step - batch_coefficient_w;
                    if (batch_coefficient_w == w_max_step)
                        state_r <= STATE_TASK_ENDPOINT;
                    else
                        state_r <= STATE_START_CORE;
                end
            end else begin
                task_write_word_r <= task_write_word_r + 1'b1;
            end
        end else if (state_r == STATE_DINTR_PREFETCH) begin
            /* Starting left's first word (word32) already prefetched; consumed next cycle (S6) */
            cycle_count_r <= cycle_count_r + 1'b1;
            state_r <= STATE_DINTR_LOAD_START;
        end else if (state_r == STATE_DINTR_LOAD_START) begin
            /* Read starting left 8 words (contiguous big-endian, bytes reversed) */
            cycle_count_r <= cycle_count_r + 1'b1;
            dintr_left_r[255 - dintr_load_word_r * 32 -: 32] <= {
                task_ram_read_r[7:0], task_ram_read_r[15:8],
                task_ram_read_r[23:16], task_ram_read_r[31:24] };
            if (dintr_load_word_r == 4'd7) begin
                dintr_load_word_r <= 4'd0;
                state_r <= STATE_DINTR_LOAD_SIB;  /* sibling[0] first word already prefetched */
            end else begin
                dintr_load_word_r <= dintr_load_word_r + 1'b1;
            end
        end else if (state_r == STATE_DINTR_LOAD_SIB) begin
            /* Read sibling[layer] 8 words; full -> KICK (build block after right complete) */
            cycle_count_r <= cycle_count_r + 1'b1;
            dintr_right_r[255 - dintr_load_word_r * 32 -: 32] <= {
                task_ram_read_r[7:0], task_ram_read_r[15:8],
                task_ram_read_r[23:16], task_ram_read_r[31:24] };
            if (dintr_load_word_r == 4'd7) begin
                dintr_load_word_r <= 4'd0;
                state_r <= STATE_DINTR_KICK;
            end else begin
                dintr_load_word_r <= dintr_load_word_r + 1'b1;
            end
        end else if (state_r == STATE_DINTR_KICK) begin
            /* right complete: kick core0 (block built combinationally by block_w; block1 init=0 continues automatically) */
            cycle_count_r <= cycle_count_r + 1'b1;
            core_start_r <= 1'b1;
            state_r <= STATE_WAIT_CORE;
        end else if (state_r == STATE_HASH_RAM_LOAD) begin
            /* HASH_ONCE_RAM read window: consume task_ram_read_r each cycle (PREFETCH already
             * fetched the first word); full (rd_words) -> KICK. rd_words=0 (pure padding) kicks immediately. */
            cycle_count_r <= cycle_count_r + 1'b1;
            if (hash_ram_word_r == hash_ram_rd_words_w) begin
                hash_ram_word_r <= 6'd0;
                state_r <= STATE_HASH_RAM_KICK;
            end else begin
                /* word w stored in the high-lane layout [575-w*32-:32] (bytes reversed, word0
                 * byte0 at [575:568]), consistent with block construction window[575-byte*8-:8] (D_INTR same) */
                hash_ram_window_r[575 - hash_ram_word_r * 32 -: 32] <= {
                    task_ram_read_r[7:0], task_ram_read_r[15:8],
                    task_ram_read_r[23:16], task_ram_read_r[31:24] };
                hash_ram_word_r <= hash_ram_word_r + 1'b1;
            end
        end else if (state_r == STATE_HASH_RAM_KICK) begin
            /* Read window full: build block combinationally (block0 block_index=0 -> init=1) + kick core0 */
            cycle_count_r <= cycle_count_r + 1'b1;
            core_start_r <= 1'b1;
            state_r <= STATE_WAIT_CORE;
        end else if (state_r == STATE_MQC_COEF) begin
            /* MSG_Q_COEF coefficient generation (S8): 1 coefficient per cycle (writes to
             * coefficient_words done by the bus always block's case expansion); while i<u also
             * accumulate checksum, at i=u-1 latch cs into q34[15:0]; i=p-1 -> done. */
            cycle_count_r <= cycle_count_r + 1'b1;
            if (mqc_idx_r < mqc_u_w) begin
                mqc_checksum_r <= mqc_checksum_r + (w_max_step - mqc_digit_w);
                if (mqc_idx_r == mqc_u_w - 9'd1) begin
                    mqc_q_be_r[15:0] <= (mqc_checksum_r + (w_max_step - mqc_digit_w)) << mqc_ls_w;
                end
            end
            if (mqc_idx_r == w_p - 9'd1) begin
                mqc_idx_r <= 9'd0;
                state_r <= STATE_IDLE;
                done_r <= 1'b1;
            end else begin
                mqc_idx_r <= mqc_idx_r + 9'd1;
            end
        end else if (state_r == STATE_TASK_ENDPOINT) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (batch_i_r[0] || batch_i_r == w_p_last) begin
                pblc_block_r <= pblc_next_block_w;
                if (batch_i_r[0]) begin
                    pblc_buffer_r <= 512'b0;
                    for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                        pblc_buffer_r[511 - output_index * 8 -: 8] <=
                            chain_value_r[255 - (10 + output_index) * 8 -: 8];
                    end
                end
                batch_phase_r <= BATCH_PBLC;
                state_r <= STATE_START_CORE;
            end else begin
                for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                    pblc_buffer_r[511 - (22 + output_index) * 8 -: 8] <=
                        chain_value_r[255 - output_index * 8 -: 8];
                end
                batch_i_r <= batch_i_r + 1'b1;
                arg_i_r <= arg_i_r + 1'b1;
                task_write_word_r <= 3'd0;
                state_r <= STATE_TASK_PREFETCH;
            end
        end

        /* REVIEW B08-R9: input_words/output_words/identifier_words/task_ram_read_r are
         * intentionally not reset -- the protocol guarantees "write before read" (command input ->
         * execute -> read OUTPUT); task_ram_read_r is the BRAM read-data capture (BRAM not reset).
         * The xprop regression (--x-initial unique) currently EXIT=0, relying on protocol order; a future "read before write" command must add reset. */
        if (rst) begin
            command_r <= 32'b0;
            input_length_r <= 32'b0;
            output_length_r <= 32'b0;
            arg_q_r <= 32'b0;
            arg_i_r <= 32'b0;
            arg_start_r <= 32'b0;
            arg_steps_r <= 32'b0;
            arg_key_r <= 32'b0;
            error_r <= 32'b0;
            cycle_count_r <= 32'b0;
            state_r <= STATE_IDLE;
            block_index_r <= 2'b0;
            block_count_r <= 2'b0;
            done_r <= 1'b0;
            error_status_r <= 1'b0;
            busy_error_pending_r <= 1'b0;
            core_start_r <= 1'b0;
            engine_start_r <= 1'b0;
            chain_value_r <= 256'b0;
            chain_j_r <= 8'b0;
            chain_steps_left_r <= 8'b0;
            batch_phase_r <= BATCH_DERIVE;
            batch_i_r <= 9'b0;
            arg_w_r <= 4'd4;   /* Default W4, zero regression */
            pblc_final_due_r <= 1'b0;
            pblc_block_count_r <= 8'b0;
            pblc_state_r <= 256'b0;
            pblc_buffer_r <= 512'b0;
            pblc_block_r <= 512'b0;
            task_addr_r <= 12'b0;
            task_prefetch_pending_r <= 1'b0;
            stream_read_r <= 1'b0;
            keygen_dleaf_r <= 1'b0;
            core_start0_r <= 1'b0;
            core_start1_r <= 1'b0;
            core0_done_latched_r <= 1'b0;
            core1_done_latched_r <= 1'b0;
            dual_pblc_delay_r <= 1'b0;
            chain_value0_r <= 256'b0;
            chain_value1_r <= 256'b0;
            chain_j0_r <= 8'b0;
            chain_j1_r <= 8'b0;
            chain_steps_left0_r <= 8'b0;
            chain_steps_left1_r <= 8'b0;
            task_digest0_r <= 256'b0;
            task_digest1_r <= 256'b0;
            task_write_word0_r <= 3'b0;
            task_write_word1_r <= 3'b0;
            dual_write_sel_r <= 1'b0;
            verify_dual_load_r <= 1'b0;
            verify_dc_mode_r <= 1'b0;
            core0_run_r <= 1'b0;
            core1_run_r <= 1'b0;
            block0_latched_r <= 512'b0;
            block1_latched_r <= 512'b0;
            arg_leaf_node_r <= 32'b0;
            task_write_word_r <= 3'b0;
            task_digest_r <= 256'b0;
            dintr_left_r <= 256'b0;
            dintr_right_r <= 256'b0;
            dintr_node_r <= 32'b0;
            dintr_layer_r <= 5'b0;
            dintr_load_word_r <= 4'b0;
            hash_ram_block_r <= 6'b0;
            hash_ram_word_r <= 6'b0;
            hash_ram_window_r <= 576'b0;
            mqc_q_be_r <= 272'b0;
            mqc_checksum_r <= 16'b0;
            mqc_idx_r <= 9'b0;
            for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                coefficient_words[output_index] <= 32'b0;
            end
        end
    end

    always @* begin
        bus_rdata = 32'b0;
        if (bus_valid && !bus_write) begin
            if (sec_bus_valid_w) begin
                /* SEC region (SIM_MC/WRAPPED readable; SEED/KWRAP/KSTATE slots not readable) */
                bus_rdata = sec_bus_rdata_w;
            end else begin
                case (bus_addr)
                REG_VERSION:       bus_rdata = VERSION;
                REG_CAPABILITY:    bus_rdata = CAPABILITY;
                REG_COMMAND:       bus_rdata = command_r;
                REG_STATUS:        bus_rdata = status_w;
                REG_ERROR:         bus_rdata = error_r;
                REG_INPUT_LENGTH:  bus_rdata = input_length_r;
                REG_OUTPUT_LENGTH: bus_rdata = output_length_r;
                REG_CYCLE_COUNT:   bus_rdata = cycle_count_r;
                REG_ARG_Q:         bus_rdata = arg_q_r;
                REG_ARG_I:         bus_rdata = arg_i_r;
                REG_ARG_START:     bus_rdata = arg_start_r;
                REG_ARG_STEPS:     bus_rdata = arg_steps_r;
                REG_ARG_KEY:       bus_rdata = arg_key_r;
                REG_ARG_LEAF_NODE: bus_rdata = arg_leaf_node_r;
                REG_ARG_W:         bus_rdata = {28'b0, arg_w_r};
                REG_TASK_ADDR:     bus_rdata = {20'b0, task_addr_r};
                REG_TASK_DATA: begin
                    if (task_addr_r < 32) begin
                        bus_rdata = coefficient_words[task_addr_r[4:0]];
                    end else begin
                        bus_rdata = task_ram_read_r;
                    end
                end
                default: begin
                    if (bus_addr >= REG_IDENTIFIER && bus_addr < REG_IDENTIFIER + 16 &&
                        bus_addr[1:0] == 2'b00) begin
                        bus_rdata = identifier_words[bus_addr[3:2]];
                    end else if (bus_addr >= REG_INPUT_BASE && bus_addr < REG_INPUT_BASE + 128 &&
                        bus_addr[1:0] == 2'b00) begin
                        bus_rdata = input_words[bus_addr[6:2]];
                    end else if (bus_addr >= REG_OUTPUT_BASE && bus_addr < REG_OUTPUT_BASE + 32 &&
                                 bus_addr[1:0] == 2'b00) begin
                        bus_rdata = output_words[bus_addr[4:2]];
                    end
                    /* KWRAP/KSTATE/SEED slots not readable: falling through here returns 0. */
                end
            endcase
            end
        end
    end

    wire unused_core_busy = core_busy_w;

endmodule

`default_nettype wire
