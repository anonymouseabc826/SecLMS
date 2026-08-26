`default_nettype none

/* Some ports/parameters are unused in HASH_TYPE branches; -Wall reports UNUSEDPARAM/UNUSEDSIGNAL. */
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */

// Hash-agnostic single-chain engine (unified refactor step 2; both branches done).
//
// Role: scheduling FSM for single-chain primitives (HASH_ONCE/CHAIN/
// DERIVE_CHAIN/DERIVE_RANDOMIZER): load task → feed core block by block →
// chain step/derive switch → complete. Hash block construction and digest
// byte order come from BlockGen (interface A); the core from Core (B).
//
// Parameters:
//   HASH_TYPE  = 1 = SHAKE256 (step 2 implementation); 0 = SHA-256 (REVIEW P1-5
//                fix: fully implemented, instantiated by lms_sha256_mmio with
//                .HASH_TYPE(0) - the old comment "step 3 placeholder" does not
//                match reality; do not read per the old comment)
//
// Timing conventions:
//   - start: single-cycle pulse (wrapper raises after command check passes)
//   - busy: state != IDLE
//   - done: completion beat (ST_DONE) held one beat; digest_out combinationally
//     outputs the final chain value (big-endian)
//   - cycle_count: accumulated core permute beats (12/block; REVIEW B09B10-R2:
//     system-level ~15 beats/block = permute 12 + ST_ABSORB latch 1 + core
//     absorb 1 + ST_DONE 1; excludes scheduling overhead, not wall clock)

module lms_hash_engine #(
    parameter HASH_TYPE = 1,           /* 1=shake256; 0=sha256 (fully implemented, REVIEW P1-5) */
    parameter INSECURE_TEST_MODE = 0,
    parameter RANDOM_DELAY = 0         /* TVLA lightweight mitigation (scheme B-RTL):
                                        * 0x6D and isolated single DERIVE_CHAIN (0x6F,
                                        * steps=0) delay core_start_r after ST_ABSORB
                                        * (LFSR random 0..1023 beats; busy already set
                                        * → DERIVE relative trigger phase randomizes,
                                        * diluting per-point t; batch bypass via kec_ext).
                                        * Default 0, off */
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [31:0] command,        /* HASH_ONCE/CHAIN/DERIVE_CHAIN/DERIVE_RANDOMIZER */
    input  wire [7:0]  input_length,
    input  wire [31:0] arg_q,
    input  wire [15:0] arg_i,
    input  wire [7:0]  arg_start,      /* CHAIN start j */
    input  wire [31:0] arg_steps,
    input  wire [127:0] identifier_flat,
    input  wire [255:0] chain_value_in, /* CHAIN initial value (concatenated by wrapper from INPUT region) */
    input  wire [255:0] seed_flat,      /* for DERIVE/RANDOMIZER (wrapper concatenates seed_words) */
    input  wire [1023:0] input_words_flat,
    input  wire        sha_ext_mode,    /* SHA-256: 1=driven directly by external batch task scheduler to core0 */
    input  wire        sha_ext_start,
    input  wire        sha_ext_init,
    input  wire        sha_ext_state_load,
    input  wire [255:0] sha_ext_state_in,
    input  wire [511:0] sha_ext_block,
    output wire        sha_ext_busy,
    output wire        sha_ext_done,
    output wire [255:0] sha_ext_digest,
    input  wire        sha_ext1_start,
    input  wire        sha_ext1_init,
    input  wire        sha_ext1_state_load,
    input  wire [255:0] sha_ext1_state_in,
    input  wire [511:0] sha_ext1_block,
    output wire        sha_ext1_busy,
    output wire        sha_ext1_done,
    output wire [255:0] sha_ext1_digest,
    /* SHAKE256 external batch task ports (Keccak 1088-bit blocks, for SHAKE256 wrapper batch scheduling) */
    input  wire        kec_ext_mode,
    input  wire        kec_ext_start,
    input  wire        kec_ext_init,
    input  wire [1087:0] kec_ext_block,
    output wire        kec_ext_busy,
    output wire        kec_ext_done,
    output wire [255:0] kec_ext_digest,
    input  wire        kec_ext1_start,
    input  wire        kec_ext1_init,
    input  wire [1087:0] kec_ext1_block,
    output wire        kec_ext1_busy,
    output wire        kec_ext1_done,
    output wire [255:0] kec_ext1_digest,
    output wire        busy,
    output wire        done,
    output wire [255:0] digest_out,     /* big-endian result (valid on done beat) */
    output reg  [31:0] cycle_count
);
    localparam [31:0] CMD_HASH_ONCE         = 32'h00000001;
    localparam [31:0] CMD_CHAIN             = 32'h00000002;
    localparam [31:0] CMD_DERIVE_CHAIN      = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER = 32'h00000005;

    generate
        if (HASH_TYPE == 1) begin : g_shake256
            localparam [1:0] TASK_HASH_ONCE  = 2'd0;
            localparam [1:0] TASK_CHAIN      = 2'd1;
            localparam [1:0] TASK_DERIVE     = 2'd2;
            localparam [1:0] TASK_RANDOMIZER = 2'd3;

            localparam [3:0] ST_IDLE      = 4'd0;
            localparam [3:0] ST_ABSORB    = 4'd1;  /* issue start (with init) */
            localparam [3:0] ST_WAIT_CORE = 4'd2;  /* wait 12 cycles */
            localparam [3:0] ST_DONE      = 4'd3;

            reg [3:0]  state_r;
            reg [1:0]  task_r;
            reg [255:0] chain_value_r;
            reg [7:0]  chain_j_r;
            reg [31:0] chain_steps_left_r;
            reg        derive_phase_r;
            reg        core_start_r;
            /* TVLA random delay (RANDOM_DELAY=1, scheme B-RTL): after ST_ABSORB
             * latches the block, core_start_r (core absorb) is delayed rnd_delay_r
             * beats; busy (state!=IDLE) already set → SCA trigger (busy rising
             * edge) fixed, absorb phase random. rnd_lfsr_r advances each beat. */
            reg [9:0]  rnd_delay_r;
            reg        rnd_pending_r;
            reg [15:0] rnd_lfsr_r;
            /* Single-chain block input register (paper-style HIL: ST_ABSORB
             * latches the block, core absorbs from register on WAIT_CORE beats,
             * avoiding blockgen combinational folding into core that inflates area) */
            reg [1087:0] core_block_r;
            reg          core_init_r;
            reg [1087:0] rate_block_w;
            reg        rate_init_w;
            /* TVLA random delay commands (2026-08-25 extension): 0x6D
             * (DERIVE_RANDOMIZER) + 0x6F isolated single x_q[i] (DERIVE_CHAIN
             * steps=0, test command passed by M3 gate). Batch tasks (kec_ext
             * bypass) and signature-path DERIVE_CHAIN (steps=1) don't hit. */
            wire rnd_apply_w = RANDOM_DELAY &&
                               (command == CMD_DERIVE_RANDOMIZER ||
                                (command == CMD_DERIVE_CHAIN && arg_steps == 32'd0));

            wire        core_busy_w;
            wire        core_done_w;
            wire [255:0] core_digest_w;
            wire        kec_core1_busy_w;
            wire        kec_core1_done_w;
            wire [255:0] kec_core1_digest_w;
            wire [255:0] digest_be_w;

            lms_keccak_core keccak (
                .clk(clk),
                .rst(rst),
                .start(kec_ext_mode ? kec_ext_start : core_start_r),
                .init(kec_ext_mode ? kec_ext_init : core_init_r),
                .block(kec_ext_mode ? kec_ext_block : core_block_r),
                .busy(core_busy_w),
                .done(core_done_w),
                .digest(core_digest_w)
            );

            lms_keccak_core keccak_core1 (
                .clk(clk),
                .rst(rst),
                .start(kec_ext1_start),
                .init(kec_ext1_init),
                .block(kec_ext1_block),
                .busy(kec_core1_busy_w),
                .done(kec_core1_done_w),
                .digest(kec_core1_digest_w)
            );

            lms_shake256_blockgen u_blockgen (
                .task_type({1'b0, task_r}),
                .input_words_flat(input_words_flat),
                .identifier_flat(identifier_flat),
                .arg_q(arg_q),
                .arg_i(arg_i),
                .chain_j(chain_j_r),
                .chain_value(chain_value_r),
                .derive_phase(derive_phase_r),
                .input_length(input_length),
                .seed_flat(seed_flat),
                .rate_block(rate_block_w),
                .rate_init(rate_init_w),
                .core_digest(core_digest_w),
                .digest_bigendian(digest_be_w)
            );

            assign busy = (state_r != ST_IDLE);
            assign done = (state_r == ST_DONE);
            assign digest_out = chain_value_r;   /* done beat = final result */
            assign sha_ext_busy = 1'b0;
            assign sha_ext_done = 1'b0;
            assign sha_ext_digest = 256'b0;
            assign sha_ext1_busy = 1'b0;
            assign sha_ext1_done = 1'b0;
            assign sha_ext1_digest = 256'b0;
            assign kec_ext_busy = core_busy_w;
            assign kec_ext_done = core_done_w;
            assign kec_ext_digest = core_digest_w;
            assign kec_ext1_busy = kec_core1_busy_w;
            assign kec_ext1_done = kec_core1_done_w;
            assign kec_ext1_digest = kec_core1_digest_w;

            always @(posedge clk) begin
                if (rst) begin
                    state_r <= ST_IDLE;
                    task_r <= TASK_HASH_ONCE;
                    chain_value_r <= 256'b0;
                    chain_j_r <= 8'b0;
                    chain_steps_left_r <= 32'b0;
                    derive_phase_r <= 1'b0;
                    core_start_r <= 1'b0;
                    rnd_delay_r <= 10'd0;
                    rnd_pending_r <= 1'b0;
                    rnd_lfsr_r <= 16'hACE1;   /* nonzero seed (XOR feedback avoids locking at 0) */
                    core_block_r <= 1088'b0;
                    core_init_r <= 1'b0;
                    cycle_count <= 32'b0;
                end else begin
                    core_start_r <= 1'b0;
                    /* LFSR advances every beat (XOR feedback; still advances with
                     * RANDOM_DELAY=0, no functional impact). ST_ABSORB latches low
                     * 10 bits as random delay → per-trace DERIVE phase random. */
                    rnd_lfsr_r <= {rnd_lfsr_r[14:0],
                                   rnd_lfsr_r[15] ^ rnd_lfsr_r[13] ^
                                   rnd_lfsr_r[12] ^ rnd_lfsr_r[10]};
                    if (start && state_r == ST_IDLE) begin
                        /* Load task (wrapper check already guarantees valid params, steps>0, etc.) */
                        case (command)
                            CMD_CHAIN:             task_r <= TASK_CHAIN;
                            CMD_DERIVE_CHAIN:      task_r <= TASK_DERIVE;
                            CMD_DERIVE_RANDOMIZER: task_r <= TASK_RANDOMIZER;
                            default:               task_r <= TASK_HASH_ONCE;
                        endcase
                        chain_j_r <= arg_start;
                        chain_steps_left_r <= arg_steps;
                        derive_phase_r <= (command == CMD_DERIVE_CHAIN);
                        chain_value_r <= chain_value_in;
                        cycle_count <= 32'b0;
                        state_r <= ST_ABSORB;
                    end
                    case (state_r)
                        ST_ABSORB: begin
                            /* Latch block: core absorbs next beat (WAIT_CORE);
                             * cycles unchanged (ST_ABSORB is a prep beat, blockgen
                             * params ready). TVLA random delay (RANDOM_DELAY=1 &&
                             * RANDOMIZER): after latching, delay core_start_r by
                             * decrementing rnd_delay_r (latched LFSR) to 0 - busy
                             * already set, SCA trigger (busy rising edge) fixed,
                             * absorb phase random. */
                            core_block_r <= rate_block_w;
                            core_init_r  <= rate_init_w;
                            if (rnd_apply_w && !rnd_pending_r) begin
                                rnd_delay_r <= rnd_lfsr_r[9:0];
                                rnd_pending_r <= 1'b1;
                            end else if (rnd_apply_w && rnd_pending_r) begin
                                if (rnd_delay_r == 10'd0) begin
                                    rnd_pending_r <= 1'b0;
                                    core_start_r <= 1'b1;
                                    state_r <= ST_WAIT_CORE;
                                end else begin
                                    rnd_delay_r <= rnd_delay_r - 10'd1;
                                end
                            end else begin
                                core_start_r <= 1'b1;
                                state_r <= ST_WAIT_CORE;
                            end
                        end
                        ST_WAIT_CORE: begin
                            if (core_done_w) begin
                                cycle_count <= cycle_count + 32'd12;
                                case (task_r)
                                    TASK_CHAIN: begin
                                        chain_value_r <= digest_be_w;
                                        if (chain_steps_left_r == 1) begin
                                            /* this is the last step */
                                            state_r <= ST_DONE;
                                        end else begin
                                            chain_j_r <= chain_j_r + 1;
                                            chain_steps_left_r <= chain_steps_left_r - 1;
                                            state_r <= ST_ABSORB;
                                        end
                                    end
                                    TASK_DERIVE: begin
                                        if (derive_phase_r) begin
                                            /* Derive done → switch to chain (j from
                                             * 0). REVIEW B09B10-R8: SHAKE branch
                                             * hardcodes j=0, SHA-256 uses arg_start;
                                             * firmware passes arg_start=0 for
                                             * DERIVE_CHAIN so both platforms match;
                                             * future non-zero start: update both. */
                                            chain_value_r <= digest_be_w;
                                            derive_phase_r <= 1'b0;
                                            chain_j_r <= 8'd0;
                                            if (chain_steps_left_r == 0) begin
                                                state_r <= ST_DONE;
                                            end else begin
                                                state_r <= ST_ABSORB;
                                            end
                                        end else begin
                                            chain_value_r <= digest_be_w;
                                            if (chain_steps_left_r == 1) begin
                                                state_r <= ST_DONE;
                                            end else begin
                                                chain_j_r <= chain_j_r + 1;
                                                chain_steps_left_r <= chain_steps_left_r - 1;
                                                state_r <= ST_ABSORB;
                                            end
                                        end
                                    end
                                    TASK_RANDOMIZER: begin
                                        chain_value_r <= digest_be_w;
                                        state_r <= ST_DONE;
                                    end
                                    default: begin
                                        /* HASH_ONCE (≤136B single block) */
                                        chain_value_r <= digest_be_w;
                                        state_r <= ST_DONE;
                                    end
                                endcase
                            end
                        end
                        ST_DONE: begin
                            state_r <= ST_IDLE;
                        end
                        default: ;
                    endcase
                end
            end
        end else begin : g_sha256
            localparam [1:0] TASK_HASH_ONCE  = 2'd0;
            localparam [1:0] TASK_CHAIN      = 2'd1;
            localparam [1:0] TASK_DERIVE     = 2'd2;
            localparam [1:0] TASK_RANDOMIZER = 2'd3;

            localparam [2:0] ST_IDLE       = 3'd0;
            localparam [2:0] ST_START_CORE = 3'd1;
            localparam [2:0] ST_WAIT_CORE  = 3'd2;
            localparam [2:0] ST_DONE       = 3'd3;

            reg [2:0] state_r;
            reg [1:0] task_r;
            reg [255:0] chain_value_r;
            reg [7:0] chain_j_r;
            reg [31:0] chain_steps_left_r;
            reg derive_phase_r;
            reg [1:0] block_index_r;
            reg [1:0] block_count_r;
            reg core_start_r;
            wire core_busy_w;
            wire core_done_w;
            wire [255:0] core_digest_w;
            wire core1_busy_w;
            wire core1_done_w;
            wire [255:0] core1_digest_w;
            wire [255:0] digest_be_w;
            wire [511:0] block_w;
            wire core_init_w;

            lms_sha256_core sha256 (
                .clk(clk),
                .rst(rst),
                .start(sha_ext_mode ? sha_ext_start : core_start_r),
                .init(sha_ext_mode ? sha_ext_init : core_init_w),
                .state_load(sha_ext_mode ? sha_ext_state_load : 1'b0),
                .state_in(sha_ext_mode ? sha_ext_state_in : 256'b0),
                .block(sha_ext_mode ? sha_ext_block : block_w),
                .busy(core_busy_w),
                .done(core_done_w),
                .digest(core_digest_w)
            );

            lms_sha256_core sha256_core1 (
                .clk(clk),
                .rst(rst),
                .start(sha_ext1_start),
                .init(sha_ext1_init),
                .state_load(sha_ext1_state_load),
                .state_in(sha_ext1_state_in),
                .block(sha_ext1_block),
                .busy(core1_busy_w),
                .done(core1_done_w),
                .digest(core1_digest_w)
            );

            lms_sha256_blockgen u_blockgen (
                .task_type(task_r),
                .input_words_flat(input_words_flat),
                .identifier_flat(identifier_flat),
                .arg_q(arg_q),
                .arg_i(arg_i),
                .chain_j(chain_j_r),
                .chain_value(chain_value_r),
                .derive_phase(derive_phase_r),
                .input_length(input_length),
                .block_index(block_index_r),
                .seed_flat(seed_flat),
                .block(block_w),
                .core_init(core_init_w),
                .core_digest(core_digest_w),
                .digest_bigendian(digest_be_w)
            );

            assign busy = (state_r != ST_IDLE);
            assign done = (state_r == ST_DONE);
            assign digest_out = chain_value_r;
            assign sha_ext_busy = core_busy_w;
            assign sha_ext_done = core_done_w;
            assign sha_ext_digest = core_digest_w;
            assign sha_ext1_busy = core1_busy_w;
            assign sha_ext1_done = core1_done_w;
            assign sha_ext1_digest = core1_digest_w;
            assign kec_ext_busy = 1'b0;
            assign kec_ext_done = 1'b0;
            assign kec_ext_digest = 256'b0;
            assign kec_ext1_busy = 1'b0;
            assign kec_ext1_done = 1'b0;
            assign kec_ext1_digest = 256'b0;

            always @(posedge clk) begin
                if (rst) begin
                    state_r <= ST_IDLE;
                    task_r <= TASK_HASH_ONCE;
                    chain_value_r <= 256'b0;
                    chain_j_r <= 8'b0;
                    chain_steps_left_r <= 32'b0;
                    derive_phase_r <= 1'b0;
                    block_index_r <= 2'b0;
                    block_count_r <= 2'b0;
                    core_start_r <= 1'b0;
                    cycle_count <= 32'b0;
                end else begin
                    core_start_r <= 1'b0;
                    if (start && state_r == ST_IDLE) begin
                        case (command)
                            CMD_CHAIN:             task_r <= TASK_CHAIN;
                            CMD_DERIVE_CHAIN:      task_r <= TASK_DERIVE;
                            CMD_DERIVE_RANDOMIZER: task_r <= TASK_RANDOMIZER;
                            default:               task_r <= TASK_HASH_ONCE;
                        endcase
                        chain_value_r <= chain_value_in;
                        chain_j_r <= arg_start;
                        chain_steps_left_r <= arg_steps;
                        derive_phase_r <= (command == CMD_DERIVE_CHAIN);
                        block_index_r <= 2'b0;
                        if (command != CMD_HASH_ONCE || input_length <= 55) begin
                            block_count_r <= 2'd1;
                        end else if (input_length <= 119) begin
                            block_count_r <= 2'd2;
                        end else begin
                            block_count_r <= 2'd3;
                        end
                        cycle_count <= 32'd1;
                        state_r <= ST_START_CORE;
                    end
                    case (state_r)
                        ST_START_CORE: begin
                            cycle_count <= cycle_count + 1'b1;
                            if (!core_busy_w) begin
                                core_start_r <= 1'b1;
                                state_r <= ST_WAIT_CORE;
                            end
                        end
                        ST_WAIT_CORE: begin
                            cycle_count <= cycle_count + 1'b1;
                            if (core_done_w) begin
                                case (task_r)
                                    TASK_CHAIN: begin
                                        chain_value_r <= digest_be_w;
                                        if (chain_steps_left_r == 1) begin
                                            state_r <= ST_DONE;
                                        end else begin
                                            chain_j_r <= chain_j_r + 1'b1;
                                            chain_steps_left_r <= chain_steps_left_r - 1'b1;
                                            state_r <= ST_START_CORE;
                                        end
                                    end
                                    TASK_DERIVE: begin
                                        chain_value_r <= digest_be_w;
                                        if (derive_phase_r) begin
                                            derive_phase_r <= 1'b0;
                                            chain_j_r <= arg_start;
                                            if (chain_steps_left_r == 0) begin
                                                state_r <= ST_DONE;
                                            end else begin
                                                state_r <= ST_START_CORE;
                                            end
                                        end else if (chain_steps_left_r == 1) begin
                                            state_r <= ST_DONE;
                                        end else begin
                                            chain_j_r <= chain_j_r + 1'b1;
                                            chain_steps_left_r <= chain_steps_left_r - 1'b1;
                                            state_r <= ST_START_CORE;
                                        end
                                    end
                                    TASK_RANDOMIZER: begin
                                        chain_value_r <= digest_be_w;
                                        state_r <= ST_DONE;
                                    end
                                    default: begin
                                        if (block_index_r + 1'b1 < block_count_r) begin
                                            block_index_r <= block_index_r + 1'b1;
                                            state_r <= ST_START_CORE;
                                        end else begin
                                            chain_value_r <= digest_be_w;
                                            state_r <= ST_DONE;
                                        end
                                    end
                                endcase
                            end
                        end
                        ST_DONE: state_r <= ST_IDLE;
                        default: ;
                    endcase
                end
            end
        end
    endgenerate

endmodule

`default_nettype wire
