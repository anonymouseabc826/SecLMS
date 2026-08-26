`default_nettype none

/* =============================================================================================
 * lms_trng.v -- LMS project TRNG entropy source (RO noise + online health check).
 *
 * Architecture ported from neoTRNG v3.3 (https://github.com/stnolting/neoTRNG), rewritten
 * in Verilog with added SP 800-90B section 4.4 style online health checks (RCT/APT).
 * neoTRNG is BSD 3-Clause License, Copyright (c) 2025, Stephan Nolting; this file retains
 * that notice and complies with its terms (retain copyright/license text, no endorsement).
 *
 * Entropy source: NUM_CELLS free-running ring oscillators (odd inverter chains decoupled by
 * latches to prevent synthesis trimming). Phase noise is sampled, XOR-combined, de-biased by
 * a John von Neumann extractor, and NUM_RAW_BITS raw bits are CRC-8 compressed into one byte.
 * Four bytes form one 32-bit word, flagged valid for the MMIO CMD_TRNG_READ to sample.
 *
 * SIM_MODE=1 replaces physical inverter delay with per-cell LFSR pseudo-noise so Verilator
 * can simulate (NOT physical entropy); on-board builds must use SIM_MODE=0.
 *
 * Online health check (SP 800-90B section 4.4 style, thresholds configurable):
 *   RCT: same de-biased raw bit repeats >= rct_cutoff times -> fail latch.
 *   APT: ones-count in a 1024-bit window > apt_cutoff -> fail latch (window-aligned check).
 * On fail, output word updates stop until a clear_fail pulse (MMIO CTRL write). Experimental
 * / denial-of-service signal only; no certified-randomness claim is made.
 * ============================================================================================= */
module lms_trng #(
    parameter NUM_CELLS     = 3,    /* number of RO cells (1..8) */
    parameter NUM_INV_START = 5,    /* inverters in first cell (odd, +2 per next cell) */
    parameter NUM_RAW_BITS  = 64,   /* XORed raw bits per output byte (power of 2) */
    parameter SIM_MODE      = 0     /* 1=sim LFSR pseudo-noise, 0=physical RO */
) (
    input  wire        clk,
    input  wire        rst,           /* synchronous reset, high active */
    input  wire        enable,        /* module enable (0 holds output) */
    input  wire [7:0]  rct_cutoff,    /* RCT threshold (e.g. 64) */
    input  wire [10:0] apt_cutoff,    /* APT ones-count threshold (e.g. 650) */
    input  wire        clear_fail,    /* pulse: clear health-fail latch */
    output wire [31:0] rnd_word,      /* random 32-bit word */
    output wire        word_valid,    /* new word ready (single-cycle pulse) */
    output wire        health_fail,   /* health-check fail latch */
    output wire [15:0] rct_count,     /* diag: current repeat count */
    output wire [15:0] apt_count,     /* diag: current window ones count */
    output wire [15:0] apt_win_pos    /* diag: current window position */
);

    /* ---------------- entropy cells ---------------- */
    wire [NUM_CELLS-1:0] cell_en_in;
    wire [NUM_CELLS-1:0] cell_en_out;
    wire [NUM_CELLS-1:0] cell_rnd;

    genvar gi;
    generate
        for (gi = 0; gi < NUM_CELLS; gi = gi + 1) begin : g_cells
            lms_trng_cell #(
                .NUM_INV   (NUM_INV_START + 2 * gi),
                .SIM_MODE  (SIM_MODE),
                .LFSR_SEED ((16'hACE1) ^ ((gi + 1) * 16'h0101))
            ) u_cell (
                .clk   (clk),
                .rst   (rst),
                .en_i  (cell_en_in[gi]),
                .en_o  (cell_en_out[gi]),
                .rnd_o (cell_rnd[gi])
            );
        end
    endgenerate

    /* enable shift chain: cell0 kicked by sample enable, then ripples */
    assign cell_en_in[0] = sample_en;
    generate
        if (NUM_CELLS > 1) begin : g_en_chain
            assign cell_en_in[NUM_CELLS-1:1] = cell_en_out[NUM_CELLS-2:0];
        end
    endgenerate

    /* combine (XOR) */
    wire cell_sum = ^cell_rnd;

    /* ---------------- von Neumann de-bias (phy) / passthrough (sim) ---------------- */
    /* verilator lint_off UNUSEDSIGNAL */
    reg [1:0] debias_sreg;   /* sim uses [0] (passthrough); [1] for phy de-bias */
    /* verilator lint_on UNUSEDSIGNAL */
    reg       debias_state;
    wire      last_cell_en = cell_en_out[NUM_CELLS-1];
    always @(posedge clk) begin
        if (rst) begin
            debias_sreg  <= 2'b00;
            debias_state <= 1'b0;
        end else begin
            debias_sreg  <= {debias_sreg[0], cell_sum};
            debias_state <= (~debias_state) & last_cell_en;
        end
    end
    /* generate-time static select to avoid runtime ternary on a parameter */
    wire debias_valid;
    generate
        if (SIM_MODE != 0) begin : g_debias_sim
            assign debias_valid = last_cell_en;
        end else begin : g_debias_phy
            assign debias_valid = debias_state & (debias_sreg[1] ^ debias_sreg[0]);
        end
    endgenerate
    wire debias_data  = debias_sreg[0];

    /* ---------------- CRC-8 compressive sampling ---------------- */
    localparam CW = (NUM_RAW_BITS <= 2) ? 2 :
                    (NUM_RAW_BITS <= 4) ? 3 :
                    (NUM_RAW_BITS <= 8) ? 4 :
                    (NUM_RAW_BITS <= 16) ? 5 :
                    (NUM_RAW_BITS <= 32) ? 6 :
                    (NUM_RAW_BITS <= 64) ? 7 :
                    (NUM_RAW_BITS <= 128) ? 8 :
                    (NUM_RAW_BITS <= 256) ? 9 :
                    (NUM_RAW_BITS <= 512) ? 10 :
                    (NUM_RAW_BITS <= 1024) ? 11 :
                    (NUM_RAW_BITS <= 2048) ? 12 : 13;
    localparam [7:0] POLY = 8'b00000111; /* x^8+x^2+x+1 */

    reg               sample_en;
    reg  [CW-1:0]     sample_cnt;
    reg  [7:0]        sample_sreg;
    wire              byte_ready = sample_cnt[CW-1];

    /* accept_byte forward declaration: sample_cnt holds once full until accept (waits for
     * debias_valid), rather than being reset on a single byte_ready beat -- under von Neumann
     * de-biasing debias_valid is sparse, so a single-beat byte_ready window would most likely
     * miss debias_valid and stall word assembly (measured on the C1.5 board: word_valid never
     * asserted, while the rct/apt health counters kept counting, proving the bit stream alive). */
    wire accept_byte;

    always @(posedge clk) begin
        if (rst) begin
            sample_en   <= 1'b0;
            sample_cnt  <= {CW{1'b0}};
            sample_sreg <= 8'b0;
        end else begin
            sample_en <= enable;
            if ((!sample_en) || accept_byte) begin
                sample_cnt  <= {CW{1'b0}};
                sample_sreg <= 8'b0;
            end else if (debias_valid && !byte_ready) begin
                sample_cnt <= sample_cnt + 1'b1;
                if (sample_sreg[7] ^ debias_data) begin
                    sample_sreg <= {sample_sreg[6:0], 1'b0} ^ POLY;
                end else begin
                    sample_sreg <= {sample_sreg[6:0], 1'b0};
                end
            end
        end
    end

    /* ---------------- 32-bit word assembly ---------------- */
    reg [31:0] word_r;
    reg [1:0]  byte_idx;
    reg        word_valid_r;

    assign accept_byte = byte_ready & debias_valid & (~health_fail_r);

    always @(posedge clk) begin
        if (rst) begin
            word_r       <= 32'b0;
            byte_idx     <= 2'b0;
            word_valid_r <= 1'b0;
        end else if (accept_byte) begin
            case (byte_idx) /* little-endian fill: byte0 -> [7:0] */
                2'd0: word_r[7:0]   <= sample_sreg;
                2'd1: word_r[15:8]  <= sample_sreg;
                2'd2: word_r[23:16] <= sample_sreg;
                2'd3: word_r[31:24] <= sample_sreg;
                default: ;
            endcase
            if (byte_idx == 2'd3) begin
                byte_idx     <= 2'b0;
                word_valid_r <= 1'b1;
            end else begin
                byte_idx     <= byte_idx + 1'b1;
                word_valid_r <= 1'b0;
            end
        end else begin
            word_valid_r <= 1'b0;
        end
    end

    assign rnd_word   = word_r;
    assign word_valid = word_valid_r;

    /* ---------------- online health check (on de-biased raw bit stream) ---------------- */
    reg        rct_last;
    reg        rct_have;
    reg [15:0] rct_cnt;
    reg [15:0] apt_cnt_r;
    reg [15:0] apt_pos_r;
    reg        health_fail_r;

    wire [15:0] rct_lim = {8'b0, rct_cutoff};
    wire [15:0] apt_lim = {5'b0, apt_cutoff};

    always @(posedge clk) begin
        if (rst) begin
            rct_last      <= 1'b0;
            rct_have      <= 1'b0;
            rct_cnt       <= 16'b0;
            apt_cnt_r     <= 16'b0;
            apt_pos_r     <= 16'b0;
            health_fail_r <= 1'b0;
        end else begin
            if (clear_fail) begin
                health_fail_r <= 1'b0;
                rct_cnt       <= 16'b0;
                rct_have      <= 1'b0;
                apt_cnt_r     <= 16'b0;
                apt_pos_r     <= 16'b0;
            end else if (debias_valid && sample_en) begin
                /* RCT */
                if (!rct_have) begin
                    rct_have <= 1'b1;
                    rct_last <= debias_data;
                    rct_cnt  <= 16'd1;
                end else if (debias_data == rct_last) begin
                    rct_cnt <= rct_cnt + 1'b1;
                    if (rct_cnt + 1'b1 >= rct_lim) begin
                        health_fail_r <= 1'b1;
                    end
                end else begin
                    rct_last <= debias_data;
                    rct_cnt  <= 16'd1;
                end
                /* APT: 1024-bit window, wraps and checks at window boundary */
                if (apt_pos_r == 16'd1023) begin
                    apt_pos_r <= 16'b0;
                    apt_cnt_r <= {15'b0, debias_data};
                    if ((apt_cnt_r + {15'b0, debias_data}) > apt_lim) begin
                        health_fail_r <= 1'b1;
                    end
                end else begin
                    apt_pos_r <= apt_pos_r + 1'b1;
                    apt_cnt_r <= apt_cnt_r + {15'b0, debias_data};
                end
            end
        end
    end

    assign health_fail = health_fail_r;
    assign rct_count   = rct_cnt;
    assign apt_count   = apt_cnt_r;
    assign apt_win_pos = apt_pos_r;

endmodule


/* =============================================================================================
 * lms_trng_cell -- entropy source cell: odd inverter ring + latch decoupling (neoTRNG arch).
 * Physical mode: ring oscillator + synchronizer. SIM mode: LFSR pseudo-noise (no comb loop).
 * ============================================================================================= */
/* verilator lint_off DECLFILENAME */
module lms_trng_cell #(
    parameter NUM_INV   = 3,
    parameter SIM_MODE  = 0,
    parameter LFSR_SEED = 16'hACE1
) (
    input  wire clk,
    input  wire rst,
    input  wire en_i,
    output wire en_o,
    output wire rnd_o
);
    reg  [NUM_INV-1:0] sreg;   /* enable shift register */

    /* enable shift: light latches one by one to stop synthesis trimming */
    always @(posedge clk) begin
        if (rst) begin
            sreg <= {NUM_INV{1'b0}};
        end else begin
            sreg <= {sreg[NUM_INV-2:0], en_i};
        end
    end
    assign en_o = sreg[NUM_INV-1];

    genvar i;
    generate
        if (!SIM_MODE) begin : g_phy
            /* physical mode: RO ring (latch-decoupled inverters) -> phase noise */
            /* verilator lint_off UNOPTFLAT */
            (* dont_touch = "true" *) reg  [NUM_INV-1:0] latch;
            /* verilator lint_on UNOPTFLAT */
            (* dont_touch = "true" *) wire [NUM_INV-1:0] inv_in;
            (* dont_touch = "true" *) wire [NUM_INV-1:0] inv_out;
            reg  [1:0] sync;
            for (i = 0; i < NUM_INV; i = i + 1) begin : g_ro
                /* latch: en_i=0 -> reset 0; sreg[i]=0 -> hold; else transparent */
                always @* begin
                    if (!en_i) begin
                        latch[i] = 1'b0;
                    end else if (!sreg[i]) begin
                        latch[i] = latch[i];
                    end else begin
                        latch[i] = inv_out[i];
                    end
                end
                assign inv_out[i] = ~inv_in[i];
            end
            assign inv_in[0] = latch[NUM_INV-1];
            assign inv_in[NUM_INV-1:1] = latch[NUM_INV-2:0];
            /* output synchronizer: sample phase noise into system clock domain */
            always @(posedge clk) begin
                if (rst) begin
                    sync <= 2'b00;
                end else begin
                    sync <= {sync[0], latch[NUM_INV-1]};
                end
            end
            assign rnd_o = sync[1];
        end else begin : g_sim
            /* SIM mode: 16-bit Fibonacci LFSR pseudo-noise (NOT physical entropy) */
            reg [15:0] lfsr;
            always @(posedge clk) begin
                if (rst) begin
                    lfsr <= LFSR_SEED[15:0];
                end else if (en_i) begin
                    lfsr <= {lfsr[14:0], lfsr[15] ^ lfsr[13] ^ lfsr[12] ^ lfsr[10]};
                end
            end
            assign rnd_o = lfsr[15];
        end
    endgenerate

endmodule
`default_nettype wire
