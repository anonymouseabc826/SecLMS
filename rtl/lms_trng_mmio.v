`default_nettype none

/* =============================================================================================
 * lms_trng_mmio.v -- standalone MMIO peripheral for the TRNG entropy source (C1).
 *
 * Independent SoC slave on its own address window (TRNG_BASE), fully decoupled from the
 * SHA-256 accelerator wrapper (lms_sha256_mmio). Hosts lms_trng (RO noise source + online
 * health check) and exposes a tiny register file. SHA-256 conditioning of the raw stream is
 * done by firmware reusing the existing HASH_ONCE command on the accelerator; this block
 * contains no hash logic of its own.
 *
 * Register map (word-aligned, offsets from TRNG_BASE):
 *   0x00 VERSION      RO  = 0x00000001
 *   0x04 CAPABILITY   RO  = 0x00000001 (bit0: trng present)
 *   0x08 CTRL         RW  [0]=enable, [1]=clear_fail pulse, [15:8]=rct_cutoff, [26:16]=apt_cutoff
 *   0x0c STAT         RO  [0]=health_fail, [8]=word_valid, [31:16]=rct_count[7:0] (diag)
 *   0x10 RND          RO  current 32-bit random word (0 when health_fail)
 *   0x14 APT_COUNT    RO  [15:0]=apt_count, [31:16]=apt_win_pos (diag)
 * ============================================================================================= */
module lms_trng_mmio #(
    parameter [31:0] TRNG_BASE = 32'h1700_0000,
    parameter SIM_MODE = 0
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        mem_valid,
    /* verilator lint_off UNUSEDSIGNAL */
    input  wire [31:0] mem_addr,   /* [31:6] decode (tightened per REVIEW B11B12-R3), [5:2] reg addr, low bits unused */
    /* verilator lint_on UNUSEDSIGNAL */
    input  wire [31:0] mem_wdata,
    input  wire [3:0]  mem_wstrb,
    output wire        mem_hit,
    output wire        mem_ready,
    output wire [31:0] mem_rdata
);
    localparam [31:0] VERSION    = 32'h00000001;
    localparam [31:0] CAPABILITY = 32'h00000001;

    localparam [3:0] REG_VERSION = 4'h0;
    localparam [3:0] REG_CAP     = 4'h1;
    localparam [3:0] REG_CTRL    = 4'h2;
    localparam [3:0] REG_STAT    = 4'h3;
    localparam [3:0] REG_RND     = 4'h4;
    localparam [3:0] REG_APT     = 4'h5;

    /* REVIEW B11B12-R3 (hardened 2026-08-17): window [31:16](64KB)->[31:6](64B),
     * removing the aliasing surface caused by unchecked [15:6] (0x1700_0040..0x1700_FFFF
     * previously silently aliased to the same set of 6 registers); register decode remains
     * [5:2], undefined offsets hit the default and return 0. */
    wire address_hit = mem_valid && mem_addr[31:6] == TRNG_BASE[31:6];
    wire full_word_write = mem_wstrb == 4'b1111;
    wire [3:0] reg_addr = mem_addr[5:2];

    reg [31:0] ctrl_r;
    reg        clear_fail_pulse_r;

    wire [31:0] rnd_word_w;
    wire        word_valid_w;
    wire        health_fail_w;
    /* verilator lint_off UNUSEDSIGNAL */
    wire [15:0] rct_count_w;   /* STAT exposes low 8 bits only */
    /* verilator lint_on UNUSEDSIGNAL */
    wire [15:0] apt_count_w;
    wire [15:0] apt_win_pos_w;

    assign mem_hit   = address_hit;
    assign mem_ready = address_hit;

    /* TRNG entropy source: free-running, RND register samples latest word. */
    lms_trng #(
        .NUM_CELLS     (3),
        .NUM_INV_START (5),
        .NUM_RAW_BITS  (64),
        .SIM_MODE      (SIM_MODE)
    ) trng_inst (
        .clk         (clk),
        .rst         (rst),
        .enable      (ctrl_r[0]),
        .rct_cutoff  (ctrl_r[15:8]),
        .apt_cutoff  (ctrl_r[26:16]),
        .clear_fail  (clear_fail_pulse_r),
        .rnd_word    (rnd_word_w),
        .word_valid  (word_valid_w),
        .health_fail (health_fail_w),
        .rct_count   (rct_count_w),
        .apt_count   (apt_count_w),
        .apt_win_pos (apt_win_pos_w)
    );

    /* write path: CTRL register + clear_fail pulse */
    always @(posedge clk) begin
        clear_fail_pulse_r <= 1'b0;
        if (rst) begin
            /* defaults: enable=1, rct_cutoff=64, apt_cutoff=650 */
            ctrl_r <= {5'b0, 11'd650, 8'd64, 7'b0, 1'b1};
        end else begin
            if (address_hit && full_word_write && reg_addr == REG_CTRL) begin
                ctrl_r <= mem_wdata;
                clear_fail_pulse_r <= mem_wdata[1];
            end
        end
    end

    /* read path: combinational mux */
    reg [31:0] rdata_r;
    always @* begin
        case (reg_addr)
            REG_VERSION: rdata_r = VERSION;
            REG_CAP:     rdata_r = CAPABILITY;
            REG_CTRL:    rdata_r = ctrl_r;
            REG_STAT:    rdata_r = {8'b0, rct_count_w[7:0], 7'b0,
                                    word_valid_w, 7'b0, health_fail_w};
            REG_RND:     rdata_r = health_fail_w ? 32'b0 : rnd_word_w;
            REG_APT:     rdata_r = {apt_win_pos_w, apt_count_w};
            default:     rdata_r = 32'b0;
        endcase
    end
    assign mem_rdata = address_hit ? rdata_r : 32'b0;

endmodule
`default_nettype wire
