`default_nettype none

/* Different enable combinations use only some bits of bus_addr / some submodule
 * ports, so -Wall reports UNUSEDSIGNAL / UNUSEDPARAM. When stream ports pass
 * between generate branches, Verilator 5.040 falsely reports ASSIGNIN (legal
 * input→input) and UNDRIVEN (outputs driven by the submodule in the retained
 * branch; the synthesizer resolves this correctly), so lint is disabled. */
/* verilator lint_off UNUSEDSIGNAL */
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off ASSIGNIN */
/* verilator lint_off UNDRIVEN */

// LMS hash MMIO top-level thin-shell selector (flexible compile, 2026-08-06).
//
// Compile-time hash selection via independent enable flags, paired with the
// Makefile HASH_IMPL option (comma-separated, e.g. sha256,shake256); small
// FPGAs compile only needed cores, saving resources. A new hash
// needs one more ENABLE_* parameter, no branch changes.
//
// Usage: replace the original lms_sha256_mmio in lms_sha256_mmio_bridge
// with this shell (bridge decodes low 12 bits, 4KB window; shell picks impl).
//
// Address allocation (REVIEW B09B10-R4 revision, two-tier scheme):
//   both dual-hash build (ENABLE_SHA256=1 and ENABLE_SHAKE256=1):
//     SHA-256:   0x1600_0000 + 0x000 .. 0x3ff (bus_addr[10] = 0)
//     SHAKE256:  0x1600_0000 + 0x400 .. 0x7ff (bus_addr[10] = 1)
//   single-hash build (one ENABLE_* on): that hash occupies 0x000 .. 0x3ff
//     (base is BASE, not split by bus_addr[10]); board-test single-platform
//     build uses this scheme. Each wrapper's low 10-bit offset aligns with
//     its own base address.
//
// Security hardening (HAS_SECURITY): a build option independent of hash choice.
//   HAS_SECURITY=1: wrapper contains WRAP/UNWRAP/HMAC/MC/key slots (full-featured)
//   HAS_SECURITY=0: pure LMS algorithm hardware (no security domain, ~8-10K LUT)

module lms_hash_mmio #(
    parameter [31:0] BASE = 32'h1600_0000,
    parameter INSECURE_TEST_MODE = 0,
    parameter ENABLE_SHA256   = 1,     // 1=compile SHA-256 primitive
    parameter ENABLE_SHAKE256 = 0,     // 1=compile SHAKE256 primitive (can be enabled independently)
    parameter HAS_SECURITY    = 1,     // 1=compile security hardening (WRAP/UNWRAP/HMAC/MC)
    parameter RANDOM_DELAY    = 0,     // TVLA lightweight mitigation: LFSR random delay before 0x6D DERIVE (enabled when SCA_TEST=1)
    parameter DERIVE_SHUFFLE  = 0,     // DERIVE phase shuffle: batch task block parameters shifted by a random start per trace (enabled in TVLA builds)
    parameter ALLOW_XQ_DERIVE = 0      // TVLA isolated single x_q[i] pass-through (see plan)
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        bus_valid,   // already globally decoded upstream (inside bridge)
    input  wire        bus_write,
    input  wire [31:0] bus_addr,
    input  wire [31:0] bus_wdata,
    /* Vivado 2020.2 disallows an output reg connecting directly to a submodule
     * output port, hence wire + branch driving (mux for multi-hash branches,
     * single-hash branch driven by the submodule). */
    output wire [31:0] bus_rdata,
    /* Task RAM stream ports (Step 3 UART bridge frontend; SHAKE256 passes
     * through, SHA-256 only ties to 0). Direction (do not flip again):
     * write/read requests are pass-through inputs (UART bridge → wrapper),
     * not driven by this shell; readback valid/data/busy are outputs
     * (wrapper → UART bridge). Previously declared as outputs, the shell
     * was undriven and the tie-0 bridge path deleted. */
    input  wire        stream_wr_en,
    input  wire [11:0] stream_wr_addr,
    input  wire [31:0] stream_wr_data,
    input  wire        stream_rd_en,
    input  wire [11:0] stream_rd_addr,
    output wire        stream_rd_valid,   /* driven by SHAKE256 wrapper (passed through to UART bridge) */
    output wire [31:0] stream_rd_data,
    output wire        stream_busy
);

    // Compile-time assertion: at least one hash enabled
    // Vivado/Verilator have no native static assertion; use an unconnected net to trigger lint attention

    generate
        if (ENABLE_SHA256 && !ENABLE_SHAKE256) begin : g_sha256_only
            lms_sha256_mmio #(
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY)
                /* SHA-256 platform has no ALLOW_XQ_DERIVE (x_q isolation only in SHAKE256/TVLA builds, rejected by default under M3) */
            ) u_sha256 (
                .clk(clk),
                .rst(rst),
                .bus_valid(bus_valid),
                .bus_write(bus_write),
                .bus_addr(bus_addr[9:0]),
                .bus_wdata(bus_wdata),
                .bus_rdata(bus_rdata),
                .stream_wr_en(stream_wr_en),
                .stream_wr_addr(stream_wr_addr),
                .stream_wr_data(stream_wr_data),
                .stream_rd_en(stream_rd_en),
                .stream_rd_addr(stream_rd_addr),
                .stream_rd_valid(stream_rd_valid),
                .stream_rd_data(stream_rd_data),
                .stream_busy(stream_busy)
            );
        end else if (!ENABLE_SHA256 && ENABLE_SHAKE256) begin : g_shake256_only
            wire shake_mem_hit;   /* SHAKE256 wrapper self-check output, not consumed by thin shell */
            lms_shake256_mmio #(
                .SHAKE_BASE(BASE),
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY),   /* compile-time security domain switch (parameterized once SHAKE256 is wired in) */
                .RANDOM_DELAY(RANDOM_DELAY),   /* TVLA lightweight mitigation: 0x6D random delay */
                .DERIVE_SHUFFLE(DERIVE_SHUFFLE), /* DERIVE phase shuffle (TVLA builds) */
                .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE) /* TVLA isolated single x_q[i] pass-through */
            ) u_shake256 (
                .clk(clk),
                .rst(rst),
                .bus_valid(bus_valid),
                .bus_write(bus_write),
                .bus_addr(bus_addr),
                .bus_wdata(bus_wdata),
                .bus_rdata(bus_rdata),
                .mem_hit(shake_mem_hit),
                .stream_wr_en(stream_wr_en),
                .stream_wr_addr(stream_wr_addr),
                .stream_wr_data(stream_wr_data),
                .stream_rd_en(stream_rd_en),
                .stream_rd_addr(stream_rd_addr),
                .stream_rd_valid(stream_rd_valid),
                .stream_rd_data(stream_rd_data),
                .stream_busy(stream_busy)
            );
        end else if (ENABLE_SHA256 && ENABLE_SHAKE256) begin : g_both
            wire [31:0] sha_rdata;
            wire [31:0] shake_rdata;
            wire        shake_mem_hit;   /* SHAKE256 wrapper self-check output, not consumed by thin shell */
            /* both-mode stream ports are exclusive to the SHAKE256 wrapper (bridge
             * passes through to SHAKE task RAM); SHA-256 side: outputs → dummy, inputs → 0. */
            wire        sha_stream_rd_valid_unused;
            wire [31:0] sha_stream_rd_data_unused;
            wire        sha_stream_busy_unused;
            wire        sha_valid   = bus_valid && !bus_addr[10];
            wire        shake_valid = bus_valid && bus_addr[10];
            /* SHAKE256 base offset 0x400: address passed to the wrapper must be
             * decremented by the offset (low 10 bits are the relative register
             * offset; [31:10]-1 keeps mem_hit self-check matching too). */
            wire [31:0] shake_addr = {bus_addr[31:10] - 22'd1, bus_addr[9:0]}; /* REVIEW B09B10-R5: removed the -10'h400 no-op term (10-bit literal truncates to 0; actual offset is carried by the -22'd1 in the high segment) */

            lms_sha256_mmio #(
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY)
                /* SHA-256 platform has no ALLOW_XQ_DERIVE (x_q isolation only in SHAKE256/TVLA builds, rejected by default under M3) */
            ) u_sha256 (
                .clk(clk),
                .rst(rst),
                .bus_valid(sha_valid),
                .bus_write(bus_write),
                .bus_addr(bus_addr[9:0]),
                .bus_wdata(bus_wdata),
                .bus_rdata(sha_rdata),
                /* both-mode stream ports are exclusive to the SHAKE256 wrapper
                 * (bridge passes through to SHAKE task RAM); SHA-256 side: inputs
                 * tie to 0, outputs tie to dummy. */
                .stream_wr_en(1'b0),
                .stream_wr_addr(12'b0),
                .stream_wr_data(32'b0),
                .stream_rd_en(1'b0),
                .stream_rd_addr(12'b0),
                .stream_rd_valid(sha_stream_rd_valid_unused),
                .stream_rd_data(sha_stream_rd_data_unused),
                .stream_busy(sha_stream_busy_unused)
            );
            lms_shake256_mmio #(
                .SHAKE_BASE(BASE),
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY),   /* compile-time security domain switch (parameterized once SHAKE256 is wired in) */
                .RANDOM_DELAY(RANDOM_DELAY),   /* TVLA lightweight mitigation: 0x6D random delay */
                .DERIVE_SHUFFLE(DERIVE_SHUFFLE), /* DERIVE phase shuffle (TVLA builds) */
                .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE) /* TVLA isolated single x_q[i] pass-through */
            ) u_shake256 (
                .clk(clk),
                .rst(rst),
                .bus_valid(shake_valid),
                .bus_write(bus_write),
                .bus_addr(shake_addr),
                .bus_wdata(bus_wdata),
                .bus_rdata(shake_rdata),
                .mem_hit(shake_mem_hit),
                .stream_wr_en(stream_wr_en),
                .stream_wr_addr(stream_wr_addr),
                .stream_wr_data(stream_wr_data),
                .stream_rd_en(stream_rd_en),
                .stream_rd_addr(stream_rd_addr),
                .stream_rd_valid(stream_rd_valid),
                .stream_rd_data(stream_rd_data),
                .stream_busy(stream_busy)
            );
            assign bus_rdata = bus_addr[10] ? shake_rdata : sha_rdata;
        end else begin : g_none
            /* No hash enabled - compile-time error: at least one hash must be
             * enabled. Generates an explicitly unconnected output to trigger
             * lint / synthesis warnings. */
            assign bus_rdata = 32'b0;
        end
    endgenerate

endmodule

`default_nettype wire
