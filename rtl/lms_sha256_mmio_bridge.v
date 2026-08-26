`default_nettype none

/* MMIO bridge layer between the SoC bus and the lms_sha256_mmio accelerator.
 * (Formerly named lms_sha256_pug_bridge; the pug core was removed in the Ibex migration,
 * leaving only the name-independent bus adaptation.) */

module lms_sha256_mmio_bridge #(
    parameter [31:0] LMS_BASE = 32'h1600_0000,
    parameter INSECURE_TEST_MODE = 0,
    parameter ENABLE_SHA256   = 1,
    parameter ENABLE_SHAKE256 = 0,
    parameter HAS_SECURITY    = 1,
    parameter RANDOM_DELAY    = 0,     // TVLA lightweight mitigation: LFSR random delay before 0x6D DERIVE
    parameter DERIVE_SHUFFLE  = 0,     // DERIVE phase shuffle: batch task block params shifted by a per-trace random start (TVLA build)
    parameter ALLOW_XQ_DERIVE = 0      // TVLA isolation: allow single x_q[i] pass-through (see plan)
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        mem_valid,
    input  wire [31:0] mem_addr,
    input  wire [31:0] mem_wdata,
    input  wire [3:0]  mem_wstrb,
    output wire        mem_hit,
    output wire        mem_ready,
    output wire [31:0] mem_rdata,
    /* Task RAM stream port passthrough (Step 3 UART bridge front-end; SHAKE256 path, SHA-256 ties 0).
     * Direction (do not reverse again): write/read requests are produced by the UART bridge
     * (output) -> passed through this bridge (input) -> consumed by the wrapper; read-back
     * valid/data/busy are produced by the wrapper -> passed through this bridge (output) ->
     * consumed by the UART bridge. Previously the write/read requests were wrongly declared
     * as outputs, leaving the thin shell undriven and synthesis tied them to 0. */
    input  wire        stream_wr_en,
    input  wire [11:0] stream_wr_addr,
    input  wire [31:0] stream_wr_data,
    input  wire        stream_rd_en,
    input  wire [11:0] stream_rd_addr,
    output wire        stream_rd_valid,   /* SHAKE256 wrapper output, passed through to the UART bridge */
    output wire [31:0] stream_rd_data,
    output wire        stream_busy
);
    /* Low 11-bit decode: 2KB window (0x000..0x7ff); in both mode SHA-256 @0x000,
     * SHAKE256 @0x400; in only mode each responds to its own register segment only
     * (the others return 0). */
    wire address_hit = mem_valid && mem_addr[31:11] == LMS_BASE[31:11];
    wire full_word_write = mem_wstrb == 4'b1111;
    wire [31:0] accelerator_rdata;

    assign mem_hit = address_hit;
    assign mem_ready = address_hit;
    assign mem_rdata = address_hit ? accelerator_rdata : 32'b0;

    lms_hash_mmio #(
        .BASE(LMS_BASE),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .ENABLE_SHA256(ENABLE_SHA256),
        .ENABLE_SHAKE256(ENABLE_SHAKE256),
        .HAS_SECURITY(HAS_SECURITY),
        .RANDOM_DELAY(RANDOM_DELAY),
        .DERIVE_SHUFFLE(DERIVE_SHUFFLE),
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE)
    ) accelerator (
        .clk(clk),
        .rst(rst),
        .bus_valid(address_hit),
        .bus_write(address_hit && full_word_write),
        .bus_addr(mem_addr),
        .bus_wdata(mem_wdata),
        .bus_rdata(accelerator_rdata),
        .stream_wr_en(stream_wr_en),
        .stream_wr_addr(stream_wr_addr),
        .stream_wr_data(stream_wr_data),
        .stream_rd_en(stream_rd_en),
        .stream_rd_addr(stream_rd_addr),
        .stream_rd_valid(stream_rd_valid),
        .stream_rd_data(stream_rd_data),
        .stream_busy(stream_busy)
    );

endmodule

`default_nettype wire
