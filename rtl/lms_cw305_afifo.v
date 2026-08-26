`default_nettype none
`timescale 1 ns / 1 ps

/* ============================================================================
 * lms_cw305_afifo.v — dual-clock async FIFO (gray-code pointers, for the CW305 USB↔UART bridge)
 * ----------------------------------------------------------------------------
 * Purpose: TX/RX byte mailboxes for lms_cw305_usb_uart.v (usb_clk domain ↔ iut_clk domain).
 * Implementation: standard gray-code pointers + two-stage sync of the peer pointer (ASYNC_REG);
 *       dual-port RAM (combinational read output, read enable edge advances the read pointer).
 * Count outputs (for host-side queries, each computed in its own domain within this module):
 *   count_rd = depth from the read domain's view (lags the write side ~2 cycles, can only be low → host pops by this count without overrun)
 *   count_wr = depth from the write domain's view (lags the read side ~2 cycles, can only be high → host waiting for it to reach zero is more conservative)
 * Reset: synchronous reset on both sides (rst is an async button signal but held long enough; each side samples on its own clock edge).
 * ========================================================================== */

module lms_cw305_afifo #(
    parameter DEPTH = 256,
    parameter ADDRW = 8,            /* log2(DEPTH) */
    parameter DW    = 8
) (
    input  wire             rst,        /* async reset (shared by both sides, button reset) */
    /* Write side (wclk domain) */
    input  wire             wclk,
    input  wire             wren,
    input  wire [DW-1:0]    wdata,
    output wire             full,
    /* Read side (rclk domain) */
    input  wire             rclk,
    input  wire             rden,
    output wire [DW-1:0]    rdata,
    output wire             empty,
    /* Depth (each side's own domain, for status queries) */
    output wire [ADDRW:0]   count_rd,
    output wire [ADDRW:0]   count_wr
);
    localparam PTRW = ADDRW + 1;

    /* Storage */
    reg [DW-1:0] mem [0:DEPTH-1];

    /* Pointers (gray-encoded, PTRW bits) */
    reg [PTRW-1:0] wr_ptr_g, rd_ptr_g;
    /* Binary pointers (write domain / read domain) */
    reg [PTRW-1:0] wr_ptr_b, rd_ptr_b;
    wire [PTRW-1:0] wr_ptr_b_next = wr_ptr_b + 1'b1;
    wire [PTRW-1:0] rd_ptr_b_next = rd_ptr_b + 1'b1;

    /* Peer pointer sync (two-stage, ASYNC_REG) */
    (* ASYNC_REG = "TRUE" *) reg [PTRW-1:0] wr_g_sync1, wr_g_sync2;   /* write pointer → read domain */
    (* ASYNC_REG = "TRUE" *) reg [PTRW-1:0] rd_g_sync1, rd_g_sync2;   /* read pointer → write domain */

    function [PTRW-1:0] gray2bin;
        input [PTRW-1:0] g;
        integer i;
        begin
            /* Standard XOR chain: bin = g ^ (g>>1) ^ (g>>2) ^ ... ^ (g>>(PTRW-1))
             * Note: must not be written as self-shift (bin ^= bin>>1 iteration) — that converges to the wrong
             * result (measured: gray(2) at 9 bits yields 2 instead of 3, corrupting all counts). */
            gray2bin = g;
            for (i = 0; i < PTRW-1; i = i + 1)
                gray2bin = gray2bin ^ (g >> (i + 1));
        end
    endfunction

    /* Write side (sync reset: rst is an async button signal held far longer than a clock cycle, each domain
     * samples the reset on its clock edge, avoiding mixing with the bridge control logic's sync-reset semantics (SYNCASYNCNET)) */
    always @(posedge wclk) begin
        if (rst) begin
            wr_ptr_b <= 0;
            wr_ptr_g <= 0;
        end else begin
            if (wren && !full) begin
                mem[wr_ptr_b[ADDRW-1:0]] <= wdata;
                wr_ptr_b <= wr_ptr_b_next;
                wr_ptr_g <= wr_ptr_b_next ^ (wr_ptr_b_next >> 1);
            end
        end
    end

    always @(posedge wclk) begin
        if (rst) begin
            rd_g_sync1 <= 0;
            rd_g_sync2 <= 0;
        end else begin
            rd_g_sync1 <= rd_ptr_g;
            rd_g_sync2 <= rd_g_sync1;
        end
    end

    /* Read side (sync reset, same as write side) */
    always @(posedge rclk) begin
        if (rst) begin
            rd_ptr_b <= 0;
            rd_ptr_g <= 0;
        end else begin
            if (rden && !empty) begin
                rd_ptr_b <= rd_ptr_b_next;
                rd_ptr_g <= rd_ptr_b_next ^ (rd_ptr_b_next >> 1);
            end
        end
    end

    always @(posedge rclk) begin
        if (rst) begin
            wr_g_sync1 <= 0;
            wr_g_sync2 <= 0;
        end else begin
            wr_g_sync1 <= wr_ptr_g;
            wr_g_sync2 <= wr_g_sync1;
        end
    end

    /* Full/empty (standard gray check: full = write pointer leads the read pointer by one full turn,
     *      i.e. wgray == {~rgray[PTRW-1:PTRW-2], rgray[PTRW-3:0]}) */
    assign full  = (wr_ptr_g == {~rd_g_sync2[PTRW-1:PTRW-2], rd_g_sync2[PTRW-3:0]});
    assign empty = (rd_ptr_g == wr_g_sync2);

    /* Read data: combinational output of the current head (advances after the read enable edge) */
    assign rdata = mem[rd_ptr_b[ADDRW-1:0]];

    /* Depth (each domain's view) */
    wire [PTRW-1:0] wr_b_in_rd = gray2bin(wr_g_sync2);   /* write pointer as seen in read domain (lagging) */
    wire [PTRW-1:0] rd_b_in_wr = gray2bin(rd_g_sync2);   /* read pointer as seen in write domain (lagging) */
    assign count_rd = wr_b_in_rd - rd_ptr_b;
    assign count_wr = wr_ptr_b - rd_b_in_wr;

endmodule

`default_nettype wire
