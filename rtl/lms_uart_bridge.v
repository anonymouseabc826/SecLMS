`default_nettype none

// UART<->task RAM pass-through bridge (Step 3, independent SoC-level module).
//
// Goal: move the MMIO transfer of the 2144B signature value out of the "cooperation window"
// (window = input already in task RAM to output already in task RAM, excluding UART serial send/receive):
//   dir=0 (RX->RAM): receive len bytes from uart_rx, pack 4B into a little-endian word, write to task RAM
//                    via the stream write port (Verify signature pass-through; firmware no longer calls write_task_bytes).
//   dir=1 (RAM->TX): read len/4 words from the task RAM stream read port, split into bytes and send via uart_tx
//                    (Sign signature pass-through; firmware no longer calls read_task_bytes).
// Available when the core is idle (!stream_busy); the CPU copy path is kept as fallback (when the bridge is disabled,
// firmware does MMIO transfer as usual). Interface-neutral: the core only exposes stream ports, and the transfer path is completed by a configurable bridge at the SoC integration layer.
//
// Control registers (BRIDGE_BASE):
//   0x00 CTRL: write [0]=start [1]=dir (0=RX->RAM, 1=RAM->TX); read = status
//              [0]=busy [1]=done [2]=error (error: started while core busy / illegal length)
//   0x04 ADDR: task RAM starting word address (0..2151)
//   0x08 LEN : byte count (must be a multiple of 4, max 8608B=2152 words)
// Byte order (aligned with firmware): RX packs byte k into bit (k%4)*8 of the word (little-endian);
//                                     TX reads a word and sends bytes split by bit (k%4)*8.

/* Port widths declared per SoC bus convention (only low 16 bits / bit0 used), lint-off harmless items */
/* verilator lint_off UNUSEDSIGNAL */

/* Keep the bridge hierarchy to prevent Vivado 2020.2 from absorbing it across layers and dropping the stream port return path. */
(* keep_hierarchy = "yes" *)
module lms_uart_bridge #(
    parameter [31:0] BRIDGE_BASE = 32'h1800_0000
) (
    input  wire        clk,
    input  wire        rst,
    // CPU MMIO control (SoC decode; mem_valid must include !reset)
    input  wire        mem_valid,
    input  wire        mem_write,
    input  wire [31:0] mem_addr,
    input  wire [31:0] mem_wdata,
    input  wire [3:0]  mem_wstrb,
    output wire        mem_hit,
    output reg  [31:0] mem_rdata,
    // UART RX bypass (reads bytes from uart_rx when the bridge is enabled)
    input  wire [7:0]  rx_data,
    input  wire        rx_rdy,
    output wire        rx_ack,
    // UART TX bypass (writes bytes to uart_tx when the bridge is enabled)
    output reg  [7:0]  tx_data,
    output wire        tx_send,
    input  wire        tx_ready,
    // Task RAM stream ports (connect to lms_shake256_mmio, available when the core is idle)
    output reg         stream_wr_en,
    output reg  [11:0] stream_wr_addr,
    output reg  [31:0] stream_wr_data,
    output reg         stream_rd_en,
    output reg  [11:0] stream_rd_addr,
    input  wire        stream_rd_valid,
    input  wire [31:0] stream_rd_data,
    input  wire        stream_busy,
    output wire        busy             /* bridge busy (for SoC-level UART bypass mux) */
);
    localparam [9:0] REG_CTRL  = 10'h000;
    localparam [9:0] REG_ADDR  = 10'h004;
    localparam [9:0] REG_LEN   = 10'h008;
    localparam [9:0] REG_DEBUG = 10'h00c;   /* DBG: word_left initial value latched at start */

    localparam [2:0] S_IDLE    = 3'd0;
    localparam [2:0] S_RX_BYTE = 3'd1;
    localparam [2:0] S_RX_WR   = 3'd2;
    localparam [2:0] S_TX_RD   = 3'd3;
    localparam [2:0] S_TX_LOAD = 3'd4;
    localparam [2:0] S_TX_PUT  = 3'd5;
    localparam [2:0] S_DONE    = 3'd6;

    /* Port widths declared per SoC bus convention (only low 16 bits / bit0 used), lint-off harmless items */
    /* verilator lint_off UNUSEDSIGNAL */
    (* fsm_encoding = "none" *) (* keep = "true" *) reg [2:0] state_r;
    reg [11:0] word_addr_r;      /* current task RAM word address (0..2151) */
    reg [15:0] byte_left_r;      /* RX: remaining bytes */
    reg [11:0] word_left_r;      /* TX: remaining words */
    (* keep = "true" *) reg [31:0] wdata_buf_r;      /* RX word assembly buffer */
    reg [1:0]  wbyte_idx_r;      /* RX buffer byte index */
    reg [1:0]  rbyte_idx_r;      /* TX byte split index */
    reg [31:0] rdata_buf_r;      /* TX word read back from task RAM */
    reg        byte_sent_r;      /* TX: >=1 byte of current word already sent (must wait for tx_ready) */
    reg        tx_hold_r;        /* TX: byte just sent, force wait next cycle (uart_tx fin only deasserts on posedge) */
    reg        busy_r;
    reg        done_r;
    reg        error_r;
    reg        tx_send_r;        /* TX send pulse */
    reg [11:0] dbg_wl_start;      /* DBG: word_left initial value latched at start */

    wire address_hit = mem_valid && mem_addr[31:10] == BRIDGE_BASE[31:10];
    assign mem_hit = address_hit;
    /* RX handshake: combinational ack (valid in S_RX_BYTE when rx_rdy), completing "sample data + pop"
     * with uart_rx on the same posedge. If ack were registered one cycle, uart_rx would still see the old
     * ack=0 at the bridge's first sample and not pop; next cycle the bridge sees rx_rdy=1 again and consumes
     * the same byte twice (bridge receives 2144B but actually gets 1072 physical bytes, task RAM write y doubles, root cause of Verify hang). */
    assign rx_ack = state_r == S_RX_BYTE && rx_rdy;
    assign tx_send = tx_send_r;
    assign busy = busy_r;

    /* Start: CTRL write [0]=start. Reject and set error when the core is busy (stream_busy).
     * LEN must be a multiple of 4 and <= 4*2152 (8608B, full task RAM). */
    wire start_req = mem_valid && mem_write && address_hit &&
                     mem_addr[9:0] == REG_CTRL && (mem_wdata[0] & mem_wstrb[0]);

    always @(posedge clk) begin
        if (rst) begin
            state_r        <= S_IDLE;
            word_addr_r    <= 12'b0;
            byte_left_r    <= 16'b0;
            word_left_r    <= 12'b0;
            wdata_buf_r    <= 32'b0;
            wbyte_idx_r    <= 2'b0;
            rbyte_idx_r    <= 2'b0;
            rdata_buf_r    <= 32'b0;
            byte_sent_r    <= 1'b0;
            tx_hold_r      <= 1'b0;
            busy_r         <= 1'b0;
            done_r         <= 1'b0;
            error_r        <= 1'b0;
            tx_send_r      <= 1'b0;
            tx_data        <= 8'b0;
            stream_wr_en   <= 1'b0;
            stream_wr_addr <= 12'b0;
            stream_wr_data <= 32'b0;
            stream_rd_en   <= 1'b0;
            stream_rd_addr <= 12'b0;
        end else begin
            tx_send_r      <= 1'b0;
            stream_wr_en   <= 1'b0;
            stream_rd_en   <= 1'b0;

            /* Register write (when not busy): latch ADDR/LEN */
            if (mem_valid && mem_write && address_hit && !busy_r) begin
                if (mem_addr[9:0] == REG_ADDR && mem_wstrb[0]) begin
                    word_addr_r <= mem_wdata[11:0];
                end else if (mem_addr[9:0] == REG_LEN && mem_wstrb[0]) begin
                    byte_left_r <= mem_wdata[15:0];
                end
            end

            case (state_r)
                S_IDLE: begin
                    if (start_req) begin
                        if (stream_busy || byte_left_r == 16'b0 ||
                            (byte_left_r & 16'h3) != 16'b0 ||
                            byte_left_r > 16'd8608) begin
                            error_r <= 1'b1;
                            done_r  <= 1'b0;
                            state_r <= S_DONE;
                        end else begin
                            busy_r      <= 1'b1;
                            done_r      <= 1'b0;
                            error_r     <= 1'b0;
                            wbyte_idx_r <= 2'b0;
                            rbyte_idx_r <= 2'b0;
                            byte_sent_r <= 1'b0;
                            tx_hold_r   <= 1'b0;
                            if (mem_wdata[1]) begin
                                word_left_r  <= byte_left_r[13:2];
                                dbg_wl_start <= byte_left_r[13:2];
                                state_r      <= S_TX_RD;
                            end else begin
                                state_r      <= S_RX_BYTE;
                            end
                        end
                    end
                end
                /* ---- RX->RAM: receive 1 byte per cycle, stream-write after 4 bytes assembled into a word ---- */
                S_RX_BYTE: begin
                    if (rx_rdy) begin
                        /* Assemble by shifting (little-endian: byte0 at LSB, new byte enters the high bits after a right shift of 8):
                         * pure concatenation with no part-select, avoiding Vivado 2020.2's incorrect implementation of
                         * non-blocking assignment with part-select (post-gate simulation gives all-zero words),
                         * while Verilator is correct. */
                        wdata_buf_r <= {rx_data, wdata_buf_r[31:8]};
                        byte_left_r <= byte_left_r - 16'd1;
                        if (wbyte_idx_r == 2'd3) begin
                            wbyte_idx_r <= 2'b0;
                            state_r     <= S_RX_WR;
                        end else begin
                            wbyte_idx_r <= wbyte_idx_r + 2'd1;
                        end
                    end
                end
                S_RX_WR: begin
                    stream_wr_en   <= 1'b1;
                    stream_wr_addr <= word_addr_r;
                    stream_wr_data <= wdata_buf_r;
                    if (byte_left_r == 16'b0) begin
                        busy_r <= 1'b0;
                        done_r <= 1'b1;
                        state_r <= S_DONE;
                    end else begin
                        word_addr_r <= word_addr_r + 12'd1;
                        state_r     <= S_RX_BYTE;
                    end
                end
                /* ---- RAM->TX: stream-read word -> byte-by-byte tx ---- */
                S_TX_RD: begin
                    stream_rd_en   <= 1'b1;
                    stream_rd_addr <= word_addr_r;
                    state_r        <= S_TX_LOAD;
                end
                S_TX_LOAD: begin
                    if (stream_rd_valid) begin
                        rdata_buf_r <= stream_rd_data;
                        rbyte_idx_r <= 2'b0;
                        byte_sent_r <= 1'b0;
                        tx_hold_r   <= 1'b0;
                        state_r     <= S_TX_PUT;
                    end
                end
                S_TX_PUT: begin
                    if (!byte_sent_r && tx_ready) begin
                        /* First byte of a new word: wait for tx_ready (uart_tx idle fin=1) before sending.
                         * If uart_tx's send arrives while fin=0 (transmitting), it unconditionally resets and overwrites
                         * tdata -- firmware starts the bridge right after sending C; if the bridge's first byte did not
                         * check tx_ready, it would overwrite the last byte of C that uart_tx is still sending (root cause of
                         * measured y shift by 1 on SoC). tx_hold set to 1: force a wait of one cycle after send (fin only deasserts on posedge). */
                        byte_sent_r <= 1'b1;
                        tx_hold_r   <= 1'b1;
                        tx_send_r   <= 1'b1;
                        tx_data     <= rdata_buf_r[7:0];
                    end else if (!tx_hold_r && tx_ready) begin
                        /* Previous byte confirmed sent, send the next byte */
                        rbyte_idx_r <= rbyte_idx_r + 2'd1;
                        if (rbyte_idx_r == 2'd3) begin
                            /* 4 bytes sent -> next word or done */
                            word_left_r <= word_left_r - 12'd1;
                            if (word_left_r == 12'd1) begin
                                busy_r <= 1'b0;
                                done_r <= 1'b1;
                                state_r <= S_DONE;
                            end else begin
                                word_addr_r <= word_addr_r + 12'd1;
                                state_r     <= S_TX_RD;
                            end
                        end else begin
                            case (rbyte_idx_r)
                                2'd0: begin
                                    tx_data <= rdata_buf_r[15:8];
                                end
                                2'd1: begin
                                    tx_data <= rdata_buf_r[23:16];
                                end
                                default: begin
                                    tx_data <= rdata_buf_r[31:24];
                                end
                            endcase
                            tx_hold_r <= 1'b1;
                            tx_send_r <= 1'b1;
                        end
                    end else begin
                        tx_hold_r <= 1'b0;
                    end
                end
                S_DONE: begin
                    dbg_wl_start <= word_left_r;   /* DBG: remaining words at done */
                    if (mem_valid && mem_write && address_hit &&
                        mem_addr[9:0] == REG_CTRL && (mem_wdata[1] & mem_wstrb[0])) begin
                        /* Clear completion status: write CTRL [1] (clear) */
                        done_r  <= 1'b0;
                        error_r <= 1'b0;
                        busy_r  <= 1'b0;
                        state_r <= S_IDLE;
                    end
                end
                default: state_r <= S_IDLE;
            endcase
        end
    end

    /* Status read */
    always @* begin
        mem_rdata = 32'b0;
        case (mem_addr[9:0])
            REG_CTRL: mem_rdata = {29'b0, error_r, done_r, busy_r};
            REG_ADDR: mem_rdata = {20'b0, word_addr_r};
            REG_LEN:  mem_rdata = {16'b0, byte_left_r};
            REG_DEBUG: mem_rdata = {20'b0, dbg_wl_start};
            default: ;
        endcase
    end

endmodule

`default_nettype wire
