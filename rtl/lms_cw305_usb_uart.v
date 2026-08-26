`default_nettype none
`include "lms_soc_config.vh"
`include "lms_cw305_regs.vh"

/* ============================================================================
 * lms_cw305_usb_uart.v — CW305 USB↔UART bridge (register mailbox)
 * ----------------------------------------------------------------------------
 * Location: between the SoC and the CW305 onboard USB interface (FTDI channel B, FT245 sync FIFO parallel bus).
 * Host side (chipwhisperer API fpga_read/fpga_write) exchanges bytes with the SoC's
 * 115200 UART via 12 registers; the SoC side still sees plain uart_rxd/uart_txd (zero SoC changes).
 *
 * Components:
 *   1) cw305_usb_reg_fe — NewAE official register frontend (BSD-3, copied verbatim from
 *      chipwhisperer/firmware/fpgas/aes/hdl/cw305_usb_reg_fe.v, see header license).
 *   2) Register map + TX/RX dual-clock FIFO mailbox (original in this file, lms_cw305_afifo.v).
 *   3) UART engine: reuses rtl/uart_rx.v, rtl/uart_tx.v (iut_clk=50 MHz domain,
 *      BITCLKS=434=50MHz/115200; simulation can override via the UART_BITCLKS parameter).
 *
 * Register semantics (lms_cw305_regs.vh):
 *   Read  REG_TX_BYTE(0x05) = pop one byte from TX FIFO (device→host);
 *   Read  REG_TX_IDX(0x06)  = TX FIFO depth (host pops in batches of this count, never overruns);
 *   Write REG_RX_BYTE(0x07) = push one byte into RX FIFO (host→device);
 *   Read  REG_RX_POS(0x09)  = RX FIFO depth (zero = device has consumed all);
 *   Unlike the NewAE/Sloth watermark-index scheme: this bridge is a real FIFO, no byte loss.
 *
 * Timing convention (same as official reg_aes): read_data valid one cycle after reg_read goes high;
 * one RD#/WR# pulse per byte, both TX pop and RX push use pulse-edge detection (exactly once per byte).
 * ========================================================================== */

/* ---------------- NewAE official register frontend (BSD-3, verbatim copy) ---------------- */
/* verilator lint_off DECLFILENAME */
/*
ChipWhisperer Artix Target - Example frontend to USB interface.
Copyright (c) 2020, NewAE Technology Inc.
Redistribution and use in source and binary forms, with or without
modification, are permitted without restriction. Note that modules within
the project may have additional restrictions, please carefully inspect
additional licenses.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
module cw305_usb_reg_fe #(
    parameter pADDR_WIDTH = 21,
    parameter pBYTECNT_SIZE = 7,
    parameter pREG_RDDLY_LEN = 3
)(
    input  wire                         usb_clk,
    input  wire                         rst,

    // Interface to host
    input  wire [7:0]                   usb_din,
    output wire [7:0]                   usb_dout,
    output wire                         usb_isout,
    input  wire [pADDR_WIDTH-1:0]       usb_addr,
    input  wire                         usb_rdn,
    input  wire                         usb_wrn,
    input  wire                         usb_alen,        // unused here
    input  wire                         usb_cen,

    // Interface to registers
    output wire [pADDR_WIDTH-1:pBYTECNT_SIZE] reg_address,  // Address of register
    output wire [pBYTECNT_SIZE-1:0]     reg_bytecnt,  // Current byte count
    output reg  [7:0]                   reg_datao,    // Data to write
    input  wire [7:0]                   reg_datai,    // Data to read
    output reg                          reg_read,     // Read flag. One clock cycle AFTER this flag is high
                                                      // valid data must be present on the reg_datai bus
    output wire                         reg_write,    // Write flag. When high on rising edge valid data is
                                                      // present on reg_datao
    output wire                         reg_addrvalid // Address valid flag
);

    /* 2026-08-22 note: input registers no longer packed into IOBs — output-side set_output_delay fixed 0x72
     * (device→host direction), input side left as-is (inputs never corrupted; packing inputs would change reg_fe
     * pipeline timing → stale TX_IDX count → phantom 0x00 prefix before large responses). */
    reg [pADDR_WIDTH-1:0] usb_addr_r;
    reg usb_rdn_r;
    reg usb_wrn_r;
    reg usb_cen_r;
    reg [pREG_RDDLY_LEN-1:0] isoutreg;

    // register USB interface inputs:
    always @(posedge usb_clk) begin
        usb_addr_r <= usb_addr;
        usb_rdn_r <= usb_rdn;
        usb_wrn_r <= usb_wrn;
        usb_cen_r <= usb_cen;
    end

    assign reg_addrvalid = 1'b1;

    // reg_address selects the register:
    assign reg_address = usb_addr_r[pADDR_WIDTH-1:pBYTECNT_SIZE];

    // reg_bytecnt selects the byte within the register:
    assign reg_bytecnt = usb_addr_r[pBYTECNT_SIZE-1:0];

    assign reg_write = ~usb_cen_r & ~usb_wrn_r;

    always @(posedge usb_clk) begin
        if (~usb_cen & ~usb_rdn)
            reg_read <= 1'b1;
        else if (usb_rdn)
            reg_read <= 1'b0;
    end

    // drive output data bus:
    always @(posedge usb_clk) begin
        if (rst) begin
            isoutreg <= 0;
        end else begin
           isoutreg[0] <= ~usb_rdn_r;
           isoutreg[pREG_RDDLY_LEN-1:1] <= isoutreg[pREG_RDDLY_LEN-2:0];
        end
    end
    assign usb_isout = (|isoutreg) | (~usb_rdn_r);

    assign usb_dout = reg_datai;

    always @(posedge usb_clk)
        reg_datao <= usb_din;

endmodule
/* verilator lint_on DECLFILENAME */

/* ---------------- Bridge body ---------------- */

module lms_cw305_usb_uart #(
    parameter pCRYPT_TYPE  = 8'h4D,       /* 'M' = LMS family */
    parameter pCRYPT_REV   = 8'h01,
    parameter pIDENTIFY    = 8'h4C,       /* 'L' */
    parameter UART_BITCLKS = `LMS_SOC_CLK / 115200   /* 434 at 50 MHz; overridable in simulation */
) (
    /* USB interface (FTDI channel B parallel bus, usb_clk domain) */
    input  wire         usb_clk,
    input  wire         rst,             /* async reset (button), shared by both domains */
    input  wire [7:0]   usb_din,
    output wire [7:0]   usb_dout,
    output wire         usb_isout,
    input  wire [20:0]  usb_addr,
    input  wire         usb_rdn,
    input  wire         usb_wrn,
    input  wire         usb_alen,        /* unused (same as official) */
    input  wire         usb_cen,
    /* SoC UART side (iut_clk domain) */
    input  wire         iut_clk,         /* 50 MHz SoC clock */
    input  wire         soc_uart_txd,    /* SoC uart_txd (device→host) */
    output wire         soc_uart_rxd,    /* SoC uart_rxd (host→device) */
    output wire         soc_uart_cts,    /* RTS flow control: 0=TX FIFO full, pause SoC UART TX */
    /* Miscellaneous */
    input  wire         trap_in,         /* SoC trap → REG_STATUS[0] */
    output reg          o_user_led
);

    /* RTS flow control (2026-08-19): pulls low when TX FIFO is full, pausing SoC UART TX (connected to lms_soc
     * uart_tx.cts). Otherwise, when the SoC streams y (2048B) out at high speed, TX FIFO(256) fills →
     * ack_pulse=0 backpressure → uart_rx drops bytes/hangs (0x53/0x61 measured stuck at 260B).
     * After reset FIFO is empty → full=0 → cts=1 allows. */
    assign soc_uart_cts = !txf_full;
    localparam UART_BITCLKS_USE = UART_BITCLKS > 0 ? UART_BITCLKS : (`LMS_SOC_CLK / 115200);

    /* ---- reg_fe wiring ---- */
    wire [13:0] reg_address;
    wire [6:0]  reg_bytecnt;
    wire [7:0]  write_data;
    reg  [7:0]  read_data;  /* output data register (2026-08-22 note: do not pack into IOBs — the 863aa74
                               * read_data<=txf_rdata timing fix is calibrated to fabric timing; packing would
                               * shift pad delay → 0x2f frame-shift regression on real hardware; the pad path is
                               * guaranteed by the set_output_delay constraint in flow/cw305.xdc) */
    wire        reg_read;
    wire        reg_write;
    wire        reg_addrvalid;

    cw305_usb_reg_fe #(
        .pADDR_WIDTH(21),
        .pBYTECNT_SIZE(7)
    ) reg_fe (
        .rst(rst),
        .usb_clk(usb_clk),
        .usb_din(usb_din),
        .usb_dout(usb_dout),
        .usb_rdn(usb_rdn),
        .usb_wrn(usb_wrn),
        .usb_cen(usb_cen),
        .usb_alen(usb_alen),
        .usb_addr(usb_addr),
        .usb_isout(usb_isout),
        .reg_address(reg_address),
        .reg_bytecnt(reg_bytecnt),
        .reg_datao(write_data),
        .reg_datai(read_data),
        .reg_read(reg_read),
        .reg_write(reg_write),
        .reg_addrvalid(reg_addrvalid)
    );

    /* ---- TX FIFO (device→host): write side iut_clk, read side usb_clk ---- */
    wire [7:0]  txf_wdata;
    wire        txf_wren;   /* combinational drive (ack_pulse && rdy), cannot be a reg */
    wire        txf_full;
    reg         txf_rden;   /* rising-edge single pulse pop (one RD# per byte, 2026-08-19 rollback) */
    wire [7:0]  txf_rdata;
    wire        txf_empty;
    wire [8:0]  txf_count_rd;

    /* ---- RX FIFO (host→device): write side usb_clk, read side iut_clk ---- */
    wire [7:0]  rxf_wdata;
    reg         rxf_wren;
    wire        rxf_full;
    reg         rxf_rden;
    wire [7:0]  rxf_rdata;
    wire        rxf_empty;
    wire [8:0]  rxf_count_wr;

    lms_cw305_afifo #(.DEPTH(256), .ADDRW(8), .DW(8)) txfifo (
        .rst(rst),
        .wclk(iut_clk), .wren(txf_wren), .wdata(txf_wdata), .full(txf_full),
        .rclk(usb_clk), .rden(txf_rden), .rdata(txf_rdata), .empty(txf_empty),
        .count_rd(txf_count_rd), .count_wr()
    );

    lms_cw305_afifo #(.DEPTH(256), .ADDRW(8), .DW(8)) rxfifo (
        .rst(rst),
        .wclk(usb_clk), .wren(rxf_wren), .wdata(rxf_wdata), .full(rxf_full),
        .rclk(iut_clk), .rden(rxf_rden), .rdata(rxf_rdata), .empty(rxf_empty),
        .count_rd(), .count_wr(rxf_count_wr)
    );

    /* ---- UART engine (iut_clk domain) ---- */

    // SRX: captures SoC uart_txd → pushes into TX FIFO.
    // Timing notes (debug conclusion, 2026-08-18):
    //   uart_rx's rdy/ack are both level signals and lag one cycle — if wren directly followed rdy it would
    //   stay high for 2 cycles (rdy lag + ack sampling delay), the FIFO would be written on 2 wclk rising edges, and the second
    //   cycle would be 0x00 garbage from the empty FIFO (measured count 1,2,3,4,5,6 = +2 per byte).
    //   Correct approach: ack_pulse is a registered follower of rdy (2-cycle width is harmless — uart_rx empty pop is a no-op),
    //   wren uses **combinational gating** ack_pulse && rdy: it is 1 only on the edge where "uart_rx pop takes effect",
    //   and on that edge data is still the pre-pop head (byte correct), written exactly once per byte.
    //   When TX FIFO is full, no ack → backpressure. SoC side has no cts, the overflow window is covered by host read pacing.
    wire [7:0] srx_byte;
    wire       srx_rdy;
    reg        ack_pulse;
    assign txf_wdata = srx_byte;         /* combinational direct: byte still stable when sampled on the wren edge */
    assign txf_wren  = ack_pulse && srx_rdy;

    uart_rx #(
        .BITCLKS(UART_BITCLKS_USE)
    ) srx_unit (
        .clk(iut_clk),
        .rst(rst),
        .ack(ack_pulse),
        .data(srx_byte),
        .rdy(srx_rdy),
        .rts(),
        .rxd(soc_uart_txd)
    );

    always @(posedge iut_clk) begin
        if (rst) begin
            ack_pulse <= 1'b0;
        end else begin
            ack_pulse <= srx_rdy && !txf_full;
        end
    end

    // STX: RX FIFO non-empty and uart_tx idle → pop one byte to send to SoC uart_rxd.
    // Timing notes (debug conclusion, 2026-08-18, third version):
    //   ① send level follows stx_cond (txok && !empty) — uart_tx loads tdata on every edge while the condition
    //      holds, so the data port must be fed the **pre-pop latched** byte
    //      (stx_byte_r): double load is idempotent, unaffected by post-pop rdata changes;
    //   ② rden uses a rising-edge single pulse of stx_cond — exactly one pop per byte;
    //   ③ fin is already 1 when idle (no rising edge), so fin edge triggering cannot be used (measured: the first byte
    //      is never sent).
    wire       stx_txok;
    reg        stx_send;
    reg        stx_cond_d;
    reg [7:0]  stx_byte_r;
    wire       stx_cond = stx_txok && !rxf_empty;

    uart_tx #(
        .BITCLKS(UART_BITCLKS_USE)
    ) stx_unit (
        .clk(iut_clk),
        .rst(rst),
        .send(stx_send),
        .data(stx_byte_r),
        .rdy(stx_txok),
        .cts(1'b1),
        .txd(soc_uart_rxd)
    );

    always @(posedge iut_clk) begin
        if (rst) begin
            stx_cond_d <= 1'b0;
            stx_send   <= 1'b0;
            rxf_rden   <= 1'b0;
            stx_byte_r <= 8'h00;
        end else begin
            stx_cond_d <= stx_cond;
            rxf_rden   <= 1'b0;
            /* 0.1.282 fix: send changed to **rising-edge single pulse** (same edge as pop). Previously it was a level
             * (stx_send <= stx_cond) — stx_cond stayed high for 2+ cycles due to the delayed empty update after FIFO pop:
             * cycle 1 uart_tx starts the byte while idle (fin=1), cycle 2 fin=0 is buffered by uart_tx's
             * busy-send (pending) → the same byte is **sent twice** →
             * SoC uart_rx receives two frames (measured / bridge simulation double response 76B). Pulse and pop are one-to-one. */
            stx_send   <= stx_cond && !stx_cond_d;
            if (stx_cond && !stx_cond_d) begin
                stx_byte_r <= rxf_rdata;  /* latch before pop */
                rxf_rden   <= 1'b1;       /* single pulse pop on condition rising edge */
            end
        end
    end

    /* ---- Register read/write (usb_clk domain) ---- */

    // synchronize trap into usb domain
    (* ASYNC_REG = "TRUE" *) reg trap_sync1, trap_sync2;
    always @(posedge usb_clk) begin
        if (rst) begin
            trap_sync1 <= 1'b0;
            trap_sync2 <= 1'b0;
        end else begin
            trap_sync1 <= trap_in;
            trap_sync2 <= trap_sync1;
        end
    end

    // buildtime: Xilinx bitstream timestamp (USR_ACCESSE2 primitive; set to 0 outside Vivado)
    wire [31:0] buildtime;
`ifdef SYNTHESIS
    USR_ACCESSE2 buildtime_0 (
        .CFGCLK(),
        .DATA(buildtime),
        .DATAVALID()
    );
`else
    assign buildtime = 32'h0;
`endif

    // read mux (combinational, official convention: read_data valid one cycle after reg_read goes high)
    reg [7:0] rdata_mux;
    always @(*) begin
        case (reg_address)
            `REG_CLKSETTINGS: rdata_mux = 8'h00;
            `REG_USER_LED:    rdata_mux = {7'b0, o_user_led};
            `REG_CRYPT_TYPE:  rdata_mux = pCRYPT_TYPE;
            `REG_CRYPT_REV:   rdata_mux = pCRYPT_REV;
            `REG_IDENTIFY:    rdata_mux = pIDENTIFY;
            `REG_TX_BYTE:     rdata_mux = txf_pop_byte;  /* byte latched on the pop edge */
            `REG_TX_IDX:      rdata_mux = txf_count_rd[8] ? 8'hFF : txf_count_rd[7:0];
            `REG_RX_BYTE:     rdata_mux = 8'h00;           /* write-only */
            `REG_RX_IDX:      rdata_mux = rxf_count_wr[8] ? 8'hFF : rxf_count_wr[7:0];
            `REG_RX_POS:      rdata_mux = rxf_count_wr[8] ? 8'hFF : rxf_count_wr[7:0];
            `REG_STATUS:      rdata_mux = {7'h00, trap_sync2};
            `REG_BUILDTIME:   rdata_mux = buildtime[reg_bytecnt*8 +: 8];
            default:          rdata_mux = 8'h00;
        endcase
    end

    // TX_BYTE pop: reg_read rising-edge single pulse pops 1 byte (one RD# pulse per byte).
    // 2026-08-19 rollback (plan A level-pop failure conclusion): real chipwhisperer register reads are
    //   **one RD pulse per byte** (usb_rdn pulses per byte, reg_read rises once per byte),
    //   not "held high for N cycles, popping 1 per cycle" — level pop would over-pop during each RD pulse high phase
    //   (v8 real hardware measured all-0xe2 garbage). The original implementation (rising-edge single pop) matches per-byte reads correctly.
    // The pop edge also **latches** the popped byte (txf_pop_byte) — after pop the FIFO head advances,
    //  read_data must latch the popped byte (on non-pop edges, reading rdata_mux=txf_pop_byte holds).
    reg reg_read_d;
    reg [7:0] txf_pop_byte;
    always @(posedge usb_clk) begin
        if (rst) begin
            reg_read_d   <= 1'b0;
            txf_rden     <= 1'b0;
            txf_pop_byte <= 8'h00;
        end else begin
            reg_read_d <= reg_read;
            txf_rden   <= 1'b0;
            if (reg_addrvalid && reg_read && !reg_read_d &&
                reg_address == `REG_TX_BYTE && !txf_empty) begin
                txf_rden     <= 1'b1;
                txf_pop_byte <= txf_rdata;   /* latch the popped byte */
            end
        end
    end

    // Write side: reg_write rising edge (one WR# pulse per byte)
    reg reg_write_d;
    always @(posedge usb_clk) begin
        if (rst) begin
            reg_write_d <= 1'b0;
            rxf_wren    <= 1'b0;
            o_user_led  <= 1'b0;
        end else begin
            reg_write_d <= reg_write;
            rxf_wren    <= 1'b0;
            if (reg_addrvalid && reg_write && !reg_write_d) begin
                case (reg_address)
                    `REG_USER_LED: o_user_led <= write_data[0];
                    `REG_RX_BYTE:  if (!rxf_full) rxf_wren <= 1'b1;
                    default: ;
                endcase
            end
        end
    end
    assign rxf_wdata = write_data;       /* combinational direct: byte still stable when sampled on the wren edge */

    // read_data registered (official convention: valid one cycle after reg_read).
    // ★ debug conclusion (2026-08-18, root cause of the on-board 0x2f leading byte): on the TX_BYTE pop edge
    //   txf_pop_byte and read_data update on the same edge — nonblocking assignment makes read_data sample the **old**
    //   txf_pop_byte (the previous frame's final byte); the real byte needs one more cycle to reach read_data, 1 cycle later
    //   than the official convention (1 cycle after reg_read) → the real sampling point grabs the previous frame's final byte,
    //   shifting the whole frame right by one (board measured [0x2f][0x52...] = previous frame's digest final byte 0x2f prepended).
    //   Fix: on the pop edge read_data directly latches txf_rdata (the popped byte, its pre-edge value is correct),
    //   other cycles still follow rdata_mux (held stable across cycles).
    //   2026-08-19 rollback: restored rising-edge single pop (reg_read && !reg_read_d), matching per-byte
    //   reads (one RD# pulse per byte); the level-pop scheme failed on real hardware and was abandoned (see above).
    always @(posedge usb_clk) begin
        if (rst) begin
            read_data <= 8'h00;
        end else if (reg_addrvalid && reg_read && !reg_read_d &&
                     reg_address == `REG_TX_BYTE && !txf_empty) begin
            read_data <= txf_rdata;
        end else begin
            read_data <= rdata_mux;
        end
    end

endmodule

`default_nettype wire
