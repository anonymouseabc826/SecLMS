`default_nettype none

/* =============================================================================================
 * lms_flash_spi.v -- SPI flash access peripheral (CW305 on-board SPI NOR)
 * ---------------------------------------------------------------------------------------------
 * Purpose: verify FPGA<->flash bidirectional access capability, paving the way for the "device-owned monotonic counter" approach.
 *   M1a (tested): JEDEC-ID readback -- measured: FPGA has no flash SO read path (SO only connects to SAM3U, hardware blocked).
 *   M1b (this version): write path verification -- WREN + page program (FPGA writes -> SAM3U reads back to verify), confirming
 *     CS(L12)/SI(J13)/SCK(CCLK) actually reach the flash; this is the prerequisite for the fly-wire fix (SO->K12 etc.).
 * Board-level routing (traced line by line from NAE-CW305-Schematic.pdf page 3, 2026-08-18):
 *   flash SCK <- FPGA CCLK (via STARTUPE2 USRCCLKO; shares the net with SAM3U SCK through R38 33 ohm)
 *   flash SI  <- FPGA J13 (R42 33 ohm; confirmed by NewAE spiflash_feedthrough)
 *   flash CS  <- FPGA L12 (R34 4.7k pull-up; same as above)
 *   flash SO  -> SAM3U SPI net (PA13 MISO), FPGA has no read pin (measured)
 * MISO candidates (spi_miso[0..4]) = B4 / K12 / J14 / K15 / L13 (B4 is on the SI net, K12/J14/K15/L13
 * floating -- fly-wire fix targets).
 *
 * Registers (FLASH_BASE=0x1900_0000, window [31:6] 64B, same scope as TRNG B11B12-R3):
 *   0x00 VERSION  RO  = 0x00000002
 *   0x04 CTRL     WO  [0]=start (execute per OP, auto-clear)
 *   0x08 STATUS   RO  [0]=busy [1]=done
 *   0x0C RESP0    RO  spi_miso[0] (B4)  4-byte readback, byte0 first (OP=0)
 *   0x10 RESP1    RO  spi_miso[1] (K12)
 *   0x14 RESP2    RO  spi_miso[2] (J14)
 *   0x18 RESP3    RO  spi_miso[3] (K15)
 *   0x1C RESP4    RO  spi_miso[4] (L13)
 *   0x20 OP       RW  0=JEDEC probe (0x9F+4B read); 1=write byte (WREN+PP); 2=raw single-byte command
 *   0x24 ADDR     RW  write target address (OP=1, 24-bit)
 *   0x28 BYTE     RW  write data byte (OP=1; bits can only be cleared, target byte must be 0xFF or the same value) / command byte (OP=2)
 *
 * SPI timing: mode 0 (CPOL=0/CPHA=0), SCK period = SCK_DIV clk cycles (default 25 -> 2 MHz @50MHz).
 * ============================================================================================= */
module lms_flash_spi #(
    parameter [31:0] FLASH_BASE = 32'h1900_0000,
    parameter [4:0]  SCK_DIV    = 5'd25
) (
    input  wire        clk,
    input  wire        rst,
    /* MMIO slave port */
    input  wire        mem_valid,
    input  wire [31:0] mem_addr,
    input  wire [31:0] mem_wdata,
    input  wire [3:0]  mem_wstrb,
    output wire        mem_hit,
    output wire        mem_ready,
    output wire [31:0] mem_rdata,
    /* SPI to flash (top-level wiring) */
    output wire        spi_sck,     /* -> STARTUPE2 USRCCLKO */
    output wire        spi_sck_en,  /* 1=drive CCLK (USRCCLKTS=0); 0=tri-state */
    output wire        spi_cs_n,
    output wire        spi_mosi,
    input  wire [4:0]  spi_miso
);
    localparam [31:0] VERSION = 32'h00000002;
    localparam [7:0]  CMD_RDID = 8'h9F;
    localparam [7:0]  CMD_WREN = 8'h06;
    localparam [7:0]  CMD_PP   = 8'h02;
    localparam [4:0]  HALF = SCK_DIV[4:1];         /* half period = SCK_DIV/2 */

    localparam [2:0] S_IDLE   = 3'd0;
    localparam [2:0] S_CSLOW  = 3'd1;              /* CS low setup */
    localparam [2:0] S_BITS   = 3'd2;              /* bit transfer */
    localparam [2:0] S_CSHIGH = 3'd3;              /* CS high release */
    localparam [2:0] S_DONE   = 3'd4;

    wire address_hit = mem_valid && mem_addr[31:6] == FLASH_BASE[31:6];
    wire full_word_write = mem_wstrb == 4'b1111;
    wire [3:0] reg_addr = mem_addr[5:2];
    wire start_req = address_hit && full_word_write && reg_addr == 4'h1 && mem_wdata[0];

    assign mem_hit   = address_hit;
    assign mem_ready = address_hit;

    reg [2:0]  state;
    reg [6:0]  bit_idx;       /* 0 .. 8*(tx+rx)-1, max 5 bytes = 40 bits */
    reg [4:0]  half_cnt;      /* CSLOW setup count */
    reg [4:0]  clk_div;       /* count within half period */
    reg        sck_r;
    reg        cs_r;
    reg        mosi_r;
    reg        done_r;
    reg [31:0] rx0_r, rx1_r, rx2_r, rx3_r, rx4_r;

    /* Operation parameters */
    reg [1:0]  op_r;          /* 0=JEDEC; 1=write byte (WREN+PP); 2=raw single-byte command */
    reg [23:0] addr_r;
    reg [7:0]  byte_r;
    reg [3:0]  prog_step;     /* write operation sub-step: 0=WREN, 1=PP */

    /* Current transaction parameters (combinational, per op/step) */
    reg [39:0] tx_shift_r;    /* transmit shift register (MSB first, shifted left bit by bit) */
    reg [3:0]  tx_bytes;
    reg [3:0]  rx_bytes;
    wire [6:0] total_bits = ({3'b0, tx_bytes} << 3) + ({3'b0, rx_bytes} << 3);

    /* Load the current transaction (combinational, sampled into tx_shift_r when entering S_CSLOW) */
    reg [39:0] tx_shift_w;
    always @* begin
        if (op_r == 2'b00) begin
            tx_shift_w = {CMD_RDID, 32'b0};   /* 1-byte command + 4-byte read */
            tx_bytes = 4'd1;
            rx_bytes = 4'd4;
        end else if (op_r == 2'b10) begin
            tx_shift_w = {byte_r, 32'b0};     /* raw single-byte command (e.g. WREN 0x06) */
            tx_bytes = 4'd1;
            rx_bytes = 4'd0;
        end else if (prog_step == 4'd0) begin
            tx_shift_w = {CMD_WREN, 32'b0};
            tx_bytes = 4'd1;
            rx_bytes = 4'd0;
        end else begin
            tx_shift_w = {CMD_PP, addr_r, byte_r};
            tx_bytes = 4'd5;
            rx_bytes = 4'd0;
        end
    end

    wire [6:0] tx_bits_w = {3'b0, tx_bytes} << 3;
    wire mosi_bit_w = (state == S_BITS && bit_idx < tx_bits_w) ? tx_shift_r[39] : 1'b0;

    /* ---- SPI transaction FSM (mosi_r is driven solely by the separate block below) ---- */
    always @(posedge clk) begin
        if (rst) begin
            state     <= S_IDLE;
            bit_idx   <= 7'd0;
            half_cnt  <= 5'd0;
            clk_div   <= 5'd0;
            sck_r     <= 1'b0;
            cs_r      <= 1'b1;
            done_r    <= 1'b0;
            prog_step <= 4'd0;
            rx0_r     <= 32'b0;
            rx1_r     <= 32'b0;
            rx2_r     <= 32'b0;
            rx3_r     <= 32'b0;
            rx4_r     <= 32'b0;
        end else begin
            case (state)
                S_IDLE: begin
                    if (start_req) begin
                        cs_r     <= 1'b0;
                        bit_idx  <= 7'd0;
                        clk_div  <= 5'd0;
                        half_cnt <= 5'd0;
                        done_r   <= 1'b0;
                        prog_step <= 4'd0;         /* write operation always starts with WREN */
                        state <= S_CSLOW;
                    end
                end

                S_CSLOW: begin
                    if (clk_div == HALF - 5'd1) begin
                        clk_div <= 5'd0;
                        if (half_cnt == 5'd2) begin
                            half_cnt <= 5'd0;
                            state    <= S_BITS;
                        end else begin
                            half_cnt <= half_cnt + 5'd1;
                        end
                    end else begin
                        clk_div <= clk_div + 5'd1;
                    end
                end

                S_BITS: begin
                    if (!sck_r) begin
                        if (clk_div == HALF - 5'd1) begin
                            clk_div <= 5'd0;
                            sck_r   <= 1'b1;
                        end else begin
                            clk_div <= clk_div + 5'd1;
                        end
                    end else begin
                        if (clk_div == 5'd0 && bit_idx >= ({3'b0, tx_bytes} << 3)) begin
                            /* read phase: sample MISO candidates */
                            rx0_r <= {rx0_r[30:0], spi_miso[0]};
                            rx1_r <= {rx1_r[30:0], spi_miso[1]};
                            rx2_r <= {rx2_r[30:0], spi_miso[2]};
                            rx3_r <= {rx3_r[30:0], spi_miso[3]};
                            rx4_r <= {rx4_r[30:0], spi_miso[4]};
                        end
                        if (clk_div == HALF - 5'd1) begin
                            clk_div <= 5'd0;
                            sck_r   <= 1'b0;
                            if (bit_idx == total_bits - 7'd1) begin
                                state <= S_CSHIGH;
                            end else begin
                                bit_idx <= bit_idx + 7'd1;
                            end
                        end else begin
                            clk_div <= clk_div + 5'd1;
                        end
                    end
                end

                S_CSHIGH: begin
                    /* release CS immediately on entry (flash commits command/latches WEL on CS rising edge) */
                    if (clk_div == 5'd0) begin
                        cs_r <= 1'b1;
                    end
                    if (clk_div == 5'd3) begin
                        clk_div <= 5'd0;
                        if (op_r == 2'b01 && prog_step == 4'd0) begin
                            /* write operation: WREN done (CS high >=4 cycles >=80ns) -> pull CS low again to execute PP;
                             * note bit_idx must be reset (WREN transaction ends at bit_idx=7, otherwise PP
                             * starts at bit 7 and the command is truncated -> flash rejects the program). */
                            prog_step <= 4'd1;
                            bit_idx   <= 7'd0;
                            cs_r      <= 1'b0;
                            state     <= S_CSLOW;
                        end else begin
                            done_r <= 1'b1;
                            state  <= S_DONE;
                        end
                    end else begin
                        clk_div <= clk_div + 5'd1;
                    end
                end

                S_DONE: begin
                    if (start_req) begin
                        state <= S_IDLE;
                    end
                end
                default: state <= S_IDLE;
            endcase
        end
    end

    /* Transmit shift register: loads the current transaction at S_CSLOW->S_BITS; shifts left 1 bit at the start of each bit's low phase */
    always @(posedge clk) begin
        if (rst) begin
            tx_shift_r <= 40'b0;
        end else if (state == S_CSLOW && clk_div == HALF - 5'd1 && half_cnt == 5'd2) begin
            tx_shift_r <= tx_shift_w;
        end else if (state == S_BITS && !sck_r && clk_div == 5'd0) begin
            tx_shift_r <= {tx_shift_r[38:0], 1'b0};
        end
    end

    /* MOSI update (separate always block, sole driver) */
    always @(posedge clk) begin
        if (rst) begin
            mosi_r <= 1'b0;
        end else if (state == S_BITS && !sck_r && clk_div == 5'd0) begin
            mosi_r <= mosi_bit_w;
        end
    end

    /* Operation parameter write (OP/ADDR/BYTE) */
    always @(posedge clk) begin
        if (rst) begin
            op_r   <= 2'b00;
            addr_r <= 24'b0;
            byte_r <= 8'b0;
        end else if (address_hit && full_word_write) begin
            case (reg_addr)
                4'h8: op_r   <= mem_wdata[1:0];
                4'h9: addr_r <= mem_wdata[23:0];
                4'ha: byte_r <= mem_wdata[7:0];
                default: ;
            endcase
        end
    end

    assign spi_sck    = sck_r;
    assign spi_sck_en = (state != S_IDLE) && (state != S_DONE);
    assign spi_cs_n   = cs_r;
    assign spi_mosi   = mosi_r;

    /* ---- Read path ---- */
    reg [31:0] rdata_r;
    always @* begin
        case (reg_addr)
            4'h0: rdata_r = VERSION;
            4'h1: rdata_r = 32'b0;
            4'h2: rdata_r = {30'b0, done_r, (state != S_IDLE && state != S_DONE)};
            4'h3: rdata_r = rx0_r;
            4'h4: rdata_r = rx1_r;
            4'h5: rdata_r = rx2_r;
            4'h6: rdata_r = rx3_r;
            4'h7: rdata_r = rx4_r;
            4'h8: rdata_r = {30'b0, op_r};
            4'h9: rdata_r = {8'b0, addr_r};
            4'ha: rdata_r = {24'b0, byte_r};
            default: rdata_r = 32'b0;
        endcase
    end
    assign mem_rdata = address_hit ? rdata_r : 32'b0;

endmodule
`default_nettype wire
