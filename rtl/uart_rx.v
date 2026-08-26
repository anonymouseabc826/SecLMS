//  uart_rx.v
//  Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.
//  Receive front-end rewritten (C1) to a 2-flop synchronizer + 16x oversampling
//  receiver for robustness on real FTDI links; the depth-2 output FIFO and the
//  data/rdy/ack/rts MMIO interface are unchanged.

//  === UART Receive (16x oversampling, 8-N-1) ===
//
//  The original 1x sampler (start-detect + 1.5*BITCLKS then 1*BITCLKS steps)
//  sampled rxd directly with no synchronizer and only one sample per bit. On a
//  real FTDI USB-UART link the host can burst bytes back-to-back, and the
//  unsynchronised, single-sample-per-bit front-end occasionally mis-sampled a
//  data bit (and in long sessions wedged the firmware waiting for a byte that
//  was silently lost). This rewrite:
//    * passes rxd through a 2-flop synchronizer (metastability hardening),
//    * oversamples at 16x the bit rate (BITCLKS/16 system clocks per tick),
//    * validates the start bit at its centre (tick 7 of 0..15),
//    * samples each data bit and the stop bit at its centre (tick 7),
//  which is the standard robust UART receiver structure.

`include "lms_soc_config.vh"

module uart_rx #(
    parameter   BITCLKS = 434,              //  system clocks per bit (50MHz/115200)
    parameter   TMR_LEN = 14                //  unused, kept for interface compat
) (
    input wire          clk,                //  system clock
    input wire          rst,                //  reset = 1
    input wire          ack,                //  pulse high to read next byte
    output reg  [7:0]   data,               //  oldest unread byte (FIFO output)
    output reg          rdy,                //  1: data byte ready in data
    //  external interface
    output wire         rts,                //  RTS out (1=ready)
    input wire          rxd                 //  RX signal in (async)
);
    assign      rts = !rdy;

    //  oversampling tick period in system clocks (BITCLKS/16, >=1)
    localparam integer OVS = (BITCLKS >= 16) ? (BITCLKS / 16) : 1;
    localparam [13:0]  OVSC = OVS[13:0] - 14'd1;  //  tick period-1, width-matched

    //  ---- 2-flop synchronizer (metastability hardening on async rxd) --------
    (* ASYNC_REG = "TRUE" *) reg rxd_meta;   //  REVIEW B11B12-R6: ASYNC_REG attribute on the async-input synchronizer
    (* ASYNC_REG = "TRUE" *) reg rxd_sync;   //  (placement puts the two flops side by side, shortening MTBF)
    always @(posedge clk) begin
        if (rst) begin
            rxd_meta <= 1'b1;
            rxd_sync <= 1'b1;
        end else begin
            rxd_meta <= rxd;
            rxd_sync <= rxd_meta;
        end
    end

    //  ---- receiver state machine -------------------------------------------
    localparam [1:0] S_IDLE  = 2'd0,        //  waiting for start bit (line high)
                     S_START = 2'd1,        //  start bit in progress
                     S_DATA  = 2'd2,        //  8 data bits
                     S_STOP  = 2'd3;        //  stop bit

    reg [1:0]   state;
    reg [13:0]  clk_cnt;                    //  system-clock countdown to next tick
    reg [3:0]   tick;                       //  oversample tick within a bit (0..15)
    reg [2:0]   bit_idx;                    //  data bit index (0..7)
    reg [7:0]   rdata;                      //  shift-in data buffer

    //  ---- depth-8 output FIFO (C1 fix, deepened for t8) ---------------------
    //  The C1 depth-2 FIFO absorbed one byte of host burst while firmware is
    //  handling the previous byte; long multi-parameter sessions still dropped
    //  bytes on firmware-layout/timing shifts (0x71 lmots-sign timeouts after
    //  LMS runs, firmware RV32 no-icache sensitive). Deepened to 8 with a ring
    //  buffer + occupancy counter, keeping the same {new_byte,ack} single-point
    //  assignment discipline (no dual-write, per C1 lesson).
    reg [7:0]   rx_fifo [0:7];
    reg [2:0]   rd_ptr;
    reg [2:0]   wr_ptr;
    reg [3:0]   fifo_count;                 //  0..8 occupancy
    reg         new_byte;                   //  a stop bit completed this clock
    reg [7:0]   new_data;                   //  the byte that just completed

    //  ---- FIFO head (combinational): data = oldest, rdy = non-empty ----------
    always @* begin
        data = (fifo_count == 4'd0) ? 8'b0 : rx_fifo[rd_ptr];
        rdy  = (fifo_count != 4'd0);
    end

    always @(posedge clk) begin
        if (rst) begin
            state    <= S_IDLE;
            clk_cnt  <= 0;
            tick     <= 0;
            bit_idx  <= 0;
            rdata    <= 0;
            new_byte <= 1'b0;
            new_data <= 0;
        end else begin
            new_byte <= 1'b0;               //  default: no new byte this clock

            if (clk_cnt != 0) begin
                clk_cnt <= clk_cnt - 1'b1;
            end else begin
                case (state)
                    //  idle: watch for falling edge (start bit), then go to its
                    //  centre (tick 7) to confirm it is really low.
                    S_IDLE: begin
                        tick <= 0;
                        if (!rxd_sync) begin
                            state   <= S_START;
                            tick    <= 0;
                            clk_cnt <= OVSC;
                        end
                    end

                    //  start bit: confirm at centre (tick 7) but KEEP COUNTING to
                    //  the bit end (tick 15) so the first data bit is sampled at its
                    //  own centre (16 ticks after the start-bit centre). Entering
                    //  S_DATA at tick 7 would sample data0 half a bit early.
                    S_START: begin
                        if (tick == 4'd7) begin
                            if (rxd_sync) begin
                                state <= S_IDLE;   //  false start (glitch), resync
                                tick  <= 0;
                            end else begin
                                tick    <= tick + 1'b1;
                                clk_cnt <= OVSC;
                            end
                        end else if (tick == 4'd15) begin
                            state   <= S_DATA;     //  start bit done, real start
                            bit_idx <= 0;
                            tick    <= 0;
                            clk_cnt <= OVSC;
                        end else begin
                            tick    <= tick + 1'b1;
                            clk_cnt <= OVSC;
                        end
                    end

                    //  data bits: sample at centre (tick 7), then next bit.
                    S_DATA: begin
                        if (tick == 4'd15) begin
                            tick <= 0;
                            if (bit_idx == 3'd7) begin
                                state   <= S_STOP;
                                clk_cnt <= OVSC;
                            end else begin
                                bit_idx <= bit_idx + 1'b1;
                                clk_cnt <= OVSC;
                            end
                        end else begin
                            if (tick == 4'd7)
                                rdata[bit_idx] <= rxd_sync;
                            tick    <= tick + 1'b1;
                            clk_cnt <= OVSC;
                        end
                    end

                    //  stop bit: at centre, if high deliver the byte.
                    S_STOP: begin
                        if (tick == 4'd7) begin
                            if (rxd_sync) begin
                                new_data <= rdata;
                                new_byte <= 1'b1;
                            end
                            state <= S_IDLE;       //  framing error also resyncs
                            tick  <= 0;
                        end else begin
                            tick    <= tick + 1'b1;
                            clk_cnt <= OVSC;
                        end
                    end

                    default: state <= S_IDLE;
                endcase
            end
        end
    end

    //  ---- FIFO push/pop ------------------------------------------------------
    //  push on new_byte (drop if full); pop on ack. Both may coincide; each
    //  state assigns every touched signal exactly once (single-point, C1 lesson).
    always @(posedge clk) begin
        if (rst) begin
            rd_ptr     <= 3'd0;
            wr_ptr     <= 3'd0;
            fifo_count <= 4'd0;
        end else begin
            case ({new_byte, ack})
                2'b10: begin                //  push only
                    if (fifo_count != 4'd8) begin
                        rx_fifo[wr_ptr] <= new_data;
                        wr_ptr          <= wr_ptr + 3'd1;
                        fifo_count      <= fifo_count + 4'd1;
                    end
                    //  full + push: drop new byte (overrun past depth-8)
                end
                2'b01: begin                //  pop only
                    if (fifo_count != 4'd0) begin
                        rd_ptr     <= rd_ptr + 3'd1;
                        fifo_count <= fifo_count - 4'd1;
                    end
                end
                2'b11: begin                //  push + pop
                    if (fifo_count == 4'd0) begin
                        rx_fifo[wr_ptr] <= new_data;   //  pop no-op, just push
                        wr_ptr          <= wr_ptr + 3'd1;
                        fifo_count      <= 4'd1;
                    end else if (fifo_count == 4'd8) begin
                        rd_ptr     <= rd_ptr + 3'd1;   //  full: drop new, pop
                        fifo_count <= 4'd7;
                    end else begin
                        rx_fifo[wr_ptr] <= new_data;   //  push + pop (count const)
                        wr_ptr          <= wr_ptr + 3'd1;
                        rd_ptr          <= rd_ptr + 3'd1;
                    end
                end
                default: ;                  //  2'b00: hold
            endcase
        end
    end

endmodule
