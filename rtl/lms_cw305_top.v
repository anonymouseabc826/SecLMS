`default_nettype none

/* ============================================================================
 * lms_cw305_top.v — CW305 (Artix-7 FTG256) board-level top
 * ----------------------------------------------------------------------------
 * Differences from the DaVinci version (DaVinci version: lms_davinci_pro_top.v; they do not override each other):
 *   - Device: xc7a100tftg256-2 (DaVinci: xc7a100tfgg484-2)
 *   - Clock: onboard 100 MHz crystal (N13/pll_clk1) → top-level divide-by-2 → 50 MHz SoC clock
 *     (SoC/firmware/Verilator all keep the 50 MHz convention, UART 115200 unchanged)
 *   - Reset: R1 button (pressed=low=reset, same as DaVinci sys_rst_n active-low)
 *   - LEDs: 3 (T2/T3/T4; DaVinci: 4)
 *   - UART: no longer wired directly to pins — communicates with the host via the lms_cw305_usb_uart bridge (USB register mailbox)
 *     (CW305 has no COM port; host uses chipwhisperer API fpga_read/fpga_write)
 *   - Added USB parallel bus port (FTDI channel B, FT245 sync FIFO)
 * Pin constraints: see flow/cw305.xdc.
 * ========================================================================== */

module lms_cw305_top #(
    parameter FIRMWARE_HEX = "",
    parameter INSECURE_TEST_MODE = 0,
    parameter TRNG_SIM_MODE = 0,
    parameter SCA_TEST     = 0,       /* 1=enable SCA trigger output (T14, for TVLA, default off) */
    parameter RANDOM_DELAY = 0,       /* TVLA random delay (in-engine LFSR): default 0=off;
                                        * 2026-08-19 measured ineffective for TVLA (phase-misalignment artifact),
                                        * independent of SCA_TEST, set to 1 separately when needed */
    parameter DERIVE_SHUFFLE = 0,     /* DERIVE phase shuffling: batch task block parameters shift by a random start per trace
                                        * (tier 1, 2026-08-21; enabled in TVLA builds) */
    parameter ENABLE_SHA256   = 0,    /* hash platform selection (0.1.280 fix: passed via top-level -generic,
                                        * bypassing the define-override problem in lms_soc_config.vh —
                                        * the verilog_define attribute was overridden by in-file `define, which once caused
                                        * the SHA-256 platform bit to actually synthesize SHAKE256) */
    parameter ENABLE_SHAKE256 = 1,
    parameter HAS_SECURITY    = 1,
    parameter ALLOW_XQ_DERIVE = 0     /* TVLA isolated single x_q[i] release (see plan; deploy defaults to 0 to keep M3) */
) (
    input  wire       sys_clk,      /* CW305 N13: onboard 100 MHz crystal (pll_clk1) */
    input  wire       sys_rst_n,    /* CW305 R1: button, pressed=low=reset */
    /* USB parallel bus (FTDI channel B) */
    input  wire       usb_clk,      /* CW305 F5: FTDI CLKOUT (FT245 sync FIFO) */
    inout  wire [7:0] usb_data,     /* CW305 A7,B6,D3,E3,F3,B5,K1,K2 */
    input  wire [20:0] usb_addr,    /* CW305 F4,G5,J1,H1,H2,G1,G2,F2,E1,E2,D1,C1,K3,L2,J3,B2,C7,C6,D6,C4,D5 */
    input  wire       usb_rdn,      /* CW305 A4: !RD */
    input  wire       usb_wrn,      /* CW305 C2: !WR */
    input  wire       usb_cen,      /* CW305 A3: !CE */
    input  wire       usb_trigger,  /* CW305 A5: trigger request (mapped to gpio_in[0] for observation) */
    output wire [2:0] led,          /* CW305 T2/T3/T4: 3 user LEDs */
    output wire       sca_trigger,  /* CW305 T14 (20-pin tio_trigger): SCA trigger output (SCA_TEST=1) */
    output wire       tio_clkout,   /* CW305 M16 (20-pin CLKOUT): sync sampling clock output (SCA_TEST=1,
                                       copied from Sloth cw305_top tio_clkout; connect Husky HS1 → clkgen_src=extclk
                                       for 1 samp/cycle phase locking, used for the full TVLA signature window) */
    /* SPI flash (onboard SPI NOR, M1 access verification; SCK routed through STARTUPE2 to the CCLK pad, no external pin) */
    output wire       flash_mosi,   /* CW305 J13: flash SI */
    output wire       flash_cs_n,   /* CW305 L12: flash CS */
    input  wire       flash_miso_b4,  /* CW305 B4 (SAM_MOSI net, candidate 0) */
    input  wire       flash_miso_k12, /* CW305 K12 (D00, candidate 1) */
    input  wire       flash_miso_j14, /* CW305 J14 (D02, candidate 2) */
    input  wire       flash_miso_k15, /* CW305 K15 (D03, candidate 3) */
    input  wire       flash_miso_l13  /* CW305 L13 (FCS_B, candidate 4) */
);

    /* ---- 100 MHz input clock buffer ---- */
    wire sys_clk_buf;
    BUFG sys_clk_bufg (.I(sys_clk), .O(sys_clk_buf));

    /* ---- Divide-by-2 → 50 MHz (async reset: clears and resets the SoC when the button is pressed) ---- */
    reg clk50_r;
    always @(posedge sys_clk_buf or negedge sys_rst_n) begin
        if (!sys_rst_n)
            clk50_r <= 1'b0;
        else
            clk50_r <= ~clk50_r;
    end
    wire clk50;
    BUFG clk50_bufg (.I(clk50_r), .O(clk50));

    wire rst = ~sys_rst_n;
    wire [7:0] gpio_out;
    wire trap;

    /* ---- SPI flash peripheral wiring (M1): SCK via STARTUPE2 → CCLK pad → flash SCK ---- */
    wire spi_sck, spi_sck_en, spi_cs_n, spi_mosi;
    wire [4:0] spi_miso;
    assign spi_miso = {flash_miso_l13, flash_miso_k15, flash_miso_j14, flash_miso_k12, flash_miso_b4};
    assign flash_mosi = spi_mosi;
    assign flash_cs_n = spi_cs_n;

    STARTUPE2 #(
        .PROG_USR("FALSE"),
        .SIM_CCLK_FREQ(0.0)
    ) startupe2_flash (
        /* USRCCLKO internally drives the CCLK pad directly (7-series STARTUPE2 has no separate O output port) */
        .USRCCLKO(spi_sck),         /* user clock -> flash SCK */
        .USRCCLKTS(~spi_sck_en),    /* 0=drive CCLK; 1=tristate (released when idle, to avoid disturbing SAM3U SCK) */
        .USRDONEO(1'b0),            /* DONE pin returned to configuration logic */
        .USRDONETS(1'b1)
    );

    /* ---- SoC UART communicates with the USB mailbox via the bridge ---- */
    wire uart_txd_soc;   /* SoC → bridge (device→host) */
    wire uart_rxd_soc;   /* bridge → SoC (host→device) */
    wire uart_cts_soc;   /* bridge → SoC RTS flow control (pulls low when TX FIFO full to pause uart_tx) */

    lms_soc #(
        .FIRMWARE_HEX(FIRMWARE_HEX),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .TRNG_SIM_MODE(TRNG_SIM_MODE),
        .SCA_TEST(SCA_TEST),
        .RANDOM_DELAY(RANDOM_DELAY),
        .DERIVE_SHUFFLE(DERIVE_SHUFFLE),
        .ENABLE_SHA256(ENABLE_SHA256),
        .ENABLE_SHAKE256(ENABLE_SHAKE256),
        .HAS_SECURITY(HAS_SECURITY),
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE)
    ) soc (
        .clk(clk50),
        .rst(rst),
        .uart_rxd(uart_rxd_soc),
        .uart_txd(uart_txd_soc),
        .uart_cts_i(uart_cts_soc),
        .gpio_in({7'b0, usb_trigger}),
        .gpio_out(gpio_out),
        .trap(trap),
        .sca_trigger(sca_trigger),
        .spi_sck(spi_sck),
        .spi_sck_en(spi_sck_en),
        .spi_cs_n(spi_cs_n),
        .spi_mosi(spi_mosi),
        .spi_miso(spi_miso)
    );

    /* ---- USB↔UART bridge ---- */
    wire [7:0] usb_dout;
    wire       usb_isout;
    wire       user_led;
    assign usb_data = usb_isout ? usb_dout : 8'hZZ;

    lms_cw305_usb_uart bridge (
        .usb_clk(usb_clk),
        .rst(rst),
        .usb_din(usb_data),
        .usb_dout(usb_dout),
        .usb_isout(usb_isout),
        .usb_addr(usb_addr),
        .usb_rdn(usb_rdn),
        .usb_wrn(usb_wrn),
        .usb_alen(1'b0),
        .usb_cen(usb_cen),
        .iut_clk(clk50),
        .soc_uart_txd(uart_txd_soc),
        .soc_uart_rxd(uart_rxd_soc),
        .soc_uart_cts(uart_cts_soc),
        .trap_in(trap),
        .o_user_led(user_led)
    );

    assign led[0] = gpio_out[0];
    assign led[1] = trap;
    assign led[2] = user_led;

    /* ---- Sync sampling clock output (20-pin CLKOUT → Husky HS1)----
     * Copied from Sloth cw305_clocks' ODDR scheme: clk50 (the SoC's actual clock) is output
     * to tio_clkout (M16) via ODDR. Output only when SCA_TEST=1 (deploy/normal builds are always 0,
     * same compile-time-disable convention as the SCA trigger); Husky clkgen_src="extclk" + adc_mul=1
     * → 1 sample/clk50-cycle sync sampling (same as SLotH §6.4). */
    wire tio_clkout_en = (SCA_TEST == 1);
    ODDR #(
        .DDR_CLK_EDGE("SAME_EDGE"),
        .INIT(1'b0),
        .SRTYPE("SYNC")
    ) clkout_oddr (
        .Q(tio_clkout),
        .C(clk50),
        .CE(tio_clkout_en),
        .D1(1'b1),
        .D2(1'b0),
        .R(1'b0),
        .S(1'b0)
    );

endmodule

`default_nettype wire
