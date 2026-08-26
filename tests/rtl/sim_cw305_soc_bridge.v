`default_nettype none
`include "lms_soc_config.vh"

/* ============================================================================
 * sim_cw305_soc_bridge.v — full-chain simulation wrapper (Verilator test only, not for synthesis)
 * ----------------------------------------------------------------------------
 * lms_soc (real firmware hex) + lms_cw305_usb_uart bridge + USB register interface:
 * the host exchanges bytes with the SoC firmware through the bridge's usb_* interface
 * (identical to the on-board path: no BUFG/divide-by-2 clock, clk50 supplied directly by the test).
 * ========================================================================== */

module sim_cw305_soc_bridge #(
    parameter FIRMWARE_HEX = "",
    parameter INSECURE_TEST_MODE = 0,
    parameter TRNG_SIM_MODE = 0,
    parameter UART_BITCLKS = 434,
    parameter ENABLE_SHA256   = `LMS_SOC_ENABLE_SHA256,
    parameter ENABLE_SHAKE256 = `LMS_SOC_ENABLE_SHAKE256,
    parameter HAS_SECURITY    = `LMS_SOC_HAS_SECURITY,
    parameter SCA_TEST        = 1
) (
    input  wire       clk50,        /* SoC and bridge shared clock (50 MHz) */
    input  wire       rst,
    /* USB interface (FTDI channel B parallel bus) */
    input  wire       usb_clk,
    input  wire [7:0] usb_din,
    output wire [7:0] usb_dout,
    output wire       usb_isout,
    input  wire [20:0] usb_addr,
    input  wire       usb_rdn,
    input  wire       usb_wrn,
    input  wire       usb_alen,
    input  wire       usb_cen,
    /* Observation */
    output wire       soc_trap,
    output wire [7:0] gpio_out_o,
    output wire [2:0] led,
    output wire       sca_trigger_o    /* SCA trigger (wide pulse on engine busy completion edge, v5) */
);
    wire uart_to_soc;   /* bridge → SoC */
    wire uart_from_soc; /* SoC → bridge */
    wire uart_cts_soc;  /* bridge → SoC RTS flow control */
    wire [7:0] gpio_out;

    lms_soc #(
        .FIRMWARE_HEX(FIRMWARE_HEX),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .TRNG_SIM_MODE(TRNG_SIM_MODE),
        .ENABLE_SHA256(ENABLE_SHA256),
        .ENABLE_SHAKE256(ENABLE_SHAKE256),
        .HAS_SECURITY(HAS_SECURITY),
        .SCA_TEST(SCA_TEST)
    ) soc (
        .clk(clk50),
        .rst(rst),
        .uart_rxd(uart_to_soc),
        .uart_txd(uart_from_soc),
        .uart_cts_i(uart_cts_soc),
        .gpio_in(8'h00),
        .gpio_out(gpio_out),
        .trap(soc_trap),
        .sca_trigger(sca_trigger_o)
    );

    lms_cw305_usb_uart #(
        .UART_BITCLKS(UART_BITCLKS)
    ) bridge (
        .usb_clk(usb_clk),
        .rst(rst),
        .usb_din(usb_din),
        .usb_dout(usb_dout),
        .usb_isout(usb_isout),
        .usb_addr(usb_addr),
        .usb_rdn(usb_rdn),
        .usb_wrn(usb_wrn),
        .usb_alen(usb_alen),
        .usb_cen(usb_cen),
        .iut_clk(clk50),
        .soc_uart_txd(uart_from_soc),
        .soc_uart_rxd(uart_to_soc),
        .soc_uart_cts(uart_cts_soc),
        .trap_in(soc_trap),
        .o_user_led(led[2])
    );

    assign led[0] = gpio_out[0];
    assign led[1] = soc_trap;
    assign gpio_out_o = gpio_out;

endmodule

`default_nettype wire
