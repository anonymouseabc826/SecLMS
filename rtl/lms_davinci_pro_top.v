`default_nettype none

module lms_davinci_pro_top #(
    parameter FIRMWARE_HEX = "",
    parameter INSECURE_TEST_MODE = 0,
    parameter TRNG_SIM_MODE = 0
) (
    input  wire       sys_clk,
    input  wire       sys_rst_n,
    input  wire       uart_rxd,
    output wire       uart_txd,
    output wire [3:0] led
);
    wire rst = ~sys_rst_n;
    wire [7:0] gpio_out;
    wire trap;

    lms_soc #(
        .FIRMWARE_HEX(FIRMWARE_HEX),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .TRNG_SIM_MODE(TRNG_SIM_MODE)
    ) soc (
        .clk(sys_clk),
        .rst(rst),
        .uart_rxd(uart_rxd),
        .uart_txd(uart_txd),
        .uart_cts_i(1'b1),   /* DaVinci has no USB bridge, no flow control (original implementation) */
        .gpio_in(8'h00),
        .gpio_out(gpio_out),
        .trap(trap)
    );

    assign led[0] = gpio_out[0];
    assign led[1] = trap;
    assign led[2] = gpio_out[1];
    assign led[3] = gpio_out[2];

endmodule

`default_nettype wire
