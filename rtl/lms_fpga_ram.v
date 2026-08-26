// Adapted from SLotH fpga_ram.v by Markku-Juhani O. Saarinen.
// The source project is distributed under the BSD 3-Clause License.

`default_nettype none

module lms_fpga_ram #(
    parameter XADR = 15,
    parameter XSIZ = 1 << XADR,
    parameter FIRMWARE_HEX = ""
) (
    input  wire            clk,
    input  wire [3:0]      wen0,
    input  wire [XADR-1:0] addr0,
    input  wire [31:0]     wdata0,
    output reg  [31:0]     rdata0,
    input  wire [XADR-1:0] addr1,
    output reg  [31:0]     rdata1
);
    reg [31:0] mem [0:XSIZ-1];

    initial begin
        if (FIRMWARE_HEX != "") begin
            $readmemh(FIRMWARE_HEX, mem);
        end
    end

    always @(posedge clk) begin
        rdata0 <= mem[addr0];
        if (wen0[0]) mem[addr0][7:0] <= wdata0[7:0];
        if (wen0[1]) mem[addr0][15:8] <= wdata0[15:8];
        if (wen0[2]) mem[addr0][23:16] <= wdata0[23:16];
        if (wen0[3]) mem[addr0][31:24] <= wdata0[31:24];
    end

    always @(posedge clk) begin
        rdata1 <= mem[addr1];
    end

endmodule

`default_nettype wire
