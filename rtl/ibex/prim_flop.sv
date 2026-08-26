// Minimal prim_flop stub: simple FF with reset.

module prim_flop #(
  parameter int unsigned Width      = 1,
  parameter logic [Width-1:0] ResetValue = '0
) (
  input  logic                 clk_i,
  input  logic                 rst_ni,
  input  logic [Width-1:0]     d_i,
  output logic [Width-1:0]     q_o
);
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      q_o <= ResetValue;
    end else begin
      q_o <= d_i;
    end
  end
endmodule
