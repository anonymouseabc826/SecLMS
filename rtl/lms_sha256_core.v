`default_nettype none

module lms_sha256_core (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire         init,
    input  wire         state_load,
    input  wire [255:0] state_in,
    input  wire [511:0] block,
    output reg          busy,
    output reg          done,
    output wire [255:0] digest
);
    localparam [255:0] SHA256_IV = {
        32'h5be0cd19, 32'h1f83d9ab, 32'h9b05688c, 32'h510e527f,
        32'ha54ff53a, 32'h3c6ef372, 32'hbb67ae85, 32'h6a09e667
    };

    reg [5:0] round_r;
    reg [255:0] state_r;
    reg [255:0] chain_r;
    reg [255:0] block_chain_r;
    reg [511:0] message_r;

    wire [255:0] round_state_w;
    wire [511:0] round_message_w;

    lms_sha256_round round_unit (
        .state_i(state_r),
        .message_i(message_r),
        .round_i(round_r),
        .state_o(round_state_w),
        .message_o(round_message_w)
    );

    function automatic [511:0] message_to_round_order;
        input [511:0] value;
        integer index;
        begin
            for (index = 0; index < 16; index = index + 1) begin
                message_to_round_order[index * 32 +: 32] =
                    value[511 - index * 32 -: 32];
            end
        end
    endfunction

    function automatic [255:0] add_state;
        input [255:0] left;
        input [255:0] right;
        integer index;
        begin
            for (index = 0; index < 8; index = index + 1) begin
                add_state[index * 32 +: 32] =
                    left[index * 32 +: 32] + right[index * 32 +: 32];
            end
        end
    endfunction

    function automatic [255:0] state_to_digest_order;
        input [255:0] value;
        integer index;
        begin
            for (index = 0; index < 8; index = index + 1) begin
                state_to_digest_order[255 - index * 32 -: 32] =
                    value[index * 32 +: 32];
            end
        end
    endfunction

    function automatic [255:0] digest_to_state_order;
        input [255:0] value;
        integer index;
        begin
            for (index = 0; index < 8; index = index + 1) begin
                digest_to_state_order[index * 32 +: 32] =
                    value[255 - index * 32 -: 32];
            end
        end
    endfunction

    assign digest = state_to_digest_order(chain_r);

    always @(posedge clk) begin
        done <= 1'b0;

        if (start && !busy) begin
            state_r <= init ? SHA256_IV :
                       (state_load ? digest_to_state_order(state_in) : chain_r);
            block_chain_r <= init ? SHA256_IV :
                             (state_load ? digest_to_state_order(state_in) : chain_r);
            message_r <= message_to_round_order(block);
            round_r <= 6'd0;
            busy <= 1'b1;
        end else if (busy) begin
            if (round_r == 6'd63) begin
                chain_r <= add_state(block_chain_r, round_state_w);
                busy <= 1'b0;
                done <= 1'b1;
            end else begin
                state_r <= round_state_w;
                message_r <= round_message_w;
                round_r <= round_r + 1'b1;
            end
        end

        if (rst) begin
            round_r <= 6'd0;
            state_r <= SHA256_IV;
            chain_r <= SHA256_IV;
            block_chain_r <= SHA256_IV;
            message_r <= 512'b0;
            busy <= 1'b0;
            done <= 1'b0;
        end
    end

endmodule

`default_nettype wire
