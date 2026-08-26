`default_nettype none

// SHA-256 block generator (unified refactor step 3, single-chain subset, purely combinational).
// Input registers are stored MMIO little-endian; the output SHA-256 block has byte0 at [511:504].

module lms_sha256_blockgen (
    input  wire [1:0]   task_type,       // 0=hash_once 1=chain 2=derive 3=randomizer
    input  wire [1023:0] input_words_flat,
    input  wire [127:0] identifier_flat,
    input  wire [31:0]  arg_q,
    input  wire [15:0]  arg_i,
    input  wire [7:0]   chain_j,
    input  wire [255:0] chain_value,
    input  wire         derive_phase,
    input  wire [7:0]   input_length,
    input  wire [1:0]   block_index,
    input  wire [255:0] seed_flat,
    output reg  [511:0] block,
    output reg          core_init,
    input  wire [255:0] core_digest,
    output wire [255:0] digest_bigendian
);
    localparam [1:0] TASK_CHAIN      = 2'd1;
    localparam [1:0] TASK_DERIVE     = 2'd2;
    localparam [1:0] TASK_RANDOMIZER = 2'd3;

    wire [255:0] chain_source_w = derive_phase ? seed_flat : chain_value;
    /* digest_bigendian is only a pass-through rename (REVIEW B08-R8): the byte-order
     * conversion is actually done in state_to_digest_order in lms_sha256_core.v; none here. */
    assign digest_bigendian = core_digest;

    integer byte_index;
    integer global_index;
    integer length_byte_index;
    reg [63:0] bit_length;
    reg [7:0] selected_byte;

    always @* begin
        block = 512'b0;
        core_init = (block_index == 0);
        bit_length = {56'b0, input_length} << 3;
        global_index = 0;
        length_byte_index = 0;
        selected_byte = 8'b0;

        for (byte_index = 0; byte_index < 64; byte_index = byte_index + 1) begin
            if (task_type == TASK_CHAIN || task_type == TASK_DERIVE) begin
                if (byte_index < 16) begin
                    selected_byte = identifier_flat[(byte_index / 4) * 32 +
                                                    (byte_index % 4) * 8 +: 8];
                end else if (byte_index < 20) begin
                    selected_byte = arg_q[(19 - byte_index) * 8 +: 8];
                end else if (byte_index < 22) begin
                    selected_byte = arg_i[(21 - byte_index) * 8 +: 8];
                end else if (byte_index == 22) begin
                    selected_byte = task_type == TASK_DERIVE && derive_phase
                        ? 8'hff : chain_j;
                end else if (byte_index < 55) begin
                    selected_byte = chain_source_w[255 - (byte_index - 23) * 8 -: 8];
                end else if (byte_index == 55) begin
                    selected_byte = 8'h80;
                end else if (byte_index == 62) begin
                    selected_byte = 8'h01;
                end else if (byte_index == 63) begin
                    selected_byte = 8'hb8;
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (task_type == TASK_RANDOMIZER) begin
                if (byte_index < 16) begin
                    selected_byte = identifier_flat[(byte_index / 4) * 32 +
                                                    (byte_index % 4) * 8 +: 8];
                end else if (byte_index < 20) begin
                    selected_byte = arg_q[(19 - byte_index) * 8 +: 8];
                end else if (byte_index == 20 || byte_index == 21) begin
                    selected_byte = 8'h85;
                end else if (byte_index < 54) begin
                    selected_byte = seed_flat[255 - (byte_index - 22) * 8 -: 8];
                end else if (byte_index == 54) begin
                    selected_byte = 8'h80;
                end else if (byte_index == 62) begin
                    selected_byte = 8'h01;
                end else if (byte_index == 63) begin
                    selected_byte = 8'hb0;
                end else begin
                    selected_byte = 8'h00;
                end
            end else begin
                global_index = block_index * 64 + byte_index;
                if (global_index < input_length) begin
                    selected_byte = input_words_flat[(global_index / 4) * 32 +
                                                     (global_index % 4) * 8 +: 8];
                end else if (global_index == {24'b0, input_length}) begin
                    selected_byte = 8'h80;
                end else if (global_index >= ((input_length <= 55) ? 64 :
                                               (input_length <= 119) ? 128 : 192) - 8) begin
                    length_byte_index = global_index -
                        (((input_length <= 55) ? 64 :
                          (input_length <= 119) ? 128 : 192) - 8);
                    selected_byte = bit_length[(7 - length_byte_index) * 8 +: 8];
                end else begin
                    selected_byte = 8'h00;
                end
            end
            block[511 - byte_index * 8 -: 8] = selected_byte;
        end
    end
endmodule

`default_nettype wire
