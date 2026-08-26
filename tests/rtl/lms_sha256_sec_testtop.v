`default_nettype none
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */

/* SEC unit-test test top (v4 step 5d): production lms_sha256_sec carries no SHA core;
 * the unit test temporarily attaches an lms_sha256_core through this top and verifies the
 * borrowed-core interface (core_start/core_init/... → core_busy/core_done/core_digest)
 * function and cycle count unchanged. */
module lms_sha256_sec_testtop #(
    parameter INSECURE_TEST_MODE = 0
) (
    input  wire        clk,
    input  wire        rst,
    /* ---- Bus: SEC own registers ---- */
    input  wire        bus_valid,
    input  wire        bus_write,
    input  wire [9:0]  bus_addr,
    input  wire [31:0] bus_wdata,
    output reg  [31:0] bus_rdata,
    /* ---- Command start ---- */
    input  wire        reg_write_ok,
    input  wire        seed_latch_en,
    input  wire        kwrap_latch_en,
    input  wire        kstate_latch_en,
    input  wire        mc_step_en,
    input  wire        mc_load_en,
    input  wire [31:0] mc_load_value,
    input  wire        wrap_start,
    input  wire        wrap_is_unwrap,
    input  wire        hmac_start,
    input  wire [7:0]  input_length,
    input  wire [1023:0] input_words_flat,
    /* ---- Completion/events/results ---- */
    output wire        busy,
    output wire        done,
    output wire        error_valid,
    output wire [31:0] error_code,
    output wire [31:0] cycles,
    output wire [255:0] result_data,
    output wire [7:0]   result_wmask,
    output wire         result_valid,
    output wire [31:0] mc_next_value,
    output wire [255:0] seed_data,
    output wire         seed_valid,
    output wire         k_wrap_valid,
    output wire         k_state_valid
);
    /* Borrowed-core interface: SEC requests → test core; core responses → SEC */
    wire        core_start;
    wire        core_init;
    wire        core_state_load;
    wire [255:0] core_state_in;
    wire        core_busy;
    wire        core_done;
    wire [255:0] core_digest;
    /* SEC block construction parameters */
    wire         sec_is_hmac;
    wire [1:0]   sec_wrap_phase;
    wire [1:0]   sec_block_index;
    wire [1:0]   sec_block_count;
    wire [255:0] sec_k_wrap;
    wire [255:0] sec_k_state;
    wire [255:0] sec_wrap_ct;
    wire [255:0] sec_wrap_tag;
    /* stc (STATE_COMMIT) ports: the SHA-256 unit test does not test fused commands
     * (enabled only on the SHAKE256 main line) → inputs tied to 0, outputs left floating
     * (to avoid PINMISSING warnings). */
    wire unused_stc_active;
    wire [31:0] unused_stc_tx;

    lms_sha256_sec #(
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE)
    ) u_sec (
        .clk(clk),
        .rst(rst),
        .bus_valid(bus_valid),
        .bus_write(bus_write),
        .bus_addr(bus_addr),
        .bus_wdata(bus_wdata),
        .bus_rdata(bus_rdata),
        .reg_write_ok(reg_write_ok),
        .seed_latch_en(seed_latch_en),
        .kwrap_latch_en(kwrap_latch_en),
        .kstate_latch_en(kstate_latch_en),
        .mc_step_en(mc_step_en),
        .mc_load_en(mc_load_en),
        .mc_load_value(mc_load_value),
        .wrap_start(wrap_start),
        .wrap_is_unwrap(wrap_is_unwrap),
        .hmac_start(hmac_start),
        .input_length(input_length),
        .stc_start(1'b0),
        .stc_state(16'b0),
        .stc_ctr(32'b0),
        .stc_aad(8'b0),
        .busy(busy),
        .done(done),
        .error_valid(error_valid),
        .error_code(error_code),
        .cycles(cycles),
        .result_data(result_data),
        .result_wmask(result_wmask),
        .result_valid(result_valid),
        .mc_next_value(mc_next_value),
        .seed_data(seed_data),
        .seed_valid(seed_valid),
        .k_wrap_valid(k_wrap_valid),
        .k_state_valid(k_state_valid),
        .core_start(core_start),
        .core_init(core_init),
        .core_state_load(core_state_load),
        .core_state_in(core_state_in),
        .sec_is_hmac(sec_is_hmac),
        .wrap_phase(sec_wrap_phase),
        .block_index(sec_block_index),
        .block_count(sec_block_count),
        .stc_active(unused_stc_active),
        .stc_tx(unused_stc_tx),
        .k_wrap(sec_k_wrap),
        .k_state(sec_k_state),
        .wrap_ct(sec_wrap_ct),
        .wrap_tag(sec_wrap_tag),
        .core_busy(core_busy),
        .core_done(core_done),
        .core_digest(core_digest)
    );

    /* Test-side block construction (aligned with the SEC branch of the OPS unified block construction, byte-for-byte identical). */
    reg [511:0] test_block_w;
    reg [63:0]  test_bit_length_w;
    integer byte_index;
    integer global_index;
    integer length_byte_index;
    reg [7:0] selected_byte;
    always @* begin
        test_bit_length_w = (sec_wrap_phase == 2'd1)
            ? ((64'd64 + {56'b0, input_length}) << 3) : (64'd96 << 3);
        test_block_w = 512'b0;
        selected_byte = 8'b0;
        global_index = 0;
        length_byte_index = 0;
        for (byte_index = 0; byte_index < 64; byte_index = byte_index + 1) begin
            global_index = sec_block_index * 64 + byte_index;
            if (sec_is_hmac) begin
                if (sec_wrap_phase == 2'd1) begin
                    if (global_index < 64) begin
                        selected_byte = (global_index < 32)
                            ? (sec_k_state[255 - global_index * 8 -: 8] ^ 8'h36)
                            : 8'h36;
                    end else if (global_index < 64 + {24'b0, input_length}) begin
                        selected_byte = input_words_flat[((global_index - 64) / 4) * 32 +
                                                         ((global_index - 64) % 4) * 8 +: 8];
                    end else if (global_index == 64 + {24'b0, input_length}) begin
                        selected_byte = 8'h80;
                    end else if (global_index >= sec_block_count * 64 - 8) begin
                        length_byte_index = global_index - (sec_block_count * 64 - 8);
                        selected_byte = test_bit_length_w[(7 - length_byte_index) * 8 +: 8];
                    end else begin
                        selected_byte = 8'h00;
                    end
                end else begin
                    if (global_index < 64) begin
                        selected_byte = (global_index < 32)
                            ? (sec_k_state[255 - global_index * 8 -: 8] ^ 8'h5c)
                            : 8'h5c;
                    end else if (global_index < 96) begin
                        selected_byte = sec_wrap_tag[255 - (global_index - 64) * 8 -: 8];
                    end else if (global_index == 96) begin
                        selected_byte = 8'h80;
                    end else if (global_index >= sec_block_count * 64 - 8) begin
                        length_byte_index = global_index - (sec_block_count * 64 - 8);
                        selected_byte = test_bit_length_w[(7 - length_byte_index) * 8 +: 8];
                    end else begin
                        selected_byte = 8'h00;
                    end
                end
            end else if (sec_wrap_phase == 2'd0) begin
                if (byte_index < 32) begin
                    selected_byte = sec_k_wrap[255 - byte_index * 8 -: 8];
                end else if (byte_index == 32) begin
                    selected_byte = 8'h4c;
                end else if (byte_index == 33) begin
                    selected_byte = 8'h4d;
                end else if (byte_index == 34) begin
                    selected_byte = 8'h53;
                end else if (byte_index == 35) begin
                    selected_byte = 8'h57;
                end else if (byte_index == 36) begin
                    selected_byte = 8'h52;
                end else if (byte_index == 37) begin
                    selected_byte = 8'h41;
                end else if (byte_index == 38) begin
                    selected_byte = 8'h50;
                end else if (byte_index == 39) begin
                    selected_byte = 8'h2d;
                end else if (byte_index == 40) begin
                    selected_byte = 8'h45;
                end else if (byte_index == 41) begin
                    selected_byte = 8'h4e;
                end else if (byte_index == 42) begin
                    selected_byte = 8'h43;
                end else if (byte_index == 43) begin
                    selected_byte = 8'h80;
                end else if (byte_index == 62) begin
                    selected_byte = 8'h01;
                end else if (byte_index == 63) begin
                    selected_byte = 8'h58;
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (sec_wrap_phase == 2'd1) begin
                if (sec_block_index == 2'd0) begin
                    if (byte_index < 32) begin
                        selected_byte = sec_k_wrap[255 - byte_index * 8 -: 8] ^ 8'h36;
                    end else begin
                        selected_byte = 8'h36;
                    end
                end else begin
                    if (byte_index < 32) begin
                        selected_byte = sec_wrap_ct[255 - byte_index * 8 -: 8];
                    end else if (byte_index == 32) begin
                        selected_byte = 8'h80;
                    end else if (byte_index == 62) begin
                        selected_byte = 8'h03;
                    end else if (byte_index == 63) begin
                        selected_byte = 8'h00;
                    end else begin
                        selected_byte = 8'h00;
                    end
                end
            end else begin
                if (sec_block_index == 2'd0) begin
                    if (byte_index < 32) begin
                        selected_byte = sec_k_wrap[255 - byte_index * 8 -: 8] ^ 8'h5c;
                    end else begin
                        selected_byte = 8'h5c;
                    end
                end else begin
                    if (byte_index < 32) begin
                        selected_byte = sec_wrap_tag[255 - byte_index * 8 -: 8];
                    end else if (byte_index == 32) begin
                        selected_byte = 8'h80;
                    end else if (byte_index == 62) begin
                        selected_byte = 8'h03;
                    end else if (byte_index == 63) begin
                        selected_byte = 8'h00;
                    end else begin
                        selected_byte = 8'h00;
                    end
                end
            end
            test_block_w[511 - byte_index * 8 -: 8] = selected_byte;
        end
    end

    lms_sha256_core u_core (
        .clk(clk),
        .rst(rst),
        .start(core_start),
        .init(core_init),
        .state_load(core_state_load),
        .state_in(core_state_in),
        .block(test_block_w),
        .busy(core_busy),
        .done(core_done),
        .digest(core_digest)
    );

endmodule

`default_nettype wire
