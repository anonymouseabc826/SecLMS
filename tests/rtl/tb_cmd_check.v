// Top module for the C++ driver (test_cmd_check_allow_xq.cpp): instantiates lms_hash_cmd_check
// and exposes all inputs/outputs as Verilator model members. No initial block (simulation is
// driven by eval from C++ main).
`timescale 1ns/1ps
`default_nettype none
module tb #(
    parameter ALLOW_XQ_DERIVE = 0
) (
    input  wire [31:0] command, input_length, output_length, arg_i, arg_start, arg_steps, arg_key,
    input  wire        seed_valid, k_wrap_valid, k_state_valid,
    input  wire [31:0] lmots_sign_y_len,
    output wire        valid,
    output wire [31:0] error_code,
    output wire [3:0]  action
);
    lms_hash_cmd_check #(
        .INSECURE_TEST_MODE(1),
        .HAS_SECURITY(1),
        .HAS_HASH_ONCE_RAM(1),
        .HAS_STATE_COMMIT(1),
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE)
    ) dut (
        .command(command), .input_length(input_length), .output_length(output_length),
        .arg_i(arg_i), .arg_start(arg_start), .arg_steps(arg_steps), .arg_key(arg_key),
        .seed_valid(seed_valid), .k_wrap_valid(k_wrap_valid), .k_state_valid(k_state_valid),
        .lmots_sign_y_len(lmots_sign_y_len),
        .valid(valid), .error_code(error_code), .action(action)
    );
endmodule
