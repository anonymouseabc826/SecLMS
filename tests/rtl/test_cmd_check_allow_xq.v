// Focused unit test: behavior of lms_hash_cmd_check's M3 gate under ALLOW_XQ_DERIVE.
//   -GALLOW_XQ_DERIVE=1 -DALLOW_TEST: DERIVE_CHAIN steps=0 allowed (ACT_START), steps=1 still rejected.
//   -GALLOW_XQ_DERIVE=0 (no -DALLOW_TEST): steps=0/1 both rejected (deploy keeps M3).
// Usage: verilator --binary +incdir+rtl --top-module tb <this file> rtl/lms_hash_cmd_check.v
`timescale 1ns/1ps
`default_nettype none
module tb;
    reg  [31:0] command, input_length, output_length, arg_i, arg_start, arg_steps, arg_key;
    reg         seed_valid, k_wrap_valid, k_state_valid;
    reg  [31:0] lmots_sign_y_len;
    wire        valid;
    wire [31:0] error_code;
    wire [3:0]  action;

    lms_hash_cmd_check #(
        .INSECURE_TEST_MODE(1),
        .HAS_SECURITY(1),
        .HAS_HASH_ONCE_RAM(1),
        .HAS_STATE_COMMIT(1),
        .ALLOW_XQ_DERIVE(`ALLOW_XQ_DERIVE)
    ) dut (
        .command(command), .input_length(input_length), .output_length(output_length),
        .arg_i(arg_i), .arg_start(arg_start), .arg_steps(arg_steps), .arg_key(arg_key),
        .seed_valid(seed_valid), .k_wrap_valid(k_wrap_valid), .k_state_valid(k_state_valid),
        .lmots_sign_y_len(lmots_sign_y_len),
        .valid(valid), .error_code(error_code), .action(action)
    );

    localparam [31:0] CMD_DERIVE_CHAIN = 32'h00000004;
    localparam [31:0] ERR_CHAIN_RANGE  = 32'h00000006;

    integer failures;

    // Drive one DERIVE_CHAIN (steps adjustable) and advance one net delta
    task drive_derive_chain(input [31:0] steps);
        begin
            command = CMD_DERIVE_CHAIN;
            input_length = 32'd0;
            output_length = 32'd32;
            arg_i = 32'd0;
            arg_start = 32'd0;
            arg_steps = steps;
            arg_key = 32'd0;
            seed_valid = 1'b1;
            k_wrap_valid = 1'b1;
            k_state_valid = 1'b1;
            lmots_sign_y_len = 32'd2144;
            #1;
        end
    endtask

    task check(string name, input [31:0] got, input [31:0] want, input [3:0] got_a, input [3:0] want_a);
        begin
            if (got != want || got_a != want_a) begin
                failures = failures + 1;
                $display("FAIL %s: error=%h (want %h) action=%0d (want %0d)",
                         name, got, want, got_a, want_a);
            end else begin
                $display("PASS %s", name);
            end
        end
    endtask

    initial begin
        failures = 0;
        command = 0; input_length = 0; output_length = 0; arg_i = 0; arg_start = 0;
        arg_steps = 0; arg_key = 0; seed_valid = 0; k_wrap_valid = 0; k_state_valid = 0;
        lmots_sign_y_len = 32'd2144;

`ifdef ALLOW_TEST
        // ALLOW_XQ_DERIVE=1
        drive_derive_chain(32'd0);
        check("derive steps=0 (ALLOW=1) -> pass", error_code, 32'd0, action, 4'd0/*ACT_START*/);
        drive_derive_chain(32'd1);
        check("derive steps=1 (ALLOW=1) -> reject", error_code, ERR_CHAIN_RANGE, action, 4'd0);
`else
        // ALLOW_XQ_DERIVE=0
        drive_derive_chain(32'd0);
        check("derive steps=0 (ALLOW=0) -> reject", error_code, ERR_CHAIN_RANGE, action, 4'd0);
        drive_derive_chain(32'd1);
        check("derive steps=1 (ALLOW=0) -> reject", error_code, ERR_CHAIN_RANGE, action, 4'd0);
`endif

        if (failures == 0)
            $display("ALL PASS");
        else
            $display("FAILURES: %0d", failures);
        $finish;
    end
endmodule
