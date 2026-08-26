`default_nettype none

/* Some input bits (e.g. arg_i[15:0]) are only checked in their high bits; -Wall reports UNUSEDSIGNAL. */
/* verilator lint_off UNUSEDSIGNAL */
/* verilator lint_off UNUSEDPARAM */

// Hash-agnostic command check module (unified refactor step 1, purely
// combinational and stateless).
//
// Converges the START check chains of both SHA-256/SHAKE256 wrappers into one
// parameterized combinational block: inputs command + parameters, outputs
// {valid, error_code, action}. The wrapper's CONTROL=START branch executes the
// action (execution stays in wrapper; check only does "validity + classify").
//
// Parameters:
//   INSECURE_TEST_MODE : whether SEED_LOAD is allowed (SEED gating)
//   HAS_SECURITY       : 1 = SHA-256 (with MC_STEP/MC_LOAD/WRAP_SEED/UNWRAP_SEED/
//                        HMAC_KSTATE/K_WRAP/K_STATE); 0 = SHAKE256 (no security)
//   MAX_ONCE_BYTES     : HASH_ONCE input limit (SHA-256=128, SHAKE256=136)
//
// action semantics (executed by wrapper):
//   ACT_START       = 0  normal start (HASH_ONCE/CHAIN>0/DERIVE_*/KEYGEN/SIGN/VERIFY)
//   ACT_DONE_SEED   = 1  SEED_LOAD normal load (set seed_valid + done)
//   ACT_DONE_CHAIN0 = 2  CHAIN steps=0 (pass input through to output + done)
//   ACT_DONE_KWRAP  = 3  SEED_LOAD arg_key=1 (latch K_WRAP + done, HAS_SECURITY)
//   ACT_DONE_KSTATE = 4  SEED_LOAD arg_key=2 (latch K_STATE + done, HAS_SECURITY)
//   ACT_DONE_MC     = 5  MC_STEP/MC_LOAD (sim_mc update + done, HAS_SECURITY)
//   ACT_START_HMAC  = 6  HMAC_KSTATE (phase=1 inner start, HAS_SECURITY)
//   ACT_START_WRAP  = 7  WRAP/UNWRAP (phase=0 mask start, HAS_SECURITY)
//
// The judgment order matches the SHA-256 wrapper's original START branches item
// by item (guarantees zero regression); SHAKE256 trims nonexistent commands/
// checks via HAS_SECURITY=0.

module lms_hash_cmd_check #(
    parameter INSECURE_TEST_MODE = 0,
    parameter HAS_SECURITY = 1,
    parameter [7:0] MAX_ONCE_BYTES = 8'd128,
    parameter HAS_HASH_ONCE_RAM = 0,       /* SHAKE256=1: enable HASH_ONCE_RAM (task RAM multi-block) */
    parameter [11:0] MAX_ONCE_BYTES_RAM = 12'd2048,  /* HASH_ONCE_RAM input limit (M=16×128B) */
    parameter HAS_STATE_COMMIT = 0,        /* SHAKE256=1: enable CMD_STATE_COMMIT (mc_step+HMAC fusion) */
    parameter ALLOW_XQ_DERIVE = 0          /* TVLA isolated single x_q[i] (side-channel SEED leakage characterization): only this build allows DERIVE_CHAIN steps=0 */
) (
    input  wire [31:0] command,
    input  wire [31:0] input_length,
    input  wire [31:0] output_length,
    input  wire [31:0] arg_i,
    input  wire [31:0] arg_start,
    input  wire [31:0] arg_steps,
    input  wire [31:0] arg_key,
    input  wire        seed_valid,
    input  wire        k_wrap_valid,
    input  wire        k_state_valid,
    input  wire [31:0] lmots_sign_y_len,   /* LMOTS_SIGN expected y length (by w: W1=8480/W2=4256/W4=2144/W8=1088) */
    output reg         valid,
    output reg  [31:0] error_code,
    output reg  [3:0]  action
);
    localparam [31:0] CMD_HASH_ONCE        = 32'h00000001;
    localparam [31:0] CMD_CHAIN            = 32'h00000002;
    localparam [31:0] CMD_SEED_LOAD        = 32'h00000003;
    localparam [31:0] CMD_DERIVE_CHAIN     = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER= 32'h00000005;
    localparam [31:0] CMD_LMOTS_KEYGEN     = 32'h00000006;
    localparam [31:0] CMD_LMOTS_SIGN       = 32'h00000007;
    localparam [31:0] CMD_LMOTS_VERIFY     = 32'h00000008;
    localparam [31:0] CMD_MC_STEP          = 32'h00000010;
    localparam [31:0] CMD_MC_LOAD          = 32'h00000011;
    localparam [31:0] CMD_WRAP_SEED        = 32'h00000012;
    localparam [31:0] CMD_UNWRAP_SEED      = 32'h00000013;
    localparam [31:0] CMD_HMAC_KSTATE      = 32'h00000014;
    localparam [31:0] CMD_STATE_COMMIT     = 32'h00000015;
    localparam [31:0] CMD_LMOTS_KEYGEN_LEAF= 32'h0000000e;
    localparam [31:0] CMD_LMOTS_VERIFY_LEAF= 32'h0000000f;
    localparam [31:0] CMD_D_INTR_CHAIN     = 32'h00000018;
    localparam [31:0] CMD_HASH_ONCE_RAM    = 32'h00000019;
    localparam [31:0] CMD_MSG_Q_COEF       = 32'h0000001a;
    localparam [31:0] CMD_SEED_WRITE_SAFE  = 32'h0000001c;

    localparam [31:0] ERR_UNSUPPORTED_COMMAND = 32'h00000001;
    localparam [31:0] ERR_INPUT_LENGTH        = 32'h00000003;
    localparam [31:0] ERR_OUTPUT_LENGTH       = 32'h00000004;
    localparam [31:0] ERR_CHAIN_INDEX         = 32'h00000005;
    localparam [31:0] ERR_CHAIN_RANGE         = 32'h00000006;
    localparam [31:0] ERR_KEY_HANDLE          = 32'h00000008;
    localparam [31:0] ERR_SEED_NOT_LOADED     = 32'h00000009;
    localparam [31:0] ERR_INSECURE_DISABLED   = 32'h0000000a;

    localparam [3:0] ACT_START       = 4'd0;
    localparam [3:0] ACT_DONE_SEED   = 4'd1;
    localparam [3:0] ACT_DONE_CHAIN0 = 4'd2;
    localparam [3:0] ACT_DONE_KWRAP  = 4'd3;
    localparam [3:0] ACT_DONE_KSTATE = 4'd4;
    localparam [3:0] ACT_DONE_MC     = 4'd5;
    localparam [3:0] ACT_START_HMAC  = 4'd6;
    localparam [3:0] ACT_START_WRAP  = 4'd7;
    localparam [3:0] ACT_START_STC   = 4'd8;

    always @* begin
        valid = 1'b0;
        error_code = 32'b0;
        action = ACT_START;

        /* Whitelist (SHAKE256: MC/WRAP/HMAC not in it → gated by HAS_SECURITY) */
        if (command != CMD_HASH_ONCE && command != CMD_CHAIN &&
            command != CMD_SEED_LOAD && command != CMD_DERIVE_CHAIN &&
            command != CMD_DERIVE_RANDOMIZER &&
            command != CMD_LMOTS_KEYGEN && command != CMD_LMOTS_KEYGEN_LEAF &&
            command != CMD_LMOTS_SIGN && command != CMD_LMOTS_VERIFY &&
            command != CMD_LMOTS_VERIFY_LEAF &&
            command != CMD_D_INTR_CHAIN &&
            command != CMD_MSG_Q_COEF &&
            !(HAS_SECURITY && command == CMD_SEED_WRITE_SAFE) &&
            !(HAS_HASH_ONCE_RAM && command == CMD_HASH_ONCE_RAM) &&
            !(HAS_STATE_COMMIT && command == CMD_STATE_COMMIT) &&
            !(HAS_SECURITY &&
              (command == CMD_MC_STEP || command == CMD_MC_LOAD ||
               command == CMD_WRAP_SEED || command == CMD_UNWRAP_SEED ||
               command == CMD_HMAC_KSTATE))) begin
            error_code = ERR_UNSUPPORTED_COMMAND;
        end else if (command == CMD_HASH_ONCE_RAM && input_length > MAX_ONCE_BYTES_RAM) begin
            error_code = ERR_INPUT_LENGTH;
        end else if (command == CMD_MSG_Q_COEF && input_length > MAX_ONCE_BYTES_RAM) begin
            /* P2 multi-block: L=54+m ≤ 2048 (m ≤ 1994, message laid out flat at task RAM word 32). */
            error_code = ERR_INPUT_LENGTH;
        end else if (HAS_SECURITY && command == CMD_HMAC_KSTATE && !k_state_valid) begin
            error_code = ERR_KEY_HANDLE;
        end else if (HAS_SECURITY && command == CMD_HMAC_KSTATE && input_length > 119) begin
            /* inner message ≤ 64+119=183B → ≤3 blocks (wrapper's block_count is 2-bit). */
            error_code = ERR_INPUT_LENGTH;
        end else if (HAS_SECURITY && command == CMD_HMAC_KSTATE) begin
            valid = 1'b1;
            action = ACT_START_HMAC;
        end else if (HAS_STATE_COMMIT && command == CMD_STATE_COMMIT && !k_state_valid) begin
            error_code = ERR_KEY_HANDLE;
        end else if (HAS_STATE_COMMIT && command == CMD_STATE_COMMIT) begin
            valid = 1'b1;
            action = ACT_START_STC;
        end else if (HAS_SECURITY && command == CMD_MC_STEP) begin
            valid = 1'b1;
            action = ACT_DONE_MC;
        end else if (HAS_SECURITY && command == CMD_MC_LOAD) begin
            valid = 1'b1;
            action = ACT_DONE_MC;
        end else if (HAS_SECURITY &&
                     (command == CMD_WRAP_SEED || command == CMD_UNWRAP_SEED) &&
                     !k_wrap_valid) begin
            error_code = ERR_KEY_HANDLE;
        end else if (HAS_SECURITY && command == CMD_WRAP_SEED && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (HAS_SECURITY &&
                     (command == CMD_WRAP_SEED || command == CMD_UNWRAP_SEED)) begin
            valid = 1'b1;
            action = ACT_START_WRAP;
        end else if (command == CMD_HASH_ONCE && input_length > MAX_ONCE_BYTES) begin
            error_code = ERR_INPUT_LENGTH;
        end else if (command == CMD_SEED_LOAD && !INSECURE_TEST_MODE &&
                     (!HAS_SECURITY || arg_key == 32'd0)) begin
            /* DEPLOY gate (P1-6): in deploy (INSECURE_TEST_MODE=0), plaintext
             * SEED load rejected (arg_key=0, plus all SEED_LOAD without a
             * security domain); K_WRAP/K_STATE staging (arg_key=1/2) kept -
             * prototype sim-PUF in firmware, K derivation enters hardware
             * non-readable slots (on-die on target; see README). */
            error_code = ERR_INSECURE_DISABLED;
        end else if (command == CMD_SEED_LOAD && HAS_SECURITY && arg_key > 2) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_SEED_LOAD && HAS_SECURITY && arg_key == 1) begin
            valid = 1'b1;
            action = ACT_DONE_KWRAP;
        end else if (command == CMD_SEED_LOAD && HAS_SECURITY && arg_key == 2) begin
            valid = 1'b1;
            action = ACT_DONE_KSTATE;
        end else if (HAS_SECURITY && command == CMD_SEED_WRITE_SAFE) begin
            /* 0.1.281 (deploy model B): controlled SEED load - same data flow as
             * SEED_LOAD(arg_key=0) (ACT_DONE_SEED), but also allowed in deploy
             * (INSECURE_TEST_MODE=0). Not in the UART request table; only the
             * firmware-internal keygen_new flow calls it (SEED generated on-device
             * by TRNG, then enters the slot); plaintext SEED_LOAD gate kept (above). */
            valid = 1'b1;
            action = ACT_DONE_SEED;
        end else if (command == CMD_SEED_LOAD) begin
            valid = 1'b1;
            action = ACT_DONE_SEED;
        end else if ((command == CMD_LMOTS_SIGN && output_length != lmots_sign_y_len) ||
                     (command != CMD_LMOTS_SIGN && output_length != 32'd32)) begin
            error_code = ERR_OUTPUT_LENGTH;
        end else if ((command == CMD_CHAIN || command == CMD_DERIVE_CHAIN) &&
                     arg_i[31:16] != 0) begin
            error_code = ERR_CHAIN_INDEX;
        end else if ((command == CMD_CHAIN || command == CMD_DERIVE_CHAIN) &&
                     (arg_start[31:8] != 0 || arg_steps[31:8] != 0 ||
                      {1'b0, arg_start[7:0]} + {1'b0, arg_steps[7:0]} > 9'd255)) begin
            error_code = ERR_CHAIN_RANGE;
        end else if (command == CMD_DERIVE_CHAIN && arg_steps < 9'd2 &&
                     !(ALLOW_XQ_DERIVE && arg_steps == 32'd0)) begin
            /* M3 hardening: zero/one-step DERIVE_CHAIN directly outputs
             * x_q[i]/H(x_q[i]) (private key elements); standalone commands always
             * rejected. Batch tasks' (LMOTS_SIGN/KEYGEN) internal 0/1-step
             * coefficient paths unaffected (output signatures/public keys, not
             * private elements). Exception: ALLOW_XQ_DERIVE && arg_steps==0 -
             * only for TVLA isolated single x_q[i] derivation (side-channel SEED
             * leakage characterization). Effective only
             * when build passes ALLOW_XQ_DERIVE=1; deploy (default 0) rejects. */
            error_code = ERR_CHAIN_RANGE;
        end else if (command == CMD_DERIVE_CHAIN && arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_DERIVE_CHAIN && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (command == CMD_DERIVE_RANDOMIZER && arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_DERIVE_RANDOMIZER && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if ((command == CMD_LMOTS_KEYGEN || command == CMD_LMOTS_KEYGEN_LEAF) &&
                     arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if ((command == CMD_LMOTS_KEYGEN || command == CMD_LMOTS_KEYGEN_LEAF) &&
                     !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (command == CMD_LMOTS_SIGN && arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_LMOTS_SIGN && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (command == CMD_CHAIN && arg_steps == 0) begin
            valid = 1'b1;
            action = ACT_DONE_CHAIN0;
        end else begin
            valid = 1'b1;
            action = ACT_START;
        end
    end

endmodule

`default_nettype wire
