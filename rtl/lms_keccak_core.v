`default_nettype none

// Keccak-p[1600] compression core (SHAKE256, rate=1088-bit, unroll-2).
//
// Interface semantics align with rtl/lms_sha256_core.v: this core only performs one
// "absorb+permute"; padding/multi-block orchestration is handled by the upper layer
// (MMIO wrapper / software).
//
//   - start+init=1      : first-block absorb (XOR that rate block after state clear)
//   - start+init=0      : continuing-block absorb (XOR that rate block into current state)
//   After each absorb, permute (12 cycles) and assert done; digest = first 32 bytes of the
//   current sponge state.
//   The upper layer (MMIO wrapper/software) handles padding, final-block layout, and final
//   readout: Squeeze directly reads bytes within the rate, no extra permute needed (SHAKE256
//   output 32B < rate 136B).
//
// Each block's core permute is 12 cycles = 24 Keccak-f rounds at 2 rounds per cycle (unroll-2,
// see lms_keccak_round.v). System-level throughput accounting (REVIEW B09B10-R2): per block
// the engine also has ST_ABSORB latch + start-to-done absorb beat + ST_DONE transition;
// measured ~15 beats per block; cycle_count accumulates only the 12 permute beats (not wall clock).
// Bit-order convention: rate block byte i is at block[i*8 +: 8]; state lane j = bits
// [j*64 +: 64] (little-endian lane, matching fips202.c); digest = first 32 bytes of state
// (state[255:0], byte 0 is the least-significant byte).
//
// Reference: FIPS 202 Keccak-p[1600], correctness oracle = hashs/fips202.c.

module lms_keccak_core (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire         init,
    input  wire [1087:0] block,
    output reg          busy,
    output reg          done,
    output wire [255:0] digest
);
    localparam [1:0] PH_IDLE    = 2'd0;
    localparam [1:0] PH_PERMUTE = 2'd1;

    reg [1599:0] state_r;
    reg [3:0]    round_r;              // 0..11 (2 rounds per cycle)
    reg [1:0]    phase_r;

    assign digest = state_r[255:0];

    // Two-stage pipeline (unroll-2): rounds 2r and 2r+1 complete in one cycle.
    wire [1599:0] step1_w;
    wire [1599:0] step2_w;

    lms_keccak_round round_u1 (
        .state_i(state_r),
        .rnd({round_r, 1'b0}),
        .state_o(step1_w)
    );
    lms_keccak_round round_u2 (
        .state_i(step1_w),
        .rnd({round_r, 1'b0} + 5'd1),
        .state_o(step2_w)
    );

    always @(posedge clk) begin
        done <= 1'b0;

        if (start && !busy) begin
            if (init) begin
                state_r <= {512'b0, block[1087:0]};
            end else begin
                state_r <= state_r ^ {512'b0, block[1087:0]};
            end
            round_r <= 4'd0;
            phase_r <= PH_PERMUTE;
            busy <= 1'b1;
        end else if (phase_r == PH_PERMUTE) begin
            state_r <= step2_w;
            if (round_r == 4'd11) begin
                phase_r <= PH_IDLE;
                busy <= 1'b0;
                done <= 1'b1;
            end else begin
                round_r <= round_r + 4'd1;
            end
        end

        if (rst) begin
            state_r <= 1600'b0;
            round_r <= 4'd0;
            phase_r <= PH_IDLE;
            busy <= 1'b0;
            done <= 1'b0;
        end
    end

endmodule

`default_nettype wire
