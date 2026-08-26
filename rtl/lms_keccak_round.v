`default_nettype none

// Keccak-p[1600] single-round combinational logic (θ→ρ+π→χ→ι).
// Implemented with module-level wire arrays + generate (reliably supported by both
// the simulator and Vivado), avoiding the sharing problem of local unpacked arrays inside a
// function across multiple unroll invocations.
//
// Bit-order convention matches lms_keccak_core.v: state lane j = bits [j*64 +: 64],
// little-endian lane (matching fips202.c).

module lms_keccak_round (
    input  wire [1599:0] state_i,
    input  wire [4:0]    rnd,        // round number 0..23
    output wire [1599:0] state_o
);
    // ρ-step rotation constants (RHO[lane] = left-rotation bit count, per Keccak standard).
    // Use explicit part-selects for the fixed rotations, avoiding barrel-shifter inference.
    localparam [6:0] RHO [0:24] = '{
        7'd0,  7'd1,  7'd62, 7'd28, 7'd27,
        7'd36, 7'd44, 7'd6,  7'd55, 7'd20,
        7'd3,  7'd10, 7'd43, 7'd25, 7'd39,
        7'd41, 7'd45, 7'd15, 7'd21, 7'd8,
        7'd18, 7'd2,  7'd61, 7'd56, 7'd14
    };

    function automatic [63:0] round_constant;
        input [4:0] rc_idx;
        begin
            case (rc_idx)
                5'd0 : round_constant = 64'h0000000000000001;
                5'd1 : round_constant = 64'h0000000000008082;
                5'd2 : round_constant = 64'h800000000000808a;
                5'd3 : round_constant = 64'h8000000080008000;
                5'd4 : round_constant = 64'h000000000000808b;
                5'd5 : round_constant = 64'h0000000080000001;
                5'd6 : round_constant = 64'h8000000080008081;
                5'd7 : round_constant = 64'h8000000000008009;
                5'd8 : round_constant = 64'h000000000000008a;
                5'd9 : round_constant = 64'h0000000000000088;
                5'd10: round_constant = 64'h0000000080008009;
                5'd11: round_constant = 64'h000000008000000a;
                5'd12: round_constant = 64'h000000008000808b;
                5'd13: round_constant = 64'h800000000000008b;
                5'd14: round_constant = 64'h8000000000008089;
                5'd15: round_constant = 64'h8000000000008003;
                5'd16: round_constant = 64'h8000000000008002;
                5'd17: round_constant = 64'h8000000000000080;
                5'd18: round_constant = 64'h000000000000800a;
                5'd19: round_constant = 64'h800000008000000a;
                5'd20: round_constant = 64'h8000000080008081;
                5'd21: round_constant = 64'h8000000000008080;
                5'd22: round_constant = 64'h0000000080000001;
                default: round_constant = 64'h8000000080008008;
            endcase
        end
    endfunction

    wire [63:0] A  [0:24];   /* unpack input */
    wire [63:0] C  [0:4];    /* θ column parity */
    wire [63:0] D  [0:4];    /* θ diffusion */
    wire [63:0] Ap [0:24];   /* after θ */
    wire [63:0] B  [0:24];   /* after ρ+π */
    wire [63:0] X  [0:24];   /* after χ (before ι) */

    genvar gx;
    genvar gy;

    generate
        for (gx = 0; gx < 25; gx = gx + 1) begin: unpack
            assign A[gx] = state_i[gx * 64 +: 64];
        end

        /* θ: C[x] = ⊕_y A[x,y]; D[x] = C[x-1] ^ ROT(C[x+1],1) */
        for (gx = 0; gx < 5; gx = gx + 1) begin: theta_c
            assign C[gx] = A[gx] ^ A[gx + 5] ^ A[gx + 10] ^ A[gx + 15] ^ A[gx + 20];
        end
        for (gx = 0; gx < 5; gx = gx + 1) begin: theta_d
            /* ROTL64 by 1 = {bits[62:0], bits[63]}, pure wire reordering */
            assign D[gx] = C[(gx + 4) % 5] ^
                {C[(gx + 1) % 5][62:0], C[(gx + 1) % 5][63]};
        end
        for (gy = 0; gy < 5; gy = gy + 1) begin: theta_y
            for (gx = 0; gx < 5; gx = gx + 1) begin: theta_xy
                assign Ap[gx + 5 * gy] = A[gx + 5 * gy] ^ D[gx];
            end
        end

        /* ρ+π: B[y][2x+3y mod 5] = ROT(Ap[x][y], RHO[x][y]),
         * fixed rotations via constant shifts (RHO from the localparam table; Vivado can
         * constant-propagate them into wire reordering) */
        for (gy = 0; gy < 5; gy = gy + 1) begin: rho_y
            for (gx = 0; gx < 5; gx = gx + 1) begin: rho_xy
                assign B[gy + 5 * ((2 * gx + 3 * gy) % 5)] =
                    RHO[gx + 5 * gy] == 7'd0
                        ? Ap[gx + 5 * gy]
                        : (Ap[gx + 5 * gy] << RHO[gx + 5 * gy]) |
                          (Ap[gx + 5 * gy] >> (7'd64 - RHO[gx + 5 * gy]));
            end
        end

        /* χ: X[x,y] = B[x,y] ^ (~B[x+1,y] & B[x+2,y]) */
        for (gy = 0; gy < 5; gy = gy + 1) begin: chi_y
            for (gx = 0; gx < 5; gx = gx + 1) begin: chi_xy
                assign X[gx + 5 * gy] = B[gx + 5 * gy] ^
                    (~B[((gx + 1) % 5) + 5 * gy] & B[((gx + 2) % 5) + 5 * gy]);
            end
        end

        /* pack (lanes 1..24) */
        for (gx = 1; gx < 25; gx = gx + 1) begin: pack
            assign state_o[gx * 64 +: 64] = X[gx];
        end
    endgenerate

    /* ι: lane0 ^= RC[rnd] */
    assign state_o[63:0] = X[0] ^ round_constant(rnd);

endmodule

`default_nettype wire
