// Adapted from SLotH sha256_round.v by Markku-Juhani O. Saarinen.
// The source project is distributed under the BSD 3-Clause License.

`default_nettype none

module lms_sha256_round (
    input  wire [255:0] state_i,
    input  wire [511:0] message_i,
    input  wire [5:0]   round_i,
    output wire [255:0] state_o,
    output wire [511:0] message_o
);
    reg [31:0] round_constant;

    always @* begin
        case (round_i)
            6'h00: round_constant = 32'h428a2f98;
            6'h01: round_constant = 32'h71374491;
            6'h02: round_constant = 32'hb5c0fbcf;
            6'h03: round_constant = 32'he9b5dba5;
            6'h04: round_constant = 32'h3956c25b;
            6'h05: round_constant = 32'h59f111f1;
            6'h06: round_constant = 32'h923f82a4;
            6'h07: round_constant = 32'hab1c5ed5;
            6'h08: round_constant = 32'hd807aa98;
            6'h09: round_constant = 32'h12835b01;
            6'h0a: round_constant = 32'h243185be;
            6'h0b: round_constant = 32'h550c7dc3;
            6'h0c: round_constant = 32'h72be5d74;
            6'h0d: round_constant = 32'h80deb1fe;
            6'h0e: round_constant = 32'h9bdc06a7;
            6'h0f: round_constant = 32'hc19bf174;
            6'h10: round_constant = 32'he49b69c1;
            6'h11: round_constant = 32'hefbe4786;
            6'h12: round_constant = 32'h0fc19dc6;
            6'h13: round_constant = 32'h240ca1cc;
            6'h14: round_constant = 32'h2de92c6f;
            6'h15: round_constant = 32'h4a7484aa;
            6'h16: round_constant = 32'h5cb0a9dc;
            6'h17: round_constant = 32'h76f988da;
            6'h18: round_constant = 32'h983e5152;
            6'h19: round_constant = 32'ha831c66d;
            6'h1a: round_constant = 32'hb00327c8;
            6'h1b: round_constant = 32'hbf597fc7;
            6'h1c: round_constant = 32'hc6e00bf3;
            6'h1d: round_constant = 32'hd5a79147;
            6'h1e: round_constant = 32'h06ca6351;
            6'h1f: round_constant = 32'h14292967;
            6'h20: round_constant = 32'h27b70a85;
            6'h21: round_constant = 32'h2e1b2138;
            6'h22: round_constant = 32'h4d2c6dfc;
            6'h23: round_constant = 32'h53380d13;
            6'h24: round_constant = 32'h650a7354;
            6'h25: round_constant = 32'h766a0abb;
            6'h26: round_constant = 32'h81c2c92e;
            6'h27: round_constant = 32'h92722c85;
            6'h28: round_constant = 32'ha2bfe8a1;
            6'h29: round_constant = 32'ha81a664b;
            6'h2a: round_constant = 32'hc24b8b70;
            6'h2b: round_constant = 32'hc76c51a3;
            6'h2c: round_constant = 32'hd192e819;
            6'h2d: round_constant = 32'hd6990624;
            6'h2e: round_constant = 32'hf40e3585;
            6'h2f: round_constant = 32'h106aa070;
            6'h30: round_constant = 32'h19a4c116;
            6'h31: round_constant = 32'h1e376c08;
            6'h32: round_constant = 32'h2748774c;
            6'h33: round_constant = 32'h34b0bcb5;
            6'h34: round_constant = 32'h391c0cb3;
            6'h35: round_constant = 32'h4ed8aa4a;
            6'h36: round_constant = 32'h5b9cca4f;
            6'h37: round_constant = 32'h682e6ff3;
            6'h38: round_constant = 32'h748f82ee;
            6'h39: round_constant = 32'h78a5636f;
            6'h3a: round_constant = 32'h84c87814;
            6'h3b: round_constant = 32'h8cc70208;
            6'h3c: round_constant = 32'h90befffa;
            6'h3d: round_constant = 32'ha4506ceb;
            6'h3e: round_constant = 32'hbef9a3f7;
            6'h3f: round_constant = 32'hc67178f2;
            default: round_constant = 32'h00000000;
        endcase
    end

    function automatic [31:0] rotate_right;
        input [31:0] value;
        input [31:0] amount;
        begin
            rotate_right = (value >> amount) | (value << (32 - amount));
        end
    endfunction

    function automatic [31:0] choose;
        input [31:0] x;
        input [31:0] y;
        input [31:0] z;
        begin
            choose = (x & y) ^ (~x & z);
        end
    endfunction

    function automatic [31:0] majority;
        input [31:0] x;
        input [31:0] y;
        input [31:0] z;
        begin
            majority = (x & y) ^ (x & z) ^ (y & z);
        end
    endfunction

    function automatic [31:0] big_sigma0;
        input [31:0] value;
        begin
            big_sigma0 = rotate_right(value, 2) ^
                         rotate_right(value, 13) ^
                         rotate_right(value, 22);
        end
    endfunction

    function automatic [31:0] big_sigma1;
        input [31:0] value;
        begin
            big_sigma1 = rotate_right(value, 6) ^
                         rotate_right(value, 11) ^
                         rotate_right(value, 25);
        end
    endfunction

    function automatic [31:0] small_sigma0;
        input [31:0] value;
        begin
            small_sigma0 = rotate_right(value, 7) ^
                           rotate_right(value, 18) ^
                           (value >> 3);
        end
    endfunction

    function automatic [31:0] small_sigma1;
        input [31:0] value;
        begin
            small_sigma1 = rotate_right(value, 17) ^
                           rotate_right(value, 19) ^
                           (value >> 10);
        end
    endfunction

    wire [31:0] schedule_word = message_i[31:0];
    wire [31:0] next_schedule_word =
        small_sigma1(message_i[479:448]) + message_i[319:288] +
        small_sigma0(message_i[63:32]) + message_i[31:0];

    assign message_o = {next_schedule_word, message_i[511:32]};

    wire [31:0] a;
    wire [31:0] b;
    wire [31:0] c;
    wire [31:0] d;
    wire [31:0] e;
    wire [31:0] f;
    wire [31:0] g;
    wire [31:0] h;
    assign {h, g, f, e, d, c, b, a} = state_i;

    wire [31:0] temp1 = h + big_sigma1(e) + choose(e, f, g) +
                        round_constant + schedule_word;
    wire [31:0] temp2 = big_sigma0(a) + majority(a, b, c);

    assign state_o = {g, f, e, d + temp1, c, b, a, temp1 + temp2};

endmodule

`default_nettype wire
