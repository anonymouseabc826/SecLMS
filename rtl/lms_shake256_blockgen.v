`default_nettype none

// SHAKE256 block generator (unified refactor step 2, SHAKE256 implementation for interface A, pure combinational).
//
// Driven by lms_hash_engine: given the task context, produce a 1088-bit rate block + init flag,
// and flip the core digest (LSB-first) to the unified big-endian. All hash-related block layout/padding/byte order
// is gathered here; the engine only does scheduling.
//
// Task types (task_type):
//   0 = HASH_ONCE: bytes0..len-1 = INPUT region, byte len = 0x1F, byte135 = 0x80
//   1 = CHAIN     : I||q||i||j||chain_value(32B)||0x1F@55||0x80@135
//   2 = DERIVE    : derive phase byte22=0xff; chain phase byte22=j (distinguished by derive_phase)
//   3 = RANDOMIZER: I||q||0x8585||seed(32B)||0x1F@54||0x80@135
//
// Byte conventions: within register words (identifier/input/seed), byte0 is at bit0 (little-endian word).
// identifier/input flat LSB-first concatenation (word0 at LSB), byte k = flat[(k/4)*32+(k%4)*8];
// seed_flat big-endian concatenation (word0 at MSB), byte k = flat[(7-k/4)*32+(k%4)*8];
// chain_value contiguous big-endian (byte0 at MSB; initially reassembled by wrapper, iteration = digest), byte k = [248-8k];
// q whole word must be byte-reversed when concatenating (lesson from [X+:W] part-select: RHS LSB lands at X).

module lms_shake256_blockgen (
    input  wire [2:0]   task_type,       // 0=hash_once 1=chain 2=derive 3=randomizer 4=dleaf 5=pblc
    input  wire [1023:0] input_words_flat,
    input  wire [127:0] identifier_flat,
    input  wire [31:0]  arg_q,
    input  wire [15:0]  arg_i,
    input  wire [7:0]   chain_j,
    input  wire [255:0] chain_value,
    input  wire         derive_phase,    // DERIVE_CHAIN: 1=derive 0=chain
    input  wire [7:0]   input_length,    // for HASH_ONCE (<=136)
    input  wire [255:0] seed_flat,       // seed_words concatenation (big-endian)
    /* Batch task extensions (D_LEAF/PBLc/D_INTR, with defaults: no change needed for old single-chain engine instances) */
    input  wire [31:0]  arg_leaf_node = 32'b0,   /* D_LEAF/D_INTR: node 4B */
    input  wire [255:0] dleaf_kq = 256'b0,       /* D_LEAF: K_q 32B (word7..word0 big-endian concatenation) */
    input  wire [1087:0] pblc_buffer = 1088'b0,  /* PBLc: buffer contents */
    input  wire [7:0]   pblc_fill = 8'b0,        /* PBLc: 0x1F fill position of the final block */
    input  wire         pblc_phase = 1'b0,       /* PBLc: 1=add padding to final block, 0=send full block directly */
    input  wire [255:0] dintr_left = 256'b0,     /* D_INTR: left 32B (contiguous big-endian, byte0 at MSB) */
    input  wire [255:0] dintr_right = 256'b0,    /* D_INTR: right/sibling 32B (same as left) */
    // Outputs
    output reg  [1087:0] rate_block,
    output reg          rate_init,       // sponge initialization (init for every block: single block, no continuation)
    // digest byte-order adaptation: core LSB-first -> unified big-endian
    input  wire [255:0] core_digest,
    output wire [255:0] digest_bigendian
);

    /* HASH_ONCE uses the default branch (task_type=0), no separate constant needed */
    localparam [2:0] TASK_CHAIN     = 3'd1;
    localparam [2:0] TASK_DERIVE    = 3'd2;
    localparam [2:0] TASK_RANDOMIZER= 3'd3;
    localparam [2:0] TASK_DLEAF     = 3'd4;
    localparam [2:0] TASK_PBLC      = 3'd5;
    localparam [2:0] TASK_DINTR     = 3'd6;

    /* Core digest LSB-first (byte b = bits[b*8 +: 8]) -> unified big-endian (byte0 at MSB) */
    assign digest_bigendian = {
        core_digest[7:0],   core_digest[15:8],  core_digest[23:16], core_digest[31:24],
        core_digest[39:32], core_digest[47:40], core_digest[55:48], core_digest[63:56],
        core_digest[71:64], core_digest[79:72], core_digest[87:80], core_digest[95:88],
        core_digest[103:96], core_digest[111:104], core_digest[119:112], core_digest[127:120],
        core_digest[135:128], core_digest[143:136], core_digest[151:144], core_digest[159:152],
        core_digest[167:160], core_digest[175:168], core_digest[183:176], core_digest[191:184],
        core_digest[199:192], core_digest[207:200], core_digest[215:208], core_digest[223:216],
        core_digest[231:224], core_digest[239:232], core_digest[247:240], core_digest[255:248]};

    integer k;
    always @* begin
        rate_block = 1088'b0;
        rate_init = 1'b0;
        case (task_type)
            TASK_CHAIN: begin
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                /* [X +: W] part-select: RHS LSB lands at bit X, so a whole word needs byte-reversed concatenation to be big-endian */
                rate_block[16 * 8 +: 32] = {arg_q[7:0], arg_q[15:8], arg_q[23:16], arg_q[31:24]};
                rate_block[20 * 8 +: 16] = {arg_i[7:0], arg_i[15:8]};
                rate_block[22 * 8 +: 8]  = chain_j;
                for (k = 0; k < 32; k = k + 1) begin
                    /* chain_value contiguous big-endian (byte0 at MSB, aligned with iteration digest) */
                    rate_block[(23 + k) * 8 +: 8] = chain_value[248 - k * 8 +: 8];
                end
                rate_block[55 * 8 +: 8]  = 8'h1f;
                rate_block[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_DERIVE: begin
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                rate_block[16 * 8 +: 32] = {arg_q[7:0], arg_q[15:8], arg_q[23:16], arg_q[31:24]};
                rate_block[20 * 8 +: 16] = {arg_i[7:0], arg_i[15:8]};
                rate_block[22 * 8 +: 8]  = derive_phase ? 8'hff : chain_j;
                for (k = 0; k < 32; k = k + 1) begin
                    /* derive phase: seed_flat word concatenation (byte k = word[k/4] bit (k%4)*8);
                     * chain phase: chain_value contiguous big-endian (byte0 at MSB, aligned with iteration digest) */
                    rate_block[(23 + k) * 8 +: 8] = derive_phase
                        ? seed_flat[(7 - k / 4) * 32 + (k % 4) * 8 +: 8]
                        : chain_value[248 - k * 8 +: 8];
                end
                rate_block[55 * 8 +: 8]  = 8'h1f;
                rate_block[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_RANDOMIZER: begin
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                rate_block[16 * 8 +: 32] = {arg_q[7:0], arg_q[15:8], arg_q[23:16], arg_q[31:24]};
                rate_block[20 * 8 +: 16] = 16'h8585;
                for (k = 0; k < 32; k = k + 1) begin
                    rate_block[(22 + k) * 8 +: 8] = seed_flat[(7 - k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                rate_block[54 * 8 +: 8]  = 8'h1f;
                rate_block[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_DLEAF: begin
                /* D_LEAF: I(16)||node(4)||0x8282(2)||K_q(32)||0x1F@54||0x80@135, single 54B block.
                 * node big-endian (byte16=MSB, matching wrapper's original inlining); K_q byte k=dleaf_kq[k*8 +: 8]. */
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                for (k = 0; k < 4; k = k + 1) begin
                    rate_block[(16 + k) * 8 +: 8] = arg_leaf_node[(3 - k) * 8 +: 8];
                end
                rate_block[20 * 8 +: 8]  = 8'h82;
                rate_block[21 * 8 +: 8]  = 8'h82;
                for (k = 0; k < 32; k = k + 1) begin
                    rate_block[(22 + k) * 8 +: 8] = dleaf_kq[k * 8 +: 8];
                end
                rate_block[54 * 8 +: 8]  = 8'h1f;
                rate_block[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_DINTR: begin
                /* D_INTR: I(16)||node(4)||0x8383(2)||left(32)||right(32)||0x1F@86||0x80@135,
                 * single 86B block. node big-endian (byte16=MSB); left/right contiguous big-endian (byte0 at MSB,
                 * same convention as chain_value, byte-reversed when loaded from task RAM), message byte22+k=left byte k,
                 * byte54+k=right byte k (read [248-8k +: 8], byte0=[255:248]). */
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                for (k = 0; k < 4; k = k + 1) begin
                    rate_block[(16 + k) * 8 +: 8] = arg_leaf_node[(3 - k) * 8 +: 8];
                end
                rate_block[20 * 8 +: 8]  = 8'h83;
                rate_block[21 * 8 +: 8]  = 8'h83;
                for (k = 0; k < 32; k = k + 1) begin
                    rate_block[(22 + k) * 8 +: 8] = dintr_left[248 - k * 8 +: 8];
                    rate_block[(54 + k) * 8 +: 8] = dintr_right[248 - k * 8 +: 8];
                end
                rate_block[86 * 8 +: 8]  = 8'h1f;
                rate_block[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_PBLC: begin
                /* PBLc: full block (pblc_phase=0) sends buffer contents directly; final block (pblc_phase=1)
                 * 0x1F@fill + 0x80@135. fill index uses a constant loop (8-bit variable part-select out of bounds). */
                rate_block = pblc_buffer;
                if (pblc_phase) begin
                    for (k = 0; k < 136; k = k + 1) begin
                        if (k[7:0] == pblc_fill)
                            rate_block[k * 8 +: 8] = 8'h1f;
                    end
                    rate_block[135 * 8 +: 8] = 8'h80;
                end
                rate_init = 1'b1;
            end
            default: begin
                /* HASH_ONCE: single block of up to 128B (unified limit with SHA-256; rate=136B, padding 0x1F@len + 0x80@135).
                /* Data loop 128: input_words_flat is only 1024 bits (32 words), k>=128 is out of bounds
                 * (Vivado Synth 8-524, Verilator does not check).
                 * Padding loop 136: rate_block is 1088 bits (byte135 in bounds), write 0x1F when k==input_length
                 * (input_length<=128), constant index avoids variable part-select out of bounds. */
                for (k = 0; k < 128; k = k + 1) begin
                    if (k[7:0] < input_length) begin
                        rate_block[k * 8 +: 8] = input_words_flat[
                            (k / 4) * 32 + (k % 4) * 8 +: 8];
                    end
                end
                for (k = 0; k < 136; k = k + 1) begin
                    if (k[7:0] == input_length) rate_block[k * 8 +: 8] = 8'h1f;
                end
                rate_block[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
        endcase
    end

endmodule

`default_nettype wire
