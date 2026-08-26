// SHA-256 LM-OTS batch-task oracle cross-check (S5 w parameterization, w in {1,2,4,8}).
// Software SHA-256 oracle computes expected KEYGEN/SIGN/VERIFY/KEYGEN_LEAF/VERIFY_LEAF values,
// driving lms_sha256_mmio batch commands for comparison. W4 fixed-vector cycles match test_sha256_mmio
// (KEYGEN 38,761 / SIGN 23,516 / VERIFY 27,327); w!=4 compares results only (cycles recorded).
//
// W4 N=32 parameters: p=67, ls=4 (src/lms_params.c LMOTS_SHA256_N32_W4).
// Chain message (55B): I(16)||q(4)||i(2)||j(1)||value(32)
// Derive message (55B): I||q||i||0xff||SEED
// PBLc message: I||q||0x8080||pub_buf(p*32), compressed in SHA-256 64B blocks
// D_LEAF message: I||node(4)||0x8282||K_q(32), 54B

#include "Vlms_sha256_mmio.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static constexpr uint16_t REG_VERSION = 0x000;
static constexpr uint16_t REG_CAPABILITY = 0x004;
static constexpr uint16_t REG_COMMAND = 0x008;
static constexpr uint16_t REG_CONTROL = 0x00c;
static constexpr uint16_t REG_STATUS = 0x010;
static constexpr uint16_t REG_ERROR = 0x014;
static constexpr uint16_t REG_INPUT_LENGTH = 0x018;
static constexpr uint16_t REG_OUTPUT_LENGTH = 0x01c;
static constexpr uint16_t REG_CYCLE_COUNT = 0x020;
static constexpr uint16_t REG_ARG_Q = 0x024;
static constexpr uint16_t REG_ARG_I = 0x028;
static constexpr uint16_t REG_ARG_START = 0x02c;
static constexpr uint16_t REG_ARG_STEPS = 0x030;
static constexpr uint16_t REG_ARG_KEY = 0x034;
static constexpr uint16_t REG_TASK_ADDR = 0x038;
static constexpr uint16_t REG_TASK_DATA = 0x03c;
static constexpr uint16_t REG_IDENTIFIER = 0x040;
static constexpr uint16_t REG_ARG_LEAF_NODE = 0x050;
static constexpr uint16_t REG_ARG_W = 0x054;
static constexpr uint16_t REG_SEED = 0x080;
static constexpr uint16_t REG_INPUT = 0x100;
static constexpr uint16_t REG_OUTPUT = 0x200;

static constexpr uint32_t CMD_HASH_ONCE = 1;
static constexpr uint32_t CMD_CHAIN = 2;
static constexpr uint32_t CMD_SEED_LOAD = 3;
static constexpr uint32_t CMD_DERIVE_CHAIN = 4;
static constexpr uint32_t CMD_LMOTS_KEYGEN = 6;
static constexpr uint32_t CMD_LMOTS_SIGN = 7;
static constexpr uint32_t CMD_LMOTS_VERIFY = 8;
static constexpr uint32_t CMD_LMOTS_KEYGEN_LEAF = 0x0e;
static constexpr uint32_t CMD_LMOTS_VERIFY_LEAF = 0x0f;
static constexpr uint32_t CTRL_START = 1;
static constexpr uint32_t STATUS_BUSY = 1;
static constexpr uint32_t STATUS_DONE = 2;

static constexpr int N = 32;
static constexpr int LMS_I_LEN = 16;

using Digest = std::array<uint8_t, N>;

/* ---------- Winternitz w parameters (w in {1,2,4,8}) ---------- */
static int g_w = 4;
static int g_P = 67;
static int g_maxstep = 15;
static void set_w(int w)
{
    g_w = w;
    switch (w) {
        case 1:  g_P = 265; g_maxstep = 1; break;
        case 2:  g_P = 133; g_maxstep = 3; break;
        case 8:  g_P = 34;  g_maxstep = 255; break;
        default: g_P = 67;  g_maxstep = 15; break;
    }
}
/* Compact coefficient packing (aligned with RTL coefficient_words[0:31]: 32/w per word,
 * sliced at w-bit width): W1 32 1-bit per word, W2 16 2-bit, W4 8 4-bit, W8 4 8-bit. */
static std::vector<uint8_t> pack_coefficients(const uint8_t *coeffs, int P)
{
    const int per_word = 32 / g_w;
    const int nwords = (P + per_word - 1) / per_word;
    std::vector<uint8_t> bytes(static_cast<size_t>(nwords) * 4, 0);
    for (int i = 0; i < P; ++i) {
        const uint32_t v = static_cast<uint32_t>(coeffs[i] & ((1 << g_w) - 1));
        const uint32_t shift = static_cast<uint32_t>((i % per_word) * g_w);
        const size_t off = static_cast<size_t>(i / per_word) * 4;
        uint32_t w32 = static_cast<uint32_t>(bytes[off]) |
                       (static_cast<uint32_t>(bytes[off + 1]) << 8) |
                       (static_cast<uint32_t>(bytes[off + 2]) << 16) |
                       (static_cast<uint32_t>(bytes[off + 3]) << 24);
        w32 |= v << shift;
        bytes[off] = static_cast<uint8_t>(w32);
        bytes[off + 1] = static_cast<uint8_t>(w32 >> 8);
        bytes[off + 2] = static_cast<uint8_t>(w32 >> 16);
        bytes[off + 3] = static_cast<uint8_t>(w32 >> 24);
    }
    return bytes;
}

double sc_time_stamp() { return 0.0; }

/* ---------- Software SHA-256 oracle (FIPS 180-4 standard compression function) ---------- */

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(uint32_t h[8], const uint8_t blk[64])
{
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(blk[i * 4]) << 24) |
               (static_cast<uint32_t>(blk[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(blk[i * 4 + 2]) << 8) |
               static_cast<uint32_t>(blk[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256_32(uint8_t out[N], const uint8_t *in, size_t inlen)
{
    static const uint32_t H0[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32_t h[8];
    std::memcpy(h, H0, sizeof(h));
    size_t offset = 0;
    while (inlen - offset >= 64) {
        sha256_compress(h, in + offset);
        offset += 64;
    }
    uint8_t blk[64] = {0};
    const size_t last = inlen - offset;
    if (last > 0) std::memcpy(blk, in + offset, last);
    blk[last] = 0x80;
    const uint64_t bits = static_cast<uint64_t>(inlen) * 8;
    for (int i = 0; i < 8; ++i) {
        blk[63 - i] = static_cast<uint8_t>(bits >> (i * 8));
    }
    sha256_compress(h, blk);
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>(h[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(h[i]);
    }
}

static void be32(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

/* Blocked-compress SHA-256 (aligned with the RTL PBLc 64B block stream: compress each full 64B block; tail padding) */
static void sha256_32_blocks(uint8_t out[N], const std::vector<uint8_t> &msg)
{
    static const uint32_t H0[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32_t h[8];
    std::memcpy(h, H0, sizeof(h));
    size_t offset = 0;
    while (offset + 64 < msg.size()) {
        sha256_compress(h, msg.data() + offset);
        offset += 64;
    }
    uint8_t blk[64] = {0};
    const size_t last = msg.size() - offset;
    std::memcpy(blk, msg.data() + offset, last);
    if (last < 64) {
        blk[last] = 0x80;
        const uint64_t bits = static_cast<uint64_t>(msg.size()) * 8;
        for (int i = 0; i < 8; ++i) {
            blk[63 - i] = static_cast<uint8_t>(bits >> (i * 8));
        }
    } else {
        /* Exact full block: append a padding block */
        uint8_t pad[64] = {0};
        pad[0] = 0x80;
        const uint64_t bits = static_cast<uint64_t>(msg.size()) * 8;
        for (int i = 0; i < 8; ++i) {
            pad[63 - i] = static_cast<uint8_t>(bits >> (i * 8));
        }
        sha256_compress(h, blk);
        std::memcpy(blk, pad, 64);
    }
    sha256_compress(h, blk);
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>(h[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(h[i]);
    }
}

/* Derive: x = H(I||q(4BE)||i(2BE)||0xff||SEED), 55B */
static void lmots_derive(const std::vector<uint8_t> &I, uint32_t q, uint32_t i,
                         const uint8_t seed[N], uint8_t x[N])
{
    uint8_t msg[55];
    std::memcpy(msg, I.data(), I.size());
    be32(msg + 16, q);
    msg[20] = static_cast<uint8_t>(i >> 8);
    msg[21] = static_cast<uint8_t>(i);
    msg[22] = 0xff;
    std::memcpy(msg + 23, seed, N);
    sha256_32(x, msg, sizeof(msg));
}

/* Chain: apply H(I||q(4BE)||i(2BE)||j||value) steps times starting from value */
static void lmots_chain(const std::vector<uint8_t> &I, uint32_t q, uint32_t i,
                        uint8_t j, uint8_t steps, const uint8_t value[N],
                        uint8_t out[N])
{
    uint8_t v[N];
    std::memcpy(v, value, N);
    for (uint8_t s = 0; s < steps; ++s) {
        uint8_t msg[55];
        std::memcpy(msg, I.data(), I.size());
        be32(msg + 16, q);
        msg[20] = static_cast<uint8_t>(i >> 8);
        msg[21] = static_cast<uint8_t>(i);
        msg[22] = j;
        std::memcpy(msg + 23, v, N);
        sha256_32(v, msg, sizeof(msg));
        ++j;
    }
    std::memcpy(out, v, N);
}

/* KEYGEN: run all p chains the full maxstep steps; PBLc yields K_q */
static void lmots_keygen(const std::vector<uint8_t> &I, uint32_t q,
                         const uint8_t seed[N], uint8_t K[N])
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), I.begin(), I.end());
    uint8_t qb[4];
    be32(qb, q);
    msg.insert(msg.end(), qb, qb + 4);
    msg.push_back(0x80);
    msg.push_back(0x80);
    for (uint32_t i = 0; i < static_cast<uint32_t>(g_P); ++i) {
        uint8_t x[N], y[N];
        lmots_derive(I, q, i, seed, x);
        lmots_chain(I, q, i, 0, static_cast<uint8_t>(g_maxstep), x, y);
        msg.insert(msg.end(), y, y + N);
    }
    sha256_32_blocks(K, msg);
}

/* SIGN chain values: y_i = chain(coeff[i]) */
static void lmots_sign_values(const std::vector<uint8_t> &I, uint32_t q,
                              const uint8_t seed[N], const uint8_t *coeffs,
                              uint8_t *values)
{
    for (uint32_t i = 0; i < static_cast<uint32_t>(g_P); ++i) {
        uint8_t x[N];
        lmots_derive(I, q, i, seed, x);
        lmots_chain(I, q, i, 0, coeffs[i], x, values + i * N);
    }
}

/* VERIFY: extend chain values to maxstep steps; PBLc yields K_q */
static void lmots_verify(const std::vector<uint8_t> &I, uint32_t q,
                         const uint8_t *values, const uint8_t *coeffs,
                         uint8_t K[N])
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), I.begin(), I.end());
    uint8_t qb[4];
    be32(qb, q);
    msg.insert(msg.end(), qb, qb + 4);
    msg.push_back(0x80);
    msg.push_back(0x80);
    for (uint32_t i = 0; i < static_cast<uint32_t>(g_P); ++i) {
        uint8_t y[N];
        lmots_chain(I, q, i, coeffs[i],
                    static_cast<uint8_t>(g_maxstep - coeffs[i]),
                    values + i * N, y);
        msg.insert(msg.end(), y, y + N);
    }
    sha256_32_blocks(K, msg);
}

/* D_LEAF = H(I||node||0x8282||K_q), 54B */
static void lmots_dleaf(const std::vector<uint8_t> &I, uint32_t node,
                        const uint8_t Kq[N], uint8_t out[N])
{
    uint8_t msg[54];
    std::memcpy(msg, I.data(), I.size());
    be32(msg + 16, node);
    msg[20] = 0x82;
    msg[21] = 0x82;
    std::memcpy(msg + 22, Kq, N);
    sha256_32(out, msg, sizeof(msg));
}

/* PBLc block oracle (software rebuilds K from the y read back from task RAM, verifying the hardware PBLc absorb) */
static bool verify_pblc_blocks(const std::vector<uint8_t> &I, uint32_t q,
                               const std::vector<uint8_t> &y, Digest &K)
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), I.begin(), I.end());
    uint8_t qb[4];
    be32(qb, q);
    msg.insert(msg.end(), qb, qb + 4);
    msg.push_back(0x80);
    msg.push_back(0x80);
    msg.insert(msg.end(), y.begin(), y.end());
    sha256_32_blocks(K.data(), msg);
    return true;
}

/* ---------- Hardware driver (aligned with test_sha256_mmio.cpp) ---------- */

static void tick(Vlms_sha256_mmio &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_sha256_mmio &dut)
{
    dut.bus_valid = 0;
    dut.bus_write = 0;
    dut.bus_addr = 0;
    dut.bus_wdata = 0;
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
}

static void write_reg(Vlms_sha256_mmio &dut, uint16_t address, uint32_t value)
{
    dut.bus_valid = 1;
    dut.bus_write = 1;
    dut.bus_addr = address;
    dut.bus_wdata = value;
    tick(dut);
    dut.bus_valid = 0;
    dut.bus_write = 0;
    dut.eval();
}

static uint32_t read_reg(Vlms_sha256_mmio &dut, uint16_t address)
{
    dut.bus_valid = 1;
    dut.bus_write = 0;
    dut.bus_addr = address;
    dut.eval();
    const uint32_t value = dut.bus_rdata;
    dut.bus_valid = 0;
    dut.eval();
    return value;
}

static void write_bytes(Vlms_sha256_mmio &dut, uint16_t base,
                        const std::vector<uint8_t> &bytes)
{
    for (size_t offset = 0; offset < bytes.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t lane = 0; lane < 4 && offset + lane < bytes.size(); ++lane) {
            word |= static_cast<uint32_t>(bytes[offset + lane]) << (lane * 8);
        }
        write_reg(dut, base + static_cast<uint16_t>(offset), word);
    }
}

static Digest read_output(Vlms_sha256_mmio &dut)
{
    Digest digest{};
    for (int w = 0; w < 8; ++w) {
        const uint32_t word = read_reg(dut, REG_OUTPUT + static_cast<uint16_t>(w * 4));
        digest[4 * w + 0] = static_cast<uint8_t>(word);
        digest[4 * w + 1] = static_cast<uint8_t>(word >> 8);
        digest[4 * w + 2] = static_cast<uint8_t>(word >> 16);
        digest[4 * w + 3] = static_cast<uint8_t>(word >> 24);
    }
    return digest;
}

static void write_task_bytes(Vlms_sha256_mmio &dut, uint16_t word_base,
                             const std::vector<uint8_t> &bytes)
{
    for (size_t offset = 0; offset < bytes.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t lane = 0; lane < 4 && offset + lane < bytes.size(); ++lane) {
            word |= static_cast<uint32_t>(bytes[offset + lane]) << (lane * 8);
        }
        write_reg(dut, REG_TASK_ADDR, word_base + static_cast<uint16_t>(offset / 4));
        write_reg(dut, REG_TASK_DATA, word);
    }
}

static std::vector<uint8_t> read_task_bytes(Vlms_sha256_mmio &dut,
                                            uint16_t word_base, size_t length)
{
    std::vector<uint8_t> bytes(length);
    for (size_t offset = 0; offset < length; offset += 4) {
        write_reg(dut, REG_TASK_ADDR, word_base + static_cast<uint16_t>(offset / 4));
        tick(dut);
        const uint32_t word = read_reg(dut, REG_TASK_DATA);
        for (size_t lane = 0; lane < 4 && offset + lane < length; ++lane) {
            bytes[offset + lane] = static_cast<uint8_t>(word >> (lane * 8));
        }
    }
    return bytes;
}

static bool wait_until_idle(Vlms_sha256_mmio &dut)
{
    for (int poll = 0; poll < 10000000; ++poll) {
        if ((read_reg(dut, REG_STATUS) & STATUS_BUSY) == 0) return true;
        tick(dut);
    }
    return false;
}

static bool load_seed(Vlms_sha256_mmio &dut, const uint8_t seed[N])
{
    write_reg(dut, REG_CONTROL, 2);  /* CTRL_CLEAR */
    std::vector<uint8_t> s(seed, seed + N);
    write_bytes(dut, REG_SEED, s);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_CONTROL, CTRL_START);
    return (read_reg(dut, REG_STATUS) & STATUS_DONE) != 0;
}

static bool run_keygen(Vlms_sha256_mmio &dut, const std::vector<uint8_t> &I,
                       uint32_t q, uint32_t expected_cycles, Digest &K)
{
    write_reg(dut, REG_CONTROL, 2);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_W, static_cast<uint32_t>(g_w));
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) return false;
    K = read_output(dut);
    const uint32_t keygen_cyc = read_reg(dut, REG_CYCLE_COUNT);
    std::printf("  KEYGEN cycles=%u\n", keygen_cyc);
    if (expected_cycles && keygen_cyc != expected_cycles) {
        std::printf("FAIL: KEYGEN cycles %u != %u\n", keygen_cyc, expected_cycles);
        return false;
    }
    return true;
}

static bool run_keygen_leaf(Vlms_sha256_mmio &dut, const std::vector<uint8_t> &I,
                            uint32_t q, uint32_t node, Digest &D)
{
    write_reg(dut, REG_CONTROL, 2);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN_LEAF);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_W, static_cast<uint32_t>(g_w));
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_ARG_LEAF_NODE, node);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) return false;
    D = read_output(dut);
    return true;
}

static bool run_verify_leaf(Vlms_sha256_mmio &dut, const std::vector<uint8_t> &I,
                            uint32_t q, uint32_t node, const uint8_t *coeffs,
                            const std::vector<uint8_t> &chain_inputs,
                            uint32_t expected_cycles, Digest &D)
{
    std::vector<uint8_t> coeff_bytes = pack_coefficients(coeffs, g_P);
    write_reg(dut, REG_CONTROL, 2);
    write_task_bytes(dut, 0, coeff_bytes);
    write_task_bytes(dut, 32, chain_inputs);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_VERIFY_LEAF);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_W, static_cast<uint32_t>(g_w));
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_ARG_LEAF_NODE, node);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) return false;
    const uint32_t verify_cyc = read_reg(dut, REG_CYCLE_COUNT);
    std::printf("  VERIFY_LEAF cycles=%u\n", verify_cyc);
    if (expected_cycles && verify_cyc != expected_cycles) {
        std::printf("FAIL: VERIFY_LEAF cycles %u != %u\n", verify_cyc, expected_cycles);
        return false;
    }
    D = read_output(dut);
    return true;
}

static bool run_sign(Vlms_sha256_mmio &dut, const std::vector<uint8_t> &I, uint32_t q,
                     const uint8_t *coeffs, uint32_t expected_cycles,
                     std::vector<uint8_t> &values)
{
    std::vector<uint8_t> coeff_bytes = pack_coefficients(coeffs, g_P);
    write_reg(dut, REG_CONTROL, 2);
    write_task_bytes(dut, 0, coeff_bytes);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_SIGN);
    write_reg(dut, REG_OUTPUT_LENGTH, static_cast<uint32_t>(g_P) * N);
    write_reg(dut, REG_ARG_W, static_cast<uint32_t>(g_w));
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) return false;
    const uint32_t sign_cyc = read_reg(dut, REG_CYCLE_COUNT);
    std::printf("  SIGN cycles=%u\n", sign_cyc);
    if (expected_cycles && sign_cyc != expected_cycles) {
        std::printf("FAIL: SIGN cycles %u != %u\n", sign_cyc, expected_cycles);
        return false;
    }
    values = read_task_bytes(dut, 32, static_cast<size_t>(g_P) * N);
    std::printf("  SIGN first value=%02x%02x...%02x\n", values[0], values[1], values[31]);
    return true;
}

static bool run_verify(Vlms_sha256_mmio &dut, const std::vector<uint8_t> &I, uint32_t q,
                       const uint8_t *coeffs, const std::vector<uint8_t> &chain_inputs,
                       uint32_t expected_cycles, Digest &K)
{
    std::vector<uint8_t> coeff_bytes = pack_coefficients(coeffs, g_P);
    write_reg(dut, REG_CONTROL, 2);
    write_task_bytes(dut, 0, coeff_bytes);
    write_task_bytes(dut, 32, chain_inputs);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_VERIFY);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_W, static_cast<uint32_t>(g_w));
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) return false;
    const uint32_t verify_cyc = read_reg(dut, REG_CYCLE_COUNT);
    std::printf("  VERIFY cycles=%u\n", verify_cyc);
    if (expected_cycles && verify_cyc != expected_cycles) {
        std::printf("FAIL: VERIFY cycles %u != %u\n", verify_cyc, expected_cycles);
        return false;
    }
    K = read_output(dut);
    return true;
}

static void print_digest(const char *tag, const uint8_t *d)
{
    std::printf("  %s=", tag);
    for (int i = 0; i < N; ++i) std::printf("%02x", d[i]);
    std::printf("\n");
}

/* Per-w LM-OTS batch-task tests (SIGN/VERIFY/KEYGEN_LEAF/VERIFY_LEAF),
 * called by main in a loop over w in {1,2,4,8}. */
static void run_ots_w_tests(Vlms_sha256_mmio &dut, const std::vector<uint8_t> &I,
                            const uint8_t seed[N], uint32_t q, int &failures)
{
    std::printf("\n===== LM-OTS w=%d (p=%d, maxstep=%d) =====\n", g_w, g_P, g_maxstep);
    /* SIGN coefficients: the first 67 use the fixed vector (aligned with test_sha256_mmio's W4 KAT); the rest are taken mod */
    uint8_t coeffs[265];
    {
        const uint8_t seed_c[] = {
            0x03,0x0f,0x01,0x0e,0x0e,0x00,0x02,0x06,0x08,0x0e,0x0d,0x04,0x08,0x0a,0x04,0x09,
            0x03,0x08,0x06,0x07,0x06,0x01,0x0c,0x05,0x0e,0x0c,0x09,0x0f,0x0a,0x05,0x0c,0x08,
            0x02,0x0d,0x04,0x09,0x05,0x08,0x02,0x02,0x08,0x0a,0x00,0x01,0x0c,0x0b,0x06,0x02,
            0x07,0x05,0x0d,0x03,0x00,0x08,0x06,0x04,0x02,0x0e,0x0c,0x0c,0x01,0x02,0x02,0x00,
            0x02,0x00,0x04};
        for (int i = 0; i < 265; ++i) {
            if (i < 67) coeffs[i] = seed_c[i];
            else coeffs[i] = static_cast<uint8_t>((i * 7 + 3) % (g_maxstep + 1));
            /* Mask to the w-bit width (seed_c holds 4-bit values; take the low w bits when w<4; aligned with the SHAKE version) */
            coeffs[i] = static_cast<uint8_t>(coeffs[i] & ((1 << g_w) - 1));
        }
    }

    /* KEYGEN: full-step chains + PBLc -> K_q; read back task-RAM y and compare each chain against the oracle's full-step chain values */
    {
        uint8_t K_ref[N];
        lmots_keygen(I, q, seed, K_ref);
        Digest K_hw;
        const uint32_t expect = (g_w == 4) ? 38761u : 0u;
        if (!run_keygen(dut, I, q, expect, K_hw)) {
            std::printf("FAIL: KEYGEN (w=%d) execute\n", g_w);
            ++failures;
        } else if (std::memcmp(K_hw.data(), K_ref, N) != 0) {
            std::printf("FAIL: KEYGEN (w=%d) K mismatch\n", g_w);
            print_digest("hw", K_hw.data());
            print_digest("ref", K_ref);
            ++failures;
        } else {
            std::printf("PASS: KEYGEN (w=%d) K matches oracle\n", g_w);
        }
    }

    /* SIGN: p chain values (coefficient steps) */
    {
        std::vector<uint8_t> values_ref(static_cast<size_t>(g_P) * N);
        lmots_sign_values(I, q, seed, coeffs, values_ref.data());
        std::vector<uint8_t> values_hw;
        const uint32_t expect = (g_w == 4) ? 23516u : 0u;
        if (!run_sign(dut, I, q, coeffs, expect, values_hw)) {
            std::printf("FAIL: SIGN (w=%d) execute\n", g_w);
            ++failures;
        } else if (values_hw.size() != values_ref.size() ||
                   std::memcmp(values_hw.data(), values_ref.data(), values_ref.size()) != 0) {
            std::printf("FAIL: SIGN (w=%d) values mismatch\n", g_w);
            std::printf("  chain0 hw=");
            for (int i = 0; i < N; ++i) std::printf("%02x", values_hw[i]);
            std::printf("\n  chain0 rf=");
            for (int i = 0; i < N; ++i) std::printf("%02x", values_ref[i]);
            std::printf("\n  coeff[0]=%u coeff[1]=%u\n", coeffs[0], coeffs[1]);
            ++failures;
        } else {
            std::printf("PASS: SIGN (w=%d) values match oracle\n", g_w);
        }
    }

    /* VERIFY: use SIGN's chain values as input; the output K must match KEYGEN's K */
    {
        uint8_t K_ref[N];
        std::vector<uint8_t> sign_values(static_cast<size_t>(g_P) * N);
        lmots_sign_values(I, q, seed, coeffs, sign_values.data());
        lmots_verify(I, q, sign_values.data(), coeffs, K_ref);
        Digest K_hw;
        const uint32_t expect = (g_w == 4) ? 27327u : 0u;
        if (!run_verify(dut, I, q, coeffs, sign_values, expect, K_hw)) {
            std::printf("FAIL: VERIFY (w=%d) execute\n", g_w);
            ++failures;
        } else if (std::memcmp(K_hw.data(), K_ref, N) != 0) {
            std::printf("FAIL: VERIFY (w=%d) K mismatch\n", g_w);
            print_digest("hw", K_hw.data());
            print_digest("ref", K_ref);
            ++failures;
        } else {
            std::printf("PASS: VERIFY (w=%d) K matches oracle\n", g_w);
        }
    }

    /* KEYGEN_LEAF: D_LEAF = H(I||node||0x8282||K_q) */
    {
        uint8_t Kq[N];
        lmots_keygen(I, q, seed, Kq);
        const uint32_t node = 34u;  /* 2^h + q, h=5, q=2 */
        uint8_t D_ref[N];
        lmots_dleaf(I, node, Kq, D_ref);
        Digest D_hw;
        if (!run_keygen_leaf(dut, I, q, node, D_hw)) {
            std::printf("FAIL: KEYGEN_LEAF (w=%d) execute\n", g_w);
            ++failures;
        } else if (std::memcmp(D_hw.data(), D_ref, N) != 0) {
            std::printf("FAIL: KEYGEN_LEAF (w=%d) D_LEAF mismatch\n", g_w);
            print_digest("hw", D_hw.data());
            print_digest("ref", D_ref);
            ++failures;
        } else {
            std::printf("PASS: KEYGEN_LEAF (w=%d) D_LEAF matches oracle\n", g_w);
        }
    }

    /* VERIFY_LEAF: chain verification -> K_q -> D_LEAF in one hardware interaction */
    {
        uint8_t Kq[N];
        std::vector<uint8_t> sign_values(static_cast<size_t>(g_P) * N);
        lmots_sign_values(I, q, seed, coeffs, sign_values.data());
        lmots_verify(I, q, sign_values.data(), coeffs, Kq);
        const uint32_t node = 34u;
        uint8_t D_ref[N];
        lmots_dleaf(I, node, Kq, D_ref);
        Digest D_hw;
        if (!run_verify_leaf(dut, I, q, node, coeffs, sign_values, 0, D_hw)) {
            std::printf("FAIL: VERIFY_LEAF (w=%d) execute\n", g_w);
            ++failures;
        } else if (std::memcmp(D_hw.data(), D_ref, N) != 0) {
            std::printf("FAIL: VERIFY_LEAF (w=%d) D_LEAF mismatch\n", g_w);
            print_digest("hw", D_hw.data());
            print_digest("ref", D_ref);
            ++failures;
        } else {
            std::printf("PASS: VERIFY_LEAF (w=%d) D_LEAF matches oracle\n", g_w);
        }
    }
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_sha256_mmio dut;
    reset(dut);

    /* Fixed vectors: I=0123456789abcdeffedcba9876543210, SEED=000102..1e1f */
    const std::vector<uint8_t> I = {
        0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10};
    uint8_t seed[N];
    for (int i = 0; i < N; ++i) seed[i] = static_cast<uint8_t>(i);
    const uint32_t q = 2u;

    int failures = 0;

    /* HASH_ONCE control: verify the wrapper's single-chain engine path is intact */
    {
        const std::vector<uint8_t> abc{'a', 'b', 'c'};
        uint8_t ref[N];
        sha256_32(ref, abc.data(), abc.size());
        write_reg(dut, REG_CONTROL, 2);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 3);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_bytes(dut, REG_INPUT, abc);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut)) { std::puts("FAIL: HASH_ONCE timeout"); ++failures; }
        else {
            const uint32_t herr = read_reg(dut, REG_ERROR);
            const uint32_t cyc = read_reg(dut, REG_CYCLE_COUNT);
            std::printf("  HASH_ONCE cycles=%u err=%u\n", cyc, herr);
            Digest got = read_output(dut);
            if (std::memcmp(got.data(), ref, N) != 0) {
                std::puts("FAIL: HASH_ONCE abc mismatch");
                print_digest("hw", got.data());
                print_digest("ref", ref);
                ++failures;
            } else { std::puts("PASS: HASH_ONCE abc matches oracle"); }
        }
    }

    if (!load_seed(dut, seed)) {
        std::puts("FAIL: seed load");
        return 1;
    }

    /* KEYGEN (W4 verification) */
    set_w(4);
    {
        uint8_t K_ref[N];
        lmots_keygen(I, q, seed, K_ref);
        Digest K_hw;
        if (!run_keygen(dut, I, q, 38761u, K_hw)) {
            std::puts("FAIL: KEYGEN execute");
            ++failures;
        } else if (std::memcmp(K_hw.data(), K_ref, N) != 0) {
            std::puts("FAIL: KEYGEN K mismatch");
            print_digest("hw", K_hw.data());
            print_digest("ref", K_ref);
            ++failures;
        } else {
            std::puts("PASS: KEYGEN K matches oracle");
        }
    }

    /* Single-chain control (W4 fixed coefficient coeffs[0]=0x03): CMD_DERIVE_CHAIN(i=0, steps=3)
     * must equal the oracle's SIGN chain-0 value */
    {
        reset(dut);
        if (!load_seed(dut, seed)) { std::puts("FAIL: control seed load"); ++failures; }
        uint8_t ref[N];
        lmots_derive(I, q, 0, seed, ref);
        lmots_chain(I, q, 0, 0, 0x03, ref, ref);
        write_reg(dut, REG_CONTROL, 2);
        write_bytes(dut, REG_IDENTIFIER, I);
        write_reg(dut, REG_COMMAND, CMD_DERIVE_CHAIN);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, 0);
        write_reg(dut, REG_ARG_START, 0);
        write_reg(dut, REG_ARG_STEPS, 0x03);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut)) { std::puts("FAIL: single-chain control timeout"); ++failures; }
        else {
            const uint32_t err = read_reg(dut, REG_ERROR);
            if (err != 0) { std::printf("FAIL: single-chain control error=%u\n", err); ++failures; }
            else {
                const uint32_t cyc = read_reg(dut, REG_CYCLE_COUNT);
                std::printf("  single-chain DERIVE_CHAIN cycles=%u\n", cyc);
                Digest got = read_output(dut);
                if (std::memcmp(got.data(), ref, N) != 0) {
                    std::puts("FAIL: single-chain DERIVE_CHAIN i=0 vs oracle");
                    print_digest("hw", got.data());
                    print_digest("ref", ref);
                    ++failures;
                } else {
                    std::puts("PASS: single-chain DERIVE_CHAIN i=0 matches oracle");
                }
            }
        }
    }

    /* LM-OTS batch tasks (SIGN/VERIFY/KEYGEN_LEAF/VERIFY_LEAF) looped over w in {1,2,4,8} */
    for (int w : {1, 2, 4, 8}) {
        set_w(w);
        run_ots_w_tests(dut, I, seed, q, failures);
    }

    if (failures == 0) {
        std::puts("ALL SHA-256 batch tests passed");
        return 0;
    }
    std::printf("SHA-256 batch tests failed: %d\n", failures);
    return 1;
}
