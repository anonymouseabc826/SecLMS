// SHAKE256 LM-OTS W4 batch-task oracle cross-check (unified refactor S4).
// The software SHAKE256 oracle computes the expected KEYGEN/SIGN/VERIFY/KEYGEN_LEAF values,
// and drives lms_shake256_mmio batch commands for comparison.
//
// W4 N=32 parameters: p=67, ls=4 (src/lms_params.c LMOTS_SHAKE256_N32_W4).
// Chain message (55B): I(16)||q(4)||i(2)||j(1)||value(32)
// Derive message (55B): I||q||i||0xff||SEED
// PBLc message: I||q||0x8080||pub_buf(67*32)
// D_LEAF message: I||node(4)||0x8282||K_q(32), 54B

#include "Vlms_shake256_mmio.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static constexpr uint32_t BASE = 0x16000000;
static constexpr uint32_t REG_VERSION = 0x000;
static constexpr uint32_t REG_CAPABILITY = 0x004;
static constexpr uint32_t REG_COMMAND = 0x008;
static constexpr uint32_t REG_CONTROL = 0x00c;
static constexpr uint32_t REG_STATUS = 0x010;
static constexpr uint32_t REG_ERROR = 0x014;
static constexpr uint32_t REG_INPUT_LENGTH = 0x018;
static constexpr uint32_t REG_OUTPUT_LENGTH = 0x01c;
static constexpr uint32_t REG_CYCLE_COUNT = 0x020;
static constexpr uint32_t REG_ARG_Q = 0x024;
static constexpr uint32_t REG_ARG_I = 0x028;
static constexpr uint32_t REG_ARG_START = 0x02c;
static constexpr uint32_t REG_ARG_STEPS = 0x030;
static constexpr uint32_t REG_ARG_KEY = 0x034;
static constexpr uint32_t REG_TASK_ADDR = 0x038;
static constexpr uint32_t REG_TASK_DATA = 0x03c;
static constexpr uint32_t REG_IDENTIFIER = 0x040;
static constexpr uint32_t REG_ARG_LEAF_NODE = 0x050;
static constexpr uint32_t REG_ARG_W = 0x054;
static constexpr uint32_t REG_SEED_BASE = 0x080;
static constexpr uint32_t REG_INPUT_BASE = 0x100;
static constexpr uint32_t REG_OUTPUT_BASE = 0x200;

static constexpr uint32_t CMD_HASH_ONCE = 1;
static constexpr uint32_t CMD_CHAIN = 2;
static constexpr uint32_t CMD_SEED_LOAD = 3;
static constexpr uint32_t CMD_DERIVE_CHAIN = 4;
static constexpr uint32_t CMD_LMOTS_KEYGEN = 6;
static constexpr uint32_t CMD_LMOTS_SIGN = 7;
static constexpr uint32_t CMD_LMOTS_VERIFY = 8;
static constexpr uint32_t CMD_LMOTS_KEYGEN_LEAF = 0x0e;
static constexpr uint32_t CMD_LMOTS_VERIFY_LEAF = 0x0f;
static constexpr uint32_t CMD_D_INTR_CHAIN = 0x18;
static constexpr uint32_t CTRL_START = 1;
static constexpr uint32_t STATUS_BUSY = 1;
static constexpr uint32_t STATUS_DONE = 2;

static constexpr int N = 32;
static constexpr int LMS_I_LEN = 16;

using Digest = std::array<uint8_t, N>;

/* ---------- Winternitz w parameters (w in {1,2,4,8}, parameterized) ---------- */
static int g_w = 4;            /* current w */
static int g_P = 67;           /* current p */
static int g_maxstep = 15;     /* current 2^w-1 */
static int g_wbits = 4;        /* current coefficient bit width */
static void set_w(int w)
{
    g_w = w;
    switch (w) {
        case 1:  g_P = 265; g_maxstep = 1;   g_wbits = 1; break;
        case 2:  g_P = 133; g_maxstep = 3;   g_wbits = 2; break;
        case 8:  g_P = 34;  g_maxstep = 255; g_wbits = 8; break;
        default: g_P = 67;  g_maxstep = 15;  g_wbits = 4; break;  /* W4 default */
    }
}
/* Compact coefficient packing (aligned with RTL: 32/w coefficients per word, sliced at w-bit width):
 * W1 32 1-bit per word, W2 16 2-bit, W4 8 4-bit, W8 4 8-bit. */
static std::vector<uint8_t> pack_coefficients(const uint8_t *coeffs, int P)
{
    const int per_word = 32 / g_wbits;
    const int nwords = (P + per_word - 1) / per_word;
    std::vector<uint8_t> bytes(nwords * 4, 0);
    for (int i = 0; i < P; ++i) {
        const int word = i / per_word;
        const int lane = i % per_word;
        const uint32_t v = static_cast<uint32_t>(coeffs[i] & ((1 << g_wbits) - 1));
        const uint32_t shift = static_cast<uint32_t>(lane * g_wbits);
        const size_t off = static_cast<size_t>(word) * 4;
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

/* ---------- Software SHAKE256 oracle (same as the Keccak core test) ---------- */

static uint64_t rotl64(uint64_t value, int amount)
{
    return amount == 0 ? value : ((value << amount) | (value >> (64 - amount)));
}

static void keccak_f1600(uint64_t st[25])
{
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    static const int RHO[25] = {
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
        41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
    for (int round = 0; round < 24; ++round) {
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x) C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        for (int x = 0; x < 5; ++x) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x) st[x + 5 * y] ^= D[x];
        uint64_t B[25];
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], RHO[x + 5 * y]);
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x) st[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y]);
        st[0] ^= RC[round];
    }
}

static void shake256_32(uint8_t out[N], const uint8_t *in, size_t inlen)
{
    constexpr int RATE = 136;
    uint64_t st[25] = {0};
    size_t offset = 0;
    while (inlen - offset >= static_cast<size_t>(RATE)) {
        for (int i = 0; i < 17; ++i) {
            uint64_t v = 0;
            for (int j = 7; j >= 0; --j) v = (v << 8) | in[offset + 8 * i + j];
            st[i] ^= v;
        }
        keccak_f1600(st);
        offset += RATE;
    }
    uint8_t blk[RATE] = {0};
    const size_t last = inlen - offset;
    if (last > 0) std::memcpy(blk, in + offset, last);
    blk[last] = 0x1F;
    blk[RATE - 1] |= 0x80;
    for (int i = 0; i < 17; ++i) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; --j) v = (v << 8) | blk[8 * i + j];
        st[i] ^= v;
    }
    keccak_f1600(st);
    for (int i = 0; i < 4; ++i) {
        uint64_t v = st[i];
        for (int j = 0; j < 8; ++j) {
            out[8 * i + j] = static_cast<uint8_t>(v & 0xff);
            v >>= 8;
        }
    }
}

static void be32(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

/* Blocked absorb SHAKE256 (RTL tail-PBLc semantics: after block 0, init=0 continues the sponge;
 * last block adds 0x1F + 0x00.. + 0x80@135 padding). msg is contiguous, auto-split into 136B blocks. */
static void shake256_32_blocks(uint8_t out[N], const std::vector<uint8_t> &msg)
{
    constexpr int RATE = 136;
    uint64_t st[25] = {0};
    size_t offset = 0;
    while (offset < msg.size()) {
        const size_t blklen = (msg.size() - offset >= static_cast<size_t>(RATE))
                                  ? static_cast<size_t>(RATE) : (msg.size() - offset);
        uint8_t blk[RATE] = {0};
        std::memcpy(blk, msg.data() + offset, blklen);
        if (blklen < static_cast<size_t>(RATE)) {
            blk[blklen] = 0x1F;
            blk[RATE - 1] |= 0x80;
        }
        for (int i = 0; i < 17; ++i) {
            uint64_t v = 0;
            for (int j = 7; j >= 0; --j) v = (v << 8) | blk[8 * i + j];
            st[i] ^= v;
        }
        keccak_f1600(st);
        offset += RATE;
    }
    for (int i = 0; i < 4; ++i) {
        uint64_t v = st[i];
        for (int j = 0; j < 8; ++j) {
            out[8 * i + j] = static_cast<uint8_t>(v & 0xff);
            v >>= 8;
        }
    }
}

static void be32_pad(std::vector<uint8_t> &msg, uint32_t v)
{
    uint8_t b[4];
    be32(b, v);
    msg.insert(msg.end(), b, b + 4);
}

/* Boundary targeting: build y (task-RAM chain values) into a full PBLc message (I||q||0x8080||y,
 * 2166B), then absorb it per the RTL tail absorb's 16 blocks (block 0 = header 22B + y[0..113];
 * blocks 1..14 full; block 15 = tail 126B + padding), compared against the hardware K.
 * Coverage: block 0/1 boundary cuts at y[3] byte17 (2-byte lane of 22==2 mod 4); tail 126B+padding. */
static bool verify_pblc_blocks(const std::vector<uint8_t> &I, uint32_t q,
                               const std::vector<uint8_t> &y, Digest &K)
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), I.begin(), I.end());
    be32_pad(msg, q);
    msg.push_back(0x80);
    msg.push_back(0x80);
    msg.insert(msg.end(), y.begin(), y.end());
    if (msg.size() != 22 + static_cast<size_t>(g_P) * N) {
        std::printf("FAIL: PBLc msg len %zu\n", msg.size());
        return false;
    }
    /* Diagnostic: block 0's chain-value part = y[0..2] + y[3][0..17] (18B); block 1 starts at y[3][18..31] */
    std::printf("  PBLc 2166B -> %zu full blocks + 126B tail\n",
                (msg.size() - 126) / 136);
    std::printf("  block0/1 boundary: y[3][15..20]=%02x %02x %02x | %02x %02x %02x\n",
                y[3 * N + 15], y[3 * N + 16], y[3 * N + 17],
                y[3 * N + 18], y[3 * N + 19], y[3 * N + 20]);
    std::printf("  last block: 126B data (last 4B=%02x %02x %02x %02x) + 0x1F..0x80 padding\n",
                msg[msg.size() - 4], msg[msg.size() - 3],
                msg[msg.size() - 2], msg[msg.size() - 1]);
    shake256_32_blocks(K.data(), msg);
    return true;
}

/* ---------- LM-OTS batch oracle ---------- */

/* v = H(I||q||i||j||value), one chain step */
static void lmots_chain_step(const std::vector<uint8_t> &I, uint32_t q, uint32_t i,
                             uint8_t j, const uint8_t value[N], uint8_t out[N])
{
    uint8_t msg[55];
    std::memcpy(msg, I.data(), LMS_I_LEN);
    be32(msg + LMS_I_LEN, q);
    msg[20] = static_cast<uint8_t>(i >> 8);
    msg[21] = static_cast<uint8_t>(i);
    msg[22] = j;
    std::memcpy(msg + 23, value, N);
    shake256_32(out, msg, 55);
}

/* x = H(I||q||i||0xff||SEED) derive */
static void lmots_derive(const std::vector<uint8_t> &I, uint32_t q, uint32_t i,
                         const uint8_t seed[N], uint8_t out[N])
{
    uint8_t msg[55];
    std::memcpy(msg, I.data(), LMS_I_LEN);
    be32(msg + LMS_I_LEN, q);
    msg[20] = static_cast<uint8_t>(i >> 8);
    msg[21] = static_cast<uint8_t>(i);
    msg[22] = 0xff;
    std::memcpy(msg + 23, seed, N);
    shake256_32(out, msg, 55);
}

/* Chain steps steps from the start value, incrementing j on each step */
static void lmots_chain(const std::vector<uint8_t> &I, uint32_t q, uint32_t i,
                        uint8_t start_j, uint8_t steps, const uint8_t value[N],
                        uint8_t out[N])
{
    std::memcpy(out, value, N);
    for (uint8_t s = 0; s < steps; ++s) {
        uint8_t next[N];
        lmots_chain_step(I, q, i, start_j + s, out, next);
        std::memcpy(out, next, N);
    }
}

/* KEYGEN: p chain endpoints -> K = H(I||q||0x8080||pub_buf) */
static void lmots_keygen(const std::vector<uint8_t> &I, uint32_t q,
                         const uint8_t seed[N], uint8_t K[N])
{
    std::vector<uint8_t> pub_buf;
    pub_buf.reserve(g_P * N);
    for (uint32_t i = 0; i < static_cast<uint32_t>(g_P); ++i) {
        uint8_t x[N];
        lmots_derive(I, q, i, seed, x);
        uint8_t y[N];
        lmots_chain(I, q, i, 0, static_cast<uint8_t>(g_maxstep), x, y);
        pub_buf.insert(pub_buf.end(), y, y + N);
    }
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), I.begin(), I.end());
    be32_pad(msg, q);
    msg.push_back(0x80);
    msg.push_back(0x80);
    msg.insert(msg.end(), pub_buf.begin(), pub_buf.end());
    shake256_32(K, msg.data(), msg.size());
}

/* SIGN: p chain values (coefficient a steps; a=0 means the derived value) */
static void lmots_sign_values(const std::vector<uint8_t> &I, uint32_t q,
                              const uint8_t seed[N], const uint8_t *coeffs,
                              uint8_t out[265 * N])   /* W1 maximum tier p=265 */
{
    for (uint32_t i = 0; i < static_cast<uint32_t>(g_P); ++i) {
        uint8_t x[N];
        lmots_derive(I, q, i, seed, x);
        uint8_t y[N];
        lmots_chain(I, q, i, 0, coeffs[i], x, y);
        std::memcpy(out + i * N, y, N);
    }
}

/* VERIFY: chain (maxstep-a) steps from the signature chain inputs -> K */
static void lmots_verify(const std::vector<uint8_t> &I, uint32_t q,
                         const uint8_t *chain_inputs, const uint8_t *coeffs,
                         uint8_t K[N])
{
    std::vector<uint8_t> pub_buf;
    pub_buf.reserve(g_P * N);
    for (uint32_t i = 0; i < static_cast<uint32_t>(g_P); ++i) {
        uint8_t y[N];
        lmots_chain(I, q, i, coeffs[i], static_cast<uint8_t>(g_maxstep - coeffs[i]),
                    chain_inputs + i * N, y);
        pub_buf.insert(pub_buf.end(), y, y + N);
    }
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), I.begin(), I.end());
    be32_pad(msg, q);
    msg.push_back(0x80);
    msg.push_back(0x80);
    msg.insert(msg.end(), pub_buf.begin(), pub_buf.end());
    shake256_32(K, msg.data(), msg.size());
}

/* D_LEAF = H(I||node||0x8282||K_q), 54B */
static void lmots_dleaf(const std::vector<uint8_t> &I, uint32_t node,
                        const uint8_t Kq[N], uint8_t out[N])
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), I.begin(), I.end());
    be32_pad(msg, node);
    msg.push_back(0x82);
    msg.push_back(0x82);
    msg.insert(msg.end(), Kq, Kq + N);
    shake256_32(out, msg.data(), msg.size());
}

/* ---------- Hardware driver (aligned with test_sha256_mmio.cpp) ---------- */

static void tick(Vlms_shake256_mmio &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_shake256_mmio &dut)
{
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
    dut.bus_valid = 0;
    dut.bus_write = 0;
    dut.eval();
}

static void write_reg(Vlms_shake256_mmio &dut, uint32_t address, uint32_t value)
{
    /* The unified command check requires output_length==32 for non-SEED_LOAD commands (SIGN sets 2144 explicitly at the call site) */
    if (address == REG_COMMAND && value != CMD_SEED_LOAD) {
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
    }
    dut.bus_valid = 1;
    dut.bus_write = 1;
    dut.bus_addr = BASE + address;
    dut.bus_wdata = value;
    tick(dut);
    dut.bus_valid = 0;
    dut.bus_write = 0;
    tick(dut);
}

static uint32_t read_reg(Vlms_shake256_mmio &dut, uint32_t address)
{
    dut.bus_valid = 1;
    dut.bus_write = 0;
    dut.bus_addr = BASE + address;
    tick(dut);
    const uint32_t value = dut.bus_rdata;
    dut.bus_valid = 0;
    tick(dut);
    return value;
}

static void write_bytes(Vlms_shake256_mmio &dut, uint32_t base,
                        const std::vector<uint8_t> &bytes)
{
    /* SHAKE256 register byte convention: byte0 holds the word's lowest byte (little-endian, aligned with firmware/SHA-256) */
    for (size_t offset = 0; offset < bytes.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t lane = 0; lane < 4 && offset + lane < bytes.size(); ++lane) {
            word |= static_cast<uint32_t>(bytes[offset + lane]) << (8 * lane);
        }
        write_reg(dut, base + static_cast<uint32_t>(offset), word);
    }
}

static Digest read_output(Vlms_shake256_mmio &dut)
{
    /* SHAKE256 output little-endian words: word's lowest byte = digest byte0 */
    Digest digest{};
    for (int w = 0; w < 8; ++w) {
        const uint32_t word = read_reg(dut, REG_OUTPUT_BASE + static_cast<uint32_t>(w * 4));
        digest[4 * w + 0] = static_cast<uint8_t>(word);
        digest[4 * w + 1] = static_cast<uint8_t>(word >> 8);
        digest[4 * w + 2] = static_cast<uint8_t>(word >> 16);
        digest[4 * w + 3] = static_cast<uint8_t>(word >> 24);
    }
    return digest;
}

static void write_task_bytes(Vlms_shake256_mmio &dut, uint32_t word_base,
                             const std::vector<uint8_t> &bytes)
{
    for (size_t offset = 0; offset < bytes.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t lane = 0; lane < 4 && offset + lane < bytes.size(); ++lane) {
            word |= static_cast<uint32_t>(bytes[offset + lane]) << (lane * 8);
        }
        write_reg(dut, REG_TASK_ADDR, word_base + static_cast<uint32_t>(offset / 4));
        write_reg(dut, REG_TASK_DATA, word);
    }
}

static std::vector<uint8_t> read_task_bytes(Vlms_shake256_mmio &dut,
                                            uint32_t word_base, size_t length)
{
    std::vector<uint8_t> bytes(length);
    for (size_t offset = 0; offset < length; offset += 4) {
        write_reg(dut, REG_TASK_ADDR, word_base + static_cast<uint32_t>(offset / 4));
        tick(dut);
        const uint32_t word = read_reg(dut, REG_TASK_DATA);
        for (size_t lane = 0; lane < 4 && offset + lane < length; ++lane) {
            bytes[offset + lane] = static_cast<uint8_t>(word >> (lane * 8));
        }
    }
    return bytes;
}

static bool wait_until_idle(Vlms_shake256_mmio &dut)
{
    for (int poll = 0; poll < 10000000; ++poll) {
        if ((read_reg(dut, REG_STATUS) & STATUS_BUSY) == 0) return true;
        tick(dut);
    }
    return false;
}

static bool load_seed(Vlms_shake256_mmio &dut, const uint8_t seed[N])
{
    write_reg(dut, REG_CONTROL, 2);  /* CTRL_CLEAR */
    std::vector<uint8_t> s(seed, seed + N);
    write_bytes(dut, REG_SEED_BASE, s);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_CONTROL, CTRL_START);
    return read_reg(dut, REG_STATUS) == STATUS_DONE;
}

static bool run_keygen(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I,
                       uint32_t q, uint32_t expected_cycles, Digest &K)
{
    write_reg(dut, REG_CONTROL, 2);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_W, g_w);
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

static bool run_keygen_leaf(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I,
                            uint32_t q, uint32_t node, Digest &D)
{
    write_reg(dut, REG_CONTROL, 2);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN_LEAF);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_W, g_w);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_ARG_LEAF_NODE, node);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) return false;
    D = read_output(dut);
    return true;
}

static bool run_verify_leaf(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I,
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
    write_reg(dut, REG_ARG_W, g_w);
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

/* D_INTR = H(I||node(4BE)||0x8383(2)||left(32)||right(32)), 86B single block */
static void lmots_dintr(const std::vector<uint8_t> &I, uint32_t node,
                        const uint8_t left[N], const uint8_t right[N],
                        uint8_t out[N])
{
    uint8_t msg[16 + 4 + 2 + N + N];
    std::memcpy(msg, I.data(), I.size());
    be32(msg + 16, node);
    msg[20] = 0x83;
    msg[21] = 0x83;
    std::memcpy(msg + 22, left, N);
    std::memcpy(msg + 54, right, N);
    shake256_32(out, msg, sizeof(msg));
}

/* Chained D_INTR (CMD_D_INTR_CHAIN): initial left in task RAM word32..39, sibling[layer] at
 * word40 + layer*8. arg = leaf node (parity included; P1-6 q=1 fix): hardware picks each layer's
 * concat direction by node parity (odd -> sibling||cur), uses >>1 for the in-block node, node>>=1
 * per layer. N = layers (auth-path height). Output root to output_words. */
static bool run_dintr_chain(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I,
                            uint32_t leaf_node, uint32_t layers,
                            const uint8_t leaf[N],
                            const std::vector<uint8_t> &siblings, Digest &root)
{
    write_reg(dut, REG_CONTROL, 2);
    write_task_bytes(dut, 32, std::vector<uint8_t>(leaf, leaf + N));
    write_task_bytes(dut, 40, siblings);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_D_INTR_CHAIN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_LEAF_NODE, leaf_node);
    write_reg(dut, REG_ARG_STEPS, layers);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) return false;
    const uint32_t dintr_cyc = read_reg(dut, REG_CYCLE_COUNT);
    std::printf("  D_INTR_CHAIN N=%u cycles=%u\n", layers, dintr_cyc);
    root = read_output(dut);
    return true;
}

static bool run_sign(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I, uint32_t q,
                     const uint8_t *coeffs, uint32_t expected_cycles,
                     std::vector<uint8_t> &values)
{
    std::vector<uint8_t> coeff_bytes = pack_coefficients(coeffs, g_P);
    write_reg(dut, REG_CONTROL, 2);
    write_task_bytes(dut, 0, coeff_bytes);
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_SIGN);
    write_reg(dut, REG_OUTPUT_LENGTH, g_P * N);
    write_reg(dut, REG_ARG_W, g_w);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || (read_reg(dut, REG_STATUS) & STATUS_DONE) == 0 ||
        read_reg(dut, REG_ERROR) != 0) {
        std::printf("DBG: SIGN w=%d status=%08x error=%08x cycles=%u\n", g_w,
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR),
                    read_reg(dut, REG_CYCLE_COUNT));
        return false;
    }
    const uint32_t sign_cyc = read_reg(dut, REG_CYCLE_COUNT);
    std::printf("  SIGN cycles=%u\n", sign_cyc);
    if (expected_cycles && sign_cyc != expected_cycles) {
#ifdef DERIVE_SHUFFLE_TEST
        /* DERIVE_SHUFFLE=1: reordering moves the 0-step chain positions -> P2 fold pacing changes
         * -> bounded cycle fluctuation (within +/-9%); functionality via the values oracle, cycle assertion relaxed to WARN. */
        std::printf("WARN: SIGN cycles %u != %u (DERIVE_SHUFFLE fold pacing)\n", sign_cyc, expected_cycles);
#else
        std::printf("FAIL: SIGN cycles %u != %u\n", sign_cyc, expected_cycles);
        return false;
#endif
    }
    values = read_task_bytes(dut, 32, g_P * N);
    std::printf("  SIGN first value=%02x%02x...%02x\n", values[0], values[1], values[31]);
    return true;
}

static bool run_verify(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I, uint32_t q,
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
    write_reg(dut, REG_ARG_W, g_w);
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

/* Measured cycles after the P2/P3 folding (2026-08-17 overnight session, frozen from
 * build/p3_fifo3.log 0 failed; old DEBUG: skip-cycles debt settled here - assertion = measured, regression locks the performance baseline). */
static uint32_t expected_sign_cycles(uint32_t w)
{
    switch (w) {
        case 1: return 3725u;
        case 2: return 3221u;
        case 4: return 4817u;
        default: return 3123u;   /* w=8 */
    }
}
static uint32_t expected_verify_cycles(uint32_t w)
{
    switch (w) {
        case 1: return 9196u;
        case 2: return 5211u;
        case 4: return 7094u;
        default: return 60565u;  /* w=8 */
    }
}
static uint32_t expected_verify_leaf_cycles(uint32_t w)
{
    switch (w) {
        case 1: return 9210u;
        case 2: return 5225u;
        case 4: return 7108u;
        default: return 60579u;  /* w=8 */
    }
}

/* Per-w LM-OTS batch-task tests (SIGN/VERIFY/KEYGEN_LEAF/VERIFY_LEAF),
 * called by main in a loop over w in {1,2,4,8} (set_w already set g_P/g_w/g_maxstep).
 * q is the message sequence number; D_INTR/HASH_ONCE/single-chain controls run separately in main (W4). */
static void run_ots_w_tests(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I,
                            const uint8_t seed[N], uint32_t q, int &failures)
{
    std::printf("\n===== LM-OTS w=%d (p=%d, maxstep=%d) =====\n", g_w, g_P, g_maxstep);
    /* SIGN coefficients: the first 67 use the fixed vector (aligned with the old test); the rest are taken mod g_maxstep, keeping them in 0..maxstep */
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
            if (coeffs[i] > static_cast<uint8_t>(g_maxstep)) coeffs[i] = static_cast<uint8_t>(g_maxstep);
        }
    }

    /* SIGN: p chain values (coefficient steps) */
    {
        uint8_t values_ref[265 * N];   /* W1 maximum tier */
        lmots_sign_values(I, q, seed, coeffs, values_ref);
        std::vector<uint8_t> values_hw;
        if (!run_sign(dut, I, q, coeffs, expected_sign_cycles(g_w), values_hw)) {
            std::printf("FAIL: SIGN (w=%d) execute\n", g_w);
            ++failures;
        } else if (values_hw.size() != static_cast<size_t>(g_P) * N ||
                   std::memcmp(values_hw.data(), values_ref, g_P * N) != 0) {
            std::printf("FAIL: SIGN (w=%d) values mismatch\n", g_w);
            {
                size_t bad = 0;
                while (bad < static_cast<size_t>(g_P) * N &&
                       values_hw[bad] == values_ref[bad]) ++bad;
                std::printf("  first bad byte=%zu (chain %zu)\n", bad, bad / N);
            }
            std::printf("  chain0 hw=");
            for (int i = 0; i < N; ++i) std::printf("%02x", values_hw[i]);
            std::printf("\n  chain0 rf=");
            for (int i = 0; i < N; ++i) std::printf("%02x", values_ref[i]);
            std::printf("\n  chain1 hw=");
            for (int i = 0; i < N; ++i) std::printf("%02x", values_hw[N + i]);
            std::printf("\n  chain1 rf=");
            for (int i = 0; i < N; ++i) std::printf("%02x", values_ref[N + i]);
            std::printf("\n  coeff[0]=%u coeff[1]=%u coeff[2]=%u\n",
                        coeffs[0], coeffs[1], coeffs[2]);
            ++failures;
        } else {
            std::printf("PASS: SIGN (w=%d) values match oracle\n", g_w);
        }
    }

    /* VERIFY: use SIGN's chain values as input; the output K must match KEYGEN's K */
    {
        uint8_t K_ref[N];
        std::vector<uint8_t> sign_values(g_P * N);
        lmots_sign_values(I, q, seed, coeffs, sign_values.data());
        lmots_verify(I, q, sign_values.data(), coeffs, K_ref);
        Digest K_hw;
        if (!run_verify(dut, I, q, coeffs, sign_values, expected_verify_cycles(g_w), K_hw)) {
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

    /* VERIFY_LEAF: chain verification -> K_q -> D_LEAF in one hardware interaction (D_LEAF never leaves hardware) */
    {
        uint8_t Kq[N];
        std::vector<uint8_t> sign_values(g_P * N);
        lmots_sign_values(I, q, seed, coeffs, sign_values.data());
        lmots_verify(I, q, sign_values.data(), coeffs, Kq);   /* K_q */
        const uint32_t node = 34u;  /* 2^h + q, h=5, q=2 */
        uint8_t D_ref[N];
        lmots_dleaf(I, node, Kq, D_ref);
        Digest D_hw;
        if (!run_verify_leaf(dut, I, q, node, coeffs, sign_values,
                             expected_verify_leaf_cycles(g_w), D_hw)) {
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

    /* Reproduction: SIGN after many KEYGEN_LEAF calls (board W4_H15: LMS Sign y all wrong after
     * building a 32768-leaf tree). Determines whether RTL-level "KEYGEN_LEAF residue" is the cause. */
    if (g_w == 4) {
        const int reps = 32768;
        const uint32_t hnode = (1u << 15) + q;   /* H15 leaf node (the large node matching the board) */
        std::printf("  KEYGEN_LEAF stress x%d (node=%u) then SIGN...\n", reps, hnode);
        Digest dummy;
        bool s_ok = true;
        for (int r = 0; r < reps; ++r) {
            if (!run_keygen_leaf(dut, I, q, hnode, dummy)) { s_ok = false; break; }
        }
        if (!s_ok) {
            std::printf("FAIL: KEYGEN_LEAF stress execute\n");
            ++failures;
        } else {
            uint8_t values_ref2[265 * N];
            lmots_sign_values(I, q, seed, coeffs, values_ref2);
            std::vector<uint8_t> values_hw2;
            if (!run_sign(dut, I, q, coeffs, expected_sign_cycles(g_w), values_hw2)) {
                std::printf("FAIL: SIGN after stress execute\n");
                ++failures;
            } else if (values_hw2.size() != static_cast<size_t>(g_P) * N ||
                       std::memcmp(values_hw2.data(), values_ref2, g_P * N) != 0) {
                std::printf("FAIL: SIGN after stress mismatch\n");
                std::printf("  chain0 hw=");
                for (int i = 0; i < N; ++i) std::printf("%02x", values_hw2[i]);
                std::printf("\n  chain0 rf=");
                for (int i = 0; i < N; ++i) std::printf("%02x", values_ref2[i]);
                std::printf("\n");
                ++failures;
            } else {
                std::printf("PASS: SIGN after stress matches oracle\n");
            }
        }
    }
}

/* W1 dense 0-step-chain SIGN stress regression (P3 bg_q FIFO backpressure hole): consecutive (0,0)
 * chain pairs pushed <16 cycles apart trigger "overwrite slot1" data loss / backpressure drop
 * without backpressure; this case locks in the fix. expected_cycles=0: functionality via values oracle. */
static void run_w1_dense_sign_stress(Vlms_shake256_mmio &dut, const std::vector<uint8_t> &I,
                                     const uint8_t seed[N], uint32_t q, int &failures)
{
    set_w(1);   /* p=265, maxstep=1 */
    std::printf("\n===== LM-OTS w=1 DENSE-0 SIGN STRESS (p=%d) =====\n", g_P);
    uint8_t coeffs[265];
    for (int i = 0; i < 265; ++i) coeffs[i] = 0;
    /* Scatter sparse 1-step chains (close to real message bit distribution) but keep long 0 runs -> many (0,0) pairs trigger backpressure */
    for (int i = 0; i < 265; ++i) if ((i % 9) == 7) coeffs[i] = 1;

    uint8_t values_ref[265 * N];
    lmots_sign_values(I, q, seed, coeffs, values_ref);
    std::vector<uint8_t> values_hw;
    if (!run_sign(dut, I, q, coeffs, 0, values_hw)) {
        std::printf("FAIL: DENSE-0 SIGN (w=1) execute\n");
        ++failures;
    } else if (values_hw.size() != static_cast<size_t>(g_P) * N ||
               std::memcmp(values_hw.data(), values_ref, g_P * N) != 0) {
        size_t bad = 0;
        while (bad < static_cast<size_t>(g_P) * N && values_hw[bad] == values_ref[bad]) ++bad;
        std::printf("FAIL: DENSE-0 SIGN (w=1) values mismatch first_bad=%zu (chain %zu)\n",
                    bad, bad / N);
        ++failures;
    } else {
        std::printf("PASS: DENSE-0 SIGN (w=1) values match oracle\n");
    }
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_shake256_mmio dut;
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
        shake256_32(ref, abc.data(), abc.size());
        write_reg(dut, REG_CONTROL, 2);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 3);
        write_bytes(dut, REG_INPUT_BASE, abc);
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

    /* KEYGEN (W4 verification + PBLc boundary targeting; batch tasks loop over w in run_ots_w_tests below) */
    set_w(4);
    {
        uint8_t K_ref[N];
        lmots_keygen(I, q, seed, K_ref);
        Digest K_hw;
        if (!run_keygen(dut, I, q, 8966u, K_hw)) {  /* measured after P2/P3 folding (frozen in p3_fifo3.log) */
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
        /* Boundary targeting: PBLc block absorb (block 0/1 boundary, tail padding) */
        {
            std::vector<uint8_t> y = read_task_bytes(dut, 32, g_P * N);
            Digest K_blocks;
            if (!verify_pblc_blocks(I, q, y, K_blocks)) {
                std::puts("FAIL: PBLc block setup");
                ++failures;
            } else if (std::memcmp(K_blocks.data(), K_hw.data(), N) != 0) {
                std::puts("FAIL: PBLc block absorb mismatch");
                print_digest("hw    ", K_hw.data());
                print_digest("blocks", K_blocks.data());
                /* Diagnostic: compare the first few y chain values against the oracle to tell "chain error" vs "absorb error" apart */
                std::printf("  y[0..31]  =");
                for (int i = 0; i < N; ++i) std::printf("%02x", y[i]);
                std::printf("\n");
                uint8_t x0[N], y0[N];
                lmots_derive(I, q, 0, seed, x0);
                lmots_chain(I, q, 0, 0, static_cast<uint8_t>(g_maxstep), x0, y0);
                std::printf("  oracle y0=");
                for (int i = 0; i < N; ++i) std::printf("%02x", y0[i]);
                std::printf("\n");
                /* Diagnostic: whether the last chain (p-1) was written */
                const int last_off = (g_P - 1) * N;
                std::printf("  y[last..] =");
                for (int i = 0; i < N; ++i) std::printf("%02x", y[last_off + i]);
                std::printf("\n");
                uint8_t xl[N], yl[N];
                lmots_derive(I, q, g_P - 1, seed, xl);
                lmots_chain(I, q, g_P - 1, 0, static_cast<uint8_t>(g_maxstep), xl, yl);
                std::printf("  oracle yL=");
                for (int i = 0; i < N; ++i) std::printf("%02x", yl[i]);
                std::printf("\n");
                ++failures;
            } else {
                std::puts("PASS: PBLc block absorb matches HW K");
            }
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

    /* W1 dense 0-step-chain SIGN stress regression (P3 bg_q FIFO backpressure drop/overwrite hole) */
    run_w1_dense_sign_stress(dut, I, seed, q, failures);

    /* D_INTR_CHAIN: N consecutive D_INTR auth-path layers (for Verify; OTS/LMS semantics layered,
     * root vs software). Covers q parity (node sequence differs) + multiple q. oracle = software
     * lmots_dintr per layer, concat direction by node parity (P1-6 q=1 fix: odd -> sibling||cur). */
    {
        const uint32_t h = 5u;
        for (uint32_t qq : {0u, 1u, 5u, 31u}) {
            const uint32_t leaf_node = (1u << h) + qq;   /* full-tree leaf node number */
            uint8_t leaf[N];
            for (int k = 0; k < N; ++k) leaf[k] = static_cast<uint8_t>(0x10 * qq + k);
            std::vector<uint8_t> siblings;
            uint8_t cur[N];
            std::memcpy(cur, leaf, N);
            for (uint32_t layer = 0; layer < h; ++layer) {
                uint8_t sib[N];
                for (int k = 0; k < N; ++k)
                    sib[k] = static_cast<uint8_t>(0x40 * (layer + 1) + qq * 3 + k);
                siblings.insert(siblings.end(), sib, sib + N);
                const uint32_t cur_node = leaf_node >> layer;
                if ((cur_node & 1u) != 0u) {
                    lmots_dintr(I, cur_node >> 1, sib, cur, cur);  /* right child: sibling||cur */
                } else {
                    lmots_dintr(I, cur_node >> 1, cur, sib, cur);  /* left child: cur||sibling */
                }
            }
            Digest root_hw;
            if (!run_dintr_chain(dut, I, leaf_node, h, leaf, siblings, root_hw)) {
                std::puts("FAIL: D_INTR_CHAIN execute");
                ++failures;
            } else if (std::memcmp(root_hw.data(), cur, N) != 0) {
                std::puts("FAIL: D_INTR_CHAIN root mismatch");
                print_digest("hw", root_hw.data());
                print_digest("ref", cur);
                ++failures;
            } else {
                std::printf("PASS: D_INTR_CHAIN q=%u root matches oracle\n", qq);
            }
        }
    }

    std::printf("SHAKE256 batch tests: %d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
