#include "Vlms_keccak_core.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using Digest = std::array<uint8_t, 32>;

static constexpr int SHAKE256_RATE = 136; /* bytes = 1088 bits */

double sc_time_stamp()
{
    return 0.0;
}

/* ---------- software Keccak-f[1600] oracle (reference hashs/fips202.c) ---------- */

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
        for (int x = 0; x < 5; ++x) {
            C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                st[x + 5 * y] ^= D[x];
            }
        }
        uint64_t B[25];
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], RHO[x + 5 * y]);
            }
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                st[x + 5 * y] = B[x + 5 * y] ^
                                (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y]);
            }
        }
        st[0] ^= RC[round];
    }
}

static uint64_t load64_le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void store64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>(v >> (8 * i));
    }
}

/* SHAKE256 outputs 32 bytes. rate=136. */
static void shake256_32(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    uint64_t st[25] = {0};
    size_t offset = 0;

    /* Absorb all complete rate blocks (an extra standalone padding block is still needed
     * when the message is an exact multiple of rate) */
    while (inlen - offset >= static_cast<size_t>(SHAKE256_RATE)) {
        for (int i = 0; i < 17; ++i) {
            st[i] ^= load64_le(in + offset + 8 * i);
        }
        keccak_f1600(st);
        offset += SHAKE256_RATE;
    }

    /* Last block (with padding): 0x1F domain separator + pad10*1 */
    uint8_t blk[SHAKE256_RATE] = {0};
    const size_t last = inlen - offset;
    if (last > 0) {
        std::memcpy(blk, in + offset, last);
    }
    blk[last] = 0x1F;
    blk[SHAKE256_RATE - 1] |= 0x80;
    for (int i = 0; i < 17; ++i) {
        st[i] ^= load64_le(blk + 8 * i);
    }
    keccak_f1600(st);

    /* squeeze: read the first 32 bytes of state directly (32B < rate, no further permute needed) */
    for (int i = 0; i < 4; ++i) {
        store64_le(out + 8 * i, st[i]);
    }
}

/* ---------- RTL driver ---------- */

static void tick(Vlms_keccak_core &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_keccak_core &dut)
{
    dut.start = 0;
    dut.init = 0;
    for (int w = 0; w < 34; ++w) {
        dut.block[w] = 0;
    }
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
}

/* byte i -> bits [i*8 +: 8]; 1088-bit -> 34 32-bit words */
static void set_block(Vlms_keccak_core &dut, const uint8_t *block)
{
    for (int w = 0; w < 34; ++w) {
        dut.block[w] = 0;
    }
    for (int i = 0; i < SHAKE256_RATE; ++i) {
        const int w = i / 4;
        const int bit = (i % 4) * 8;
        dut.block[w] |= static_cast<uint32_t>(block[i]) << bit;
    }
}

static Digest get_digest(const Vlms_keccak_core &dut)
{
    Digest digest{};
    for (int i = 0; i < 32; ++i) {
        const int w = i / 4;
        const int bit = (i % 4) * 8;
        digest[i] = static_cast<uint8_t>(dut.digest[w] >> bit);
    }
    return digest;
}

/* Start one rate-block absorb; return the cycle count it took (expected 12). */
static int absorb_block(Vlms_keccak_core &dut,
                        const uint8_t *block,
                        bool init)
{
    set_block(dut, block);
    dut.init = init ? 1 : 0;
    dut.start = 1;
    tick(dut);
    dut.start = 0;

    int cycles = 0;
    while (!dut.done && cycles < 30) {
        tick(dut);
        ++cycles;
    }
    if (!dut.done || dut.busy) {
        std::printf("FAIL: block completion busy=%u done=%u cycles=%d\n",
                    static_cast<unsigned>(dut.busy),
                    static_cast<unsigned>(dut.done),
                    cycles);
        return -1;
    }
    return cycles;
}

static std::vector<uint8_t> hex_bytes(const std::string &hex)
{
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

static std::string digest_hex(const Digest &digest)
{
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (uint8_t b : digest) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

/* Build the rate-block sequence (last block includes padding), consistent with shake256_32's pad rule */
struct RateBlock {
    std::vector<uint8_t> data;
    bool is_last;
};

static std::vector<RateBlock> build_blocks(const std::vector<uint8_t> &message)
{
    std::vector<RateBlock> blocks;
    size_t offset = 0;
    while (message.size() - offset >= static_cast<size_t>(SHAKE256_RATE)) {
        RateBlock b;
        b.data.assign(message.begin() + static_cast<long>(offset),
                      message.begin() + static_cast<long>(offset) + SHAKE256_RATE);
        b.is_last = false;
        blocks.push_back(b);
        offset += SHAKE256_RATE;
    }
    RateBlock last;
    last.data.assign(SHAKE256_RATE, 0);
    const size_t rem = message.size() - offset;
    if (rem > 0) {
        std::memcpy(last.data.data(), message.data() + offset, rem);
    }
    last.data[rem] = 0x1F;
    last.data[SHAKE256_RATE - 1] |= 0x80;
    last.is_last = true;
    blocks.push_back(last);
    return blocks;
}

static int run_case(Vlms_keccak_core &dut,
                    const char *name,
                    const std::vector<uint8_t> &message,
                    const std::string &expected_hex)
{
    const std::vector<RateBlock> blocks = build_blocks(message);

    /* Expected: software oracle */
    uint8_t expect[32];
    shake256_32(expect, message.data(), message.size());
    Digest expected{};
    for (int i = 0; i < 32; ++i) {
        expected[i] = expect[i];
    }
    if (!expected_hex.empty()) {
        const std::vector<uint8_t> kat = hex_bytes(expected_hex);
        for (int i = 0; i < 32; ++i) {
            expected[i] = kat[i];
        }
    }

    reset(dut);
    int total_cycles = 0;
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        const int cycles = absorb_block(dut, blocks[idx].data.data(),
                                        idx == 0u);
        if (cycles < 0) {
            return 1;
        }
        total_cycles += cycles;
    }

    const Digest digest = get_digest(dut);
    if (digest != expected) {
        std::printf("FAIL: %s\n  got      %s\n  expected %s\n",
                    name, digest_hex(digest).c_str(), digest_hex(expected).c_str());
        return 1;
    }
    std::printf("PASS: %-22s blocks=%zu cycles=%d\n", name, blocks.size(), total_cycles);
    return 0;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_keccak_core dut;
    reset(dut);

    int failures = 0;

    /* Authoritative KAT: first 32 bytes of SHAKE256("") (NIST FIPS 202 test vector) */
    {
        std::vector<uint8_t> empty;
        failures += run_case(dut, "empty (KAT)", empty,
                             "46b9dd2b0ba88d13233b3feb743eeb24"
                             "3fcd52ea62b81b82b50c27646ed5762f");
    }
    {
        const std::vector<uint8_t> abc = {'a', 'b', 'c'};
        failures += run_case(dut, "abc", abc, "");
    }
    {
        /* LMS derive-style input: I(16)||q(4)||i(2)||0xff(1)||SEED(32) = 55B */
        std::vector<uint8_t> lms_input;
        for (int i = 0; i < 55; ++i) {
            lms_input.push_back(static_cast<uint8_t>(i * 7 + 3));
        }
        failures += run_case(dut, "lms derive 55B", lms_input, "");
    }
    {
        /* 135B: single block, padding bytes 0x1F and 0x80 in the same byte (0x9F) */
        std::vector<uint8_t> m135(135);
        for (size_t i = 0; i < m135.size(); ++i) {
            m135[i] = static_cast<uint8_t>(0xa0 + (i % 16));
        }
        failures += run_case(dut, "135B single block", m135, "");
    }
    {
        /* 136B: full block + standalone padding block (2 blocks) */
        std::vector<uint8_t> m136(136, 0x11);
        failures += run_case(dut, "136B + pad block", m136, "");
    }
    {
        /* 137B: 1 full block + 1B remainder (2 blocks) */
        std::vector<uint8_t> m137(137, 0x22);
        failures += run_case(dut, "137B two blocks", m137, "");
    }
    {
        /* 200B: 1 full block + 64B remainder */
        std::vector<uint8_t> m200(200);
        for (size_t i = 0; i < m200.size(); ++i) {
            m200[i] = static_cast<uint8_t>(i);
        }
        failures += run_case(dut, "200B", m200, "");
    }
    {
        /* 1000B: 7 full blocks + remainder */
        std::vector<uint8_t> m1000(1000);
        for (size_t i = 0; i < m1000.size(); ++i) {
            m1000[i] = static_cast<uint8_t>((i * 31 + 7) & 0xff);
        }
        failures += run_case(dut, "1000B multi-block", m1000, "");
    }

    dut.final();
    if (failures != 0) {
        std::printf("Keccak core tests failed: %d\n", failures);
        return 1;
    }
    std::puts("Keccak core tests passed");
    return 0;
}
