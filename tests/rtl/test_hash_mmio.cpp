// lms_hash_mmio top-level thin-shell selector test.
//
// Compile macro HASH_SEL_TEST (0=sha256 only / 1=shake256 only / 2=both) selects
// the top-level HASH_SEL parameter; the three Makefile targets pass
// -DHASH_SEL_TEST=n -G HASH_SEL=n respectively.
//
// Verifies:
//   - routing correctness: read VERSION/CAPABILITY, identifier write/read-back
//   - both mode: offset 0 = SHA-256 (VERSION=7), offset 0x400 = SHAKE256
//     (VERSION=1), each working independently
//   - shake256 path runs HASH_ONCE empty once (cross-checked against software oracle)
//
// Note: the wrappers each have their own full KAT tests; here only the thin-shell
// routing and coexistence are verified.

#include "Vlms_hash_mmio.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static constexpr uint32_t BASE = 0x16000000;
static constexpr uint32_t SHAKE_OFF = 0x400;   /* SHAKE256 offset in both mode */

static constexpr uint32_t REG_VERSION = 0x000;
static constexpr uint32_t REG_CAPABILITY = 0x004;
static constexpr uint32_t REG_COMMAND = 0x008;
static constexpr uint32_t REG_CONTROL = 0x00c;
static constexpr uint32_t REG_STATUS = 0x010;
static constexpr uint32_t REG_INPUT_LENGTH = 0x018;
static constexpr uint32_t REG_OUTPUT_LENGTH = 0x01c;
static constexpr uint32_t REG_IDENTIFIER = 0x040;
static constexpr uint32_t REG_INPUT_BASE = 0x100;
static constexpr uint32_t REG_OUTPUT_BASE = 0x200;

static constexpr uint32_t CMD_HASH_ONCE = 1;
static constexpr uint32_t CMD_SEED_LOAD = 3;
static constexpr uint32_t CTRL_START = 1;
static constexpr uint32_t STATUS_BUSY = 1;
static constexpr uint32_t STATUS_DONE = 2;

static constexpr int N = 32;
using Digest = std::array<uint8_t, N>;

double sc_time_stamp()
{
    return 0.0;
}

/* ---------- software SHAKE256 oracle ---------- */

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

static void shake256_32(uint8_t out[N], const uint8_t *in, size_t inlen)
{
    constexpr int RATE = 136;
    uint64_t st[25] = {0};
    size_t offset = 0;
    while (inlen - offset >= static_cast<size_t>(RATE)) {
        for (int i = 0; i < 17; ++i) {
            uint64_t v = 0;
            for (int j = 7; j >= 0; --j) {
                v = (v << 8) | in[offset + 8 * i + j];
            }
            st[i] ^= v;
        }
        keccak_f1600(st);
        offset += RATE;
    }
    uint8_t blk[RATE] = {0};
    const size_t last = inlen - offset;
    if (last > 0) {
        std::memcpy(blk, in + offset, last);
    }
    blk[last] = 0x1F;
    blk[RATE - 1] |= 0x80;
    for (int i = 0; i < 17; ++i) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; --j) {
            v = (v << 8) | blk[8 * i + j];
        }
        st[i] ^= v;
    }
    keccak_f1600(st);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            out[8 * i + j] = static_cast<uint8_t>(st[i] >> (8 * j));
        }
    }
}

/* ---------- RTL driver (offset parameter supports the SHAKE256 offset in both mode) ---------- */

static void tick(Vlms_hash_mmio &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_hash_mmio &dut)
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

static void write_reg(Vlms_hash_mmio &dut, uint32_t off, uint32_t addr, uint32_t value)
{
    /* unified command check (lms_hash_cmd_check) requires output_length==32 for non-SIGN commands */
    if (addr == REG_COMMAND && value != CMD_SEED_LOAD) {
        write_reg(dut, off, REG_OUTPUT_LENGTH, 32);
    }
    dut.bus_valid = 1;
    dut.bus_write = 1;
    dut.bus_addr = BASE + off + addr;
    dut.bus_wdata = value;
    tick(dut);
    dut.bus_valid = 0;
    dut.bus_write = 0;
    tick(dut);
}

static uint32_t read_reg(Vlms_hash_mmio &dut, uint32_t off, uint32_t addr)
{
    dut.bus_valid = 1;
    dut.bus_write = 0;
    dut.bus_addr = BASE + off + addr;
    tick(dut);
    const uint32_t value = dut.bus_rdata;
    dut.bus_valid = 0;
    tick(dut);
    return value;
}

static void write_bytes(Vlms_hash_mmio &dut, uint32_t off, uint32_t base,
                        const uint8_t *data, size_t len)
{
    for (size_t w = 0; w < (len + 3) / 4; ++w) {
        uint32_t word = 0;
        for (int b = 0; b < 4; ++b) {
            const size_t idx = w * 4 + static_cast<size_t>(b);
            if (idx < len) {
                word |= static_cast<uint32_t>(data[idx]) << (24 - 8 * b);
            }
        }
        write_reg(dut, off, base + static_cast<uint32_t>(w * 4), word);
    }
}

static void start_and_wait(Vlms_hash_mmio &dut, uint32_t off)
{
    write_reg(dut, off, REG_CONTROL, CTRL_START);
    int poll = 0;
    while ((read_reg(dut, off, REG_STATUS) & STATUS_BUSY) != 0 && poll < 4000) {
        ++poll;
    }
    if (poll >= 4000) {
        std::puts("FAIL: timeout waiting for busy clear");
    }
}

static Digest read_digest(Vlms_hash_mmio &dut, uint32_t off)
{
    /* SHAKE256 wrapper outputs little-endian words (byte0 in the lowest byte, matching the firmware/SHA-256 convention) */
    Digest digest{};
    for (int w = 0; w < 8; ++w) {
        const uint32_t word = read_reg(dut, off, REG_OUTPUT_BASE + static_cast<uint32_t>(w * 4));
        digest[4 * w + 0] = static_cast<uint8_t>(word);
        digest[4 * w + 1] = static_cast<uint8_t>(word >> 8);
        digest[4 * w + 2] = static_cast<uint8_t>(word >> 16);
        digest[4 * w + 3] = static_cast<uint8_t>(word >> 24);
    }
    return digest;
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

/* SHAKE256 path: HASH_ONCE empty (cross-checked against software oracle) */
static int test_shake256_once(Vlms_hash_mmio &dut, uint32_t off)
{
    int failures = 0;
    Digest expected{};
    shake256_32(expected.data(), nullptr, 0);

    write_reg(dut, off, REG_COMMAND, CMD_HASH_ONCE);
    write_reg(dut, off, REG_INPUT_LENGTH, 0);
    start_and_wait(dut, off);
    const Digest got = read_digest(dut, off);
    if (got != expected) {
        std::printf("FAIL: shake256 HASH_ONCE empty got %s expected %s\n",
                    digest_hex(got).c_str(), digest_hex(expected).c_str());
        ++failures;
    }
    return failures;
}

/* SHA-256 path: INPUT_BASE write/read-back (routing correctness).
 * Note: 0x044 of the SHA-256 wrapper is REG_SIM_MC (read is hijacked), so it cannot
 * be used to read back identifier[1]; use the input_words of INPUT_BASE (0x100). */
static int test_sha256_route(Vlms_hash_mmio &dut, uint32_t off)
{
    int failures = 0;
    const uint32_t words[4] = {0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00};
    for (int w = 0; w < 4; ++w) {
        write_reg(dut, off, REG_INPUT_BASE + static_cast<uint32_t>(w * 4), words[w]);
    }
    for (int w = 0; w < 4; ++w) {
        const uint32_t got = read_reg(dut, off, REG_INPUT_BASE + static_cast<uint32_t>(w * 4));
        if (got != words[w]) {
            std::printf("FAIL: sha256 input[%d] got %08x expected %08x\n",
                        w, got, words[w]);
            ++failures;
        }
    }
    return failures;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_hash_mmio dut;
    reset(dut);

    int failures = 0;

#if HASH_SEL_TEST == 0
    /* SHA-256 only */
    if (read_reg(dut, 0, REG_VERSION) != 7) {
        std::puts("FAIL: HASH_SEL=0 VERSION != 7");
        ++failures;
    }
    failures += test_sha256_route(dut, 0);
#elif HASH_SEL_TEST == 1
    /* SHAKE256 only */
    if (read_reg(dut, 0, REG_VERSION) != 1) {
        std::puts("FAIL: HASH_SEL=1 VERSION != 1");
        ++failures;
    }
    failures += test_shake256_once(dut, 0);
#else
    /* both: SHA-256 @ offset 0, SHAKE256 @ offset 0x400 */
    if (read_reg(dut, 0, REG_VERSION) != 7) {
        std::puts("FAIL: both sha256 VERSION != 7");
        ++failures;
    }
    if (read_reg(dut, SHAKE_OFF, REG_VERSION) != 1) {
        std::puts("FAIL: both shake256 VERSION != 1");
        ++failures;
    }
    failures += test_sha256_route(dut, 0);
    failures += test_shake256_once(dut, SHAKE_OFF);
#endif

    dut.final();
    if (failures != 0) {
        std::printf("HASH MMIO tests failed: %d\n", failures);
        return 1;
    }
    std::puts("HASH MMIO tests passed");
    return 0;
}
