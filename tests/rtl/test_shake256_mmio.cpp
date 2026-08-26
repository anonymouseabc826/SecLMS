#include "Vlms_shake256_mmio.h"
#include "verilated.h"
#include "verilated_vcd_c.h"

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
static constexpr uint32_t REG_ARG_KEY = 0x034;
static constexpr uint32_t REG_ARG_STEPS = 0x030;
static constexpr uint32_t REG_IDENTIFIER = 0x040;
static constexpr uint32_t REG_SIM_MC = 0x060;      /* secure-domain monotonic counter (SEC slot) */
static constexpr uint32_t REG_SEED_BASE = 0x080;
static constexpr uint32_t REG_WRAPPED_BASE = 0x0a0; /* 48B (SEC slot) */
static constexpr uint32_t REG_KWRAP_BASE = 0x0e0;   /* 32B (SEC slot, K_WRAP/K_STATE) */
static constexpr uint32_t REG_INPUT_BASE = 0x100;
static constexpr uint32_t REG_OUTPUT_BASE = 0x200;
static constexpr uint32_t REG_TASK_ADDR = 0x038;
static constexpr uint32_t REG_TASK_DATA = 0x03c;
static constexpr uint32_t REG_ARG_W = 0x054;

static constexpr uint32_t CMD_HASH_ONCE = 1;
static constexpr uint32_t CMD_CHAIN = 2;
static constexpr uint32_t CMD_SEED_LOAD = 3;
static constexpr uint32_t CMD_DERIVE_CHAIN = 4;
static constexpr uint32_t CMD_DERIVE_RANDOMIZER = 5;
static constexpr uint32_t CMD_MC_STEP = 16;          /* 0x10 secure domain */
static constexpr uint32_t CMD_MC_LOAD = 17;
static constexpr uint32_t CMD_WRAP_SEED = 18;
static constexpr uint32_t CMD_UNWRAP_SEED = 19;
static constexpr uint32_t CMD_HMAC_KSTATE = 20;
static constexpr uint32_t CMD_STATE_COMMIT = 21;
static constexpr uint32_t CMD_HASH_ONCE_RAM = 25;   /* 0x19: multi-block task-RAM input absorb */
static constexpr uint32_t CMD_MSG_Q_COEF = 26;      /* 0x1a: message hash -> Q -> checksum -> coefficients */
static constexpr uint32_t CTRL_START = 1;
static constexpr uint32_t STATUS_BUSY = 1;
static constexpr uint32_t KEY_KWRAP = 1;
static constexpr uint32_t KEY_KSTATE = 2;

static constexpr int N = 32;

using Digest = std::array<uint8_t, N>;

double sc_time_stamp()
{
    return 0.0;
}

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

/* ---------- Software HMAC-SHAKE256 / WRAP oracle (SEC platform instance, cross-checked against the RTL block construction) ----------
 * HMAC-SHAKE256 (RFC 2104 generic construction): K padded to 136B (zeros on the right), ipad/opad = 0x36/0x5c.
 *   inner = SHAKE256((K||0^104) xor ipad || msg, 32B); outer = SHAKE256((K||0^104) xor opad || inner, 32B)
 * WRAP: mask = SHAKE256(k_wrap[32B] || "LMSWRAP-ENC"[11B]); ct = seed xor mask;
 *       tag = first 16B of HMAC-SHAKE256(k_wrap, ct); wrapped = ct || tag (48B). */

static void hmac_shake256_32(uint8_t out[N], const uint8_t *key,
                             const uint8_t *msg, size_t msg_len)
{
    uint8_t block[136];
    std::memset(block, 0x36, sizeof(block));
    for (int i = 0; i < N; ++i) block[i] ^= key[i];
    std::vector<uint8_t> inner_msg(block, block + 136);
    inner_msg.insert(inner_msg.end(), msg, msg + msg_len);
    uint8_t inner[N];
    shake256_32(inner, inner_msg.data(), inner_msg.size());

    std::memset(block, 0x5c, sizeof(block));
    for (int i = 0; i < N; ++i) block[i] ^= key[i];
    std::vector<uint8_t> outer_msg(block, block + 136);
    outer_msg.insert(outer_msg.end(), inner, inner + N);
    shake256_32(out, outer_msg.data(), outer_msg.size());
}

static void wrap_oracle(const uint8_t *kwrap, const uint8_t *seed, uint8_t wrapped[48])
{
    std::vector<uint8_t> m(43);
    std::memcpy(m.data(), kwrap, 32);
    const uint8_t str[11] = {'L', 'M', 'S', 'W', 'R', 'A', 'P', '-', 'E', 'N', 'C'};
    std::memcpy(m.data() + 32, str, 11);
    uint8_t mask[N];
    shake256_32(mask, m.data(), 43);
    uint8_t ct[32];
    for (int i = 0; i < 32; ++i) ct[i] = seed[i] ^ mask[i];
    uint8_t tag[N];
    hmac_shake256_32(tag, kwrap, ct, 32);
    std::memcpy(wrapped, ct, 32);
    std::memcpy(wrapped + 32, tag, 16);   /* first 16B of tag */
}

/* ---------- RTL driver ---------- */

static VerilatedVcdC *g_tfp = nullptr;

static void tick(Vlms_shake256_mmio &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
    Verilated::timeInc(1);
    if (g_tfp) {
        g_tfp->dump(Verilated::time());
    }
}

static void reset(Vlms_shake256_mmio &dut)
{
    dut.bus_valid = 0;
    dut.bus_write = 0;
    dut.bus_addr = 0;
    dut.bus_wdata = 0;
    dut.stream_wr_en = 0;
    dut.stream_wr_addr = 0;
    dut.stream_wr_data = 0;
    dut.stream_rd_en = 0;
    dut.stream_rd_addr = 0;
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
}

static void write_reg(Vlms_shake256_mmio &dut, uint32_t addr, uint32_t value)
{
    /* The unified command check (lms_hash_cmd_check) requires output_length==32 for non-SIGN commands */
    if (addr == REG_COMMAND && value != CMD_SEED_LOAD) {
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
    }
    dut.bus_valid = 1;
    dut.bus_write = 1;
    dut.bus_addr = BASE + addr;
    dut.bus_wdata = value;
    tick(dut);
    dut.bus_valid = 0;
    dut.bus_write = 0;
    tick(dut);
}

static uint32_t read_reg(Vlms_shake256_mmio &dut, uint32_t addr)
{
    dut.bus_valid = 1;
    dut.bus_write = 0;
    dut.bus_addr = BASE + addr;
    tick(dut);
    const uint32_t value = dut.bus_rdata;
    dut.bus_valid = 0;
    tick(dut);
    return value;
}

/* Byte stream -> big-endian word array written to the register region */
static void write_bytes(Vlms_shake256_mmio &dut,
                        uint32_t base,
                        const uint8_t *data,
                        size_t len)
{
    /* Little-endian word convention (aligned with firmware/SHA-256): byte0 holds the word's lowest byte */
    for (size_t w = 0; w < (len + 3) / 4; ++w) {
        uint32_t word = 0;
        for (int b = 0; b < 4; ++b) {
            const size_t idx = w * 4 + static_cast<size_t>(b);
            if (idx < len) {
                word |= static_cast<uint32_t>(data[idx]) << (8 * b);
            }
        }
        write_reg(dut, base + static_cast<uint32_t>(w * 4), word);
    }
}

/* Byte stream -> task RAM (starting at word wbase; write side auto-increments; little-endian word convention same as write_bytes) */
static void write_task_bytes(Vlms_shake256_mmio &dut,
                             uint32_t wbase,
                             const uint8_t *data,
                             size_t len)
{
    write_reg(dut, REG_TASK_ADDR, wbase);
    for (size_t w = 0; w < (len + 3) / 4; ++w) {
        uint32_t word = 0;
        for (int b = 0; b < 4; ++b) {
            const size_t idx = w * 4 + static_cast<size_t>(b);
            if (idx < len) {
                word |= static_cast<uint32_t>(data[idx]) << (8 * b);
            }
        }
        write_reg(dut, REG_TASK_DATA, word);
    }
}

static Digest read_digest(Vlms_shake256_mmio &dut)
{
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

static void start_and_wait(Vlms_shake256_mmio &dut)
{
    write_reg(dut, REG_CONTROL, CTRL_START);
    int poll = 0;
    while ((read_reg(dut, REG_STATUS) & STATUS_BUSY) != 0 && poll < 4000) {
        ++poll;
    }
    if (poll >= 4000) {
        std::puts("FAIL: timeout waiting for busy clear");
    }
    std::printf("DBG: poll=%d cycle_count=%u\n",
                poll, read_reg(dut, REG_CYCLE_COUNT));
}

static uint32_t read_task_word(Vlms_shake256_mmio &dut, uint32_t w)
{
    write_reg(dut, REG_TASK_ADDR, w);
    return read_reg(dut, REG_TASK_DATA);
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

static std::vector<uint8_t> rand_bytes(size_t len, uint32_t seed)
{
    std::vector<uint8_t> out(len);
    uint32_t s = seed;
    for (size_t i = 0; i < len; ++i) {
        s = s * 1664525u + 1013904223u;
        out[i] = static_cast<uint8_t>(s >> 24);
    }
    return out;
}

static void store_u32(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

static void store_u16(uint8_t *p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

/* ---------- Test cases ---------- */

static int test_hash_once(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    /* empty message */
    {
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 0);
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        shake256_32(expected.data(), nullptr, 0);
        if (got != expected) {
            std::printf("FAIL: HASH_ONCE empty got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    /* abc */
    {
        const std::vector<uint8_t> msg = {'a', 'b', 'c'};
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 3);
        write_bytes(dut, REG_INPUT_BASE, msg.data(), msg.size());
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        shake256_32(expected.data(), msg.data(), msg.size());
        if (got != expected) {
            std::printf("FAIL: HASH_ONCE abc got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    /* 128B (upper limit) */
    {
        const std::vector<uint8_t> msg = rand_bytes(128, 0x1234);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 128);
        write_bytes(dut, REG_INPUT_BASE, msg.data(), msg.size());
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        shake256_32(expected.data(), msg.data(), msg.size());
        if (got != expected) {
            std::printf("FAIL: HASH_ONCE 128B got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    std::puts(failures ? "FAIL: HASH_ONCE" : "PASS: HASH_ONCE");
    return failures;
}

static int test_hash_once_ram(Vlms_shake256_mmio &dut)
{
    /* HASH_ONCE_RAM: multi-block absorb from task RAM (starting at word 32) (level 0).
     * Coverage: single block 54B / rem==135 (0x9F boundary) / rem==0 (pure padding block) / 137B (full + tail) /
     * 271B (2 full + tail) / 1078B (~1KB message) / 2048B (upper limit M=16). */
    int failures = 0;
    const uint32_t lens[] = {54u, 135u, 136u, 137u, 271u, 1078u, 2048u};
    uint32_t caseno = 0;
    for (uint32_t len : lens) {
        ++caseno;
        const std::vector<uint8_t> msg = rand_bytes(len, 0xA000 + caseno);
        write_task_bytes(dut, 32, msg.data(), msg.size());
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE_RAM);
        write_reg(dut, REG_INPUT_LENGTH, len);
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        shake256_32(expected.data(), msg.data(), msg.size());
        if (got != expected) {
            std::printf("FAIL: HASH_ONCE_RAM len=%u got %s expected %s\n",
                        len, digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        } else {
            std::printf("PASS: HASH_ONCE_RAM len=%u\n", len);
        }
    }
    std::puts(failures ? "FAIL: HASH_ONCE_RAM" : "PASS: HASH_ONCE_RAM");
    return failures;
}


/* ---------- CMD_MSG_Q_COEF (message hash -> Q -> checksum -> coefficients; P3 unified task-RAM path) ---------- */

static uint32_t lmots_coef_sw(const uint8_t *Q, uint32_t i, uint32_t w)
{
    uint32_t index = (i * w) / 8;
    uint32_t dper = 8 / w;
    uint32_t shift = w * ((~i) & (dper - 1));
    uint32_t mask = (1u << w) - 1u;
    return (Q[index] >> shift) & mask;
}

static uint32_t lmots_checksum_sw(const uint8_t *Q, uint32_t w, uint32_t ls)
{
    uint32_t u = 256 / w;   /* n=32 */
    uint32_t max_digit = (1u << w) - 1u;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < u; ++i) {
        sum += max_digit - lmots_coef_sw(Q, i, w);
    }
    return sum << ls;
}

static int test_msg_q_coef(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    const uint32_t ws[] = {1u, 2u, 4u, 8u};
    const uint32_t ptab[] = {265u, 133u, 67u, 34u};
    const uint32_t lstab[] = {7u, 6u, 4u, 0u};
    /* P3 unified task-RAM path: short messages (0/19/74) + multi-block boundaries (75/81 (block-0
     * last chunk, 0x9F boundary when L=135), 82 (pure padding at L=136), 83, 217 (L=271=2*136-1,
     * last block 0x9F), 300, 1024, 1994 (limit L=2048)) all use the same layout (header word 32 + message word 46) */
    const size_t msglens[] = {0u, 19u, 74u, 75u, 81u, 82u, 83u, 217u, 300u, 1024u, 1994u};
    const std::vector<uint8_t> I = rand_bytes(16, 0x77);
    const uint32_t q = 0x44556677;
    const std::vector<uint8_t> C = rand_bytes(32, 0x88);

    for (int wi = 0; wi < 4; ++wi) {
        const uint32_t w = ws[wi];
        const uint32_t p = ptab[wi];
        const uint32_t ls = lstab[wi];
        for (size_t ml : msglens) {
            const std::vector<uint8_t> msg =
                rand_bytes(ml, 0x9000u + static_cast<uint32_t>(wi * 10u + ml));
            /* Software oracle: Q = shake256(I||q||0x8181||C||message) */
            std::vector<uint8_t> input(54 + ml);
            std::memcpy(input.data(), I.data(), 16);
            store_u32(input.data() + 16, q);
            store_u16(input.data() + 20, 0x8181);
            std::memcpy(input.data() + 22, C.data(), 32);
            if (ml) {
                std::memcpy(input.data() + 54, msg.data(), ml);
            }
            Digest q_exp{};
            shake256_32(q_exp.data(), input.data(), input.size());

            /* checksum + coefficient oracle (Q||checksum16 big-endian, then uniformly sliced) */
            const uint32_t checksum = lmots_checksum_sw(q_exp.data(), w, ls);
            std::vector<uint8_t> Qcs(34);
            std::memcpy(Qcs.data(), q_exp.data(), 32);
            Qcs[32] = static_cast<uint8_t>(checksum >> 8);
            Qcs[33] = static_cast<uint8_t>(checksum);
            std::vector<uint8_t> coef_exp(p);
            for (uint32_t i = 0; i < p; ++i) {
                coef_exp[i] = static_cast<uint8_t>(lmots_coef_sw(Qcs.data(), i, w));
            }

            /* P3.2: MQC read-window base - short messages (L<=128) per w (W4=568/W2=1096/W8=304/W1=568),
             * large messages (L>128) fixed at 568 (message 582) */
            const uint32_t L = 54u + static_cast<uint32_t>(ml);
            const uint32_t mqc_base = (ml <= 74u) ?
                ((w == 1u) ? 568u : 32u + ptab[wi] * 8u) : 568u;
            write_reg(dut, REG_ARG_W, w);
            write_reg(dut, REG_COMMAND, CMD_MSG_Q_COEF);
            write_reg(dut, REG_INPUT_LENGTH, L);
            write_reg(dut, REG_ARG_Q, q);
            write_bytes(dut, REG_IDENTIFIER, I.data(), 16);
            write_task_bytes(dut, mqc_base, input.data(), 54u);
            write_task_bytes(dut, mqc_base + 14u, input.data() + 54, ml);
            start_and_wait(dut);

            const Digest q_got = read_digest(dut);
            bool ok = (q_got == q_exp);

            /* Read coefficient words (0..nwords-1; coefficient-region read side does not auto-increment -> one word at a time) -> unpack */
            const uint32_t nwords = (p * w + 31u) / 32u;
            uint32_t packed[32] = {0u};
            for (uint32_t wd = 0; wd < nwords && wd < 32; ++wd) {
                packed[wd] = read_task_word(dut, wd);
            }
            bool coef_ok = true;
            for (uint32_t i = 0; i < p; ++i) {
                uint32_t bit = i * w;
                uint32_t word = bit / 32u;
                uint32_t shift = bit % 32u;
                uint32_t mask = (w == 8u) ? 0xffu : ((1u << w) - 1u);
                uint8_t got = static_cast<uint8_t>((packed[word] >> shift) & mask);
                if (got != coef_exp[i]) {
                    coef_ok = false;
                    if (i < 3) {
                        std::printf("FAIL: MQC w=%u ml=%zu coef[%u] got %u exp %u\n",
                                    w, ml, i, got, coef_exp[i]);
                    }
                }
            }
            if (!ok) {
                std::printf("FAIL: MQC w=%u ml=%zu Q got %s exp %s\n",
                            w, ml, digest_hex(q_got).c_str(), digest_hex(q_exp).c_str());
            }
            if (!coef_ok) {
                std::printf("FAIL: MQC w=%u ml=%zu coefficients mismatch\n", w, ml);
            }
            if (ok && coef_ok) {
                std::printf("PASS: MQC w=%u ml=%zu\n", w, ml);
            } else {
                ++failures;
            }
        }
    }
    std::puts(failures ? "FAIL: MSG_Q_COEF" : "PASS: MSG_Q_COEF");
    return failures;
}

static int test_chain(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    const std::vector<uint8_t> I = rand_bytes(16, 0x55);
    const uint32_t q = 0x11223344;
    const uint32_t i = 0x0102;
    const std::vector<uint8_t> value = rand_bytes(32, 0x99);

    /* steps=0: output the input directly */
    {
        write_reg(dut, REG_COMMAND, CMD_CHAIN);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, i);
        write_reg(dut, REG_ARG_START, 7);
        write_reg(dut, REG_ARG_STEPS, 0);
        write_bytes(dut, REG_IDENTIFIER, I.data(), I.size());
        write_bytes(dut, REG_INPUT_BASE, value.data(), value.size());
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        for (int k = 0; k < N; ++k) {
            expected[k] = value[k];
        }
        if (got != expected) {
            std::printf("FAIL: CHAIN steps=0 got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    /* steps=1, start=3: single step, isolating block construction vs the multi-step flow */
    {
        const int start = 3;
        const int steps = 1;
        std::vector<uint8_t> v = value;
        for (int j = start; j < start + steps; ++j) {
            std::vector<uint8_t> input(55);
            std::memcpy(input.data(), I.data(), 16);
            store_u32(input.data() + 16, q);
            store_u16(input.data() + 20, static_cast<uint16_t>(i));
            input[22] = static_cast<uint8_t>(j);
            std::memcpy(input.data() + 23, v.data(), N);
            Digest h{};
            shake256_32(h.data(), input.data(), input.size());
            std::memcpy(v.data(), h.data(), N);
        }
        write_reg(dut, REG_COMMAND, CMD_CHAIN);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, i);
        write_reg(dut, REG_ARG_START, start);
        write_reg(dut, REG_ARG_STEPS, steps);
        write_bytes(dut, REG_IDENTIFIER, I.data(), I.size());
        write_bytes(dut, REG_INPUT_BASE, value.data(), value.size());
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        for (int k = 0; k < N; ++k) {
            expected[k] = v[k];
        }
        if (got != expected) {
            std::printf("FAIL: CHAIN steps=1 got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    /* steps=5, start=3 */
    {
        const int start = 3;
        const int steps = 5;
        std::vector<uint8_t> v = value;
        for (int j = start; j < start + steps; ++j) {
            std::vector<uint8_t> input(55);
            std::memcpy(input.data(), I.data(), 16);
            store_u32(input.data() + 16, q);
            store_u16(input.data() + 20, static_cast<uint16_t>(i));
            input[22] = static_cast<uint8_t>(j);
            std::memcpy(input.data() + 23, v.data(), N);
            Digest h{};
            shake256_32(h.data(), input.data(), input.size());
            std::memcpy(v.data(), h.data(), N);
        }
        write_reg(dut, REG_COMMAND, CMD_CHAIN);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, i);
        write_reg(dut, REG_ARG_START, start);
        write_reg(dut, REG_ARG_STEPS, steps);
        write_bytes(dut, REG_IDENTIFIER, I.data(), I.size());
        write_bytes(dut, REG_INPUT_BASE, value.data(), value.size());
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        for (int k = 0; k < N; ++k) {
            expected[k] = v[k];
        }
        if (got != expected) {
            std::printf("FAIL: CHAIN steps=5 start=3 got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    /* steps=15 (w=4 full chain) */
    {
        const int start = 0;
        const int steps = 15;
        std::vector<uint8_t> v = value;
        for (int j = start; j < start + steps; ++j) {
            std::vector<uint8_t> input(55);
            std::memcpy(input.data(), I.data(), 16);
            store_u32(input.data() + 16, q);
            store_u16(input.data() + 20, static_cast<uint16_t>(i));
            input[22] = static_cast<uint8_t>(j);
            std::memcpy(input.data() + 23, v.data(), N);
            Digest h{};
            shake256_32(h.data(), input.data(), input.size());
            std::memcpy(v.data(), h.data(), N);
        }
        write_reg(dut, REG_COMMAND, CMD_CHAIN);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, i);
        write_reg(dut, REG_ARG_START, start);
        write_reg(dut, REG_ARG_STEPS, steps);
        write_bytes(dut, REG_IDENTIFIER, I.data(), I.size());
        write_bytes(dut, REG_INPUT_BASE, value.data(), value.size());
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        Digest expected{};
        for (int k = 0; k < N; ++k) {
            expected[k] = v[k];
        }
        if (got != expected) {
            std::printf("FAIL: CHAIN steps=15 got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    std::puts(failures ? "FAIL: CHAIN" : "PASS: CHAIN");
    return failures;
}

static int test_derive_chain(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    const std::vector<uint8_t> I = rand_bytes(16, 0xaa);
    const std::vector<uint8_t> seed = rand_bytes(32, 0xbb);
    const uint32_t q = 0x00000005;
    const uint32_t i = 0x0007;

    /* I and seed must be written to the RTL registers. SEED moves into the SEC slot (step 2): the
     * SEC latch clears staging, so staging must be rewritten before a repeated SEED_LOAD. */
    write_bytes(dut, REG_IDENTIFIER, I.data(), I.size());
    write_bytes(dut, REG_SEED_BASE, seed.data(), seed.size());
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_CONTROL, CTRL_START);

    /* steps=0/1: after M3 hardening, standalone DERIVE_CHAIN rejects zero/one step
     * (it would expose the private-key elements x_q[i]/H(x_q[i]); ERR_CHAIN_RANGE=6) */
    {
        write_reg(dut, REG_COMMAND, CMD_DERIVE_CHAIN);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, i);
        write_reg(dut, REG_ARG_STEPS, 0);
        start_and_wait(dut);
        if (read_reg(dut, REG_ERROR) != 6) {
            std::printf("FAIL: DERIVE_CHAIN steps=0 expect error 6 got %u\n",
                        read_reg(dut, REG_ERROR));
            ++failures;
        }
    }
    {
        write_reg(dut, REG_COMMAND, CMD_DERIVE_CHAIN);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, i);
        write_reg(dut, REG_ARG_STEPS, 1);
        start_and_wait(dut);
        if (read_reg(dut, REG_ERROR) != 6) {
            std::printf("FAIL: DERIVE_CHAIN steps=1 expect error 6 got %u\n",
                        read_reg(dut, REG_ERROR));
            ++failures;
        }
    }
    /* steps=15: derive + full chain */
    {
        const int steps = 15;
        std::vector<uint8_t> x(55);
        std::memcpy(x.data(), I.data(), 16);
        store_u32(x.data() + 16, q);
        store_u16(x.data() + 20, static_cast<uint16_t>(i));
        x[22] = 0xff;
        std::memcpy(x.data() + 23, seed.data(), N);
        std::vector<uint8_t> v(N);
        shake256_32(v.data(), x.data(), x.size());
        for (int j = 0; j < steps; ++j) {
            std::vector<uint8_t> input(55);
            std::memcpy(input.data(), I.data(), 16);
            store_u32(input.data() + 16, q);
            store_u16(input.data() + 20, static_cast<uint16_t>(i));
            input[22] = static_cast<uint8_t>(j);
            std::memcpy(input.data() + 23, v.data(), N);
            Digest h{};
            shake256_32(h.data(), input.data(), input.size());
            std::memcpy(v.data(), h.data(), N);
        }
        Digest expected{};
        for (int k = 0; k < N; ++k) {
            expected[k] = v[k];
        }

        write_reg(dut, REG_COMMAND, CMD_DERIVE_CHAIN);
        write_reg(dut, REG_ARG_Q, q);
        write_reg(dut, REG_ARG_I, i);
        write_reg(dut, REG_ARG_STEPS, steps);
        start_and_wait(dut);
        const Digest got = read_digest(dut);
        if (got != expected) {
            std::printf("FAIL: DERIVE_CHAIN steps=15 got %s expected %s\n",
                        digest_hex(got).c_str(), digest_hex(expected).c_str());
            ++failures;
        }
    }
    std::puts(failures ? "FAIL: DERIVE_CHAIN" : "PASS: DERIVE_CHAIN");
    return failures;
}

static int test_randomizer(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    const std::vector<uint8_t> I = rand_bytes(16, 0xcc);
    const std::vector<uint8_t> seed = rand_bytes(32, 0xdd);
    const uint32_t q = 0x00000003;

    std::vector<uint8_t> input(54);
    std::memcpy(input.data(), I.data(), 16);
    store_u32(input.data() + 16, q);
    store_u16(input.data() + 20, 0x8585);
    std::memcpy(input.data() + 22, seed.data(), N);
    Digest expected{};
    shake256_32(expected.data(), input.data(), input.size());

    /* I must be written to the RTL registers (seed was already written by setup) */
    write_bytes(dut, REG_IDENTIFIER, I.data(), I.size());
    write_reg(dut, REG_COMMAND, CMD_DERIVE_RANDOMIZER);
    write_reg(dut, REG_ARG_Q, q);
    start_and_wait(dut);
    const Digest got = read_digest(dut);
    if (got != expected) {
        std::printf("FAIL: RANDOMIZER got %s expected %s\n",
                    digest_hex(got).c_str(), digest_hex(expected).c_str());
        ++failures;
    }
    std::puts(failures ? "FAIL: RANDOMIZER" : "PASS: RANDOMIZER");
    return failures;
}

/* ---------- Secure domain SEC (step 2: SHAKE256 wired into lms_sha256_sec with HASH_TYPE=1) ---------- */

static int test_sec_mc(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    /* MC_STEP: sim_mc 0->1, output_words[0] reads back the new value */
    write_reg(dut, REG_COMMAND, CMD_MC_STEP);
    start_and_wait(dut);
    uint32_t mc = read_reg(dut, REG_SIM_MC);
    uint32_t out0 = read_reg(dut, REG_OUTPUT_BASE);
    if (mc != 1u || out0 != 1u) {
        std::printf("FAIL: SEC MC_STEP sim_mc=%u out0=%u\n", mc, out0);
        ++failures;
    }
    /* MC_STEP increments again */
    write_reg(dut, REG_COMMAND, CMD_MC_STEP);
    start_and_wait(dut);
    mc = read_reg(dut, REG_SIM_MC);
    if (mc != 2u) {
        std::printf("FAIL: SEC MC_STEP2 sim_mc=%u\n", mc);
        ++failures;
    }
    /* MC_LOAD: reload the initial value (REVIEW B07-R3: out0 readback must equal the loaded value; the old semantics wrongly reported sim_mc+1) */
    write_reg(dut, REG_COMMAND, CMD_MC_LOAD);
    write_reg(dut, REG_ARG_Q, 0x12345678u);
    start_and_wait(dut);
    mc = read_reg(dut, REG_SIM_MC);
    out0 = read_reg(dut, REG_OUTPUT_BASE);
    if (mc != 0x12345678u || out0 != 0x12345678u) {
        std::printf("FAIL: SEC MC_LOAD sim_mc=%08x out0=%08x\n", mc, out0);
        ++failures;
    }
    std::puts(failures ? "FAIL: SEC MC" : "PASS: SEC MC");
    return failures;
}

static int test_sec_hmac(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    const std::vector<uint8_t> K = rand_bytes(32, 0x11);
    const std::vector<uint8_t> msg = rand_bytes(55, 0x22);
    /* Load K_STATE (SEED_LOAD arg_key=2 -> SEC k_state slot) */
    write_bytes(dut, REG_KWRAP_BASE, K.data(), K.size());
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, KEY_KSTATE);
    start_and_wait(dut);
    /* HMAC_KSTATE: INPUT <=119B, cross-checked against software HMAC-SHAKE256 */
    write_reg(dut, REG_COMMAND, CMD_HMAC_KSTATE);
    write_reg(dut, REG_INPUT_LENGTH, static_cast<uint32_t>(msg.size()));
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_bytes(dut, REG_INPUT_BASE, msg.data(), msg.size());
    start_and_wait(dut);
    const Digest got = read_digest(dut);
    Digest expected{};
    hmac_shake256_32(expected.data(), K.data(), msg.data(), msg.size());
    if (got != expected) {
        std::printf("FAIL: HMAC_KSTATE got %s expected %s\n",
                    digest_hex(got).c_str(), digest_hex(expected).c_str());
        ++failures;
    }
    std::puts(failures ? "FAIL: SEC HMAC" : "PASS: SEC HMAC");
    return failures;
}

static int test_sec_state_commit(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    const std::vector<uint8_t> K = rand_bytes(32, 0x66);
    /* Load K_STATE */
    write_bytes(dut, REG_KWRAP_BASE, K.data(), K.size());
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, KEY_KSTATE);
    start_and_wait(dut);

    /* Expected tx = sim_mc+1 (generated monotonically by hardware) */
    const uint32_t mc = read_reg(dut, REG_SIM_MC);
    const uint32_t tx = mc + 1u;
    const uint16_t state = 0x0002u;   /* SEC_ST_RESERVED */
    const uint32_t ctr = 0x00000042u;
    const uint8_t aad = 0u;           /* slot A */

    /* Expected body = magic"LMSS"||state BE||ctr BE||tx BE||reserved(34,0)||aad */
    uint8_t body[49] = {};
    body[0] = 0x4c; body[1] = 0x4d; body[2] = 0x53; body[3] = 0x53;
    body[4] = static_cast<uint8_t>(state >> 8);
    body[5] = static_cast<uint8_t>(state);
    body[6] = static_cast<uint8_t>(ctr >> 24);
    body[7] = static_cast<uint8_t>(ctr >> 16);
    body[8] = static_cast<uint8_t>(ctr >> 8);
    body[9] = static_cast<uint8_t>(ctr);
    body[10] = static_cast<uint8_t>(tx >> 24);
    body[11] = static_cast<uint8_t>(tx >> 16);
    body[12] = static_cast<uint8_t>(tx >> 8);
    body[13] = static_cast<uint8_t>(tx);
    body[48] = aad;
    Digest expected{};
    hmac_shake256_32(expected.data(), K.data(), body, 49);

    write_reg(dut, REG_ARG_I, state);
    write_reg(dut, REG_ARG_Q, ctr);
    write_reg(dut, REG_ARG_KEY, aad);
    write_reg(dut, REG_COMMAND, CMD_STATE_COMMIT);
    start_and_wait(dut);

    /* Result: word0=tx, word1..4=tag (first 16B), word5..7=0 */
    const uint32_t got_tx = read_reg(dut, REG_OUTPUT_BASE);
    if (got_tx != tx) {
        std::printf("FAIL: STATE_COMMIT tx=%08x expected %08x\n", got_tx, tx);
        ++failures;
    }
    for (int w = 0; w < 4; ++w) {
        const uint32_t word = read_reg(dut, REG_OUTPUT_BASE + 4u + static_cast<uint32_t>(w * 4));
        const uint8_t got_b[4] = {
            static_cast<uint8_t>(word), static_cast<uint8_t>(word >> 8),
            static_cast<uint8_t>(word >> 16), static_cast<uint8_t>(word >> 24)};
        if (std::memcmp(got_b, expected.data() + 4 * w, 4) != 0) {
            std::printf("FAIL: STATE_COMMIT tag word%d %02x%02x%02x%02x expected %02x%02x%02x%02x\n",
                        w, got_b[0], got_b[1], got_b[2], got_b[3],
                        expected[4 * w], expected[4 * w + 1],
                        expected[4 * w + 2], expected[4 * w + 3]);
            ++failures;
        }
    }
    /* sim_mc has incremented to tx */
    if (read_reg(dut, REG_SIM_MC) != tx) {
        std::printf("FAIL: STATE_COMMIT sim_mc=%08x expected %08x\n",
                    read_reg(dut, REG_SIM_MC), tx);
        ++failures;
    }
    /* Second back-to-back commit: tx stays monotonic (tx'=tx+1, tag cross-checked as it varies with tx) */
    {
        const uint32_t tx2 = tx + 1u;
        uint8_t body2[49] = {};
        std::memcpy(body2, body, 49);
        body2[10] = static_cast<uint8_t>(tx2 >> 24);
        body2[11] = static_cast<uint8_t>(tx2 >> 16);
        body2[12] = static_cast<uint8_t>(tx2 >> 8);
        body2[13] = static_cast<uint8_t>(tx2);
        Digest expected2{};
        hmac_shake256_32(expected2.data(), K.data(), body2, 49);
        write_reg(dut, REG_COMMAND, CMD_STATE_COMMIT);
        start_and_wait(dut);
        if (read_reg(dut, REG_OUTPUT_BASE) != tx2) {
            std::printf("FAIL: STATE_COMMIT2 tx=%08x expected %08x\n",
                        read_reg(dut, REG_OUTPUT_BASE), tx2);
            ++failures;
        }
        const uint32_t word = read_reg(dut, REG_OUTPUT_BASE + 4u);
        const uint8_t got_b[4] = {
            static_cast<uint8_t>(word), static_cast<uint8_t>(word >> 8),
            static_cast<uint8_t>(word >> 16), static_cast<uint8_t>(word >> 24)};
        if (std::memcmp(got_b, expected2.data(), 4) != 0) {
            std::puts("FAIL: STATE_COMMIT2 tag word0");
            ++failures;
        }
    }
    std::puts(failures ? "FAIL: SEC STATE_COMMIT" : "PASS: SEC STATE_COMMIT");
    return failures;
}

static int test_sec_wrap_unwrap(Vlms_shake256_mmio &dut)
{
    int failures = 0;
    const std::vector<uint8_t> K = rand_bytes(32, 0x33);
    const std::vector<uint8_t> seed = rand_bytes(32, 0x44);
    /* Load K_WRAP (arg_key=1) */
    write_bytes(dut, REG_KWRAP_BASE, K.data(), K.size());
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, KEY_KWRAP);
    start_and_wait(dut);
    /* Load SEED (arg_key=0 -> SEC seed slot; the latch clears staging, so it must be written first).
     * NOTE: arg_key must be reset to 0 first: a leftover KEY_KWRAP makes cmd_check treat it as ACT_DONE_KWRAP. */
    write_bytes(dut, REG_SEED_BASE, seed.data(), seed.size());
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    start_and_wait(dut);
    /* WRAP_SEED: read the 48B WRAPPED and cross-check against the oracle */
    write_reg(dut, REG_COMMAND, CMD_WRAP_SEED);
    start_and_wait(dut);
    uint8_t wrapped[48];
    for (int w = 0; w < 12; ++w) {
        const uint32_t word = read_reg(dut, REG_WRAPPED_BASE + static_cast<uint32_t>(w * 4));
        wrapped[4 * w + 0] = static_cast<uint8_t>(word);
        wrapped[4 * w + 1] = static_cast<uint8_t>(word >> 8);
        wrapped[4 * w + 2] = static_cast<uint8_t>(word >> 16);
        wrapped[4 * w + 3] = static_cast<uint8_t>(word >> 24);
    }
    uint8_t expected[48];
    wrap_oracle(K.data(), seed.data(), expected);
    if (std::memcmp(wrapped, expected, 48) != 0) {
        std::printf("FAIL: SEC WRAP ct/tag mismatch\n  K    = ");
        for (int i = 0; i < 32; ++i) std::printf("%02x", K[i]);
        std::printf("\n  seed = ");
        for (int i = 0; i < 32; ++i) std::printf("%02x", seed[i]);
        std::printf("\n  hw ct = ");
        for (int i = 0; i < 32; ++i) std::printf("%02x", wrapped[i]);
        std::printf("\n  sw ct = ");
        for (int i = 0; i < 32; ++i) std::printf("%02x", expected[i]);
        std::printf("\n  hw tag = ");
        for (int i = 32; i < 48; ++i) std::printf("%02x", wrapped[i]);
        std::printf("\n  sw tag = ");
        for (int i = 32; i < 48; ++i) std::printf("%02x", expected[i]);
        std::printf("\n");
        ++failures;
    }
    /* UNWRAP_SEED: write WRAPPED -> unwrap (tag verified) -> DERIVE(2 steps) verifies seed restore
     * (after M3 hardening, zero-step DERIVE_CHAIN is rejected; a two-step chain verifies the same semantics) */
    write_bytes(dut, REG_WRAPPED_BASE, wrapped, 48);
    write_reg(dut, REG_COMMAND, CMD_UNWRAP_SEED);
    start_and_wait(dut);
    const std::vector<uint8_t> I = rand_bytes(16, 0x55);
    const uint32_t q = 0x00000007;
    const uint32_t i = 0x0003;
    write_bytes(dut, REG_IDENTIFIER, I.data(), I.size());
    std::vector<uint8_t> input(55);
    std::memcpy(input.data(), I.data(), 16);
    store_u32(input.data() + 16, q);
    store_u16(input.data() + 20, static_cast<uint16_t>(i));
    input[22] = 0xff;
    std::memcpy(input.data() + 23, seed.data(), N);
    std::vector<uint8_t> v(N);
    shake256_32(v.data(), input.data(), input.size());
    for (int j = 0; j < 2; ++j) {
        std::vector<uint8_t> step_in(55);
        std::memcpy(step_in.data(), I.data(), 16);
        store_u32(step_in.data() + 16, q);
        store_u16(step_in.data() + 20, static_cast<uint16_t>(i));
        step_in[22] = static_cast<uint8_t>(j);
        std::memcpy(step_in.data() + 23, v.data(), N);
        Digest h{};
        shake256_32(h.data(), step_in.data(), step_in.size());
        std::memcpy(v.data(), h.data(), N);
    }
    Digest exp_derive{};
    for (int k = 0; k < N; ++k) {
        exp_derive[k] = v[k];
    }
    write_reg(dut, REG_COMMAND, CMD_DERIVE_CHAIN);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_ARG_I, i);
    write_reg(dut, REG_ARG_STEPS, 2);
    start_and_wait(dut);
    const Digest got_derive = read_digest(dut);
    if (got_derive != exp_derive) {
        std::printf("FAIL: SEC UNWRAP seed restore (DERIVE) got %s expected %s\n",
                    digest_hex(got_derive).c_str(), digest_hex(exp_derive).c_str());
        ++failures;
    }
    std::puts(failures ? "FAIL: SEC WRAP/UNWRAP" : "PASS: SEC WRAP/UNWRAP");
    return failures;
}

/* ---------- Task-RAM stream port (Step 2, in front of the UART bridge) ---------- */

static int test_stream_port(Vlms_shake256_mmio &dut)
{
    int failures = 0;

    /* 1) Stream write -> MMIO readback: set done first (SEED_LOAD completes immediately and does
     *    not touch task RAM; MMIO task-RAM reads need done_r=1). Stream-write 4 words, MMIO readback verifies cross-path consistency. */
    {
        write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
        write_reg(dut, REG_CONTROL, CTRL_START);
        const uint32_t wbase = 32;
        const uint32_t wdata[4] = {0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u};
        for (int i = 0; i < 4; ++i) {
            dut.stream_wr_en = 1;
            dut.stream_wr_addr = wbase + static_cast<uint32_t>(i);
            dut.stream_wr_data = wdata[i];
            tick(dut);
        }
        dut.stream_wr_en = 0;
        tick(dut);
        bool ok = true;
        for (int i = 0; i < 4; ++i) {
            write_reg(dut, REG_TASK_ADDR, wbase + static_cast<uint32_t>(i));
            tick(dut);
            const uint32_t v = read_reg(dut, REG_TASK_DATA);
            if (v != wdata[i]) {
                ok = false;
                std::printf("FAIL: stream-wr->mmio-rd word %d got %08x want %08x\n",
                            i, v, wdata[i]);
            }
        }
        if (ok) std::puts("PASS: stream-wr -> mmio-rd roundtrip");
        else ++failures;
    }

    /* 2) MMIO write -> stream readback (verifies the stream_rd_valid/stream_rd_data handshake timing) */
    {
        const uint32_t wbase = 40;
        const uint32_t wdata[4] = {0xdeadbeefu, 0x12345678u, 0xa5a5a5a5u, 0x0f0f0f0fu};
        for (int i = 0; i < 4; ++i) {
            write_reg(dut, REG_TASK_ADDR, wbase + static_cast<uint32_t>(i));
            write_reg(dut, REG_TASK_DATA, wdata[i]);
        }
        bool ok = true;
        for (int i = 0; i < 4; ++i) {
            dut.stream_rd_en = 1;
            dut.stream_rd_addr = wbase + static_cast<uint32_t>(i);
            tick(dut);                 /* posedge: pending<=1, task_ram_read_r<=task_words[addr] */
            dut.stream_rd_en = 0;
            /* Synchronous read handshake: valid/data are ready after the request cycle's posedge (the next posedge clears pending) */
            if (!dut.stream_rd_valid || dut.stream_rd_data != wdata[i]) {
                ok = false;
                std::printf("FAIL: mmio-wr->stream-rd word %d valid=%u data=%08x want=%08x\n",
                            i, static_cast<unsigned>(dut.stream_rd_valid),
                            static_cast<unsigned>(dut.stream_rd_data), wdata[i]);
            }
            tick(dut);                 /* idle cycle (clears pending) */
        }
        if (ok) std::puts("PASS: mmio-wr -> stream-rd roundtrip");
        else ++failures;
    }

    /* 3) The stream port is ignored while the core is busy (mutual exclusion): stream writes inside the HASH_ONCE busy window do not overwrite task RAM */
    {
        const uint32_t wbase = 48;
        const uint32_t golden = 0x12345678u;
        write_reg(dut, REG_TASK_ADDR, wbase);
        write_reg(dut, REG_TASK_DATA, golden);
        const std::vector<uint8_t> abc{'a', 'b', 'c'};
        write_bytes(dut, REG_INPUT_BASE, abc.data(), abc.size());
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 3);
        write_reg(dut, REG_CONTROL, CTRL_START);
        tick(dut);
        tick(dut);
        tick(dut);                     /* enter the busy window */
        const bool was_busy = dut.stream_busy;
        if (was_busy) {
            dut.stream_wr_en = 1;
            dut.stream_wr_addr = wbase;
            dut.stream_wr_data = 0xffffffffu;
            tick(dut);
            dut.stream_wr_en = 0;
            tick(dut);
        }
        int poll = 0;
        while ((read_reg(dut, REG_STATUS) & STATUS_BUSY) != 0 && poll < 4000) {
            ++poll;
        }
        write_reg(dut, REG_TASK_ADDR, wbase);
        tick(dut);
        const uint32_t v = read_reg(dut, REG_TASK_DATA);
        if (!was_busy) {
            std::puts("NOTE: busy window not observed, mutual-exclusion check skipped");
        } else if (v == golden) {
            std::puts("PASS: stream-wr ignored while busy");
        } else {
            std::printf("FAIL: stream-wr clobbered task RAM while busy (got %08x)\n", v);
            ++failures;
        }
    }

    return failures;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Verilated::traceEverOn(true);
    Vlms_shake256_mmio dut;
    reset(dut);

    VerilatedVcdC *tfp = new VerilatedVcdC;
    dut.trace(tfp, 99);
    tfp->open("build/shake_trace.vcd");
    g_tfp = tfp;

    int failures = 0;

    /* VERSION/CAPABILITY */
    if (read_reg(dut, REG_VERSION) != 1) {
        std::puts("FAIL: VERSION");
        ++failures;
    }

    /* Prepare I/SEED (for DERIVE/RANDOMIZER) */
    write_bytes(dut, REG_IDENTIFIER, nullptr, 0); /* placeholder; each test case writes its own */

    failures += test_stream_port(dut);
    failures += test_hash_once(dut);
    failures += test_hash_once_ram(dut);
    failures += test_msg_q_coef(dut);
    failures += test_chain(dut);
    tfp->close();

    /* DERIVE_CHAIN/RANDOMIZER need SEED */
    {
        const std::vector<uint8_t> seed = rand_bytes(32, 0xbb);
        write_bytes(dut, REG_SEED_BASE, seed.data(), seed.size());
        write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
        write_reg(dut, REG_CONTROL, CTRL_START);
    }
    failures += test_derive_chain(dut);

    {
        const std::vector<uint8_t> seed = rand_bytes(32, 0xdd);
        write_bytes(dut, REG_SEED_BASE, seed.data(), seed.size());
        write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
        write_reg(dut, REG_CONTROL, CTRL_START);
    }
    failures += test_randomizer(dut);

    /* Secure domain SEC (step 2): MC/HMAC/WRAP/UNWRAP cross-checked against the software oracle.
     * Kept last: SEC tests overwrite the SEC slots (seed/k_wrap/k_state/sim_mc) without affecting earlier cases. */
    failures += test_sec_mc(dut);
    failures += test_sec_hmac(dut);
    failures += test_sec_wrap_unwrap(dut);
    failures += test_sec_state_commit(dut);

    dut.final();
    if (failures != 0) {
        std::printf("SHAKE256 MMIO tests failed: %d\n", failures);
        return 1;
    }
    std::puts("SHAKE256 MMIO tests passed");
    return 0;
}
