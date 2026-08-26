#include "Vlms_sha256_mmio.h"
#include "verilated.h"
#include "verilated_vcd_c.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using Digest = std::array<uint8_t, 32>;

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
static constexpr uint16_t REG_SIM_MC = 0x060;
static constexpr uint16_t REG_ARG_LEAF_NODE = 0x050;
static constexpr uint16_t REG_ARG_W = 0x054;
static constexpr uint16_t REG_SEED = 0x080;
static constexpr uint16_t REG_WRAPPED = 0x0a0;
static constexpr uint16_t REG_KWRAP = 0x0e0;
static constexpr uint16_t REG_INPUT = 0x100;
static constexpr uint16_t REG_OUTPUT = 0x200;

static constexpr uint32_t CMD_HASH_ONCE = 1;
static constexpr uint32_t CMD_CHAIN = 2;
static constexpr uint32_t CMD_SEED_LOAD = 3;
static constexpr uint32_t CMD_DERIVE_CHAIN = 4;
static constexpr uint32_t CMD_DERIVE_RANDOMIZER = 5;
static constexpr uint32_t CMD_LMOTS_KEYGEN = 6;
static constexpr uint32_t CMD_LMOTS_SIGN = 7;
static constexpr uint32_t CMD_LMOTS_VERIFY = 8;
static constexpr uint32_t CMD_MC_STEP = 16;
static constexpr uint32_t CMD_MC_LOAD = 17;
static constexpr uint32_t CMD_WRAP_SEED = 18;
static constexpr uint32_t CMD_UNWRAP_SEED = 19;
static constexpr uint32_t CMD_HMAC_KSTATE = 20;
static constexpr uint32_t CMD_STATE_COMMIT = 21;   /* 0x15 (S9 fused command) */
static constexpr uint32_t CMD_D_INTR_CHAIN = 24;   /* 0x18 (S6 chained auth path) */
static constexpr uint32_t CMD_HASH_ONCE_RAM = 25;  /* 0x19 (S7 multi-block task-RAM absorb) */
static constexpr uint32_t CMD_MSG_Q_COEF = 26;    /* 0x1A (S8 message hash -> Q -> checksum -> coefficients) */
static constexpr uint32_t CMD_LMOTS_KEYGEN_LEAF = 14;
static constexpr uint32_t CMD_LMOTS_VERIFY_LEAF = 15;
static constexpr uint32_t CTRL_START = 1;
static constexpr uint32_t CTRL_CLEAR = 2;
static constexpr uint32_t STATUS_BUSY = 1;
static constexpr uint32_t STATUS_DONE = 2;
static constexpr uint32_t STATUS_ERROR = 4;

double sc_time_stamp()
{
    return 0.0;
}

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

static void write_bytes(Vlms_sha256_mmio &dut,
                        uint16_t base,
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

static Digest parse_digest(const std::string &hex)
{
    Digest digest{};
    for (size_t index = 0; index < digest.size(); ++index) {
        digest[index] = static_cast<uint8_t>(std::stoul(hex.substr(index * 2, 2), nullptr, 16));
    }
    return digest;
}

static std::vector<uint8_t> parse_hex(const std::string &hex)
{
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>(
            std::stoul(hex.substr(index * 2, 2), nullptr, 16));
    }
    return bytes;
}

static std::vector<uint8_t> load_vector(const std::string &name)
{
    std::ifstream input("build/lms_verify_vector.txt");
    const std::string prefix = name + "=";
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind(prefix, 0) == 0) {
            return parse_hex(line.substr(prefix.size()));
        }
    }
    return {};
}

static std::vector<uint8_t> load_lmots_signature()
{
    return load_vector("LMOTS_SIGNATURE");
}

/* Compact coefficient packing (aligned with RTL coefficient_words[0:31]: 32/w per word,
 * sliced at w-bit width). Since S5, SHA-256 and SHAKE256 share one compact layout. */
static std::vector<uint8_t> pack_coefficients(const std::vector<uint8_t> &coeffs, int w)
{
    const int per = 32 / w;
    const int nwords = (static_cast<int>(coeffs.size()) + per - 1) / per;
    std::vector<uint8_t> bytes(static_cast<size_t>(nwords) * 4, 0);
    for (size_t i = 0; i < coeffs.size(); ++i) {
        const uint32_t v = static_cast<uint32_t>(coeffs[i]) & ((1u << w) - 1u);
        const size_t off = (i / static_cast<size_t>(per)) * 4;
        const uint32_t shift = static_cast<uint32_t>((i % static_cast<size_t>(per)) * w);
        uint32_t word = static_cast<uint32_t>(bytes[off]) |
                        (static_cast<uint32_t>(bytes[off + 1]) << 8) |
                        (static_cast<uint32_t>(bytes[off + 2]) << 16) |
                        (static_cast<uint32_t>(bytes[off + 3]) << 24);
        word |= v << shift;
        bytes[off] = static_cast<uint8_t>(word);
        bytes[off + 1] = static_cast<uint8_t>(word >> 8);
        bytes[off + 2] = static_cast<uint8_t>(word >> 16);
        bytes[off + 3] = static_cast<uint8_t>(word >> 24);
    }
    return bytes;
}

static void write_task_bytes(Vlms_sha256_mmio &dut,
                             uint16_t word_base,
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
                                            uint16_t word_base,
                                            size_t length)
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

static void write_input(Vlms_sha256_mmio &dut, const std::vector<uint8_t> &message)
{
    for (size_t offset = 0; offset < message.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t lane = 0; lane < 4 && offset + lane < message.size(); ++lane) {
            word |= static_cast<uint32_t>(message[offset + lane]) << (lane * 8);
        }
        write_reg(dut, REG_INPUT + static_cast<uint16_t>(offset), word);
    }
}

static Digest read_output(Vlms_sha256_mmio &dut)
{
    Digest digest{};
    for (size_t offset = 0; offset < digest.size(); offset += 4) {
        const uint32_t word = read_reg(dut, REG_OUTPUT + static_cast<uint16_t>(offset));
        for (size_t lane = 0; lane < 4; ++lane) {
            digest[offset + lane] = static_cast<uint8_t>(word >> (lane * 8));
        }
    }
    return digest;
}

static bool wait_until_idle(Vlms_sha256_mmio &dut)
{
    for (int poll = 0; poll < 100000; ++poll) {
        if ((read_reg(dut, REG_STATUS) & STATUS_BUSY) == 0) {
            return true;
        }
        tick(dut);
    }
    return false;
}

static int run_hash_case(Vlms_sha256_mmio &dut,
                         const char *name,
                         const std::vector<uint8_t> &message,
                         const char *expected_hex,
                         uint32_t expected_cycles)
{
    reset(dut);
    write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
    write_reg(dut, REG_INPUT_LENGTH, static_cast<uint32_t>(message.size()));
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_input(dut, message);
    write_reg(dut, REG_CONTROL, CTRL_START);

    if (read_reg(dut, REG_STATUS) != STATUS_BUSY || !wait_until_idle(dut)) {
        std::printf("FAIL: %s did not execute\n", name);
        return 1;
    }
    const uint32_t status = read_reg(dut, REG_STATUS);
    const uint32_t cycles = read_reg(dut, REG_CYCLE_COUNT);
    if (status != STATUS_DONE || read_reg(dut, REG_ERROR) != 0 ||
        read_output(dut) != parse_digest(expected_hex) || cycles != expected_cycles) {
        std::printf("FAIL: %s status=%u error=%u cycles=%u expected_cycles=%u\n",
                    name, status, read_reg(dut, REG_ERROR), cycles, expected_cycles);
        return 1;
    }
    std::printf("PASS: %-6s bytes=%3zu cycles=%u\n", name, message.size(), cycles);
    return 0;
}

static int expect_error(Vlms_sha256_mmio &dut,
                        uint32_t command,
                        uint32_t input_length,
                        uint32_t output_length,
                        uint32_t expected_error,
                        const char *name)
{
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, command);
    write_reg(dut, REG_INPUT_LENGTH, input_length);
    write_reg(dut, REG_OUTPUT_LENGTH, output_length);
    write_reg(dut, REG_CONTROL, CTRL_START);
    const uint32_t status = read_reg(dut, REG_STATUS);
    const uint32_t error = read_reg(dut, REG_ERROR);
    if (status != STATUS_ERROR || error != expected_error) {
        std::printf("FAIL: %s status=%u error=%u\n", name, status, error);
        return 1;
    }
    return 0;
}

static int test_errors_and_clear(Vlms_sha256_mmio &dut)
{
    int failures = 0;
    failures += expect_error(dut, CMD_HASH_ONCE, 129, 32, 3, "input length");
    failures += expect_error(dut, CMD_HASH_ONCE, 3, 31, 4, "output length");

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    if (read_reg(dut, REG_STATUS) != 0 || read_reg(dut, REG_ERROR) != 0 ||
        read_reg(dut, REG_CYCLE_COUNT) != 0) {
        std::puts("FAIL: CLEAR did not reset sticky state");
        ++failures;
    }
    write_reg(dut, REG_CONTROL, CTRL_START | CTRL_CLEAR);
    if (read_reg(dut, REG_STATUS) != STATUS_ERROR || read_reg(dut, REG_ERROR) != 7) {
        std::puts("FAIL: invalid CONTROL combination");
        ++failures;
    }
    return failures;
}

static int run_chain_case(Vlms_sha256_mmio &dut,
                          uint32_t start,
                          uint32_t steps,
                          const char *expected_hex,
                          uint32_t expected_cycles)
{
    std::vector<uint8_t> identifier(16);
    std::vector<uint8_t> value(32);
    for (size_t index = 0; index < identifier.size(); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }
    for (size_t index = 0; index < value.size(); ++index) {
        value[index] = static_cast<uint8_t>(index);
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_CHAIN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_Q, 2);
    write_reg(dut, REG_ARG_I, 3);
    write_reg(dut, REG_ARG_START, start);
    write_reg(dut, REG_ARG_STEPS, steps);
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_bytes(dut, REG_INPUT, value);
    write_reg(dut, REG_CONTROL, CTRL_START);

    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 || read_output(dut) != parse_digest(expected_hex) ||
        read_reg(dut, REG_CYCLE_COUNT) != expected_cycles) {
        std::printf("FAIL: CHAIN start=%u steps=%u status=%u error=%u cycles=%u\n",
                    start, steps, read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR),
                    read_reg(dut, REG_CYCLE_COUNT));
        return 1;
    }
    std::printf("PASS: CHAIN start=%u steps=%u cycles=%u\n", start, steps, expected_cycles);
    return 0;
}

static int test_derive_chain(Vlms_sha256_mmio &dut)
{
    std::vector<uint8_t> identifier(16);
    std::vector<uint8_t> seed(32);
    for (size_t index = 0; index < identifier.size(); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }
    for (size_t index = 0; index < seed.size(); ++index) {
        seed[index] = static_cast<uint8_t>(index);
    }

    write_bytes(dut, REG_SEED, seed);
    if (read_reg(dut, REG_SEED) != 0) {
        std::puts("FAIL: seed staging window is readable");
        return 1;
    }
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_DONE || read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: seed load status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_DERIVE_CHAIN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_Q, 2);
    write_reg(dut, REG_ARG_I, 3);
    write_reg(dut, REG_ARG_START, 0);
    write_reg(dut, REG_ARG_STEPS, 5);
    write_reg(dut, REG_ARG_KEY, 0);
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 ||
        read_output(dut) != parse_digest(
            "e907a64a1cf902d6071558ebb11074a2ed0872409e692d47c45dac2439bab290") ||
        read_reg(dut, REG_CYCLE_COUNT) != 403) {
        std::printf("FAIL: DERIVE_CHAIN status=%u error=%u cycles=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR),
                    read_reg(dut, REG_CYCLE_COUNT));
        return 1;
    }
    std::puts("PASS: DERIVE_CHAIN fixed vector cycles=403 seed_readback=0");

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_DERIVE_RANDOMIZER);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 ||
        read_output(dut) != parse_digest(
            "b01a71bccdd3906f4efbeb7829c262c0bf813bbd7a4f26e0aeee95b307ac4735") ||
        read_reg(dut, REG_CYCLE_COUNT) != 68) {
        std::printf("FAIL: DERIVE_RANDOMIZER fixed vector status=%u error=%u cycles=%u\n",
                read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR),
                read_reg(dut, REG_CYCLE_COUNT));
        return 1;
    }
    std::puts("PASS: DERIVE_RANDOMIZER fixed vector cycles=68");
    return 0;
}

/* Read wrapped_seed 48B. */
static std::vector<uint8_t> read_wrapped(Vlms_sha256_mmio &dut)
{
    std::vector<uint8_t> bytes(48);
    for (size_t offset = 0; offset < bytes.size(); offset += 4) {
        const uint32_t word = read_reg(dut, REG_WRAPPED + static_cast<uint16_t>(offset));
        for (size_t lane = 0; lane < 4; ++lane) {
            bytes[offset + lane] = static_cast<uint8_t>(word >> (lane * 8));
        }
    }
    return bytes;
}

/* v6: sim_mc monotonic counter + wrapped_seed wrap/unwrap fixed vectors. */
static int test_v6_mc_wrap(Vlms_sha256_mmio &dut)
{
    /* sim_mc: resets to 0, MC_STEP only increments, MC_LOAD restores the initial value. */
    if (read_reg(dut, REG_SIM_MC) != 0) {
        std::printf("FAIL: SIM_MC reset value=%u\n", read_reg(dut, REG_SIM_MC));
        return 1;
    }
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_MC_STEP);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_SIM_MC) != 1 || read_reg(dut, REG_OUTPUT) != 1) {
        std::printf("FAIL: MC_STEP status=%u mc=%u out=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_SIM_MC),
                    read_reg(dut, REG_OUTPUT));
        return 1;
    }
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_MC_STEP);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_SIM_MC) != 2) {
        std::printf("FAIL: MC_STEP second mc=%u\n", read_reg(dut, REG_SIM_MC));
        return 1;
    }
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_MC_LOAD);
    write_reg(dut, REG_ARG_Q, 7);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_SIM_MC) != 7) {
        std::printf("FAIL: MC_LOAD mc=%u\n", read_reg(dut, REG_SIM_MC));
        return 1;
    }
    /* H2 hardening: MC_LOAD is monotonic (increment-only) - rollback loads are clamped, forbidding in-session tx rewind. */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_MC_LOAD);
    write_reg(dut, REG_ARG_Q, 3);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_SIM_MC) != 7) {
        std::printf("FAIL: MC_LOAD rollback clamp mc=%u (expect 7)\n",
                    read_reg(dut, REG_SIM_MC));
        return 1;
    }
    std::puts("PASS: SIM_MC step/load monotonic (H2 rollback clamp)");

    /* wrap/unwrap: load K_WRAP and SEED, wrap yields 48B, unwrap restores. */
    std::vector<uint8_t> k_wrap(32), seed(32);
    for (size_t index = 0; index < 32; ++index) {
        k_wrap[index] = static_cast<uint8_t>(index);          /* 00..1f */
        seed[index] = static_cast<uint8_t>(0x20 + index);     /* 20..3f */
    }

    /* K_WRAP slot is not readable after loading. */
    write_bytes(dut, REG_KWRAP, k_wrap);
    if (read_reg(dut, REG_KWRAP) != 0) {
        std::puts("FAIL: K_WRAP staging window is readable");
        return 1;
    }
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, 1);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_DONE || read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: K_WRAP load status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }

    /* SEED slot load. */
    write_bytes(dut, REG_SEED, seed);
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_DONE || read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: SEED load status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }

    /* wrap: 48B = ct(32) || tag(16). */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_WRAP_SEED);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: WRAP_SEED status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }
    const std::vector<uint8_t> expected = parse_hex(
        "f8fc46023af2b649e8c04d9f85d5fcf7c01152e8d8531708ea3b131210269db7"
        "45e43b904beae6b6fdf5750e7ebd3e7c");
    const std::vector<uint8_t> actual_wrapped = read_wrapped(dut);
    if (actual_wrapped != expected) {
        std::printf("FAIL: WRAP_SEED fixed vector\n  actual=");
        for (uint8_t b : actual_wrapped) std::printf("%02x", b);
        std::printf("\n  expect=");
        for (uint8_t b : expected) std::printf("%02x", b);
        std::printf("\n");
        return 1;
    }
    std::puts("PASS: WRAP_SEED fixed vector 48B");

    /* Corrupted tag -> unwrap rejected. */
    std::vector<uint8_t> corrupted = expected;
    corrupted[47] ^= 0xff;
    write_bytes(dut, REG_WRAPPED, corrupted);
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_UNWRAP_SEED);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_ERROR) {
        std::printf("FAIL: UNWRAP_SEED bad tag accepted status=%u\n",
                    read_reg(dut, REG_STATUS));
        return 1;
    }
    std::puts("PASS: UNWRAP_SEED bad tag rejected");

    /* Correct wrapped -> unwrap restores SEED; DERIVE chain result matches the original SEED. */
    write_bytes(dut, REG_WRAPPED, expected);
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_UNWRAP_SEED);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: UNWRAP_SEED status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }
    std::puts("PASS: UNWRAP_SEED restored (tag ok)");

    /* Restore SEED=00..1f (consistent with test_derive_chain) to avoid polluting later LMOTS cases. */
    std::vector<uint8_t> orig_seed(32);
    for (size_t index = 0; index < 32; ++index) {
        orig_seed[index] = static_cast<uint8_t>(index);
    }
    write_bytes(dut, REG_SEED, orig_seed);
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_DONE || read_reg(dut, REG_ERROR) != 0) {
        std::puts("FAIL: restore SEED after v6");
        return 1;
    }
    return 0;
}

/* v6: generic HMAC-SHA256(K_STATE, msg) fixed vectors (key resides in the hardware slot, unreadable by firmware). */
static int test_v6_hmac_kstate(Vlms_sha256_mmio &dut)
{
    /* Load K_STATE=0x40..0x5f (via the KWRAP staging window, arg_key=2). */
    std::vector<uint8_t> k_state(32);
    for (size_t index = 0; index < 32; ++index) {
        k_state[index] = static_cast<uint8_t>(0x40 + index);
    }
    write_bytes(dut, REG_KWRAP, k_state);
    if (read_reg(dut, REG_KWRAP) != 0) {
        std::puts("FAIL: K_STATE staging window is readable");
        return 1;
    }
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, 2);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_DONE || read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: K_STATE load status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }

    /* HMAC(abc): inner=64+3=67B -> 2 blocks. */
    const std::vector<uint8_t> abc{'a', 'b', 'c'};
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_HMAC_KSTATE);
    write_reg(dut, REG_INPUT_LENGTH, static_cast<uint32_t>(abc.size()));
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_bytes(dut, REG_INPUT, abc);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 ||
        read_output(dut) != parse_digest(
            "910f4315f170bdf2f5a197d760828322c22cf67c043b7df72b6920db6e4caf97")) {
        std::printf("FAIL: HMAC_KSTATE(abc) status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }
    std::puts("PASS: HMAC_KSTATE(abc) 2-block");

    /* HMAC(63B): inner=64+63=127B -> 3 blocks (variable block-count path). */
    std::vector<uint8_t> msg63(63);
    for (size_t index = 0; index < 63; ++index) {
        msg63[index] = static_cast<uint8_t>(index);
    }
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_HMAC_KSTATE);
    write_reg(dut, REG_INPUT_LENGTH, static_cast<uint32_t>(msg63.size()));
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_bytes(dut, REG_INPUT, msg63);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 ||
        read_output(dut) != parse_digest(
            "cce614020f64033173f851870641dbbc8263ccb272e35975d290f779992194bc")) {
        std::printf("FAIL: HMAC_KSTATE(63B) status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }
    std::puts("PASS: HMAC_KSTATE(63B) 3-block");
    return 0;
}

/* v9: CMD_STATE_COMMIT fused command (S9): sim_mc+1 hardware-monotonic tx + HMAC-SHA256(K_STATE, body)
 * output in a single transaction. body = magic(4,"LMSS")||state(2,BE)||ctr(4,BE)||tx(4,BE)||reserved(34,0)||aad(1).
 * oracle = first 16B of software HMAC-SHA256 (K_STATE=0x40..0x5f fixed); monotonic back-to-back tx check.
 * Output layout: word0=tx (little-endian), word1..4=tag, word5..7=0. */
static int test_v9_state_commit(Vlms_sha256_mmio &dut)
{
    /* After H2 hardening, MC_LOAD is monotonic (increment-only): reset clears sim_mc=0 so the
     * mc=7 left by test_v6_mc_wrap cannot be clamped into a higher tx. */
    reset(dut);

    /* Load K_STATE=0x40..0x5f (via the KWRAP staging window, arg_key=2). */
    std::vector<uint8_t> k_state(32);
    for (size_t index = 0; index < 32; ++index) {
        k_state[index] = static_cast<uint8_t>(0x40 + index);
    }
    write_bytes(dut, REG_KWRAP, k_state);
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
    write_reg(dut, REG_ARG_KEY, 2);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: STATE_COMMIT K_STATE load status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }

    /* MC_LOAD 3 -> first commit tx=4 (hardware sim_mc+1 monotonic). */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_MC_LOAD);
    write_reg(dut, REG_ARG_Q, 3);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::puts("FAIL: STATE_COMMIT MC_LOAD");
        return 1;
    }

    /* commit1: state=0x0102, ctr=5, aad=7 -> tx=4, tag = first 16B of HMAC(K, body1). */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_STATE_COMMIT);
    write_reg(dut, REG_ARG_I, 0x0102);
    write_reg(dut, REG_ARG_Q, 5);
    write_reg(dut, REG_ARG_KEY, 7);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: STATE_COMMIT#1 status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }
    {
        const Digest out = read_output(dut);
        const uint32_t tx = static_cast<uint32_t>(out[0]) |
                            (static_cast<uint32_t>(out[1]) << 8) |
                            (static_cast<uint32_t>(out[2]) << 16) |
                            (static_cast<uint32_t>(out[3]) << 24);
        const Digest expected = parse_digest(
            "0400000009dcb311e3cb450c13df3cb74c5f9d0100000000000000000000000000000000");
        if (tx != 4 || out != expected) {
            std::printf("FAIL: STATE_COMMIT#1 tx=%u\n  actual=", tx);
            for (uint8_t b : out) std::printf("%02x", b);
            std::printf("\n  expect=");
            for (uint8_t b : expected) std::printf("%02x", b);
            std::puts("");
            return 1;
        }
    }
    std::puts("PASS: STATE_COMMIT#1 tx=4 tag matches HMAC oracle");

    /* commit2: state=0x0103, ctr=6, aad=0 -> tx=5 (monotonic), tag2. */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_STATE_COMMIT);
    write_reg(dut, REG_ARG_I, 0x0103);
    write_reg(dut, REG_ARG_Q, 6);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::printf("FAIL: STATE_COMMIT#2 status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        return 1;
    }
    {
        const Digest out = read_output(dut);
        const uint32_t tx = static_cast<uint32_t>(out[0]) |
                            (static_cast<uint32_t>(out[1]) << 8) |
                            (static_cast<uint32_t>(out[2]) << 16) |
                            (static_cast<uint32_t>(out[3]) << 24);
        const Digest expected = parse_digest(
            "05000000eb89c4af4ae3f28555b19231008f90990000000000000000000000000000000");
        if (tx != 5 || out != expected) {
            std::printf("FAIL: STATE_COMMIT#2 tx=%u\n  actual=", tx);
            for (uint8_t b : out) std::printf("%02x", b);
            std::printf("\n  expect=");
            for (uint8_t b : expected) std::printf("%02x", b);
            std::puts("");
            return 1;
        }
    }
    std::puts("PASS: STATE_COMMIT#2 tx=5 monotonic tag matches HMAC oracle");
    return 0;
}

/* v10: CMD_D_INTR_CHAIN chained auth path (S6): one MMIO completes N D_INTR layers (I||node||
 * 0x8383||left||right, 86B in 2 blocks). Input: task RAM word32..39=leaf, word40..=siblings;
 * ARG_LEAF_NODE=leaf node (parity bit included; P1-6 q=1 fix: odd-node layers concat sibling||cur),
 * ARG_STEPS=N. oracle = software SHA-256, checked layer by layer (incl. parity swap). */
static int test_v10_dintr_chain(Vlms_sha256_mmio &dut)
{
    std::vector<uint8_t> identifier(16);
    for (size_t index = 0; index < 16; ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }
    const Digest leaf = parse_digest(
        "f7c3dfbef50b7712ac77a1bb77953ed1aed068deadadb74653b4152371261af5");
    const Digest sib0 = parse_digest(
        "0f51b21010153b39672453775206e19487af89a563a879ab9a4a567ee11db7bb");
    const Digest sib1 = parse_digest(
        "2413397e842aa04246f6d7d61d0522e584153052b10ead0f6d2d853811527535");
    const Digest sib2 = parse_digest(
        "9151ca54150c43b8dff4f8f2cb70cf1d4112a5cab237402751358088f17a49a2");
    const Digest root = parse_digest(
        "0d1474b75f320d0cee408873b28b6f4973760cfaee0c4510eb277478f8613bb4");

    /* Task RAM: word32..39=leaf; word40..47/48..55/56..63=sib0/1/2 */
    write_task_bytes(dut, 32, std::vector<uint8_t>(leaf.begin(), leaf.end()));
    write_task_bytes(dut, 40, std::vector<uint8_t>(sib0.begin(), sib0.end()));
    write_task_bytes(dut, 48, std::vector<uint8_t>(sib1.begin(), sib1.end()));
    write_task_bytes(dut, 56, std::vector<uint8_t>(sib2.begin(), sib2.end()));
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_D_INTR_CHAIN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_LEAF_NODE, 8);  /* leaf node 8 (even leaf; first-layer D_INTR node=4) */
    write_reg(dut, REG_ARG_STEPS, 1);
    write_reg(dut, REG_CONTROL, CTRL_START);
    {
        const Digest expect1 = parse_digest(
            "4815410733cf791502f9edcb338cb4eeb22e8299f9622393f785053cf87437d3");
        if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
            read_reg(dut, REG_ERROR) != 0 || read_output(dut) != expect1) {
            std::printf("FAIL: D_INTR_CHAIN h=1 status=%u error=%u\n",
                        read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
            std::printf("  actual=");
            for (uint8_t b : read_output(dut)) std::printf("%02x", b);
            std::printf("\n  expect=");
            for (uint8_t b : expect1) std::printf("%02x", b);
            std::puts("");
            return 1;
        }
    }
    std::puts("PASS: D_INTR_CHAIN h=1 root matches oracle");

    /* Switch to N=3 (same input, 3 consecutive layers) */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_D_INTR_CHAIN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_LEAF_NODE, 8);  /* leaf node 8 (same input, 3 consecutive layers) */
    write_reg(dut, REG_ARG_STEPS, 3);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 || read_output(dut) != root) {
        std::printf("FAIL: D_INTR_CHAIN status=%u error=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
        std::printf("  actual=");
        for (uint8_t b : read_output(dut)) std::printf("%02x", b);
        std::printf("\n  expect=");
        for (uint8_t b : root) std::printf("%02x", b);
        std::puts("");
        return 1;
    }
    std::printf("PASS: D_INTR_CHAIN h=3 root matches oracle cycles=%u\n",
                read_reg(dut, REG_CYCLE_COUNT));

    /* h=5 + vector I (simulating the SoC verify scenario: node chain 16->8->4->2->1, 5 layers) */
    {
        const std::vector<uint8_t> vid = parse_hex(
            "0123456789abcdeffedcba9876543210");
        const Digest vleaf = parse_digest(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const std::vector<uint8_t> vpath = parse_hex(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"  /* sib0 */
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"  /* sib1 */
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"  /* sib2 */
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"  /* sib3 */
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"); /* sib4 */
        const Digest vroot = parse_digest(
            "e3bd96f4e938dc61b00a6497ac65269ea219ff0fd7daeb6278f9e53e0e2814dd");
        write_task_bytes(dut, 32, std::vector<uint8_t>(vleaf.begin(), vleaf.end()));
        write_task_bytes(dut, 40, vpath);
        write_bytes(dut, REG_IDENTIFIER, vid);
        write_reg(dut, REG_CONTROL, CTRL_CLEAR);
        write_reg(dut, REG_COMMAND, CMD_D_INTR_CHAIN);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_LEAF_NODE, 32);
        write_reg(dut, REG_ARG_STEPS, 5);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
            read_reg(dut, REG_ERROR) != 0 || read_output(dut) != vroot) {
            std::printf("FAIL: D_INTR_CHAIN h=5 status=%u error=%u\n",
                        read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
            std::printf("  actual=");
            for (uint8_t b : read_output(dut)) std::printf("%02x", b);
            std::printf("\n  expect=");
            for (uint8_t b : vroot) std::printf("%02x", b);
            std::puts("");
            return 1;
        }

        /* h=5 odd leaf (leaf 33, q=1): layer-0 concat direction = sibling||leaf (P1-6 q=1 fix).
         * Expected root computed by the software oracle (per-node parity swap): 621d626e... (Python hashlib authoritative). */
        const Digest vroot_odd = parse_digest(
            "621d626e6e0fcb7daf6fa5a7c19ae5091d915312f4595c8e63b9e07b742bc0a3");
        write_task_bytes(dut, 32, std::vector<uint8_t>(vleaf.begin(), vleaf.end()));
        write_task_bytes(dut, 40, vpath);
        write_bytes(dut, REG_IDENTIFIER, vid);
        write_reg(dut, REG_CONTROL, CTRL_CLEAR);
        write_reg(dut, REG_COMMAND, CMD_D_INTR_CHAIN);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_LEAF_NODE, 33);
        write_reg(dut, REG_ARG_STEPS, 5);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
            read_reg(dut, REG_ERROR) != 0 || read_output(dut) != vroot_odd) {
            std::printf("FAIL: D_INTR_CHAIN h=5 odd-leaf status=%u error=%u\n",
                        read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
            std::printf("  actual=");
            for (uint8_t b : read_output(dut)) std::printf("%02x", b);
            std::printf("\n  expect=");
            for (uint8_t b : vroot_odd) std::printf("%02x", b);
            std::puts("");
            return 1;
        }
    }
    std::puts("PASS: D_INTR_CHAIN h=5 (vector I) root matches oracle");
    std::puts("PASS: D_INTR_CHAIN h=5 odd-leaf (q=1) root matches oracle");
    return 0;
}

/* v11: CMD_HASH_ONCE_RAM multi-block absorb (S7): input (total-length framing; full message
 * incl. the 54B prefix assembled by firmware) written to task RAM from word32; hardware chunks
 * into 64B blocks (last 0x80 + 8B length). 7 boundaries cover block edges / padding overflow
 * (total=54/135/136/137/271/1078/2048, same framing as SHAKE). oracle = software SHA-256. */
static int test_v11_hash_once_ram(Vlms_sha256_mmio &dut)
{
    struct Case {
        int total_len;
        const char *expected_hex;
    };
    static const Case cases[] = {
        { 54,  "406d0be6298586cec192bf3f68905c4a058e005736e41d8e125e1832a8d1e7df" },
        { 135, "c787f22e42824f7f9f7062a89b2b4d68b2612a0d6d99ff2dc6b27905785be481" },
        { 136, "be2ed9a2aa735f93a37c9136046fc48bee5cfd121b733a82a7885728a8d67363" },
        { 137, "5349d6193c831b97e522b5afb286ad397a116544998d46a7b316c69aeb19d976" },
        { 271, "980a1c620201ea9a5593f7e2bbfd3317a74b29d28d0db9fe6fa89b637e542ce6" },
        { 1078, "df2ffd2f6c3463bd22564805dd39b7398f7245e738dd0150edbc7b15a2444d4a" },
        { 2048, "11220e1c80774647d186733c8449bb60c84472384873050cb0b1cbbc21d7063e" },
    };

    for (const Case &c : cases) {
        std::vector<uint8_t> input;
        for (int index = 0; index < c.total_len; ++index) {
            input.push_back(static_cast<uint8_t>(0xa0 + (index % 96)));
        }
        reset(dut);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE_RAM);
        write_reg(dut, REG_INPUT_LENGTH, static_cast<uint32_t>(input.size()));
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_task_bytes(dut, 32, input);
        write_reg(dut, REG_CONTROL, CTRL_START);
        const bool idle = wait_until_idle(dut);
        const Digest actual = read_output(dut);
        const Digest expected = parse_digest(c.expected_hex);
        if (!idle || read_reg(dut, REG_STATUS) != STATUS_DONE ||
            read_reg(dut, REG_ERROR) != 0 || actual != expected) {
            std::printf("FAIL: HASH_ONCE_RAM len=%d status=%u error=%u\n",
                        c.total_len, read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR));
            std::printf("  actual=");
            for (uint8_t b : actual) std::printf("%02x", b);
            std::printf("\n  expect=");
            for (uint8_t b : expected) std::printf("%02x", b);
            std::puts("");
            return 1;
        }
    }
    std::puts("PASS: HASH_ONCE_RAM 7 boundaries root matches oracle");
    return 0;
}

/* v12: CMD_MSG_Q_COEF (S8): message hash -> Q -> checksum -> coefficients. Input layout (P3):
 * header 54B (I||q BE||0x8181||C) written to mqc_base (short messages per w: W4=568/W2=1096/W8=304/
 * W1=568; large messages fixed at 568); message written to mqc_base+14 words (+56B).
 * Output: Q (output_words) + coefficients (coefficient_words compact-packed, read back from
 * word0..). oracle = build/s8_expect.txt (precomputed in Python, 44 cases: 4w x 11 message lengths). */
static std::vector<uint8_t> v12_rand_bytes(size_t n, uint32_t seed)
{
    std::vector<uint8_t> bytes(n);
    for (size_t i = 0; i < n; ++i) {
        bytes[i] = static_cast<uint8_t>((seed * 31u + i * 17u + 3u) & 0xffu);
    }
    return bytes;
}

static int test_v12_msg_q_coef(Vlms_sha256_mmio &dut)
{
    std::ifstream input("build/s8_expect.txt");
    std::string line;
    int cases = 0;
    int failures = 0;
    while (std::getline(input, line)) {
        uint32_t w, ml;
        char qhex[80], phex[512];
        if (std::sscanf(line.c_str(), "w%u ml%u Q=%64s coef=%256s", &w, &ml, qhex, phex) != 4) {
            continue;
        }
        const uint32_t ptab[4] = {265u, 133u, 67u, 34u};
        uint32_t wi = (w == 1u) ? 0u : (w == 2u) ? 1u : (w == 4u) ? 2u : 3u;
        const uint32_t p = ptab[wi];
        const std::vector<uint8_t> I = v12_rand_bytes(16, 0x77);
        const uint32_t q = 0x44556677u;
        const std::vector<uint8_t> C = v12_rand_bytes(32, 0x88);
        const std::vector<uint8_t> msg = v12_rand_bytes(ml, 0x9000u + w * 10u + ml);
        std::vector<uint8_t> input_bytes(54 + ml);
        std::memcpy(input_bytes.data(), I.data(), 16);
        input_bytes[16] = static_cast<uint8_t>(q >> 24);
        input_bytes[17] = static_cast<uint8_t>(q >> 16);
        input_bytes[18] = static_cast<uint8_t>(q >> 8);
        input_bytes[19] = static_cast<uint8_t>(q);
        input_bytes[20] = 0x81; input_bytes[21] = 0x81;
        std::memcpy(input_bytes.data() + 22, C.data(), 32);
        if (ml) {
            std::memcpy(input_bytes.data() + 54, msg.data(), ml);
        }
        const uint32_t mqc_base = (ml <= 74u) ?
            ((w == 1u) ? 568u : 32u + p * 8u) : 568u;

        reset(dut);
        write_reg(dut, REG_ARG_W, w);
        write_reg(dut, REG_COMMAND, CMD_MSG_Q_COEF);
        write_reg(dut, REG_INPUT_LENGTH, 54u + ml);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_Q, q);
        write_bytes(dut, REG_IDENTIFIER, I);
        write_task_bytes(dut, static_cast<uint16_t>(mqc_base),
                         std::vector<uint8_t>(input_bytes.begin(), input_bytes.begin() + 54));
        write_task_bytes(dut, static_cast<uint16_t>(mqc_base + 14u),
                         std::vector<uint8_t>(input_bytes.begin() + 54, input_bytes.end()));
        write_reg(dut, REG_CONTROL, CTRL_START);
        const bool idle = wait_until_idle(dut);
        const Digest q_got = read_output(dut);
        const Digest q_exp = parse_digest(std::string(qhex));
        bool ok = idle && read_reg(dut, REG_STATUS) == STATUS_DONE &&
                  read_reg(dut, REG_ERROR) == 0 && q_got == q_exp;

        /* Read back coefficient words (word0.., one word per ADDR+DATA) -> compare against expected compact words */
        const uint32_t nwords = (p * w + 31u) / 32u;
        std::string exp = phex;
        bool coef_ok = true;
        for (uint32_t wd = 0; wd < nwords; ++wd) {
            write_reg(dut, REG_TASK_ADDR, static_cast<uint16_t>(wd));
            tick(dut);
            const uint32_t got = read_reg(dut, REG_TASK_DATA);
            const uint32_t want = static_cast<uint32_t>(
                std::stoul(exp.substr(wd * 8, 8), nullptr, 16));
            if (got != want) {
                coef_ok = false;
                std::printf("FAIL: MQC w=%u ml=%u word%u got %08x exp %08x\n",
                            w, ml, wd, got, want);
            }
        }
        if (!ok) {
            std::printf("FAIL: MQC w=%u ml=%u Q got ", w, ml);
            for (uint8_t b : q_got) std::printf("%02x", b);
            std::printf(" exp %s\n", qhex);
        }
        if (ok && coef_ok) {
            std::printf("PASS: MQC w=%u ml=%u\n", w, ml);
        } else {
            ++failures;
        }
        ++cases;
    }
    /* Restore the default W4 (later batch-task tests depend on the arg_w_r default) */
    write_reg(dut, REG_ARG_W, 4);
    if (cases == 0) {
        std::puts("FAIL: MSG_Q_COEF expect file missing");
        return 1;
    }
    std::printf(failures ? "FAIL: MSG_Q_COEF (%d fail)\n" : "PASS: MSG_Q_COEF %d cases\n",
                failures, cases);
    return failures;
}

static int test_lmots_keygen(Vlms_sha256_mmio &dut)
{
    std::vector<uint8_t> identifier(16);
    for (size_t index = 0; index < identifier.size(); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, 2);
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_reg(dut, REG_CONTROL, CTRL_START);
    const bool idle = wait_until_idle(dut);
    const Digest actual = read_output(dut);
    if (!idle || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 ||
        actual != parse_digest(
            "c5347dc85e397959942e5acc1de4984a10fa829b0a353a34ac966f8dc849e4e8") ||
        read_reg(dut, REG_CYCLE_COUNT) != 38761) {
        std::printf("FAIL: LMOTS_KEYGEN status=%u error=%u cycles=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR),
                    read_reg(dut, REG_CYCLE_COUNT));
        std::printf("      digest=");
        for (uint8_t value : actual) std::printf("%02x", value);
        std::puts("");
        return 1;
    }
    std::puts("PASS: LMOTS_KEYGEN 67 chains + streaming D_PBLC cycles=38761");
    return 0;
}

static int test_lmots_sign(Vlms_sha256_mmio &dut)
{
    const std::vector<uint8_t> coefficients = parse_hex(
        "030f010e0e000206080e0d04080a04090308060706010c050e0c090f0a050c08"
        "020d040905080202080a00010c0b060207050d0300080604020e0c0c01020200"
        "020004");
    const std::vector<uint8_t> signature = load_lmots_signature();
    const std::vector<uint8_t> identifier =
        parse_hex("0123456789abcdeffedcba9876543210");
    if (coefficients.size() != 67 || signature.size() != 2180) {
        std::puts("FAIL: load LMOTS_SIGN oracle");
        return 1;
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_task_bytes(dut, 0, pack_coefficients(coefficients, 4));
    write_reg(dut, REG_COMMAND, CMD_LMOTS_SIGN);
    write_reg(dut, REG_OUTPUT_LENGTH, 2144);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, 0);
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 ||
        read_reg(dut, REG_CYCLE_COUNT) != 23516 ||
        read_task_bytes(dut, 32, 2144) !=
            std::vector<uint8_t>(signature.begin() + 36, signature.end())) {
        std::printf("FAIL: LMOTS_SIGN status=%u error=%u cycles=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR),
                    read_reg(dut, REG_CYCLE_COUNT));
        const std::vector<uint8_t> got = read_task_bytes(dut, 32, 2144);
        std::printf("  got[0..15]=");
        for (size_t idx = 0; idx < 16; ++idx) std::printf("%02x", got[idx]);
        std::printf("\n  exp[0..15]=");
        for (size_t idx = 0; idx < 16; ++idx) std::printf("%02x", signature[36 + idx]);
        std::puts("");
        return 1;
    }
    std::puts("PASS: LMOTS_SIGN one command, 67 outputs, cycles=23516");
    return 0;
}

static int test_lmots_verify(Vlms_sha256_mmio &dut)
{
    const std::vector<uint8_t> coefficients = parse_hex(
        "030f010e0e000206080e0d04080a04090308060706010c050e0c090f0a050c08"
        "020d040905080202080a00010c0b060207050d0300080604020e0c0c01020200"
        "020004");
    const std::vector<uint8_t> signature = load_lmots_signature();
    const std::vector<uint8_t> identifier =
        parse_hex("0123456789abcdeffedcba9876543210");
    if (coefficients.size() != 67 || signature.size() != 2180) {
        std::puts("FAIL: load LMOTS_VERIFY oracle");
        return 1;
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    const std::vector<uint8_t> packed = pack_coefficients(coefficients, 4);
    write_task_bytes(dut, 0, packed);
    const std::vector<uint8_t> chain_inputs(signature.begin() + 36, signature.end());
    write_task_bytes(dut, 32, chain_inputs);
    if (read_task_bytes(dut, 0, packed.size()) != packed ||
        read_task_bytes(dut, 32, chain_inputs.size()) != chain_inputs) {
        std::puts("FAIL: LMOTS_VERIFY task RAM readback");
        return 1;
    }
    write_reg(dut, REG_COMMAND, CMD_LMOTS_VERIFY);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_Q, 0);
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_reg(dut, REG_CONTROL, CTRL_START);
    const bool idle = wait_until_idle(dut);
    const Digest actual = read_output(dut);
    if (!idle || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0 ||
        read_reg(dut, REG_CYCLE_COUNT) != 27327 ||
        actual != parse_digest(
            "4e04196ca2b08517e90373f79eb93adbb59c0f9107020328bbc3dcd878b95431")) {
        std::printf("FAIL: LMOTS_VERIFY status=%u error=%u cycles=%u\n",
                    read_reg(dut, REG_STATUS), read_reg(dut, REG_ERROR),
                    read_reg(dut, REG_CYCLE_COUNT));
        std::printf("      digest=");
        for (uint8_t value : actual) std::printf("%02x", value);
        std::puts("");
        return 1;
    }
    std::puts("PASS: LMOTS_VERIFY one command, 2144-byte input, cycles=27327");
    return 0;
}

static int test_chain_errors(Vlms_sha256_mmio &dut)
{
    int failures = 0;
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_CHAIN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_I, 0x10000);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_ERROR || read_reg(dut, REG_ERROR) != 5) {
        std::puts("FAIL: CHAIN index error");
        ++failures;
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_ARG_I, 3);
    write_reg(dut, REG_ARG_START, 250);
    write_reg(dut, REG_ARG_STEPS, 6);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_ERROR || read_reg(dut, REG_ERROR) != 6) {
        std::puts("FAIL: CHAIN range error");
        ++failures;
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_ARG_START, 256);
    write_reg(dut, REG_ARG_STEPS, 0);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_ERROR || read_reg(dut, REG_ERROR) != 6) {
        std::puts("FAIL: CHAIN start width error");
        ++failures;
    }

    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_ARG_START, 0);
    write_reg(dut, REG_ARG_STEPS, 256);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_ERROR || read_reg(dut, REG_ERROR) != 6) {
        std::puts("FAIL: CHAIN steps width error");
        ++failures;
    }

    /* M3 hardening: DERIVE_CHAIN rejects zero/one step (gate on exposing private-key elements;
     * check order precedes seed_valid, so ERR_CHAIN_RANGE=6 is reported even without SEED) */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_reg(dut, REG_COMMAND, CMD_DERIVE_CHAIN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_START, 0);
    write_reg(dut, REG_ARG_STEPS, 1);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (read_reg(dut, REG_STATUS) != STATUS_ERROR || read_reg(dut, REG_ERROR) != 6) {
        std::puts("FAIL: DERIVE_CHAIN steps<2 gate");
        ++failures;
    }
    return failures;
}

static int test_busy_rejection(Vlms_sha256_mmio &dut)
{
    reset(dut);
    write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
    write_reg(dut, REG_INPUT_LENGTH, 3);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_INPUT, 0x00636261);
    write_reg(dut, REG_CONTROL, CTRL_START);
    write_reg(dut, REG_INPUT, 0x007a7a7a);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_ERROR ||
        read_reg(dut, REG_ERROR) != 2 || read_reg(dut, REG_INPUT) != 0x00636261) {
        std::puts("FAIL: BUSY rejection or input-window lock");
        return 1;
    }
    return 0;
}

/* KEYGEN_LEAF correctness: compare against the D_LEAF from KEYGEN->K_q->software-built D_LEAF message->HASH_ONCE. */
static int test_keygen_leaf(Vlms_sha256_mmio &dut)
{
    /* All-zero I + q=0: rule out ambiguity in I and q */
    std::vector<uint8_t> I(16, 0);
    const uint32_t q = 0u;
    const uint32_t node_num = 32u;

    reset(dut);

    /* Load SEED = all zeros */
    {
        for (size_t i = 0; i < 8; ++i) {
            write_reg(dut, REG_SEED + static_cast<uint16_t>(i * 4), 0u);
        }
        write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
        write_reg(dut, REG_ARG_KEY, 0);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE) {
            std::puts("FAIL: KEYGEN_LEAF seed load"); return 1;
        }
    }

    /* Step 1: KEYGEN(q=2) -> K_q */
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::puts("FAIL: KEYGEN_LEAF ref keygen");
        return 1;
    }
    const Digest Kq = read_output(dut);

    /* Step 2: KEYGEN_LEAF -> D_LEAF_hw. Pre-fill the correct D_LEAF message into input_words,
     * then check whether KEYGEN_LEAF's STATE_TASK_PREFETCH overwrites it. */
    {
        std::vector<uint8_t> msg;
        msg.insert(msg.end(), I.begin(), I.end());
        msg.push_back(0x00); msg.push_back(0x00); msg.push_back(0x00); msg.push_back(0x20);
        msg.push_back(0x82); msg.push_back(0x82);
        msg.insert(msg.end(), Kq.begin(), Kq.end());
        write_bytes(dut, REG_INPUT, msg);
    }
    write_bytes(dut, REG_IDENTIFIER, I);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN_LEAF);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_KEY, 0);
    write_reg(dut, REG_ARG_Q, q);
    write_reg(dut, REG_ARG_LEAF_NODE, node_num);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::puts("FAIL: KEYGEN_LEAF command");
        return 1;
    }
    const Digest D_LEAF_hw = read_output(dut);

    /* Step 3: manually build the D_LEAF message and HASH_ONCE it */
    {
        std::vector<uint8_t> msg;
        msg.insert(msg.end(), I.begin(), I.end());           /* bytes 0-15: I */
        msg.push_back(static_cast<uint8_t>(node_num >> 24));
        msg.push_back(static_cast<uint8_t>(node_num >> 16));
        msg.push_back(static_cast<uint8_t>(node_num >> 8));
        msg.push_back(static_cast<uint8_t>(node_num));       /* bytes 16-19 */
        msg.push_back(0x82); msg.push_back(0x82);             /* bytes 20-21: D_LEAF */
        msg.insert(msg.end(), Kq.begin(), Kq.end());          /* bytes 22-53: K_q */

        write_bytes(dut, REG_INPUT, msg);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 54);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
            read_reg(dut, REG_ERROR) != 0) {
            std::puts("FAIL: KEYGEN_LEAF hash-once ref");
            return 1;
        }
        const Digest D_LEAF_ref = read_output(dut);

        if (D_LEAF_hw != D_LEAF_ref) {
            std::puts("FAIL: KEYGEN_LEAF D_LEAF mismatch");
            return 1;
        }
    }

    std::puts("PASS: KEYGEN_LEAF D_LEAF matches KEYGEN+HASH_ONCE ref");

    /* q=1 checked as well */
    {
        const uint32_t q2 = 1u;
        const uint32_t node_num2 = 33u;
        write_bytes(dut, REG_IDENTIFIER, I);
        write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_KEY, 0);
        write_reg(dut, REG_ARG_Q, q2);
        write_reg(dut, REG_CONTROL, CTRL_START);
        wait_until_idle(dut);
        const Digest Kq2 = read_output(dut);

        write_bytes(dut, REG_IDENTIFIER, I);
        write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN_LEAF);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_KEY, 0);
        write_reg(dut, REG_ARG_Q, q2);
        write_reg(dut, REG_ARG_LEAF_NODE, node_num2);
        write_reg(dut, REG_CONTROL, CTRL_START);
        wait_until_idle(dut);
        const Digest D_LEAF_hw2 = read_output(dut);

        std::vector<uint8_t> msg;
        msg.insert(msg.end(), I.begin(), I.end());
        msg.push_back(0x00); msg.push_back(0x00); msg.push_back(0x00); msg.push_back(0x21);
        msg.push_back(0x82); msg.push_back(0x82);
        msg.insert(msg.end(), Kq2.begin(), Kq2.end());
        write_bytes(dut, REG_INPUT, msg);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 54);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_CONTROL, CTRL_START);
        wait_until_idle(dut);
        const Digest D_LEAF_ref2 = read_output(dut);

        if (D_LEAF_hw2 != D_LEAF_ref2) {
            std::printf("FAIL: KEYGEN_LEAF q=1 D_LEAF mismatch\n");
            return 1;
        }
        std::puts("PASS: KEYGEN_LEAF q=1 OK");
    }

    /* KAT vector with the actual I/SEED */
    {
        reset(dut);
        /* KAT: I=0123456789abcdeffedcba9876543210, SEED=00010203...1c1d1e1f */
        const uint32_t seed_vals[8] = {
            0x00010203u, 0x04050607u, 0x08090a0bu, 0x0c0d0e0fu,
            0x10111213u, 0x14151617u, 0x18191a1bu, 0x1c1d1e1fu
        };
        for (size_t i = 0; i < 8; ++i)
            write_reg(dut, REG_SEED + (uint16_t)(i * 4), seed_vals[i]);
        write_reg(dut, REG_COMMAND, CMD_SEED_LOAD);
        write_reg(dut, REG_ARG_KEY, 0);
        write_reg(dut, REG_CONTROL, CTRL_START);
        wait_until_idle(dut);

        const uint8_t I_kat[16] = {
            0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
            0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
        };
        std::vector<uint8_t> Ivec(I_kat, I_kat + 16);
        const uint32_t q_kat = 0u;
        const uint32_t node_kat = 32u;

        write_bytes(dut, REG_IDENTIFIER, Ivec);
        write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_KEY, 0);
        write_reg(dut, REG_ARG_Q, q_kat);
        write_reg(dut, REG_CONTROL, CTRL_START);
        wait_until_idle(dut);
        const Digest Kq_kat = read_output(dut);

        write_bytes(dut, REG_IDENTIFIER, Ivec);
        write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN_LEAF);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_ARG_KEY, 0);
        write_reg(dut, REG_ARG_Q, q_kat);
        write_reg(dut, REG_ARG_LEAF_NODE, node_kat);
        write_reg(dut, REG_CONTROL, CTRL_START);
        wait_until_idle(dut);
        const Digest D_LEAF_kat_hw = read_output(dut);

        std::vector<uint8_t> msg;
        msg.insert(msg.end(), Ivec.begin(), Ivec.end());
        msg.push_back(0x00); msg.push_back(0x00); msg.push_back(0x00); msg.push_back(0x20);
        msg.push_back(0x82); msg.push_back(0x82);
        msg.insert(msg.end(), Kq_kat.begin(), Kq_kat.end());
        write_bytes(dut, REG_INPUT, msg);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 54);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_CONTROL, CTRL_START);
        wait_until_idle(dut);
        const Digest D_LEAF_kat_ref = read_output(dut);

        if (D_LEAF_kat_hw != D_LEAF_kat_ref) {
            std::printf("FAIL: KEYGEN_LEAF KAT I/SEED D_LEAF mismatch\n");
            return 1;
        }
        std::printf("DBG: KAT D_LEAF q=0 = ");
        for (uint8_t v : D_LEAF_kat_hw) std::printf("%02x", v);
        std::printf("\n");
        std::puts("PASS: KEYGEN_LEAF KAT I/SEED OK");

        /* Two consecutive back-to-back KEYGEN_LEAF calls (simulating the firmware tree build: no reset/seed reload between calls) */
        {
            Digest D_LEAF_consec[2];
            for (uint32_t qq = 0u; qq < 2u; qq++) {
                uint32_t nnum = 32u + qq;
                write_bytes(dut, REG_IDENTIFIER, Ivec);
                write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN_LEAF);
                write_reg(dut, REG_OUTPUT_LENGTH, 32);
                write_reg(dut, REG_ARG_KEY, 0);
                write_reg(dut, REG_ARG_Q, qq);
                write_reg(dut, REG_ARG_LEAF_NODE, nnum);
                write_reg(dut, REG_CONTROL, CTRL_START);
                wait_until_idle(dut);
                D_LEAF_consec[qq] = read_output(dut);
            }
            /* Then verify both results with independent KEYGEN+HASH_ONCE */
            for (uint32_t qq = 0u; qq < 2u; qq++) {
                uint32_t nnum = 32u + qq;
                write_bytes(dut, REG_IDENTIFIER, Ivec);
                write_reg(dut, REG_COMMAND, CMD_LMOTS_KEYGEN);
                write_reg(dut, REG_OUTPUT_LENGTH, 32);
                write_reg(dut, REG_ARG_KEY, 0);
                write_reg(dut, REG_ARG_Q, qq);
                write_reg(dut, REG_CONTROL, CTRL_START);
                wait_until_idle(dut);
                const Digest Kq_qq = read_output(dut);

                std::vector<uint8_t> msg_qq;
                msg_qq.insert(msg_qq.end(), Ivec.begin(), Ivec.end());
                uint8_t nb[4] = {(uint8_t)(nnum>>24),(uint8_t)(nnum>>16),(uint8_t)(nnum>>8),(uint8_t)nnum};
                msg_qq.insert(msg_qq.end(), nb, nb+4);
                msg_qq.push_back(0x82); msg_qq.push_back(0x82);
                msg_qq.insert(msg_qq.end(), Kq_qq.begin(), Kq_qq.end());
                write_bytes(dut, REG_INPUT, msg_qq);
                write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
                write_reg(dut, REG_INPUT_LENGTH, 54);
                write_reg(dut, REG_OUTPUT_LENGTH, 32);
                write_reg(dut, REG_CONTROL, CTRL_START);
                wait_until_idle(dut);
                const Digest D_LEAF_ref_qq = read_output(dut);

                if (D_LEAF_consec[qq] != D_LEAF_ref_qq) {
                    std::printf("FAIL: KEYGEN_LEAF back-to-back q=%u mismatch\n", qq);
                    return 1;
                }
            }
        }
        std::puts("PASS: KEYGEN_LEAF back-to-back OK");
    }

    return 0;
}

/* VERIFY_LEAF correctness: compare against the D_LEAF from VERIFY->K_q->software-built D_LEAF->HASH_ONCE.
 * Verifies that hardware continues computing D_LEAF internally once chain verification yields K_q. */
static int test_verify_leaf(Vlms_sha256_mmio &dut)
{
    /* Correct firmware-KAT coefficients (checksum = sum<<2, ls=2):
     * distinct from test_lmots_verify's historical fixed values (checksum missing the ls shift). */
    const std::vector<uint8_t> coefficients = parse_hex(
        "030f010e0e000206080e0d04080a04090308060706010c050e0c090f0a050c08"
        "020d040905080202080a00010c0b060207050d0300080604020e0c0c01020200"
        "020004");
    const std::vector<uint8_t> signature = load_lmots_signature();
    const std::vector<uint8_t> identifier =
        parse_hex("0123456789abcdeffedcba9876543210");
    const uint32_t node_num = 32u;
    if (coefficients.size() != 67 || signature.size() != 2180) {
        std::puts("FAIL: load VERIFY_LEAF oracle");
        return 1;
    }
    const std::vector<uint8_t> chain_inputs(signature.begin() + 36, signature.end());

    /* Step 1: VERIFY -> K_q (reference) */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_task_bytes(dut, 0, pack_coefficients(coefficients, 4));
    write_task_bytes(dut, 32, chain_inputs);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_VERIFY);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_Q, 0);
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::puts("FAIL: VERIFY_LEAF ref verify");
        return 1;
    }
    const Digest Kq = read_output(dut);
    std::printf("  VERIFY(0x204) Kq=%02x%02x...%02x%02x\n",
                Kq[0], Kq[1], Kq[30], Kq[31]);

    /* Simulate the firmware order: compute Q first (HASH_ONCE via the engine) before VERIFY_LEAF */
    {
        std::vector<uint8_t> qmsg;
        qmsg.insert(qmsg.end(), identifier.begin(), identifier.end());
        qmsg.push_back(0); qmsg.push_back(0); qmsg.push_back(0); qmsg.push_back(0);
        qmsg.push_back(0x81); qmsg.push_back(0x81);
        qmsg.insert(qmsg.end(), signature.begin() + 4, signature.begin() + 36);
        const char *m = "RV32 hardware Verify";
        qmsg.insert(qmsg.end(), m, m + std::strlen(m));
        write_reg(dut, REG_CONTROL, CTRL_CLEAR);
        write_bytes(dut, REG_INPUT, qmsg);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 74);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
            read_reg(dut, REG_ERROR) != 0) {
            std::puts("FAIL: VERIFY_LEAF Q hash-once");
            return 1;
        }
        const Digest Q = read_output(dut);
        std::printf("  Q=%02x%02x...%02x%02x\n", Q[0], Q[1], Q[30], Q[31]);
    }

    /* Step 2: VERIFY_LEAF -> D_LEAF_hw (same input + node_num) */
    write_reg(dut, REG_CONTROL, CTRL_CLEAR);
    write_task_bytes(dut, 0, pack_coefficients(coefficients, 4));
    write_task_bytes(dut, 32, chain_inputs);
    write_reg(dut, REG_COMMAND, CMD_LMOTS_VERIFY_LEAF);
    write_reg(dut, REG_OUTPUT_LENGTH, 32);
    write_reg(dut, REG_ARG_Q, 0);
    write_reg(dut, REG_ARG_LEAF_NODE, node_num);
    write_bytes(dut, REG_IDENTIFIER, identifier);
    write_reg(dut, REG_CONTROL, CTRL_START);
    if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
        read_reg(dut, REG_ERROR) != 0) {
        std::puts("FAIL: VERIFY_LEAF command");
        return 1;
    }
    const Digest D_LEAF_hw = read_output(dut);
    std::printf("  VERIFY_LEAF cycles=%u\n", read_reg(dut, REG_CYCLE_COUNT));

    /* Step 3: manually build the D_LEAF message and HASH_ONCE it as reference */
    {
        std::vector<uint8_t> msg;
        msg.insert(msg.end(), identifier.begin(), identifier.end());
        msg.push_back(static_cast<uint8_t>(node_num >> 24));
        msg.push_back(static_cast<uint8_t>(node_num >> 16));
        msg.push_back(static_cast<uint8_t>(node_num >> 8));
        msg.push_back(static_cast<uint8_t>(node_num));
        msg.push_back(0x82); msg.push_back(0x82);
        msg.insert(msg.end(), Kq.begin(), Kq.end());

        write_bytes(dut, REG_INPUT, msg);
        write_reg(dut, REG_COMMAND, CMD_HASH_ONCE);
        write_reg(dut, REG_INPUT_LENGTH, 54);
        write_reg(dut, REG_OUTPUT_LENGTH, 32);
        write_reg(dut, REG_CONTROL, CTRL_START);
        if (!wait_until_idle(dut) || read_reg(dut, REG_STATUS) != STATUS_DONE ||
            read_reg(dut, REG_ERROR) != 0) {
            std::puts("FAIL: VERIFY_LEAF hash-once ref");
            return 1;
        }
        const Digest D_LEAF_ref = read_output(dut);

        if (D_LEAF_hw != D_LEAF_ref) {
            std::puts("FAIL: VERIFY_LEAF D_LEAF mismatch");
            return 1;
        }
    }

    std::puts("PASS: VERIFY_LEAF D_LEAF matches VERIFY+HASH_ONCE ref");
    return 0;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_sha256_mmio dut;
    std::vector<uint8_t> sequence55(55);
    std::vector<uint8_t> sequence64(64);
    std::vector<uint8_t> sequence128(128);
    for (size_t index = 0; index < sequence128.size(); ++index) {
        sequence128[index] = static_cast<uint8_t>(index);
        if (index < sequence64.size()) {
            sequence64[index] = static_cast<uint8_t>(index);
        }
        if (index < sequence55.size()) {
            sequence55[index] = static_cast<uint8_t>(index);
        }
    }

    reset(dut);
    int failures = 0;
    /* v7: VERSION=7, CAPABILITY=0xefff (0xafff | MSG_Q_COEF 0x4000, S8);
     * S9: | STATE_COMMIT 0x8000; S6: | D_INTR_CHAIN 0x2000; S8: | MSG_Q_COEF
     * 0x4000 -> 0xefff. */
    if (read_reg(dut, REG_VERSION) != 7 || read_reg(dut, REG_CAPABILITY) != 61439) {
        std::printf("FAIL: VERSION=%u or CAPABILITY=%u\n",
                    read_reg(dut, REG_VERSION), read_reg(dut, REG_CAPABILITY));
        ++failures;
    }
    failures += run_hash_case(dut, "empty", {},
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 68);
    failures += run_hash_case(dut, "abc", {'a', 'b', 'c'},
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 68);
    failures += run_hash_case(dut, "seq55", sequence55,
        "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59", 68);
    failures += run_hash_case(dut, "seq64", sequence64,
        "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108", 135);
    failures += run_hash_case(dut, "seq128", sequence128,
        "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5", 202);
    failures += run_chain_case(dut, 4, 5,
        "226554e747dff2248698fb6a44dec122abea95361500a10635932db09ae7aff7", 336);
    failures += run_chain_case(dut, 255, 0,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1);
    failures += run_chain_case(dut, 254, 1,
        "8718851f18300a4583655d2e91460cb85e8160caa510589488d764d54416baaf", 68);
    failures += run_chain_case(dut, 0, 255,
        "9cbef37c55fa62f02c6c3a4343902bd6d0734f4bd27ba8f120a3f7c9c9c9e2ac", 17086);
    failures += test_derive_chain(dut);
    failures += test_v6_mc_wrap(dut);
    failures += test_v6_hmac_kstate(dut);
    failures += test_v9_state_commit(dut);
    failures += test_v10_dintr_chain(dut);
    failures += test_v11_hash_once_ram(dut);
    failures += test_v12_msg_q_coef(dut);
    failures += test_derive_chain(dut);
    failures += test_lmots_keygen(dut);
    failures += test_lmots_sign(dut);
    failures += test_lmots_verify(dut);
    failures += test_chain_errors(dut);
    failures += test_errors_and_clear(dut);
    failures += test_busy_rejection(dut);

    /* KEYGEN_LEAF correctness: compare against D_LEAF built via KEYGEN->K_q->software HASH_ONCE */
    failures += test_keygen_leaf(dut);
    /* VERIFY_LEAF correctness: compare against D_LEAF built via VERIFY->K_q->software HASH_ONCE */
    failures += test_verify_leaf(dut);

    dut.final();
    if (failures != 0) {
        std::printf("SHA-256 MMIO RTL tests failed: %d\n", failures);
        return 1;
    }
    std::puts("SHA-256 MMIO RTL tests passed");
    return 0;
}