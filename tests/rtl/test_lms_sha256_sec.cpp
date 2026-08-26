#include "Vlms_sha256_sec_testtop.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

double sc_time_stamp()
{
    return 0.0;
}

static constexpr uint16_t REG_SIM_MC    = 0x060;
static constexpr uint16_t REG_SEED      = 0x080;
static constexpr uint16_t REG_WRAPPED   = 0x0a0;
static constexpr uint16_t REG_KWRAP     = 0x0e0;

static void tick(Vlms_sha256_sec_testtop &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_sha256_sec_testtop &dut)
{
    dut.bus_valid = 0;
    dut.bus_write = 0;
    dut.bus_addr = 0;
    dut.bus_wdata = 0;
    dut.reg_write_ok = 1;
    dut.seed_latch_en = 0;
    dut.kwrap_latch_en = 0;
    dut.kstate_latch_en = 0;
    dut.mc_step_en = 0;
    dut.mc_load_en = 0;
    dut.mc_load_value = 0;
    dut.wrap_start = 0;
    dut.wrap_is_unwrap = 0;
    dut.hmac_start = 0;
    dut.input_length = 0;
    for (int index = 0; index < 32; ++index) dut.input_words_flat[index] = 0;
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
}

static void write_reg(Vlms_sha256_sec_testtop &dut, uint16_t address, uint32_t value)
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

static void write_bytes(Vlms_sha256_sec_testtop &dut,
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

static uint32_t read_reg(Vlms_sha256_sec_testtop &dut, uint16_t address)
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

/* MMIO convention: bytes[i] -> bits (i%4)*8 of words[i/4] (little-endian word packing a big-endian stream). */
static void set_words(uint32_t *words, const uint8_t *bytes, int length)
{
    for (int index = 0; index < length; ++index) {
        words[index / 4] |= static_cast<uint32_t>(bytes[index]) << ((index % 4) * 8);
    }
}

/* SEC result/SEED are both big-endian byte semantics: byte b is at bits (3 - b%4)*8 of word (7 - b/4). */
static uint8_t read_byte_be(const uint32_t *words, int byte_index)
{
    return static_cast<uint8_t>(words[7 - byte_index / 4] >>
                                ((3 - byte_index % 4) * 8));
}

static std::array<uint8_t, 32> read_digest(const uint32_t *words)
{
    /* result_data shares the same layout as the shell's output_words: word i's bytes in order (byte0 at bits[7:0]).
     * Consistent with how the old wrapper test's read_output extracts. */
    std::array<uint8_t, 32> digest{};
    for (int offset = 0; offset < 32; offset += 4) {
        const uint32_t word = words[7 - offset / 4];
        for (int lane = 0; lane < 4; ++lane) {
            digest[offset + lane] = static_cast<uint8_t>(word >> (lane * 8));
        }
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

/* Multi-cycle command: wait for done=1 (one-tick SEC_DONE level). */
static bool wait_done(Vlms_sha256_sec_testtop &dut, int limit = 100000)
{
    for (int count = 0; count < limit; ++count) {
        if (dut.done) return true;
        tick(dut);
    }
    return false;
}

static std::vector<uint8_t> read_wrapped(Vlms_sha256_sec_testtop &dut)
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

static int test_slots_mc(Vlms_sha256_sec_testtop &dut)
{
    reset(dut);

    /* MC: resets to 0, STEP only increments, LOAD restores to the loaded value.
     * mc_next_value semantics (REVIEW B07-R3): during the command tick it reports
     * "the new value this command will load" (LOAD=max(load, old), STEP=old+1
     * saturated); while idle it keeps the sim_mc+1 lookahead. */
    if (read_reg(dut, REG_SIM_MC) != 0) {
        std::printf("FAIL: SIM_MC reset=%u\n", read_reg(dut, REG_SIM_MC));
        return 1;
    }
    dut.mc_step_en = 1;
    tick(dut);
    dut.mc_step_en = 0;
    dut.eval();
    if (read_reg(dut, REG_SIM_MC) != 1 || dut.mc_next_value != 2) {
        std::printf("FAIL: MC_STEP#1 mc=%u next=%u\n",
                    read_reg(dut, REG_SIM_MC), dut.mc_next_value);
        return 1;
    }
    dut.mc_step_en = 1;
    tick(dut);
    dut.mc_step_en = 0;
    dut.eval();
    if (read_reg(dut, REG_SIM_MC) != 2) {
        std::printf("FAIL: MC_STEP#2 mc=%u\n", read_reg(dut, REG_SIM_MC));
        return 1;
    }
    dut.mc_load_en = 1;
    dut.mc_load_value = 7;
    tick(dut);
    dut.mc_load_en = 0;
    dut.eval();
    if (read_reg(dut, REG_SIM_MC) != 7) {
        std::printf("FAIL: MC_LOAD mc=%u\n", read_reg(dut, REG_SIM_MC));
        return 1;
    }
    /* MC_LOAD rollback injection (H2 monotonicity): load=3 < sim_mc=7 -> stays 7. */
    dut.mc_load_en = 1;
    dut.mc_load_value = 3;
    tick(dut);
    dut.mc_load_en = 0;
    dut.eval();
    if (read_reg(dut, REG_SIM_MC) != 7) {
        std::printf("FAIL: MC_LOAD rollback mc=%u\n", read_reg(dut, REG_SIM_MC));
        return 1;
    }
    std::puts("PASS: MC step/load monotonic");

    /* SEED slot: staging write is unreadable; after latching, seed_valid=1 and seed_data correct. */
    std::vector<uint8_t> seed(32);
    for (size_t index = 0; index < 32; ++index) seed[index] = static_cast<uint8_t>(0x20 + index);
    write_bytes(dut, REG_SEED, seed);
    if (read_reg(dut, REG_SEED) != 0 || dut.seed_valid) {
        std::puts("FAIL: SEED staging readable or valid pre-latch");
        return 1;
    }
    dut.seed_latch_en = 1;
    tick(dut);
    dut.seed_latch_en = 0;
    dut.eval();
    if (!dut.seed_valid) {
        std::puts("FAIL: SEED latch valid");
        return 1;
    }
    for (int index = 0; index < 32; ++index) {
        if (read_byte_be(dut.seed_data, index) != seed[index]) {
            std::printf("FAIL: SEED data[%d]\n", index);
            return 1;
        }
    }
    std::puts("PASS: SEED slot latch + seed_data");

    /* K_WRAP slot: staging write is unreadable; after latching, k_wrap_valid=1. */
    std::vector<uint8_t> k_wrap(32);
    for (size_t index = 0; index < 32; ++index) k_wrap[index] = static_cast<uint8_t>(index);
    write_bytes(dut, REG_KWRAP, k_wrap);
    if (read_reg(dut, REG_KWRAP) != 0) {
        std::puts("FAIL: KWRAP staging readable");
        return 1;
    }
    dut.kwrap_latch_en = 1;
    tick(dut);
    dut.kwrap_latch_en = 0;
    dut.eval();
    if (!dut.k_wrap_valid) {
        std::puts("FAIL: KWRAP latch valid");
        return 1;
    }
    std::puts("PASS: K_WRAP slot latch");
    return 0;
}

static int test_wrap(Vlms_sha256_sec_testtop &dut)
{
    reset(dut);
    std::vector<uint8_t> k_wrap(32), seed(32);
    for (size_t index = 0; index < 32; ++index) {
        k_wrap[index] = static_cast<uint8_t>(index);
        seed[index] = static_cast<uint8_t>(0x20 + index);
    }
    write_bytes(dut, REG_KWRAP, k_wrap);
    dut.kwrap_latch_en = 1;
    tick(dut);
    dut.kwrap_latch_en = 0;
    dut.eval();
    write_bytes(dut, REG_SEED, seed);
    dut.seed_latch_en = 1;
    tick(dut);
    dut.seed_latch_en = 0;
    dut.eval();

    /* WRAP: 48B = ct(32) || tag(16). */
    dut.wrap_start = 1;
    dut.wrap_is_unwrap = 0;
    tick(dut);
    dut.wrap_start = 0;
    dut.eval();
    if (!wait_done(dut)) {
        std::puts("FAIL: WRAP did not complete");
        return 1;
    }
    if (dut.error_valid || dut.result_valid) {
        std::printf("FAIL: WRAP error=%u result=%u\n", dut.error_valid, dut.result_valid);
        return 1;
    }
    if (dut.cycles != 336) {
        std::printf("FAIL: WRAP cycles=%u expected=336\n", dut.cycles);
        return 1;
    }
    tick(dut);  /* exit SEC_DONE */
    const std::vector<uint8_t> expected = parse_hex(
        "f8fc46023af2b649e8c04d9f85d5fcf7c01152e8d8531708ea3b131210269db7"
        "45e43b904beae6b6fdf5750e7ebd3e7c");
    const std::vector<uint8_t> actual = read_wrapped(dut);
    if (actual != expected) {
        std::printf("FAIL: WRAP fixed vector\n  actual=");
        for (uint8_t byte : actual) std::printf("%02x", byte);
        std::printf("\n  expect=");
        for (uint8_t byte : expected) std::printf("%02x", byte);
        std::printf("\n");
        return 1;
    }
    std::puts("PASS: WRAP_SEED fixed vector 48B cycles=336");
    return 0;
}

static int test_unwrap(Vlms_sha256_sec_testtop &dut)
{
    reset(dut);
    std::vector<uint8_t> k_wrap(32), seed(32);
    for (size_t index = 0; index < 32; ++index) {
        k_wrap[index] = static_cast<uint8_t>(index);
        seed[index] = static_cast<uint8_t>(0x20 + index);
    }
    write_bytes(dut, REG_KWRAP, k_wrap);
    dut.kwrap_latch_en = 1;
    tick(dut);
    dut.kwrap_latch_en = 0;
    dut.eval();
    write_bytes(dut, REG_SEED, seed);
    dut.seed_latch_en = 1;
    tick(dut);
    dut.seed_latch_en = 0;
    dut.eval();

    const std::vector<uint8_t> expected = parse_hex(
        "f8fc46023af2b649e8c04d9f85d5fcf7c01152e8d8531708ea3b131210269db7"
        "45e43b904beae6b6fdf5750e7ebd3e7c");

    /* Corrupted tag -> unwrap rejects. */
    std::vector<uint8_t> corrupted = expected;
    corrupted[47] ^= 0xff;
    write_bytes(dut, REG_WRAPPED, corrupted);
    dut.wrap_start = 1;
    dut.wrap_is_unwrap = 1;
    tick(dut);
    dut.wrap_start = 0;
    dut.eval();
    if (!wait_done(dut) || !dut.error_valid || dut.error_code != 7) {
        std::printf("FAIL: UNWRAP bad tag accepted error=%u code=%u\n",
                    dut.error_valid, dut.error_code);
        return 1;
    }
    if (dut.cycles != 336) {
        std::printf("FAIL: UNWRAP_BAD cycles=%u expected=336\n", dut.cycles);
        return 1;
    }
    tick(dut);
    std::puts("PASS: UNWRAP_SEED bad tag rejected cycles=336");

    /* First corrupt SEED (all zeros), then correct wrapped -> unwrap restores SEED. */
    for (int index = 0; index < 8; ++index) {
        write_reg(dut, REG_SEED + static_cast<uint16_t>(index * 4), 0u);
    }
    dut.seed_latch_en = 1;
    tick(dut);
    dut.seed_latch_en = 0;
    dut.eval();
    if (read_byte_be(dut.seed_data, 0) != 0) {
        std::puts("FAIL: seed not zeroed before unwrap-good");
        return 1;
    }

    write_bytes(dut, REG_WRAPPED, expected);
    dut.wrap_start = 1;
    dut.wrap_is_unwrap = 1;
    tick(dut);
    dut.wrap_start = 0;
    dut.eval();
    if (!wait_done(dut) || dut.error_valid) {
        std::printf("FAIL: UNWRAP good error=%u\n", dut.error_valid);
        return 1;
    }
    if (dut.cycles != 336) {
        std::printf("FAIL: UNWRAP_OK cycles=%u expected=336\n", dut.cycles);
        return 1;
    }
    tick(dut);
    for (int index = 0; index < 32; ++index) {
        if (read_byte_be(dut.seed_data, index) != seed[index]) {
            std::printf("FAIL: UNWRAP seed[%d]\n", index);
            return 1;
        }
    }
    std::puts("PASS: UNWRAP_SEED restored cycles=336");
    return 0;
}

static int test_hmac(Vlms_sha256_sec_testtop &dut)
{
    reset(dut);
    /* K_STATE = 0x40..0x5f. */
    std::vector<uint8_t> k_state(32);
    for (size_t index = 0; index < 32; ++index) k_state[index] = static_cast<uint8_t>(0x40 + index);
    write_bytes(dut, REG_KWRAP, k_state);
    dut.kstate_latch_en = 1;
    tick(dut);
    dut.kstate_latch_en = 0;
    dut.eval();

    /* HMAC(abc): inner=64+3=67B -> 2 blocks. */
    const std::vector<uint8_t> abc{'a', 'b', 'c'};
    for (int index = 0; index < 32; ++index) dut.input_words_flat[index] = 0;
    set_words(dut.input_words_flat, abc.data(), 3);
    dut.hmac_start = 1;
    dut.input_length = 3;
    tick(dut);
    dut.hmac_start = 0;
    dut.eval();
    if (!wait_done(dut) || dut.error_valid || !dut.result_valid) {
        std::printf("FAIL: HMAC(abc) error=%u result=%u\n",
                    dut.error_valid, dut.result_valid);
        return 1;
    }
    if (dut.cycles != 269) {
        std::printf("FAIL: HMAC(abc) cycles=%u expected=269\n", dut.cycles);
        return 1;
    }
    const std::array<uint8_t, 32> hmac_abc = read_digest(dut.result_data);
    const std::vector<uint8_t> expect_abc = parse_hex(
        "910f4315f170bdf2f5a197d760828322c22cf67c043b7df72b6920db6e4caf97");
    if (hmac_abc != std::array<uint8_t, 32>{
            expect_abc[0], expect_abc[1], expect_abc[2], expect_abc[3],
            expect_abc[4], expect_abc[5], expect_abc[6], expect_abc[7],
            expect_abc[8], expect_abc[9], expect_abc[10], expect_abc[11],
            expect_abc[12], expect_abc[13], expect_abc[14], expect_abc[15],
            expect_abc[16], expect_abc[17], expect_abc[18], expect_abc[19],
            expect_abc[20], expect_abc[21], expect_abc[22], expect_abc[23],
            expect_abc[24], expect_abc[25], expect_abc[26], expect_abc[27],
            expect_abc[28], expect_abc[29], expect_abc[30], expect_abc[31]}) {
        std::puts("FAIL: HMAC(abc) digest mismatch");
        return 1;
    }
    tick(dut);
    std::puts("PASS: HMAC_KSTATE(abc) 2-block cycles=269");

    /* HMAC(63B): inner=64+63=127B -> 3 blocks. */
    std::vector<uint8_t> msg63(63);
    for (size_t index = 0; index < 63; ++index) msg63[index] = static_cast<uint8_t>(index);
    for (int index = 0; index < 32; ++index) dut.input_words_flat[index] = 0;
    set_words(dut.input_words_flat, msg63.data(), 63);
    dut.hmac_start = 1;
    dut.input_length = 63;
    tick(dut);
    dut.hmac_start = 0;
    dut.eval();
    if (!wait_done(dut) || dut.error_valid || !dut.result_valid) {
        std::printf("FAIL: HMAC(63B) error=%u result=%u\n",
                    dut.error_valid, dut.result_valid);
        return 1;
    }
    if (dut.cycles != 336) {
        std::printf("FAIL: HMAC(63B) cycles=%u expected=336\n", dut.cycles);
        return 1;
    }
    const std::array<uint8_t, 32> hmac_63 = read_digest(dut.result_data);
    const std::vector<uint8_t> expect_63 = parse_hex(
        "cce614020f64033173f851870641dbbc8263ccb272e35975d290f779992194bc");
    bool ok63 = true;
    for (int index = 0; index < 32; ++index) {
        if (hmac_63[index] != expect_63[index]) ok63 = false;
    }
    if (!ok63) {
        std::puts("FAIL: HMAC(63B) digest mismatch");
        return 1;
    }
    tick(dut);
    std::puts("PASS: HMAC_KSTATE(63B) 3-block cycles=336");
    return 0;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_sha256_sec_testtop dut;
    int failures = 0;
    failures += test_slots_mc(dut);
    failures += test_wrap(dut);
    failures += test_unwrap(dut);
    failures += test_hmac(dut);
    dut.final();
    if (failures != 0) {
        std::printf("SHA-256 SEC RTL tests failed: %d\n", failures);
        return 1;
    }
    std::puts("SHA-256 SEC RTL tests passed");
    return 0;
}
