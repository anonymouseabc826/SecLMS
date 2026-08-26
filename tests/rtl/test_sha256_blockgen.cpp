#include "Vlms_sha256_blockgen.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>

double sc_time_stamp()
{
    return 0.0;
}

static uint8_t block_byte(const Vlms_sha256_blockgen &dut, int index)
{
    const int word = 15 - index / 4;
    const int shift = (3 - index % 4) * 8;
    return static_cast<uint8_t>(dut.block[word] >> shift);
}

static void set_mmio_bytes(uint32_t *words, const uint8_t *bytes, int length)
{
    for (int index = 0; index < length; ++index) {
        words[index / 4] |= static_cast<uint32_t>(bytes[index]) << ((index % 4) * 8);
    }
}

static void set_bigendian_bytes(uint32_t *words, const uint8_t *bytes, int length)
{
    for (int index = 0; index < length; ++index) {
        words[7 - index / 4] |= static_cast<uint32_t>(bytes[index]) << ((3 - index % 4) * 8);
    }
}

static bool expect_byte(const Vlms_sha256_blockgen &dut, int index, uint8_t expected,
                        const char *name)
{
    const uint8_t actual = block_byte(dut, index);
    if (actual != expected) {
        std::printf("FAIL %-18s byte=%d expected=%02x actual=%02x\n",
                    name, index, expected, actual);
        return false;
    }
    return true;
}

static void clear_inputs(Vlms_sha256_blockgen &dut)
{
    dut.task_type = 0;
    dut.arg_q = 0;
    dut.arg_i = 0;
    dut.chain_j = 0;
    dut.derive_phase = 0;
    dut.input_length = 0;
    dut.block_index = 0;
    for (int index = 0; index < 32; ++index) dut.input_words_flat[index] = 0;
    for (int index = 0; index < 4; ++index) dut.identifier_flat[index] = 0;
    for (int index = 0; index < 8; ++index) {
        dut.chain_value[index] = 0;
        dut.seed_flat[index] = 0;
        dut.core_digest[index] = 0;
    }
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_sha256_blockgen dut;
    int passed = 0;
    int failed = 0;

    clear_inputs(dut);
    const uint8_t abc[] = {'a', 'b', 'c'};
    set_mmio_bytes(dut.input_words_flat, abc, 3);
    dut.input_length = 3;
    dut.eval();
    bool ok = expect_byte(dut, 0, 'a', "hash abc") &&
              expect_byte(dut, 1, 'b', "hash abc") &&
              expect_byte(dut, 2, 'c', "hash abc") &&
              expect_byte(dut, 3, 0x80, "hash abc") &&
              expect_byte(dut, 63, 0x18, "hash abc");
    ok ? ++passed : ++failed;

    clear_inputs(dut);
    std::array<uint8_t, 56> msg56{};
    for (int index = 0; index < 56; ++index) msg56[index] = static_cast<uint8_t>(index);
    set_mmio_bytes(dut.input_words_flat, msg56.data(), 56);
    dut.input_length = 56;
        dut.eval();
        ok = expect_byte(dut, 55, 0x37, "hash 56 block0") &&
            expect_byte(dut, 56, 0x80, "hash 56 block0") && dut.core_init;
    dut.block_index = 1;
    dut.eval();
        ok = expect_byte(dut, 0, 0x00, "hash 56 block1") && ok &&
         expect_byte(dut, 61, 0x00, "hash 56 block1") &&
         expect_byte(dut, 62, 0x01, "hash 56 block1") &&
         expect_byte(dut, 63, 0xc0, "hash 56 block1") && !dut.core_init;
    ok ? ++passed : ++failed;

    std::array<uint8_t, 16> identifier{};
    std::array<uint8_t, 32> value{};
    for (int index = 0; index < 16; ++index) identifier[index] = static_cast<uint8_t>(index);
    for (int index = 0; index < 32; ++index) value[index] = static_cast<uint8_t>(0x23 + index);

    clear_inputs(dut);
    dut.task_type = 1;
    set_mmio_bytes(dut.identifier_flat, identifier.data(), 16);
    set_bigendian_bytes(dut.chain_value, value.data(), 32);
    dut.arg_q = 0x10111213;
    dut.arg_i = 0x2021;
    dut.chain_j = 0x22;
    dut.eval();
    ok = expect_byte(dut, 15, 0x0f, "chain") &&
         expect_byte(dut, 16, 0x10, "chain") &&
         expect_byte(dut, 20, 0x20, "chain") &&
         expect_byte(dut, 22, 0x22, "chain") &&
         expect_byte(dut, 23, 0x23, "chain") &&
         expect_byte(dut, 54, 0x42, "chain") &&
         expect_byte(dut, 55, 0x80, "chain") &&
         expect_byte(dut, 63, 0xb8, "chain");
    ok ? ++passed : ++failed;

    clear_inputs(dut);
    dut.task_type = 2;
    dut.derive_phase = 1;
    set_mmio_bytes(dut.identifier_flat, identifier.data(), 16);
    set_bigendian_bytes(dut.seed_flat, value.data(), 32);
    dut.arg_q = 0x10111213;
    dut.arg_i = 0x2021;
    dut.eval();
    ok = expect_byte(dut, 22, 0xff, "derive") &&
         expect_byte(dut, 23, 0x23, "derive") &&
         expect_byte(dut, 54, 0x42, "derive") &&
         expect_byte(dut, 63, 0xb8, "derive");
    ok ? ++passed : ++failed;

    clear_inputs(dut);
    dut.task_type = 3;
    set_mmio_bytes(dut.identifier_flat, identifier.data(), 16);
    set_bigendian_bytes(dut.seed_flat, value.data(), 32);
    dut.arg_q = 0x10111213;
    dut.eval();
    ok = expect_byte(dut, 20, 0x85, "randomizer") &&
         expect_byte(dut, 21, 0x85, "randomizer") &&
         expect_byte(dut, 22, 0x23, "randomizer") &&
         expect_byte(dut, 53, 0x42, "randomizer") &&
         expect_byte(dut, 54, 0x80, "randomizer") &&
         expect_byte(dut, 63, 0xb0, "randomizer");
    ok ? ++passed : ++failed;

    std::printf("SHA-256 blockgen tests: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}