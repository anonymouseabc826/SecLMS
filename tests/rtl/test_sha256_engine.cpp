#include "Vlms_hash_engine.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

double sc_time_stamp()
{
    return 0.0;
}

static void tick(Vlms_hash_engine &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_hash_engine &dut)
{
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
}

static void clear_inputs(Vlms_hash_engine &dut)
{
    dut.start = 0;
    dut.command = 0;
    dut.input_length = 0;
    dut.arg_q = 0;
    dut.arg_i = 0;
    dut.arg_start = 0;
    dut.arg_steps = 0;
    dut.sha_ext_mode = 0;
    dut.sha_ext_start = 0;
    dut.sha_ext_init = 0;
    dut.sha_ext_state_load = 0;
    dut.sha_ext1_start = 0;
    dut.sha_ext1_init = 0;
    dut.sha_ext1_state_load = 0;
    for (int index = 0; index < 4; ++index) dut.identifier_flat[index] = 0;
    for (int index = 0; index < 8; ++index) {
        dut.chain_value_in[index] = 0;
        dut.seed_flat[index] = 0;
        dut.sha_ext_state_in[index] = 0;
        dut.sha_ext1_state_in[index] = 0;
    }
    for (int index = 0; index < 16; ++index) {
        dut.sha_ext_block[index] = 0;
        dut.sha_ext1_block[index] = 0;
    }
    for (int index = 0; index < 32; ++index) dut.input_words_flat[index] = 0;
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

static bool digest_matches(const Vlms_hash_engine &dut, const char *hex)
{
    for (int index = 0; index < 32; ++index) {
        const uint8_t expected = static_cast<uint8_t>(
            std::stoul(std::string(hex + index * 2, 2), nullptr, 16));
        const int word = 7 - index / 4;
        const int shift = (3 - index % 4) * 8;
        const uint8_t actual = static_cast<uint8_t>(dut.digest_out[word] >> shift);
        if (actual != expected) return false;
    }
    return true;
}

static bool run(Vlms_hash_engine &dut, const char *name, const char *digest,
                uint32_t expected_cycles)
{
    dut.start = 1;
    tick(dut);
    dut.start = 0;
    for (int count = 0; count < 20000 && !dut.done; ++count) tick(dut);
    const bool ok = dut.done && digest_matches(dut, digest) &&
                    dut.cycle_count == expected_cycles;
    std::printf("%s: %-18s cycles=%u\n", ok ? "PASS" : "FAIL", name,
                dut.cycle_count);
    tick(dut);
    return ok;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_hash_engine dut;
    reset(dut);
    int failures = 0;

    clear_inputs(dut);
    dut.command = 1;
    dut.input_length = 3;
    const uint8_t abc[] = {'a', 'b', 'c'};
    set_mmio_bytes(dut.input_words_flat, abc, 3);
    if (!run(dut, "HASH_ONCE abc",
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 68)) {
        ++failures;
    }

    clear_inputs(dut);
    dut.command = 2;
    dut.arg_q = 2;
    dut.arg_i = 3;
    dut.arg_start = 4;
    dut.arg_steps = 5;
    std::array<uint8_t, 16> identifier{};
    std::array<uint8_t, 32> value{};
    for (int index = 0; index < 16; ++index) identifier[index] = static_cast<uint8_t>(index);
    for (int index = 0; index < 32; ++index) value[index] = static_cast<uint8_t>(index);
    set_mmio_bytes(dut.identifier_flat, identifier.data(), 16);
    set_bigendian_bytes(dut.chain_value_in, value.data(), 32);
    if (!run(dut, "CHAIN 5",
             "226554e747dff2248698fb6a44dec122abea95361500a10635932db09ae7aff7", 336)) {
        ++failures;
    }

    clear_inputs(dut);
    dut.command = 4;
    dut.arg_q = 2;
    dut.arg_i = 3;
    dut.arg_steps = 5;
    set_mmio_bytes(dut.identifier_flat, identifier.data(), 16);
    set_bigendian_bytes(dut.seed_flat, value.data(), 32);
    if (!run(dut, "DERIVE_CHAIN 5",
             "e907a64a1cf902d6071558ebb11074a2ed0872409e692d47c45dac2439bab290", 403)) {
        ++failures;
    }

    clear_inputs(dut);
    dut.command = 5;
    dut.arg_q = 2;
    set_mmio_bytes(dut.identifier_flat, identifier.data(), 16);
    set_bigendian_bytes(dut.seed_flat, value.data(), 32);
    if (!run(dut, "RANDOMIZER",
             "b01a71bccdd3906f4efbeb7829c262c0bf813bbd7a4f26e0aeee95b307ac4735", 68)) {
        ++failures;
    }

    std::printf("SHA-256 engine tests: %d failed\n", failures);
    return failures == 0 ? 0 : 1;
}