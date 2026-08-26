#include "Vlms_sha256_core.h"
#include "verilated.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using Digest = std::array<uint8_t, 32>;

double sc_time_stamp()
{
    return 0.0;
}

static void tick(Vlms_sha256_core &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_sha256_core &dut)
{
    dut.start = 0;
    dut.init = 0;
    dut.state_load = 0;
    for (size_t index = 0; index < 8; ++index) {
        dut.state_in[index] = 0;
    }
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
}

static void set_block(Vlms_sha256_core &dut, const uint8_t *block)
{
    for (int word = 0; word < 16; ++word) {
        dut.block[word] = 0;
    }
    for (int index = 0; index < 64; ++index) {
        const int low_bit = 504 - index * 8;
        dut.block[low_bit / 32] |= static_cast<uint32_t>(block[index]) << (low_bit % 32);
    }
}

static Digest get_digest(const Vlms_sha256_core &dut)
{
    Digest digest{};
    for (int index = 0; index < 32; ++index) {
        const int low_bit = 248 - index * 8;
        digest[index] = static_cast<uint8_t>(dut.digest[low_bit / 32] >> (low_bit % 32));
    }
    return digest;
}

static int compress(Vlms_sha256_core &dut, const uint8_t *block, bool init)
{
    set_block(dut, block);
    dut.init = init;
    dut.start = 1;
    tick(dut);
    dut.start = 0;

    int cycles = 0;
    while (!dut.done && cycles < 65) {
        tick(dut);
        ++cycles;
    }
    if (!dut.done || dut.busy || cycles != 64) {
        std::printf("FAIL: compression completion busy=%u done=%u cycles=%d\n",
                    static_cast<unsigned>(dut.busy),
                    static_cast<unsigned>(dut.done),
                    cycles);
        return -1;
    }
    return cycles;
}

static std::vector<uint8_t> pad_message(const std::vector<uint8_t> &message)
{
    std::vector<uint8_t> padded = message;
    const uint64_t bit_length = static_cast<uint64_t>(message.size()) * 8u;
    padded.push_back(0x80);
    while ((padded.size() % 64u) != 56u) {
        padded.push_back(0x00);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        padded.push_back(static_cast<uint8_t>(bit_length >> shift));
    }
    return padded;
}

static Digest parse_digest(const std::string &hex)
{
    Digest digest{};
    for (size_t index = 0; index < digest.size(); ++index) {
        digest[index] = static_cast<uint8_t>(std::stoul(hex.substr(index * 2u, 2u), nullptr, 16));
    }
    return digest;
}

static int run_case(Vlms_sha256_core &dut,
                    const char *name,
                    const std::vector<uint8_t> &message,
                    const char *expected_hex)
{
    const std::vector<uint8_t> padded = pad_message(message);
    reset(dut);

    int total_cycles = 0;
    for (size_t offset = 0; offset < padded.size(); offset += 64u) {
        const int cycles = compress(dut, padded.data() + offset, offset == 0u);
        if (cycles < 0) {
            return 1;
        }
        total_cycles += cycles;
    }

    const Digest actual = get_digest(dut);
    const Digest expected = parse_digest(expected_hex);
    if (actual != expected) {
        std::printf("FAIL: %s digest mismatch\n", name);
        return 1;
    }

    std::printf("PASS: %-6s bytes=%3zu blocks=%zu cycles=%d\n",
                name, message.size(), padded.size() / 64u, total_cycles);
    return 0;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_sha256_core dut;
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

    int failures = 0;
    failures += run_case(dut, "empty", {},
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    failures += run_case(dut, "abc", {'a', 'b', 'c'},
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    failures += run_case(dut, "seq55", sequence55,
                         "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59");
    failures += run_case(dut, "seq64", sequence64,
                         "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108");
    failures += run_case(dut, "seq128", sequence128,
                         "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5");

    dut.final();
    if (failures != 0) {
        std::printf("SHA-256 RTL tests failed: %d\n", failures);
        return 1;
    }
    std::puts("SHA-256 RTL tests passed");
    return 0;
}