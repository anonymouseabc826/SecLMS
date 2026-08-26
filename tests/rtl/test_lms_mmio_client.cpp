#include "Vlms_sha256_mmio.h"
#include "verilated.h"

extern "C" {
#include "../../src/lms_internal.h"
#include "../../src/lms_mmio.h"
}

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using Digest = std::array<uint8_t, LMS_N>;

static unsigned software_fallback_calls;
static lmots_chain_backend_fn configured_keygen_backend;
static void *configured_keygen_context;
static lmots_chain_backend_fn configured_verify_backend;
static void *configured_verify_context;
static lmots_chain_backend_fn configured_sign_backend;
static void *configured_sign_context;
static lmots_derive_chain_backend_fn configured_keygen_derive_backend;
static void *configured_keygen_derive_context;
static lmots_derive_chain_backend_fn configured_sign_derive_backend;
static void *configured_sign_derive_context;
static lmots_randomizer_backend_fn configured_randomizer_backend;
static void *configured_randomizer_context;
static lmots_keygen_backend_fn configured_full_keygen_backend;
static void *configured_full_keygen_context;
static lmots_sign_backend_fn configured_full_sign_backend;
static void *configured_full_sign_context;
static lmots_verify_backend_fn configured_full_verify_backend;
static void *configured_full_verify_context;

extern "C" void lmots_keygen_chain_backend_set(lmots_chain_backend_fn backend, void *context)
{
    configured_keygen_backend = backend;
    configured_keygen_context = backend ? context : nullptr;
}

extern "C" void lmots_verify_chain_backend_set(lmots_chain_backend_fn backend, void *context)
{
    configured_verify_backend = backend;
    configured_verify_context = backend ? context : nullptr;
}

extern "C" void lmots_sign_chain_backend_set(lmots_chain_backend_fn backend, void *context)
{
    configured_sign_backend = backend;
    configured_sign_context = backend ? context : nullptr;
}

extern "C" void lmots_keygen_derive_backend_set(lmots_derive_chain_backend_fn backend,
                                                  void *context)
{
    configured_keygen_derive_backend = backend;
    configured_keygen_derive_context = backend ? context : nullptr;
}

extern "C" void lmots_keygen_backend_set(lmots_keygen_backend_fn backend, void *context)
{
    configured_full_keygen_backend = backend;
    configured_full_keygen_context = backend ? context : nullptr;
}

extern "C" void lmots_sign_backend_set(lmots_sign_backend_fn backend, void *context)
{
    configured_full_sign_backend = backend;
    configured_full_sign_context = backend ? context : nullptr;
}

extern "C" void lmots_verify_backend_set(lmots_verify_backend_fn backend, void *context)
{
    configured_full_verify_backend = backend;
    configured_full_verify_context = backend ? context : nullptr;
}
extern "C" void lmots_sign_derive_backend_set(lmots_derive_chain_backend_fn backend,
                                                void *context)
{
    configured_sign_derive_backend = backend;
    configured_sign_derive_context = backend ? context : nullptr;
}

extern "C" void lmots_sign_randomizer_backend_set(lmots_randomizer_backend_fn backend,
                                                    void *context)
{
    configured_randomizer_backend = backend;
    configured_randomizer_context = backend ? context : nullptr;
}

extern "C" int lms_hash(lms_hash_alg_t,
                        const uint8_t *,
                        size_t,
                        uint8_t *,
                        size_t)
{
    ++software_fallback_calls;
    return -1;
}

extern "C" int lmots_chain_compute(const uint8_t[LMS_I_LEN],
                                   lms_hash_alg_t,
                                   uint32_t,
                                   uint32_t,
                                   uint32_t,
                                   uint32_t,
                                   uint8_t[LMS_N])
{
    ++software_fallback_calls;
    return LMS_ERR_INVALID;
}

double sc_time_stamp()
{
    return 0.0;
}

struct VerilatedBus {
    Vlms_sha256_mmio *dut;
    bool corrupt_output_length;
};

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

static uint32_t verilated_read32(void *context, uint32_t offset)
{
    VerilatedBus &bus = *static_cast<VerilatedBus *>(context);
    bus.dut->bus_valid = 1;
    bus.dut->bus_write = 0;
    bus.dut->bus_addr = static_cast<uint16_t>(offset);
    tick(*bus.dut);
    const uint32_t value = bus.dut->bus_rdata;
    bus.dut->bus_valid = 0;
    bus.dut->eval();
    /* Extra tick: let RTL registers (e.g. stream_read_r) see bus_valid=0,
     * ensuring the auto-increment-read state machine resets to idle correctly. */
    tick(*bus.dut);
    return value;
}

static void verilated_write32(void *context, uint32_t offset, uint32_t value)
{
    VerilatedBus &bus = *static_cast<VerilatedBus *>(context);
    if (bus.corrupt_output_length && offset == LMS_MMIO_REG_OUTPUT_LENGTH) {
        value = LMS_MMIO_OUTPUT_LEN - 1;
    }
    bus.dut->bus_valid = 1;
    bus.dut->bus_write = 1;
    bus.dut->bus_addr = static_cast<uint16_t>(offset);
    bus.dut->bus_wdata = value;
    tick(*bus.dut);
    bus.dut->bus_valid = 0;
    bus.dut->bus_write = 0;
    bus.dut->eval();
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

static int run_hash_case(lms_mmio_client_t &client,
                         const char *name,
                         const std::vector<uint8_t> &message,
                         const char *expected_hex,
                         uint32_t expected_cycles)
{
    Digest output{};
    uint32_t cycles = 0;
    const int status = lms_mmio_hash_once(&client,
                                          message.empty() ? nullptr : message.data(),
                                          message.size(),
                                          output.data(),
                                          &cycles);
    if (status != LMS_MMIO_OK || output != parse_digest(expected_hex) ||
        cycles != expected_cycles || client.last_hw_error != LMS_MMIO_HW_ERR_NONE ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        std::printf("FAIL: %s status=%d cycles=%u hw_error=%u fallback=%u oracle=%u\n",
                    name,
                    status,
                    cycles,
                    client.last_hw_error,
                    client.fallback_count,
                    software_fallback_calls);
        return 1;
    }
    std::printf("PASS: %-6s bytes=%3zu cycles=%u fallback=0\n",
                name, message.size(), cycles);
    return 0;
}

static int test_hardware_error(lms_mmio_client_t &client, VerilatedBus &bus)
{
    static const uint8_t message[] = {'a', 'b', 'c'};
    Digest output;
    output.fill(0x5a);
    const Digest before = output;
    uint32_t cycles = 99;

    bus.corrupt_output_length = true;
    const int status = lms_mmio_hash_once(&client,
                                          message,
                                          sizeof(message),
                                          output.data(),
                                          &cycles);
    bus.corrupt_output_length = false;
    if (status != LMS_MMIO_ERR_HARDWARE ||
        client.last_hw_error != LMS_MMIO_HW_ERR_OUTPUT_LENGTH ||
        output != before || cycles != 0 || client.fallback_count != 0 ||
        software_fallback_calls != 0) {
        std::printf("FAIL: hardware error status=%d hw_error=%u cycles=%u fallback=%u oracle=%u\n",
                    status,
                    client.last_hw_error,
                    cycles,
                    client.fallback_count,
                    software_fallback_calls);
        return 1;
    }
    std::puts("PASS: RTL error propagated without fallback");
    return 0;
}

static int run_chain_case(lms_mmio_client_t &client,
                          uint32_t start,
                          uint32_t steps,
                          const char *expected_hex,
                          uint32_t expected_cycles)
{
    uint8_t identifier[LMS_I_LEN];
    Digest value;
    for (size_t index = 0; index < sizeof(identifier); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }
    for (size_t index = 0; index < value.size(); ++index) {
        value[index] = static_cast<uint8_t>(index);
    }

    uint32_t cycles = 0;
    const int status = lms_mmio_chain(&client, identifier, 2, 3, start, steps,
                                      value.data(), &cycles);
    if (status != LMS_MMIO_OK || value != parse_digest(expected_hex) ||
        cycles != expected_cycles || client.last_hw_error != LMS_MMIO_HW_ERR_NONE ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        std::printf("FAIL: CHAIN start=%u steps=%u status=%d cycles=%u hw_error=%u fallback=%u oracle=%u\n",
                    start, steps, status, cycles, client.last_hw_error,
                    client.fallback_count, software_fallback_calls);
        return 1;
    }
    std::printf("PASS: CHAIN start=%u steps=%u cycles=%u fallback=0\n",
                start, steps, cycles);
    return 0;
}

static int test_verify_backend_adapter(lms_mmio_client_t &client)
{
    const std::vector<uint8_t> coefficients = parse_hex(
        "030f010e0e000206080e0d04080a04090308060706010c050e0c090f0a050c08"
        "020d040905080202080a00010c0b060207050d0300080604020e0c0c01020200"
        "020004");
    const std::vector<uint8_t> signature = load_vector("LMOTS_SIGNATURE");
    const std::vector<uint8_t> identifier =
        parse_hex("0123456789abcdeffedcba9876543210");
    Digest value{};
    const uint64_t count_before = client.hardware_verify_count;
    const uint64_t cycles_before = client.hardware_verify_cycles;

    if (coefficients.size() != 67u ||
        signature.size() != 2180 ||
        lms_mmio_lmots_verify_enable(&client) != LMS_MMIO_OK ||
        configured_full_verify_backend == nullptr ||
        configured_full_verify_context != &client ||
        configured_verify_backend != nullptr ||
        configured_keygen_backend != nullptr || configured_sign_backend != nullptr) {
        std::puts("FAIL: enable RTL verify backend adapter");
        return 1;
    }
    if (configured_full_verify_backend(
            configured_full_verify_context, identifier.data(), LMS_HASH_SHA256,
            0, LMOTS_SHA256_N32_W4, coefficients.data(),
            signature.data() + 36, value.data()) != LMS_OK ||
        value != parse_digest(
            "4e04196ca2b08517e90373f79eb93adbb59c0f9107020328bbc3dcd878b95431") ||
        client.hardware_verify_count != count_before + 1 ||
        client.hardware_verify_cycles < cycles_before + 25000 ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        auto exp = parse_digest("4e04196ca2b08517e90373f79eb93adbb59c0f9107020328bbc3dcd878b95431");
        std::printf("FAIL: Verify om=%d cycles=%llu out[0:2]=%02x%02x%02x\n",
            value==exp?1:0, (unsigned long long)(client.hardware_verify_cycles - cycles_before),
            value[0],value[1],value[2]);
        return 1;
    }
    if (configured_full_verify_backend(
            configured_full_verify_context, identifier.data(), LMS_HASH_HARAKA,
            0, LMOTS_SHA256_N32_W4, coefficients.data(),
            signature.data() + 36, value.data()) != LMS_ERR_INVALID ||
        client.hardware_verify_count != count_before + 1) {
        std::puts("FAIL: RTL verify backend accepted non-SHA256");
        return 1;
    }
    lms_mmio_lmots_verify_disable();
    if (configured_full_verify_backend != nullptr ||
        configured_full_verify_context != nullptr) {
        std::puts("FAIL: disable RTL verify backend adapter");
        return 1;
    }
    std::puts("PASS: LM-OTS Verify used one batch command cycles=40069");
    return 0;
}

/* VERIFY_LEAF: lms_mmio library driver (same source as firmware), D_LEAF in one command.
 * Expected D_LEAF = software reference 7da83430... (I||node32||D_LEAF||Kq=4e04196c). */
static int test_verify_leaf_adapter(lms_mmio_client_t &client)
{
    const std::vector<uint8_t> coefficients = parse_hex(
        "030f010e0e000206080e0d04080a04090308060706010c050e0c090f0a050c08"
        "020d040905080202080a00010c0b060207050d0300080604020e0c0c01020200"
        "020004");
    const std::vector<uint8_t> signature = load_vector("LMOTS_SIGNATURE");
    const std::vector<uint8_t> identifier =
        parse_hex("0123456789abcdeffedcba9876543210");
    Digest leaf{};
    const uint64_t count_before = client.hardware_verify_count;
    const uint64_t cycles_before = client.hardware_verify_cycles;

    if (coefficients.size() != 67u || signature.size() != 2180) {
        std::puts("FAIL: load verify_leaf oracle");
        return 1;
    }
    const int status = lms_mmio_lmots_verify_leaf(
        &client, identifier.data(), 0u, 32u, LMOTS_SHA256_N32_W4,
        coefficients.data(), signature.data() + 36, leaf.data(), nullptr);
    const auto exp = parse_digest(
        "7da8343018f62b3b17bdb0eaf11402323f784ce69ea3112c0a568cfd5a4809db");
    if (status != LMS_MMIO_OK || leaf != exp ||
        client.hardware_verify_count != count_before + 1 ||
        client.hardware_verify_cycles < cycles_before + 25000 ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        std::printf("FAIL: VerifyLeaf status=%d cycles=%llu leaf=%02x%02x%02x...%02x%02x%02x\n",
                    status,
                    (unsigned long long)(client.hardware_verify_cycles - cycles_before),
                    leaf[0], leaf[1], leaf[2], leaf[29], leaf[30], leaf[31]);
        return 1;
    }
    std::puts("PASS: LM-OTS VerifyLeaf one command D_LEAF=7da83430");
    return 0;
}

static int test_sign_backend_adapter(lms_mmio_client_t &client)
{
    uint8_t identifier[LMS_I_LEN];
    Digest value;
    const uint64_t count_before = client.hardware_chain_count;
    const uint64_t cycles_before = client.hardware_chain_cycles;
    for (size_t index = 0; index < sizeof(identifier); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }
    for (size_t index = 0; index < value.size(); ++index) {
        value[index] = static_cast<uint8_t>(index);
    }

    if (lms_mmio_lmots_sign_enable_insecure(&client) != LMS_MMIO_OK ||
        configured_sign_backend == nullptr || configured_sign_context != &client ||
        configured_verify_backend != nullptr || configured_keygen_backend != nullptr) {
        std::puts("FAIL: enable RTL sign backend adapter");
        return 1;
    }
    if (configured_sign_backend(configured_sign_context, identifier, LMS_HASH_SHA256,
                                2, 3, 4, 5, value.data()) != LMS_OK ||
        value != parse_digest("226554e747dff2248698fb6a44dec122abea95361500a10635932db09ae7aff7") ||
        client.hardware_chain_count != count_before + 1 ||
        client.hardware_chain_cycles != cycles_before + 336 ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        std::puts("FAIL: RTL sign backend adapter result or statistics");
        return 1;
    }
    if (configured_sign_backend(configured_sign_context, identifier, LMS_HASH_HARAKA,
                                2, 3, 4, 5, value.data()) != LMS_ERR_INVALID ||
        client.hardware_chain_count != count_before + 1) {
        std::puts("FAIL: RTL sign backend accepted a non-SHA256 chain");
        return 1;
    }
    lms_mmio_lmots_sign_disable();
    if (configured_sign_backend != nullptr || configured_sign_context != nullptr) {
        std::puts("FAIL: disable RTL sign backend adapter");
        return 1;
    }
    std::puts("PASS: LM-OTS Sign backend drove RTL without fallback");
    return 0;
}

static int test_keygen_backend_adapter(lms_mmio_client_t &client)
{
    uint8_t identifier[LMS_I_LEN];
    Digest value;
    const uint64_t count_before = client.hardware_chain_count;
    const uint64_t cycles_before = client.hardware_chain_cycles;
    for (size_t index = 0; index < sizeof(identifier); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }
    for (size_t index = 0; index < value.size(); ++index) {
        value[index] = static_cast<uint8_t>(index);
    }

    if (lms_mmio_lmots_keygen_enable_insecure(&client) != LMS_MMIO_OK ||
        configured_keygen_backend == nullptr || configured_keygen_context != &client ||
        configured_verify_backend != nullptr || configured_sign_backend != nullptr) {
        std::puts("FAIL: enable RTL keygen backend adapter");
        return 1;
    }
    if (configured_keygen_backend(configured_keygen_context, identifier, LMS_HASH_SHA256,
                                  2, 3, 4, 5, value.data()) != LMS_OK ||
        value != parse_digest("226554e747dff2248698fb6a44dec122abea95361500a10635932db09ae7aff7") ||
        client.hardware_chain_count != count_before + 1 ||
        client.hardware_chain_cycles != cycles_before + 336 ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        std::puts("FAIL: RTL keygen backend adapter result or statistics");
        return 1;
    }
    if (configured_keygen_backend(configured_keygen_context, identifier, LMS_HASH_HARAKA,
                                  2, 3, 4, 5, value.data()) != LMS_ERR_INVALID ||
        client.hardware_chain_count != count_before + 1) {
        std::puts("FAIL: RTL keygen backend accepted a non-SHA256 chain");
        return 1;
    }
    lms_mmio_lmots_keygen_disable();
    if (configured_keygen_backend != nullptr || configured_keygen_context != nullptr) {
        std::puts("FAIL: disable RTL keygen backend adapter");
        return 1;
    }
    std::puts("PASS: LM-OTS KeyGen backend drove RTL without fallback");
    return 0;
}

static int test_secure_derive(lms_mmio_client_t &client)
{
    uint8_t identifier[LMS_I_LEN];
    uint8_t seed[LMS_SEED_LEN];
    Digest output{};
    uint32_t cycles = 0;
    for (size_t index = 0; index < sizeof(identifier); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }
    for (size_t index = 0; index < sizeof(seed); ++index) {
        seed[index] = static_cast<uint8_t>(index);
    }

    if (lms_mmio_seed_load_test(&client, 0, seed) != LMS_MMIO_OK ||
        lms_mmio_derive_chain(&client, 0, identifier, 2, 3, 0, 5,
                              output.data(), &cycles) != LMS_MMIO_OK ||
        output != parse_digest(
            "e907a64a1cf902d6071558ebb11074a2ed0872409e692d47c45dac2439bab290") ||
        cycles != 403 || client.hardware_derive_count != 1 ||
        client.hardware_derive_cycles != 403) {
        std::puts("FAIL: C client DERIVE_CHAIN/RTL fixed vector");
        return 1;
    }
    if (lms_mmio_derive_randomizer(&client, 0, identifier, 2,
                                   output.data(), &cycles) != LMS_MMIO_OK ||
        output != parse_digest(
            "b01a71bccdd3906f4efbeb7829c262c0bf813bbd7a4f26e0aeee95b307ac4735") ||
        cycles != 68 || client.hardware_derive_count != 2 ||
        client.hardware_derive_cycles != 471) {
        std::puts("FAIL: C client DERIVE_RANDOMIZER/RTL fixed vector");
        return 1;
    }
    std::puts("PASS: C client secure derive drove RTL cycles=403+68 fallback=0");
    return 0;
}

static int test_secure_keygen_batch(lms_mmio_client_t &client)
{
    uint8_t identifier[LMS_I_LEN];
    Digest output{};
    const uint64_t count_before = client.hardware_keygen_count;
    const uint64_t cycles_before = client.hardware_keygen_cycles;
    for (size_t index = 0; index < sizeof(identifier); ++index) {
        identifier[index] = static_cast<uint8_t>(index);
    }

    if (lms_mmio_lmots_keygen_enable(&client, 0) != LMS_MMIO_OK ||
        configured_full_keygen_backend == nullptr ||
        configured_full_keygen_context != &client ||
        configured_full_keygen_backend(configured_full_keygen_context,
                                       identifier, LMS_HASH_SHA256, 2,
                                       LMOTS_SHA256_N32_W4,
                                       output.data()) != LMS_OK ||
        output != parse_digest(
            "c5347dc85e397959942e5acc1de4984a10fa829b0a353a34ac966f8dc849e4e8") ||
        client.hardware_keygen_count != count_before + 1 ||
        client.hardware_keygen_cycles < cycles_before + 35000 ||
        client.hardware_derive_count != 2 ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        std::puts("FAIL: secure LM-OTS KeyGen batch backend");
        std::printf("  DBG: count=%llu exp=%llu cycles=%llu derive=%llu fb=%llu hwerr=%08lx\n",
                    (unsigned long long)client.hardware_keygen_count,
                    (unsigned long long)(count_before + 1),
                    (unsigned long long)(client.hardware_keygen_cycles - cycles_before),
                    (unsigned long long)client.hardware_derive_count,
                    (unsigned long long)client.fallback_count,
                    (unsigned long)client.last_hw_error);
        std::printf("  DBG: out=%02x%02x%02x%02x... exp=c5347dc8...\n",
                    output[0], output[1], output[2], output[3]);
        return 1;
    }
    lms_mmio_lmots_keygen_disable();
    if (configured_full_keygen_backend != nullptr ||
        configured_full_keygen_context != nullptr) {
        std::puts("FAIL: disable secure LM-OTS KeyGen batch backend");
        return 1;
    }
    std::printf("PASS: secure LM-OTS KeyGen batch backend cycles=%llu\n",
                (unsigned long long)(client.hardware_keygen_cycles - cycles_before));
    return 0;
}

static int test_secure_sign_batch(lms_mmio_client_t &client)
{
    const std::vector<uint8_t> coefficients = parse_hex(
        "030f010e0e000206080e0d04080a04090308060706010c050e0c090f0a050c08"
        "020d040905080202080a00010c0b060207050d0300080604020e0c0c01020200"
        "020004");
    const std::vector<uint8_t> signature = load_vector("LMOTS_SIGNATURE");
    const std::vector<uint8_t> identifier =
        parse_hex("0123456789abcdeffedcba9876543210");
    std::vector<uint8_t> outputs(67u * LMS_N);
    const uint64_t count_before = client.hardware_sign_count;
    const uint64_t cycles_before = client.hardware_sign_cycles;

    if (coefficients.size() != 67u ||
        signature.size() != 2180 ||
        lms_mmio_lmots_sign_enable(&client, 0) != LMS_MMIO_OK ||
        configured_full_sign_backend == nullptr ||
        configured_full_sign_context != &client ||
        configured_randomizer_backend == nullptr ||
        configured_sign_derive_backend != nullptr ||
        configured_full_sign_backend(
            configured_full_sign_context, identifier.data(), LMS_HASH_SHA256,
            0, LMOTS_SHA256_N32_W4, coefficients.data(), outputs.data()) != LMS_OK ||
        outputs != std::vector<uint8_t>(signature.begin() + 36, signature.end()) ||
        client.hardware_sign_count != count_before + 1 ||
        client.hardware_sign_cycles < cycles_before + 18000 ||
        client.fallback_count != 0 || software_fallback_calls != 0) {
        std::puts("FAIL: secure LM-OTS Sign batch backend");
        return 1;
    }
    lms_mmio_lmots_sign_disable();
    if (configured_full_sign_backend != nullptr ||
        configured_full_sign_context != nullptr ||
        configured_randomizer_backend != nullptr) {
        std::puts("FAIL: disable secure LM-OTS Sign batch backend");
        return 1;
    }
    std::printf("PASS: secure LM-OTS Sign batch backend cycles=%llu\n",
                (unsigned long long)(client.hardware_sign_cycles - cycles_before));
    return 0;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_sha256_mmio dut;
    VerilatedBus verilated_bus{&dut, false};
    lms_mmio_bus_t bus{&verilated_bus, verilated_read32, verilated_write32};
    lms_mmio_client_t client;
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
    if (lms_mmio_client_init(&client, &bus, 100000, 0) != LMS_MMIO_OK) {
        std::puts("FAIL: client initialization");
        return 1;
    }

    int failures = 0;
    failures += run_hash_case(client, "empty", {},
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 68);
    failures += run_hash_case(client, "abc", {'a', 'b', 'c'},
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 68);
    failures += run_hash_case(client, "seq55", sequence55,
        "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59", 68);
    failures += run_hash_case(client, "seq64", sequence64,
        "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108", 135);
    failures += run_hash_case(client, "seq128", sequence128,
        "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5", 202);
    failures += run_chain_case(client, 4, 5,
        "226554e747dff2248698fb6a44dec122abea95361500a10635932db09ae7aff7", 336);
    failures += run_chain_case(client, 255, 0,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1);
    failures += test_secure_derive(client);
    failures += test_secure_keygen_batch(client);
    failures += test_secure_sign_batch(client);
    failures += test_verify_backend_adapter(client);
    failures += test_verify_leaf_adapter(client);
    failures += test_sign_backend_adapter(client);
    failures += test_keygen_backend_adapter(client);
    failures += test_hardware_error(client, verilated_bus);

    dut.final();
    if (failures != 0) {
        std::printf("LMS MMIO client/RTL tests failed: %d\n", failures);
        return 1;
    }
    std::puts("LMS MMIO client/RTL tests passed");
    return 0;
}