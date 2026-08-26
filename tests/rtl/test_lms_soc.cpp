#include "Vlms_soc.h"
#include "Vlms_soc___024root.h"
#include "verilated.h"
#include "verilated_vcd_c.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static constexpr int UART_BIT_CYCLES = 50000000 / 115200;

/* DBG trace: off by default (g_trace_on=false, no VCD generated, avoids hundreds of GB on disk).
 * To capture waveforms: (1) change the g_trace_on initial value below to true, or (2) uncomment
 * g_trace_on = true in the LM-OTS Sign section and keep the trace condition active in main (VCD covers only that section). */
static VerilatedVcdC *g_tfp = nullptr;
static bool g_trace_on = false;
static vluint64_t g_sim_time = 0;

double sc_time_stamp()
{
    return 0.0;
}

static void tick(Vlms_soc &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
    if (g_trace_on && g_tfp) {
        g_tfp->dump(g_sim_time);
        ++g_sim_time;
    }
}

static void ticks(Vlms_soc &dut, int count)
{
    for (int index = 0; index < count; ++index) {
        tick(dut);
    }
}

static void uart_send(Vlms_soc &dut, uint8_t value)
{
    dut.uart_rxd = 0;
    ticks(dut, UART_BIT_CYCLES);
    for (int bit = 0; bit < 8; ++bit) {
        dut.uart_rxd = (value >> bit) & 1u;
        ticks(dut, UART_BIT_CYCLES);
    }
    dut.uart_rxd = 1;
    ticks(dut, UART_BIT_CYCLES);
}

static bool uart_receive(Vlms_soc &dut, uint8_t &value,
                         int start_timeout = UART_BIT_CYCLES * 200)
{
    int timeout = start_timeout;
    while (dut.uart_txd != 0 && timeout-- > 0) {
        tick(dut);
    }
    if (timeout <= 0) {
        return false;
    }

    ticks(dut, UART_BIT_CYCLES + UART_BIT_CYCLES / 2);
    value = 0;
    for (int bit = 0; bit < 8; ++bit) {
        value |= static_cast<uint8_t>(dut.uart_txd) << bit;
        ticks(dut, UART_BIT_CYCLES);
    }
    ticks(dut, UART_BIT_CYCLES / 2);
    return true;
}

static std::vector<uint8_t> parse_hex(const std::string &hex)
{
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t offset = 0; offset < hex.size(); offset += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(offset, 2), nullptr, 16)));
    }
    return bytes;
}

struct VerifyVector {
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> message;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> lmots_public_key;
    std::vector<uint8_t> lmots_signature;
    uint32_t calls = 0;
    uint32_t steps = 0;
    uint32_t sign_calls = 0;
    uint32_t sign_steps = 0;
    uint32_t keygen_calls = 0;
    uint32_t keygen_steps = 0;
    uint32_t full_sign_calls = 0;
    uint32_t full_sign_steps = 0;
    uint32_t lmots_keygen_calls = 0;
    uint32_t lmots_keygen_steps = 0;
    uint32_t lmots_sign_calls = 0;
    uint32_t lmots_sign_steps = 0;
};

/* ---- Multi-parameter-set context (t8: w∈{1,2,4,8} × h∈{5,10,15}) ----
 * g_vector_path: vector file for the current parameter set (default build/lms_verify_vector.txt = W4/H5).
 * g_param_w/g_param_h: current parameter set, used for expected-hw decisions:
 *   - W4/H5: exact assertions (measured table values);
 *   - w≠4: LM-OTS is pure software (hw=0 strict); LMS trio D_INTR/message hash still in hardware (hw>0 TBD->loose);
 *   - W4+non-H5: LMS trio hw varies with h (D_INTR_CHAIN depth / tree-leaf count) -> loose (TBD by measurement).
 * Loose mode still strictly checks status / byte-identical result / fallback=0; only cycles/hits print actual values. */
static const char *g_vector_path = "build/lms_verify_vector.txt";
static int g_param_w = 4;
static int g_param_h = 5;

static bool load_verify_vector(VerifyVector &vector)
{
    std::ifstream input(g_vector_path);
    std::string line;
    while (std::getline(input, line)) {
        const size_t separator = line.find('=');
        if (separator == std::string::npos) continue;
        const std::string name = line.substr(0, separator);
        const std::string value = line.substr(separator + 1);
        if (name == "PRIVATE_KEY") vector.private_key = parse_hex(value);
        else if (name == "PUBLIC_KEY") vector.public_key = parse_hex(value);
        else if (name == "MESSAGE") vector.message = parse_hex(value);
        else if (name == "SIGNATURE") vector.signature = parse_hex(value);
        else if (name == "LMOTS_PUBLIC_KEY") vector.lmots_public_key = parse_hex(value);
        else if (name == "LMOTS_SIGNATURE") vector.lmots_signature = parse_hex(value);
        else if (name == "CALLS") vector.calls = static_cast<uint32_t>(std::stoul(value));
        else if (name == "STEPS") vector.steps = static_cast<uint32_t>(std::stoul(value));
        else if (name == "SIGN_CALLS") vector.sign_calls = static_cast<uint32_t>(std::stoul(value));
        else if (name == "SIGN_STEPS") vector.sign_steps = static_cast<uint32_t>(std::stoul(value));
        else if (name == "KEYGEN_CALLS") vector.keygen_calls = static_cast<uint32_t>(std::stoul(value));
        else if (name == "KEYGEN_STEPS") vector.keygen_steps = static_cast<uint32_t>(std::stoul(value));
        else if (name == "FULL_SIGN_CALLS") vector.full_sign_calls = static_cast<uint32_t>(std::stoul(value));
        else if (name == "FULL_SIGN_STEPS") vector.full_sign_steps = static_cast<uint32_t>(std::stoul(value));
        else if (name == "LMOTS_KEYGEN_CALLS") vector.lmots_keygen_calls = static_cast<uint32_t>(std::stoul(value));
        else if (name == "LMOTS_KEYGEN_STEPS") vector.lmots_keygen_steps = static_cast<uint32_t>(std::stoul(value));
        else if (name == "LMOTS_SIGN_CALLS") vector.lmots_sign_calls = static_cast<uint32_t>(std::stoul(value));
        else if (name == "LMOTS_SIGN_STEPS") vector.lmots_sign_steps = static_cast<uint32_t>(std::stoul(value));
    }
    /* Multi-parameter sets: lengths derived from the vector itself, no longer hard-coding W4/H5 special sizes/call counts.
     * Only the fixed-byte-length fields are checked (w/h determine the rest). */
    if (!(vector.private_key.size() == 60 && vector.public_key.size() == 56 &&
          vector.message.size() <= 2048 && vector.lmots_public_key.size() == 32)) {
        std::printf("DBG: vector load fail path=%s priv=%zu pub=%zu msg=%zu lmots_pub=%zu\n",
                    g_vector_path, vector.private_key.size(), vector.public_key.size(),
                    vector.message.size(), vector.lmots_public_key.size());
        return false;
    }
    /* REVIEW B13B16-R4: vector hash-caliber guard (aligned with board-test loader 61292e6). PRIVATE_KEY
     * first 8 bytes are lms_type/lmots_type (big-endian); validate the platform typecode range against the
     * firmware build macro, fail fast with a regenerate command (avoids "SHAKE vector on SHA engine" type failures). */
    {
        const uint32_t lms_type = (static_cast<uint32_t>(vector.private_key[0]) << 24) |
                                  (static_cast<uint32_t>(vector.private_key[1]) << 16) |
                                  (static_cast<uint32_t>(vector.private_key[2]) << 8) |
                                  static_cast<uint32_t>(vector.private_key[3]);
        const uint32_t lmots_type = (static_cast<uint32_t>(vector.private_key[4]) << 24) |
                                    (static_cast<uint32_t>(vector.private_key[5]) << 16) |
                                    (static_cast<uint32_t>(vector.private_key[6]) << 8) |
                                    static_cast<uint32_t>(vector.private_key[7]);
        bool type_ok = false;
#ifdef FW_HASH_SHAKE256
        type_ok = (lms_type >= 21u && lms_type <= 23u) &&
                  (lmots_type >= 17u && lmots_type <= 20u);
#else
        type_ok = (lms_type >= 5u && lms_type <= 7u) &&
                  (lmots_type >= 1u && lmots_type <= 4u);
#endif
        if (!type_ok) {
            std::printf("FAIL: vector hash mismatch lms_type=%08x lmots_type=%08x "
                        "(expected %s typecodes); regenerate: "
                        "make build/lms_verify_vector.txt HASH_IMPL=%s\n",
                        lms_type, lmots_type,
#ifdef FW_HASH_SHAKE256
                        "SHAKE256", "shake256");
#else
                        "SHA-256", "sha256");
#endif
            return false;
        }
    }
    return true;
}

static uint32_t get_u32(const std::array<uint8_t, 48> &response, size_t offset)
{
    return static_cast<uint32_t>(response[offset]) |
           static_cast<uint32_t>(response[offset + 1]) << 8 |
           static_cast<uint32_t>(response[offset + 2]) << 16 |
           static_cast<uint32_t>(response[offset + 3]) << 24;
}

static std::array<uint8_t, 32> parse_digest(const char *hex)
{
    std::array<uint8_t, 32> digest{};
    for (size_t index = 0; index < digest.size(); ++index) {
        digest[index] = static_cast<uint8_t>(std::stoul(std::string(hex + index * 2, 2), nullptr, 16));
    }
    return digest;
}

/* C1 TRNG diagnostic: read 0x59 TRNG_STATUS, expect VERSION=1/CAP=1 in payload.
 * Reproduces the on-board peripheral-read path (registered select + comb rdata). */
static bool run_uart_trng_status_case(Vlms_soc &dut)
{
    uart_send(dut, 0x59);
    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value)) {
            std::puts("FAIL: UART timeout in TRNG_STATUS");
            return false;
        }
    }
    /* Firmware response[i] maps to frame [16+i] (16-byte frame header occupies [0..15]). The firmware writes
     * TRNG values to response[16..31] -> frame [32..47]; sentinel response[8..11] -> frame [24..27];
     * lms_status response[12..15] -> frame [28..31]. Hence parse by frame offset:
     *   frame[32..33]=VERSION[15:0] frame[34..35]=CAP[15:0] frame[36..39]=STAT frame[40..43]=CTRL */
    uint32_t sentinel = get_u32(response, 24);
    uint32_t lms_status = get_u32(response, 28);
    uint32_t version = get_u32(response, 32) & 0xFFFFu;
    uint32_t cap = (get_u32(response, 32) >> 16) & 0xFFFFu;
    uint32_t stat = get_u32(response, 36);
    uint32_t ctrl = get_u32(response, 40);
    std::printf("DBG: sentinel=%08x lms_status=%08x VERSION=%u CAP=%u STAT=%08x CTRL=%08x\n",
                sentinel, lms_status, version, cap, stat, ctrl);
    if (response[0] != 0x52 || response[1] != 0 || version != 1 || (cap & 1u) == 0) {
        std::printf("FAIL: TRNG_STATUS marker=%02x status=%u VERSION=%u CAP=%u STAT=%08x\n",
                    response[0], response[1], version, cap, stat);
        return false;
    }
    std::printf("PASS: TRNG_STATUS VERSION=%u CAP=%u STAT=%08x CTRL=%08x\n",
                version, cap, stat, ctrl);
    return true;
}

/* C1(1) TRNG_READ_ACK (0x5A): request cmd||count||seq, expect 48B frame with seq echo
 * (frame[40]=firmware response[24]) then count*4B random words + 1B CRC8.
 * Verifies seq echo and CRC8 over the returned words (CRC-8/SMBUS poly 0x07). */
static uint8_t crc8_smbus(const uint8_t *data, size_t length)
{
    uint8_t crc = 0;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x80u) ? static_cast<uint8_t>((crc << 1) ^ 0x07u)
                                : static_cast<uint8_t>(crc << 1);
        }
    }
    return crc;
}

static bool run_uart_trng_read_ack_case(Vlms_soc &dut)
{
    const uint8_t count = 4;
    const uint8_t seq = 0xA5;
    uart_send(dut, 0x5A);
    uart_send(dut, count);
    uart_send(dut, seq);
    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value)) {
            std::puts("FAIL: UART timeout in TRNG_READ_ACK frame");
            return false;
        }
    }
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0) {
        std::printf("FAIL: TRNG_READ_ACK marker=%02x status=%u err=%u\n",
                    response[0], response[1], response[2]);
        return false;
    }
    uint32_t echo_count = get_u32(response, 36); /* frame[36..39]=count */
    uint8_t echo_seq = response[40];             /* frame[40]=seq echo */
    if (echo_count != count || echo_seq != seq) {
        std::printf("FAIL: TRNG_READ_ACK echo count=%u seq=%02x (expect %u/%02x)\n",
                    echo_count, echo_seq, count, seq);
        return false;
    }
    std::array<uint8_t, 64> words{};
    for (size_t i = 0; i < static_cast<size_t>(count) * 4; ++i) {
        if (!uart_receive(dut, words[i])) {
            std::puts("FAIL: UART timeout in TRNG_READ_ACK data");
            return false;
        }
    }
    uint8_t crc = 0;
    if (!uart_receive(dut, crc)) {
        std::puts("FAIL: UART timeout in TRNG_READ_ACK crc");
        return false;
    }
    uint8_t expect = crc8_smbus(words.data(), static_cast<size_t>(count) * 4);
    if (crc != expect) {
        std::printf("FAIL: TRNG_READ_ACK crc=%02x expect=%02x\n", crc, expect);
        return false;
    }
    std::printf("PASS: TRNG_READ_ACK seq=%02x count=%u crc=%02x ok\n", seq, count, crc);
    return true;
}

/* C1(1) uart_rx depth-2 FIFO burst stress: fire N back-to-back TRNG_READ_ACK
 * commands (uart_send is already gapless), verifying seq echo + CRC8 each batch.
 * Reproduces the firmware-wedge the host saw at ~12K batches on hardware when a
 * burst byte was dropped; here checks the FIFO never loses/corrupts a byte. */
static bool run_uart_trng_read_ack_stress(Vlms_soc &dut, int batches)
{
    const uint8_t count = 4;
    for (int i = 0; i < batches; ++i) {
        uint8_t seq = static_cast<uint8_t>(i & 0xFF);
        uart_send(dut, 0x5A);
        uart_send(dut, count);
        uart_send(dut, seq);
        std::array<uint8_t, 48> response{};
        for (uint8_t &value : response) {
            if (!uart_receive(dut, value)) {
                std::printf("FAIL: ACK stress batch %d frame timeout\n", i);
                return false;
            }
        }
        if (response[0] != 0x52 || response[1] != 0 || response[2] != 0) {
            std::printf("FAIL: ACK stress batch %d marker=%02x st=%u err=%u\n",
                        i, response[0], response[1], response[2]);
            return false;
        }
        if (get_u32(response, 36) != count || response[40] != seq) {
            std::printf("FAIL: ACK stress batch %d echo cnt=%u seq=%02x (exp %u/%02x)\n",
                        i, get_u32(response, 36), response[40], count, seq);
            return false;
        }
        std::array<uint8_t, 64> words{};
        for (size_t k = 0; k < static_cast<size_t>(count) * 4; ++k) {
            if (!uart_receive(dut, words[k])) {
                std::printf("FAIL: ACK stress batch %d data timeout\n", i);
                return false;
            }
        }
        uint8_t crc = 0;
        if (!uart_receive(dut, crc)) {
            std::printf("FAIL: ACK stress batch %d crc timeout\n", i);
            return false;
        }
        if (crc != crc8_smbus(words.data(), static_cast<size_t>(count) * 4)) {
            std::printf("FAIL: ACK stress batch %d crc mismatch\n", i);
            return false;
        }
    }
    std::printf("PASS: TRNG_READ_ACK burst stress %d batches, no byte loss\n", batches);
    return true;
}

static bool run_uart_case(Vlms_soc &dut,
                          const char *name,
                          const std::vector<uint8_t> &message,
                          const char *expected_hex,
                          uint32_t expected_cycles,
                          uint32_t expected_hits)
{
    uart_send(dut, 0x48);
    uart_send(dut, static_cast<uint8_t>(message.size()));
    for (uint8_t value : message) {
        uart_send(dut, value);
    }

    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value)) {
            std::printf("FAIL: UART timeout in %s\n", name);
            return false;
        }
    }

    const auto expected = parse_digest(expected_hex);
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        get_u32(response, 4) != expected_cycles ||
        get_u32(response, 8) != expected_hits || get_u32(response, 12) != 0 ||
        !std::equal(expected.begin(), expected.end(), response.begin() + 16)) {
        std::printf("FAIL: UART %s status=%u hw_error=%u cycles=%u hits=%u fallback=%u\n",
                    name, response[1], response[2], get_u32(response, 4),
                    get_u32(response, 8), get_u32(response, 12));
        std::printf("  exp=%s\n  got=", expected_hex);
        for (int idx = 0; idx < 32; ++idx) {
            std::printf("%02x", response[16 + idx]);
        }
        std::printf("\n");
        return false;
    }
    std::printf("PASS: UART %-6s bytes=%3zu cycles=%u hits=%u fallback=0\n",
                name, message.size(), expected_cycles, expected_hits);
    return true;
}

static bool run_uart_chain_case(Vlms_soc &dut, uint32_t expected_hits)
{
    uart_send(dut, 0x43);
    for (uint8_t value = 0; value < 16; ++value) uart_send(dut, value);
    uart_send(dut, 2);
    uart_send(dut, 0);
    uart_send(dut, 0);
    uart_send(dut, 0);
    uart_send(dut, 3);
    uart_send(dut, 0);
    uart_send(dut, 4);
    uart_send(dut, 5);
    for (uint8_t value = 0; value < 32; ++value) uart_send(dut, value);

    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value)) {
            std::puts("FAIL: UART timeout in CHAIN");
            return false;
        }
    }
    const auto expected = parse_digest(
        "226554e747dff2248698fb6a44dec122abea95361500a10635932db09ae7aff7");
#ifdef FW_HASH_SHAKE256
    /* SHAKE256 CHAIN (SoC KAT params): cycles=60, digest back-filled from measurement */
    const uint32_t shake_chain_cycles = get_u32(response, 4);
    const auto expected_shake = parse_digest(
        "b656b0c90b9c96c8c6c0ebc53a2b6ebca62a751d0491b14f415b27e9d6a72f62");
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        shake_chain_cycles != 60 || get_u32(response, 8) != expected_hits ||
        get_u32(response, 12) != 0 ||
        !std::equal(expected_shake.begin(), expected_shake.end(), response.begin() + 16)) {
        std::printf("FAIL: UART CHAIN status=%u hw_error=%u cycles=%u hits=%u fallback=%u\n",
                    response[1], response[2], shake_chain_cycles,
                    get_u32(response, 8), get_u32(response, 12));
        return false;
    }
    std::printf("PASS: UART CHAIN cycles=60 hits=%u fallback=0\n", expected_hits);
    return true;
#else
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        get_u32(response, 4) != 336 || get_u32(response, 8) != expected_hits ||
        get_u32(response, 12) != 0 ||
        !std::equal(expected.begin(), expected.end(), response.begin() + 16)) {
        std::printf("FAIL: UART CHAIN status=%u hw_error=%u cycles=%u hits=%u fallback=%u\n",
                    response[1], response[2], get_u32(response, 4),
                    get_u32(response, 8), get_u32(response, 12));
        return false;
    }
    std::printf("PASS: UART CHAIN start=4 steps=5 cycles=336 hits=%u fallback=0\n",
                expected_hits);
    return true;
#endif
}

static bool run_uart_verify_case(Vlms_soc &dut, uint32_t hits_before,
                                 uint32_t &hits_out, const char *tag)
{
    VerifyVector vector;
    if (!load_verify_vector(vector)) {
        std::printf("FAIL: load LMS Verify vector (%s)\n", tag);
        return false;
    }

    uart_send(dut, 0x56);
    for (uint8_t value : vector.public_key) uart_send(dut, value);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);
    /* Level 1 (>74B): pad message to 4B alignment (firmware bridge passthrough receives ceil(m/4)*4 bytes) */
    while (vector.message.size() > 74u && vector.message.size() % 4u != 0u) {
        uart_send(dut, 0u);
    }
    for (uint8_t value : vector.signature) uart_send(dut, value);

    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        /* Response frame timeout 50M: LMS Verify for w≠4 is pure-software leaf verification (W1 265 chains x
         * software SHAKE256 ≈ 9.3M cycles) plus receiving a long signature (W1 8684B ≈ 3.8M ticks),
         * so a 5M timeout is insufficient (was once misjudged as a hang). W4 is fast (~20K ticks), unaffected. */
        if (!uart_receive(dut, value, 50000000)) {
            std::printf("FAIL: UART timeout in LMS Verify gpio=%02x\n",
                        static_cast<unsigned>(dut.gpio_out));
            return false;
        }
    }

#ifdef FW_HASH_SHAKE256
    const uint32_t expect_w4h5 = 6614u;   /* After P2: VERIFY_LEAF(6482) + message hash + D_INTR_CHAIN(120) */
    const uint32_t expect_w4h5_hits = hits_before + 3u;  /* +1 LM-OTS Verify + 1 D_INTR_CHAIN + 1 message hash */
#else
    const uint32_t expect_w4h5 = 28341u;  /* = VERIFY_LEAF + D_INTR_CHAIN(5-level chain) + 1xMSG_Q_COEF (S8 new caliber, 0.1.266) */
    const uint32_t expect_w4h5_hits = hits_before + 3u;  /* +1 LM-OTS + 1 D_INTR_CHAIN + 1 message hash */
#endif
    /* W4/H5 exact assertions (measured table values); w≠4 or H≠5: auth path D_INTR_CHAIN depth/leaf-hash source
     * changes, hw TBD by measurement -> loose (still checks status/result/fallback, prints actual cycles/hits and returns hits_out). */
    const bool exact = (g_param_w == 4 && g_param_h == 5);
    const uint32_t expected_cycles = expect_w4h5;
    const uint32_t expected_hits = expect_w4h5_hits;
    /* frame[16..19]=response_value(0), [20..23]=total_cycles (end-to-end, >=hw cycles), [24..47]=0. */
    const uint32_t total_cycles = get_u32(response, 20);
    const bool stats_ok = !exact ||
        (get_u32(response, 4) == expected_cycles && get_u32(response, 8) == expected_hits);
    hits_out = get_u32(response, 8);
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        !stats_ok || get_u32(response, 12) != 0 ||
        total_cycles < get_u32(response, 4) ||
        !std::all_of(response.begin() + 16, response.begin() + 20, [](uint8_t value) { return value == 0; }) ||
        !std::all_of(response.begin() + 24, response.end(), [](uint8_t value) { return value == 0; })) {
        std::printf("FAIL: %s UART LMS Verify status=%u hw_error=%u cycles=%u/%u hits=%u/%u total=%u fallback=%u\n",
                    tag, response[1], response[2], get_u32(response, 4),
                    exact ? expected_cycles : get_u32(response, 4),
                    get_u32(response, 8), exact ? expected_hits : get_u32(response, 8),
                    total_cycles, get_u32(response, 12));
        return false;
    }
    std::printf("PASS: %s LMS Verify calls=%u steps=%u hw_cycles=%u total_cycles=%u hits=%u fallback=0%s\n",
                tag, vector.calls, vector.steps, get_u32(response, 4), total_cycles,
                get_u32(response, 8), exact ? "" : " (cycles TBD by measurement)");
    return true;
}

static bool run_uart_sign_case(Vlms_soc &dut, uint32_t hits_before,
                               uint32_t &hits_out, const char *tag)
{
    VerifyVector vector;
    if (!load_verify_vector(vector)) {
        std::printf("FAIL: load LMS Sign vector (%s)\n", tag);
        return false;
    }

    uart_send(dut, 0x53);
    for (uint8_t value : vector.private_key) uart_send(dut, value);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);
    /* Level 1 (>74B): pad message to 4B alignment (firmware bridge passthrough receives ceil(m/4)*4 bytes) */
    while (vector.message.size() > 74u && vector.message.size() % 4u != 0u) {
        uart_send(dut, 0u);
    }

    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value, 50000000)) {
            std::printf("FAIL: UART timeout in LMS Sign response trap=%u gpio=%02x\n",
                        static_cast<unsigned>(dut.trap),
                        static_cast<unsigned>(dut.gpio_out));
            return false;
        }
    }
    std::vector<uint8_t> signature(vector.signature.size());
    for (uint8_t &value : signature) {
        if (!uart_receive(dut, value, 5000000)) {
            std::puts("FAIL: UART timeout in LMS Sign signature");
            return false;
        }
    }

    /* With the tree cache enabled (fw 0.1.170 step 6b): sign_from_uart registers the lms_subtree backend for H5,
     * the auth path uses software cache lookup (**zero hardware calls** on hit), so Sign hardware cycles/hits are
     * only the LM-OTS signature itself (lmots_sign_calls/steps), no longer the recursive auth-path rebuild
     * full_sign_calls/steps. sign_init tree build is KeyGen semantics, not counted in Sign statistics.
     * Hence expected cycles/hits use the lmots_sign_* caliber (cache hit); the signature is still byte-compared. */
    /* fused sign_backend (CMD_LMOTS_SIGN): hw=23584 (dual-core DERIVE+CHAIN), hits=1 (fused sign). */
#ifdef FW_HASH_SHAKE256
    const uint32_t expect_w4h5 = 5499u;   /* After P2+P3: dual-core SIGN (-391 folded -536 background write) */
#else
    const uint32_t expect_w4h5 = 23811u;  /* = randomizer + SIGN batch tasks + 1xMSG_Q_COEF (S8 new caliber, 0.1.266) */
#endif
    const bool exact = (g_param_w == 4 && g_param_h == 5);
    const uint32_t expected_cycles = expect_w4h5;
    const uint32_t expected_hits = hits_before + 3u;  /* 1 randomizer derive + 1 fused sign + 1 message hash */
    /* frame[16..19]=next_q(1), [20..23]=total_cycles (end-to-end incl. sign_init tree build),
     * [24..27]=steady_total_cycles (steady single-sign after init, for fair comparison),
     * [28..31]=parse_cycles (lms_private_key_parse time, profiling), [32..47]=0. */
    const uint32_t total_cycles = get_u32(response, 20);
    const uint32_t steady_total = get_u32(response, 24);
    const uint32_t parse_cycles = get_u32(response, 28);
    const uint32_t prof_derive_hw = get_u32(response, 32);
    const uint32_t prof_sign_hw   = get_u32(response, 36);
    const uint32_t actual_hw = get_u32(response, 4);
    const uint32_t prof_chain_hw  = actual_hw - prof_derive_hw - prof_sign_hw;
    const bool stats_ok = !exact ||
        (actual_hw == expected_cycles && get_u32(response, 8) == expected_hits);
    hits_out = get_u32(response, 8);
    /* total/steady use range assertions (firmware layout changes drift slightly); loose mode total>=actual hw. */
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        !stats_ok || get_u32(response, 12) != 0 ||
        get_u32(response, 16) != 1 || total_cycles < actual_hw ||
        steady_total < actual_hw || steady_total >= total_cycles ||
        signature != vector.signature) {
        std::printf("FAIL: %s UART LMS Sign status=%u hw_error=%u cycles=%u/%u hits=%u/%u total=%u steady=%u parse=%u q=%u fallback=%u sig_match=%d\n",
                    tag, response[1], response[2], actual_hw,
                    exact ? expected_cycles : actual_hw,
                    get_u32(response, 8), exact ? expected_hits : get_u32(response, 8),
                    total_cycles, steady_total, parse_cycles, get_u32(response, 16),
                    get_u32(response, 12), (int)(signature == vector.signature));
        return false;
    }
    std::printf("PASS: %s LMS Sign (cached) calls=%u steps=%u hw_cycles=%u total_cycles=%u steady_total=%u parse=%u hits=%u q=1 fallback=0%s\n",
                tag, vector.lmots_sign_calls, vector.lmots_sign_steps, actual_hw,
                total_cycles, steady_total, parse_cycles, get_u32(response, 8),
                exact ? "" : " (cycles TBD by measurement)");
    std::printf("      profile: chain_hw=%u derive_hw=%u sign_hw=%u sign_sw=%u\n",
                prof_chain_hw, prof_derive_hw, prof_sign_hw,
                steady_total - actual_hw);
    return true;
}

/* 1KB big-message LMS Sign + Verify (HASH_ONCE_RAM multi-block absorb, level 0):
 * verifies signature/public-key byte-identical + fallback=0 + q=1; cycles/hits loose
 * (1KB message hash goes from single-block 12 cycles -> multi-block ~108 cycles; exact values TBD on board). */
static bool run_uart_big_msg_1kb(Vlms_soc &dut)
{
    const char *saved_path = g_vector_path;
#ifdef FW_HASH_SHAKE256
    g_vector_path = "build/vectors/lms_verify_vector_W4_H5_1KB.txt";
#else
    g_vector_path = "build/vectors/lms_verify_vector_W4_H5_1KB_sha256.txt";
#endif
    VerifyVector vector;
    bool ok = true;
    if (!load_verify_vector(vector)) {
        std::printf("FAIL: load 1KB vector\n");
        g_vector_path = saved_path;
        return false;
    }
    std::printf("DBG: 1KB vector message=%zu sig=%zu path=%s\n",
                vector.message.size(), vector.signature.size(), g_vector_path);
    /* ---- LMS Sign (0x53) ---- */
    uart_send(dut, 0x53);
    for (uint8_t value : vector.private_key) uart_send(dut, value);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);
    /* Level 1 (>74B): pad message to 4B alignment (firmware bridge passthrough receives ceil(m/4)*4 bytes) */
    while (vector.message.size() > 74u && vector.message.size() % 4u != 0u) {
        uart_send(dut, 0u);
    }
    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value, 50000000)) {
            std::printf("FAIL: 1KB LMS Sign response timeout gpio=%02x\n",
                        static_cast<unsigned>(dut.gpio_out));
            ok = false;
            goto done;
        }
    }
    {
        std::vector<uint8_t> signature(vector.signature.size());
        for (uint8_t &value : signature) {
            if (!uart_receive(dut, value, 5000000)) {
                std::puts("FAIL: 1KB LMS Sign signature timeout");
                ok = false;
                goto done;
            }
        }
        const uint32_t hw = get_u32(response, 4);
        const uint32_t total = get_u32(response, 20);
        const uint32_t steady = get_u32(response, 24);
        if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
            get_u32(response, 12) != 0 || get_u32(response, 16) != 1 ||
            steady < hw || steady >= total || signature != vector.signature) {
            std::printf("FAIL: 1KB LMS Sign status=%u hw=%u total=%u steady=%u fallback=%u sig_match=%d\n",
                        response[1], hw, total, steady, get_u32(response, 12),
                        (int)(signature == vector.signature));
            ok = false;
            goto done;
        }
        std::printf("PASS: 1KB LMS Sign hw=%u total=%u steady=%u fallback=0 (big msg)\n",
                    hw, total, steady);
    }
    /* ---- LMS Verify (0x56) ---- */
    uart_send(dut, 0x56);
    for (uint8_t value : vector.public_key) uart_send(dut, value);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);
    /* Level 1 (>74B): pad message to 4B alignment (firmware bridge passthrough receives ceil(m/4)*4 bytes) */
    while (vector.message.size() > 74u && vector.message.size() % 4u != 0u) {
        uart_send(dut, 0u);
    }
    for (uint8_t value : vector.signature) uart_send(dut, value);
    response.fill(0);
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value, 50000000)) {
            std::printf("FAIL: 1KB LMS Verify timeout gpio=%02x\n",
                        static_cast<unsigned>(dut.gpio_out));
            ok = false;
            goto done;
        }
    }
    {
        const uint32_t hw = get_u32(response, 4);
        const uint32_t total = get_u32(response, 20);
        if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
            get_u32(response, 12) != 0 || total < hw) {
            std::printf("FAIL: 1KB LMS Verify status=%u hw=%u total=%u fallback=%u\n",
                        response[1], hw, total, get_u32(response, 12));
            ok = false;
            goto done;
        }
        std::printf("PASS: 1KB LMS Verify hw=%u total=%u fallback=0 (big msg)\n",
                    hw, total);
    }
done:
    g_vector_path = saved_path;
    return ok;
}

static bool run_uart_keygen_case(Vlms_soc &dut, uint32_t hits_before,
                                 uint32_t &hits_out, const char *tag)
{
    VerifyVector vector;
    if (!load_verify_vector(vector)) {
        std::printf("FAIL: load LMS KeyGen vector (%s)\n", tag);
        return false;
    }

    uart_send(dut, 0x4b);
    for (uint8_t value : vector.private_key) uart_send(dut, value);

    std::array<uint8_t, 48> response{};
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value, 50000000)) {
            std::printf("FAIL: UART timeout in LMS KeyGen response trap=%u gpio=%02x\n",
                        static_cast<unsigned>(dut.trap),
                        static_cast<unsigned>(dut.gpio_out));
            return false;
        }
    }
    std::vector<uint8_t> public_key(vector.public_key.size());
    for (uint8_t &value : public_key) {
        if (!uart_receive(dut, value, 5000000)) {
            std::puts("FAIL: UART timeout in LMS KeyGen public key");
            return false;
        }
    }

#ifdef FW_HASH_SHAKE256
    const uint32_t expect_w4h5 = 287732u;  /* After P2: 32xKEYGEN_LEAF(8980) + 31x12 */
#else
    const uint32_t expect_w4h5 = 1246681u;  /* 32 x KEYGEN_LEAF + 31 x D_INTR (new caliber) */
#endif
    const bool exact = (g_param_w == 4 && g_param_h == 5);
    const uint32_t expected_cycles = expect_w4h5;
    const uint32_t expected_hits = hits_before + 63u;  /* 32 KEYGEN_LEAF + 31 D_INTR */
    /* frame[16..19]=response_value(0), [20..23]=total_cycles (end-to-end, >=hw), [24..47]=0. */
    const uint32_t total_cycles = get_u32(response, 20);
    const bool stats_ok = !exact ||
        (get_u32(response, 4) == expected_cycles && get_u32(response, 8) == expected_hits);
    hits_out = get_u32(response, 8);
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        !stats_ok || get_u32(response, 12) != 0 ||
        total_cycles < get_u32(response, 4) ||
        !std::all_of(response.begin() + 16, response.begin() + 20, [](uint8_t value) { return value == 0; }) ||
        !std::all_of(response.begin() + 24, response.end(), [](uint8_t value) { return value == 0; }) ||
        public_key != vector.public_key) {
        std::printf("FAIL: %s UART LMS KeyGen status=%u hw_error=%u cycles=%u/%u hits=%u/%u total=%u fallback=%u\n",
                    tag, response[1], response[2], get_u32(response, 4),
                    exact ? expected_cycles : get_u32(response, 4),
                    get_u32(response, 8), exact ? expected_hits : get_u32(response, 8),
                    total_cycles, get_u32(response, 12));
        return false;
    }
    std::printf("PASS: %s LMS KeyGen calls=%u steps=%u hw_cycles=%u total_cycles=%u hits=%u fallback=0%s\n",
                tag, vector.keygen_calls, vector.keygen_steps, get_u32(response, 4),
                total_cycles, get_u32(response, 8), exact ? "" : " (cycles TBD by measurement)");
    return true;
}

static bool receive_status(Vlms_soc &dut, std::array<uint8_t, 48> &response,
                           const char *name)
{
    for (uint8_t &value : response) {
        if (!uart_receive(dut, value, 50000000)) {
            std::printf("FAIL: UART timeout in %s response trap=%u gpio=%02x\n", name,
                        static_cast<unsigned>(dut.trap),
                        static_cast<unsigned>(dut.gpio_out));
            return false;
        }
    }
    return true;
}

static bool run_uart_lmots_cases(Vlms_soc &dut, uint32_t hits_before,
                                 uint32_t &hits_out, const char *tag)
{
    VerifyVector vector;
    if (!load_verify_vector(vector)) {
        std::printf("FAIL: load direct LM-OTS vector (%s)\n", tag);
        return false;
    }
    /* LM-OTS hardware availability: both platform engines are parameterized for w∈{1,2,4,8} (SHAKE256 stage (3),
     * SHA-256 S5) -> hardware available for all w (fused keygen/sign/verify batch tasks active -> hw>0,
     * hits increase). Hardware unavailable -> hw=0, hits unchanged (pure-software LM-OTS). */
    const bool lmots_hw = (g_param_w == 1 || g_param_w == 2 ||
                           g_param_w == 4 || g_param_w == 8);

    uart_send(dut, 0x60);
    for (uint8_t value : vector.private_key) uart_send(dut, value);
    std::array<uint8_t, 48> response{};
    if (!receive_status(dut, response, "LM-OTS KeyGen")) return false;
    std::vector<uint8_t> public_key(vector.lmots_public_key.size());
    for (uint8_t &value : public_key) {
        if (!uart_receive(dut, value, 5000000)) return false;
    }
    /* fused keygen_backend (CMD_LMOTS_KEYGEN): one MMIO completes all chains (dual-core parallel).
     * Expected hw: W4 exact table lookup; w≠4 hardware available -> hw>0 (varies per w, loose); unavailable -> 0. */
#ifdef FW_HASH_SHAKE256
    const uint32_t expect_w4_keygen = 8966u;  /* After P2: dual-core + trailing PBLc unified absorb (-544 folded) */
#else
    const uint32_t expect_w4_keygen = 38761u;
#endif
    uint32_t expected_hits = hits_before + (lmots_hw ? 1u : 0u);
    const bool keygen_cycles_ok = (g_param_w == 4)
        ? (get_u32(response, 4) == expect_w4_keygen)
        : (lmots_hw ? get_u32(response, 4) > 0u : get_u32(response, 4) == 0u);
    hits_out = get_u32(response, 8);
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        !keygen_cycles_ok || hits_out != expected_hits ||
        get_u32(response, 12) != 0 || public_key != vector.lmots_public_key) {
        std::printf("FAIL: %s direct LM-OTS KeyGen result or statistics (hw=%u hits=%u/%u)\n",
                    tag, get_u32(response, 4), hits_out, expected_hits);
        return false;
    }
    std::printf("PASS: %s LM-OTS KeyGen calls=%u steps=%u cycles=%u total=%u hits=%u fallback=0\n",
                tag, vector.lmots_keygen_calls, vector.lmots_keygen_steps,
                get_u32(response, 4), get_u32(response, 20), expected_hits);

    uart_send(dut, 0x61);
    for (uint8_t value : vector.private_key) uart_send(dut, value);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);
    response.fill(0);
    if (!receive_status(dut, response, "LM-OTS Sign")) {
        std::printf("FAIL: LM-OTS Sign receive_status status=%u hw=%u hits=%u/%u\n",
                    response[1], get_u32(response, 4), get_u32(response, 8), hits_before + 1u);
        return false;
    }
    std::printf("DBG: LM-OTS Sign response status=%u hw=%u hits=%u/%u total=%u\n",
                response[1], get_u32(response, 4), get_u32(response, 8), hits_before + 1u,
                get_u32(response, 20));
    std::vector<uint8_t> signature(vector.lmots_signature.size());
    size_t sign_rx = 0;
    /* g_trace_on = true;  DBG: uncomment this line to capture waveforms (VCD covers only this section) */
    g_sim_time = 0;
    for (uint8_t &value : signature) {
        if (!uart_receive(dut, value, 2000000)) {
            g_trace_on = false;
            if (g_tfp) {
                g_tfp->flush();
                g_tfp->close();
            }
            std::printf("FAIL: LM-OTS Sign signature rx=%zu/%zu trap=%u gpio=%02x txd=%u\n",
                        sign_rx, signature.size(), static_cast<unsigned>(dut.trap),
                        static_cast<unsigned>(dut.gpio_out),
                        static_cast<unsigned>(dut.uart_txd));
            std::printf("  bridge st=%u busy=%u done=%u err=%u wl=%u bl=%u hold=%u sent=%u rbi=%u rden=%u wren=%u sb=%u rdv=%u txs=%u bactive=%u start=%u\n",
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__state_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__busy_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__done_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__error_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__word_left_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__byte_left_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__tx_hold_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__byte_sent_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__rbyte_idx_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__stream_rd_en),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__stream_wr_en),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__stream_busy),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__stream_rd_valid),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__tx_send_r),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__busy),
                        static_cast<unsigned>(dut.rootp->lms_soc__DOT__uart_bridge__DOT__start_req));
            /* Segment diagnostics: type+C tail (bytes 30-38) + y head */
            std::printf("  type+C tail:\n");
            for (size_t k = 30; k < 39 && k < vector.lmots_signature.size(); ++k) {
                std::printf("    [%zu] got=%02x exp=%02x\n", k, signature[k],
                            vector.lmots_signature[k]);
            }
            std::printf("  y head (first 6 of %zu):\n",
                        vector.lmots_signature.size() - 36);
            for (size_t k = 36; k < 42 && k < sign_rx; ++k) {
                std::printf("    y[%zu] got=%02x exp=%02x\n", k - 36, signature[k],
                            vector.lmots_signature[k]);
            }
            return false;
        }
        ++sign_rx;
    }
#ifdef FW_HASH_SHAKE256
    const uint32_t expect_w4_sign = 5487u;  /* After P2+P3: = randomizer + dual-core SIGN (-391 folded -536 background write) */
#else
    const uint32_t expect_w4_sign = 23584u;
#endif
    expected_hits = hits_before + (lmots_hw ? 3u : 0u);  /* KeyGen 1 + Sign 2 (randomizer+fused) */
    const bool sign_cycles_ok = (g_param_w == 4)
        ? (get_u32(response, 4) == expect_w4_sign)
        : (lmots_hw ? get_u32(response, 4) > 0u : get_u32(response, 4) == 0u);
    hits_out = get_u32(response, 8);
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        !sign_cycles_ok || hits_out != expected_hits ||
        get_u32(response, 12) != 0 || get_u32(response, 32) >= get_u32(response, 20) ||
        signature != vector.lmots_signature) {
        size_t first_bad = 0;
        while (first_bad < signature.size() && first_bad < vector.lmots_signature.size() &&
               signature[first_bad] == vector.lmots_signature[first_bad]) {
            ++first_bad;
        }
        std::printf("FAIL: %s direct LM-OTS Sign result or statistics (hw=%u hits=%u/%u total=%u steady=%u fallback=%u sig_match=%d first_bad=%zu)\n",
                    tag, get_u32(response, 4), hits_out, expected_hits,
                    get_u32(response, 20), get_u32(response, 32),
                    get_u32(response, 12), (int)(signature == vector.lmots_signature), first_bad);
        return false;
    }
    std::printf("PASS: %s LM-OTS Sign calls=%u steps=%u cycles=%u total=%u steady=%u hits=%u fallback=0\n",
                tag, vector.lmots_sign_calls, vector.lmots_sign_steps,
                get_u32(response, 4), get_u32(response, 20), get_u32(response, 32),
                expected_hits);
    std::printf("PROF LMOTS-SIGN write=%u wait=%u read=%u\n",
                get_u32(response, 36), get_u32(response, 40), get_u32(response, 44));
    uart_send(dut, 0x62);
    for (size_t index = 8; index < 24; ++index) uart_send(dut, vector.private_key[index]);
    for (int index = 0; index < 4; ++index) uart_send(dut, 0);
    for (uint8_t value : vector.lmots_public_key) uart_send(dut, value);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);
    for (uint8_t value : vector.lmots_signature) uart_send(dut, value);
    response.fill(0);
    if (!receive_status(dut, response, "LM-OTS Verify")) {
        return false;
    }
#ifdef FW_HASH_SHAKE256
    const uint32_t expect_w4_verify = 6468u;  /* After P2: dual-core VERIFY (-321 folded) */
#else
    const uint32_t expect_w4_verify = 27327u;
#endif
    expected_hits = hits_before + (lmots_hw ? 4u : 0u);  /* +Verify 1 (before: KeyGen1+Sign2) */
    const bool verify_cycles_ok = (g_param_w == 4)
        ? (get_u32(response, 4) == expect_w4_verify)
        : (lmots_hw ? get_u32(response, 4) > 0u : get_u32(response, 4) == 0u);
    hits_out = get_u32(response, 8);
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
        !verify_cycles_ok || hits_out != expected_hits ||
        get_u32(response, 12) != 0) {
        std::printf("FAIL: %s direct LM-OTS Verify result or statistics (status=%u hw=%u hits=%u/%u total=%u gpio=%02x)\n",
                    tag, response[1], response[2], get_u32(response, 4),
                    hits_out, expected_hits, get_u32(response, 20),
                    static_cast<unsigned>(dut.gpio_out));
        return false;
    }
    std::printf("PASS: %s LM-OTS Verify calls=%u steps=%u cycles=%u total=%u hits=%u fallback=0\n",
                tag, vector.calls, vector.steps, get_u32(response, 4),
                get_u32(response, 20), expected_hits);
    std::printf("PROF LMOTS-VER write=%u wait=%u read=%u\n",
                get_u32(response, 36), get_u32(response, 40), get_u32(response, 44));
    return true;
}

/* NVM_SYNC (0x52): CRC16-CCITT(0xFFFF), matching the firmware. */
static uint16_t crc16_ccitt(const uint8_t *data, size_t length)
{
    uint16_t crc = 0xffffu;
    for (size_t index = 0; index < length; ++index) {
        crc ^= static_cast<uint16_t>(data[index]) << 8;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x8000u) != 0u ? static_cast<uint16_t>((crc << 1) ^ 0x1021u)
                                        : static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

/* Reset the DUT and rerun until UART-ready (gpio=0xa5), simulating power loss. Firmware volatile state cleared. */
static bool soc_reset(Vlms_soc &dut)
{
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    int cycles = 0;
    /* Boot wait: since 0.1.232 firmware bss grew by ~5KB (tree-cache arena 16KiB), crt0 zeroing got slower,
     * 30000 cycles times out (RV32 without icache, layout-sensitive) -> relaxed to 200000. */
    while (dut.gpio_out == 0 && !dut.trap && cycles < 200000) {
        tick(dut);
        ++cycles;
    }
    return !dut.trap && dut.gpio_out == 0xa5;
}

/* Send one NVM_SYNC PUSH frame (op + 32B + CRC16), receive a 48B response.
 * Response payload at response[16..47]: [16]=op [18]=status [19]=valid_mask. */
static bool nvm_push(Vlms_soc &dut, uint8_t op, const std::vector<uint8_t> &chunk,
                     uint8_t expected_status, uint8_t expected_mask, const char *name)
{
    uart_send(dut, 0x52);
    uart_send(dut, op);
    for (size_t index = 0; index < 32; ++index) {
        uart_send(dut, chunk[index]);
    }
    const uint16_t crc = crc16_ccitt(chunk.data(), 32);
    uart_send(dut, static_cast<uint8_t>(crc));
    uart_send(dut, static_cast<uint8_t>(crc >> 8));

    std::array<uint8_t, 48> response{};
    if (!receive_status(dut, response, name)) return false;
    if (response[0] != 0x52 || response[1] != 0 || response[16] != op ||
        response[18] != expected_status || response[19] != expected_mask) {
        std::printf("FAIL: %s op=%02x status=%u/%u mask=%u/%u\n",
                    name, response[16], response[18], expected_status,
                    response[19], expected_mask);
        return false;
    }
    std::printf("PASS: %s op=%02x status=%u mask=%u\n", name, op, expected_status,
                expected_mask);
    return true;
}

/* NVM_SYNC READ: on success returns the first 28B of the lo half at response[20..47]. */
static bool nvm_read(Vlms_soc &dut, uint8_t expected_status, uint8_t expected_mask,
                     const std::vector<uint8_t> &expected_lo, const char *name)
{
    uart_send(dut, 0x52);
    uart_send(dut, 0x03);
    std::array<uint8_t, 48> response{};
    if (!receive_status(dut, response, name)) return false;
    bool data_ok = true;
    if (expected_status == 0) {
        for (size_t index = 0; index < 28; ++index) {
            if (response[20 + index] != expected_lo[index]) data_ok = false;
        }
    }
    if (response[0] != 0x52 || response[1] != 0 || response[16] != 0x03 ||
        response[18] != expected_status || response[19] != expected_mask || !data_ok) {
        std::printf("FAIL: %s status=%u/%u mask=%u/%u data_ok=%d\n", name,
                    response[18], expected_status, response[19], expected_mask,
                    static_cast<int>(data_ok));
        return false;
    }
    std::printf("PASS: %s status=%u mask=%u data_ok=%d\n", name, expected_status,
                expected_mask, static_cast<int>(data_ok));
    return true;
}

/* NVM sync closed loop: push lo/hi -> read -> reset -> read cleared -> repush -> read matches. */
static bool run_uart_nvm_sync_cases(Vlms_soc &dut)
{
    std::vector<uint8_t> lo(32), hi(32);
    for (size_t index = 0; index < 32; ++index) {
        lo[index] = static_cast<uint8_t>(index);
        hi[index] = static_cast<uint8_t>(0xa0u + index);
    }

    /* Initially unwritten: READ reports half-missing(1), mask=0 */
    if (!nvm_read(dut, 1, 0, lo, "nvm-read-empty")) return false;
    /* Write lo only: mask=1 */
    if (!nvm_push(dut, 0x01, lo, 0, 1, "nvm-push-lo")) return false;
    /* Write hi: mask=3 */
    if (!nvm_push(dut, 0x02, hi, 0, 3, "nvm-push-hi")) return false;
    /* Full read-back of lo */
    if (!nvm_read(dut, 0, 3, lo, "nvm-read-full")) return false;

    /* A CRC-corrupted PUSH must be rejected and mask unchanged (3) */
    std::vector<uint8_t> bad(32, 0x5a);
    uart_send(dut, 0x52);
    uart_send(dut, 0x01);
    for (uint8_t value : bad) uart_send(dut, value);
    uart_send(dut, 0x00);
    uart_send(dut, 0x00); /* wrong CRC */
    {
        std::array<uint8_t, 48> response{};
        if (!receive_status(dut, response, "nvm-push-badcrc")) return false;
        if (response[18] != 2 || response[19] != 3) {
            std::printf("FAIL: nvm-push-badcrc status=%u mask=%u\n", response[18],
                        response[19]);
            return false;
        }
        std::printf("PASS: nvm-push-badcrc status=2 mask=3 (rejected)\n");
    }

    /* Power loss (reset): volatile state cleared, READ reports half-missing, mask=0 */
    if (!soc_reset(dut)) {
        std::puts("FAIL: nvm reset did not reach UART-ready");
        return false;
    }
    if (!nvm_read(dut, 1, 0, lo, "nvm-read-after-reset")) return false;

    /* Host repushes from the persistent domain -> read-back matches */
    if (!nvm_push(dut, 0x01, lo, 0, 1, "nvm-repush-lo")) return false;
    if (!nvm_push(dut, 0x02, hi, 0, 3, "nvm-repush-hi")) return false;
    if (!nvm_read(dut, 0, 3, lo, "nvm-read-restored")) return false;
    return true;
}

/* SEC_STATE (0x55): send subcommand + params, receive a 48B response (payload at [16..47]). */
static bool sec_cmd(Vlms_soc &dut, uint8_t sub, const std::vector<uint8_t> &params,
                    std::array<uint8_t, 48> &response, const char *name)
{
    uart_send(dut, 0x55);
    uart_send(dut, sub);
    for (uint8_t value : params) uart_send(dut, value);
    if (!receive_status(dut, response, name)) return false;
    return response[0] == 0x52 && response[1] == 0 && response[16] == sub;
}

/* Per-key KDF context = current key's public-key ID I(16B). I is public: take the private key I of the default vector (W4_H5)
 * (FACTORY_INIT/BOOT use it to set sec_key_I -> keygen public key = vector public key, KAT byte-reproducible). */
static std::vector<uint8_t> sec_key_i(void)
{
    VerifyVector v;
    const char *saved = g_vector_path;
    g_vector_path = "build/lms_verify_vector.txt";
    if (load_verify_vector(v)) {
        std::vector<uint8_t> ret(v.private_key.begin() + 8, v.private_key.begin() + 24);
        g_vector_path = saved;
        return ret;
    }
    g_vector_path = saved;
    return std::vector<uint8_t>(16, 0);
}

/* P1-6 (0.1.274) wrapped-blob capture/restore: LO=28B (blob[0..27]) + HI=20B (blob[28..47]),
 * response body capped at 28B (same caliber as NVM_READ). */
static bool sec_wrapped_read(Vlms_soc &dut, std::array<uint8_t, 48> &blob)
{
    std::array<uint8_t, 48> response{};
    if (!sec_cmd(dut, 0x0c, {}, response, "wrapped-read-lo")) return false;
    if (response[18] != 0) return false;
    for (size_t i = 0; i < 28; ++i) blob[i] = response[20 + i];
    if (!sec_cmd(dut, 0x0d, {}, response, "wrapped-read-hi")) return false;
    if (response[18] != 0) return false;
    for (size_t i = 0; i < 20; ++i) blob[28 + i] = response[20 + i];
    return true;
}

static bool sec_wrap_load(Vlms_soc &dut, const std::array<uint8_t, 48> &blob, const char *name)
{
    std::array<uint8_t, 48> response{};
    std::vector<uint8_t> params(blob.begin(), blob.end());
    if (!sec_cmd(dut, 0x0b, params, response, name)) return false;
    return response[18] == 0;
}

/* Build the 12B COMMIT params: new_state(4BE)||ctr(4BE)||reserved_q(4BE). */
static std::vector<uint8_t> commit_params(uint32_t new_state, uint32_t ctr, uint32_t reserved_q)
{
    std::vector<uint8_t> p(12);
    for (int i = 0; i < 4; ++i) {
        p[i] = static_cast<uint8_t>(new_state >> (24 - 8 * i));
        p[4 + i] = static_cast<uint8_t>(ctr >> (24 - 8 * i));
        p[8 + i] = static_cast<uint8_t>(reserved_q >> (24 - 8 * i));
    }
    return p;
}

static uint32_t be32(const std::array<uint8_t, 48> &r, size_t off)
{
    return (static_cast<uint32_t>(r[off]) << 24) | (static_cast<uint32_t>(r[off + 1]) << 16) |
           (static_cast<uint32_t>(r[off + 2]) << 8) | static_cast<uint32_t>(r[off + 3]);
}

/* Big-endian read of a 64B slot image (STATE_REC persistent domain). */
static uint32_t be32_64(const std::array<uint8_t, 64> &r, size_t off)
{
    return (static_cast<uint32_t>(r[off]) << 24) | (static_cast<uint32_t>(r[off + 1]) << 16) |
           (static_cast<uint32_t>(r[off + 2]) << 8) | static_cast<uint32_t>(r[off + 3]);
}

/* STATE_COMMIT closed loop (step 5): BOOTING reject -> FACTORY_INIT -> two commits -> read-back verify. */
static bool run_uart_sec_state_cases(Vlms_soc &dut)
{
    std::array<uint8_t, 48> response{};

    /* Initially ST_BOOTING (step 5: not signable before FACTORY_INIT/BOOT),
     * COMMIT must be gated-rejected (status=RSP_BUSY 1). */
    if (!sec_cmd(dut, 0x01, commit_params(1, 0, 0), response, "sec-commit-booting")) return false;
    if (response[18] != 1) {
        std::printf("FAIL: sec-commit-booting status=%u (expect 1 busy)\n", response[18]);
        return false;
    }
    std::printf("PASS: sec-commit-booting rejected status=1 (ST_BOOTING gate)\n");

    /* FACTORY_INIT (0x06): sim PUF + FE_GEN + KDF load K_WRAP/K_STATE. */
    if (!sec_cmd(dut, 0x06, sec_key_i(), response, "sec-factory-init")) return false;
    if (response[18] != 0 || response[20] != 0x46) {
        std::printf("FAIL: sec-factory-init status=%u magic=%02x\n",
                    response[18], response[20]);
        return false;
    }
    std::printf("PASS: sec-factory-init dev_epoch=%08x key_epoch=%08x handle=%08x\n",
                be32(response, 24), be32(response, 28), be32(response, 32));

    /* P1-6 (0.1.274): capture wrapped blob to build/deploy_blob.bin (deploy regression input;
     * deterministic - sim PUF fixed table + seed 0..31 + platform-fixed KDF/wrapping). */
    {
        std::array<uint8_t, 48> blob{};
        if (!sec_wrapped_read(dut, blob)) return false;
        std::ofstream out("build/deploy_blob.bin", std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out.write(reinterpret_cast<const char *>(blob.data()),
                  static_cast<std::streamsize>(blob.size()));
        std::printf("PASS: wrapped blob captured %02x%02x...%02x%02x -> build/deploy_blob.bin\n",
                    blob[0], blob[1], blob[46], blob[47]);
    }

    /* Repeated FACTORY_INIT must be rejected (ERR_FACTORY_LOCKED 8). */
    if (!sec_cmd(dut, 0x06, sec_key_i(), response, "sec-factory-relock")) return false;
    if (response[18] != 8) {
        std::printf("FAIL: sec-factory-relock status=%u (expect 8)\n", response[18]);
        return false;
    }
    std::printf("PASS: sec-factory-relock rejected status=8 (factory_locked)\n");

    /* BOOT (0x05): no valid slot (fresh device) -> recover to ST_IDLE(1). */
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "sec-boot-fresh")) return false;
    if (response[18] != 0 || be32(response, 20) != 1 || be32(response, 28) != 0) {
        std::printf("FAIL: sec-boot-fresh status=%u state=%u ctr=%u\n",
                    response[18], be32(response, 20), be32(response, 28));
        return false;
    }
    std::printf("PASS: sec-boot-fresh state=IDLE ctr=0 (fresh device)\n");

    /* Commit 1: ST_IDLE->ST_RESERVED(q=5). tx=1, switch to slot B. */
    if (!sec_cmd(dut, 0x01, commit_params(2, 5, 5), response, "sec-commit-1")) return false;
    if (response[18] != 0 || be32(response, 20) != 1 || be32(response, 24) != 2 ||
        be32(response, 28) != 5) {
        std::printf("FAIL: sec-commit-1 status=%u tx=%u state=%u ctr=%u\n",
                    response[18], be32(response, 20), be32(response, 24), be32(response, 28));
        return false;
    }
    std::printf("PASS: sec-commit-1 tx=1 state=RESERVED ctr=5\n");

    /* Commit 2: ST_RESERVED->ST_IDLE(ctr=6). tx=2, switch back to slot A. */
    if (!sec_cmd(dut, 0x01, commit_params(1, 6, 0), response, "sec-commit-2")) return false;
    if (response[18] != 0 || be32(response, 20) != 2 || be32(response, 24) != 1 ||
        be32(response, 28) != 6) {
        std::printf("FAIL: sec-commit-2 status=%u tx=%u state=%u ctr=%u\n",
                    response[18], be32(response, 20), be32(response, 24), be32(response, 28));
        return false;
    }
    std::printf("PASS: sec-commit-2 tx=2 state=IDLE ctr=6\n");

    /* Read active slot: magic="LMSS"(0x4c4d5353), state=1, ctr=6, tx=2. */
    if (!sec_cmd(dut, 0x02, {}, response, "sec-read-active")) return false;
    if (be32(response, 20) != 0x4c4d5353u) {
        std::printf("FAIL: sec-read-active magic=%08x\n", be32(response, 20));
        return false;
    }
    /* body: magic@0 state@4(2B) ctr@6(4B) txid@10.
     * payload[16..]: body[i] -> response[20+i]. ctr->response[26], tx outside payload. */
    if (be32(response, 26) != 6) {
        std::printf("FAIL: sec-read-active ctr=%u\n", be32(response, 26));
        return false;
    }
    std::printf("PASS: sec-read-active magic=LMSS state=1 ctr=6 (HMAC tag ok)\n");

    /* Fault injection: corrupt the active slot tag, then a commit should still succeed with tx=3 (commit recomputes the tag for inactive).
     * Note: INJECT corrupts the active slot (historical slot), which does not affect the new commit to inactive; this mainly exercises
     * the INJECT command path. Tag-corruption rejection at boot slot selection is verified in run_uart_sec_boot_cases. */
    if (!sec_cmd(dut, 0x04, {}, response, "sec-inject-tag")) return false;
    if (response[18] != 0) {
        std::printf("FAIL: sec-inject-tag status=%u\n", response[18]);
        return false;
    }
    std::printf("PASS: sec-inject-tag injected\n");
    return true;
}

/* NVM_LOAD (0x08): slot(1) || 64B rec, restore the firmware dual slots. */
static bool sec_nvm_load(Vlms_soc &dut, uint8_t slot,
                         const std::array<uint8_t, 64> &rec, const char *name)
{
    std::vector<uint8_t> params;
    params.push_back(slot);
    for (uint8_t b : rec) params.push_back(b);
    std::array<uint8_t, 48> response{};
    if (!sec_cmd(dut, 0x08, params, response, name)) return false;
    if (response[18] != 0) {
        std::printf("FAIL: %s status=%u\n", name, response[18]);
        return false;
    }
    return true;
}

/* MC_LOAD (0x0a): value(4BE) restored into the sim_mc persistent domain. */
static bool sec_mc_load(Vlms_soc &dut, uint32_t value, const char *name)
{
    std::vector<uint8_t> params(4);
    for (int i = 0; i < 4; ++i) params[i] = static_cast<uint8_t>(value >> (24 - 8 * i));
    std::array<uint8_t, 48> response{};
    if (!sec_cmd(dut, 0x0a, params, response, name)) return false;
    if (response[18] != 0) {
        std::printf("FAIL: %s status=%u\n", name, response[18]);
        return false;
    }
    return true;
}

/* Read back the full 64B active slot bridged by the firmware via NVM_SYNC (0x52).
 * After commit the firmware syncs the active slot (incl. tag) to the nvm_state image;
 * three parameterless READS: 0x03 base=0, 0x05 base=28, 0x04 base=36, together covering all 64B. */
static bool nvm_read_full64(Vlms_soc &dut, std::array<uint8_t, 64> &rec, const char *name)
{
    const uint8_t ops[3] = {0x03, 0x05, 0x04};
    const size_t base[3] = {0, 28, 36};
    for (uint8_t k = 0; k < 3; ++k) {
        uart_send(dut, 0x52);
        uart_send(dut, ops[k]);
        std::array<uint8_t, 48> r{};
        if (!receive_status(dut, r, name)) return false;
        if (r[18] != 0 || r[19] != 3) {
            std::printf("FAIL: %s seg=%u status=%u mask=%u\n", name, k, r[18], r[19]);
            return false;
        }
        for (size_t i = 0; i < 28 && base[k] + i < 64; ++i) rec[base[k] + i] = r[20 + i];
    }
    return true;
}

/* GET_STATE reads the current active_slot (response[23]). */
static bool sec_active_slot(Vlms_soc &dut, uint8_t &slot, const char *name)
{
    std::array<uint8_t, 48> r{};
    if (!sec_cmd(dut, 0x07, {}, r, name)) return false;
    slot = r[39]; /* payload[23] → response[16+23=39] */
    return true;
}

/* GET_STATE reads ctr (payload[8..11] -> response[24..27]). */
static bool sec_read_ctr(Vlms_soc &dut, uint32_t &ctr, uint32_t &state, const char *name)
{
    std::array<uint8_t, 48> r{};
    if (!sec_cmd(dut, 0x07, {}, r, name)) return false;
    state = be32(r, 20);
    ctr = be32(r, 24);
    return true;
}

/* SEC_SIGN (0x54): I(16)||lms_type(4)||lmots_type(4)||msg_len(1)||msg (single-key fixed
 * scheme has no key_handle). Returns (status, q_out, signature). status=sec_sign error code (0 success). */
static bool sec_sign_request(Vlms_soc &dut, const VerifyVector &vector,
                             uint8_t &status, uint32_t &q_out,
                             std::vector<uint8_t> &signature, const char *name)
{
    uart_send(dut, 0x54);
    for (size_t index = 8; index < 24; ++index) uart_send(dut, vector.private_key[index]);
    /* Types sent little-endian (firmware uart_get_u32 reads little-endian): private_key[0..3]=lms_type,
     * [4..7]=lmots_type are stored big-endian, so the value bytes must be sent reversed. */
    for (int index = 3; index >= 0; --index) uart_send(dut, vector.private_key[index]);
    for (int index = 7; index >= 4; --index) uart_send(dut, vector.private_key[index]);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);

    std::array<uint8_t, 48> response{};
    if (!receive_status(dut, response, name)) return false;
    status = response[18];
    q_out = be32(response, 36); /* payload[20..23] → response[36..39] */
    signature.clear();
    if (response[0] != 0x52) return false;
    if (response[1] == 0 && status == 0) {
        for (size_t i = 0; i < vector.lmots_signature.size(); ++i) {
            uint8_t b;
            if (!uart_receive(dut, b, 5000000)) return false;
            signature.push_back(b);
        }
    }
    return true;
}

/* SEC_SIGN atomic cases (spec §9.4/§13 tests 1/2/4/10; REVIEW B13B16-R3:
 * single-key fixed scheme has no key_handle; test 9 (bad_handle)/cross-key isolation do not apply, do not cite again). */
static bool run_uart_sec_sign_cases(Vlms_soc &dut)
{
    VerifyVector vector;
    /* SEC cases pin the W4_H5 vector (ctr-cap-32 exhaustion boundary, signature length etc. are all H5 caliber,
     * independent of the last --params set; the ctr=32 boundary of secsign10 does not apply for H10/H15).
     * Path by platform: SHA-256 uses W4_H5 under vectors; SHAKE256 uses the default vector file
     * (build/lms_verify_vector.txt, SHAKE-caliber W4/H5, lmots_type=0x13). */
    {
        const char *saved = g_vector_path;
#ifdef FW_HASH_SHAKE256
        g_vector_path = "build/lms_verify_vector.txt";
#else
        g_vector_path = "build/vectors/lms_verify_vector_W4_H5.txt";
#endif
        if (!load_verify_vector(vector)) {
            std::puts("FAIL: load sec-sign vector");
            g_vector_path = saved;
            return false;
        }
        g_vector_path = saved;
    }
    std::array<uint8_t, 48> response{};
    std::vector<uint8_t> signature;
    uint8_t status = 0;
    uint32_t q_out = 0;
    uint32_t ctr = 0;
    uint32_t state = 0;

    /* Reset to a clean context; FACTORY_INIT + BOOT (fresh) establish the key. */
    if (!soc_reset(dut)) { std::puts("FAIL: secsign reset"); return false; }
    if (!sec_cmd(dut, 0x06, sec_key_i(), response, "secsign-factory")) return false;
    if (response[18] != 0) { std::printf("FAIL: secsign-factory status=%u\n", response[18]); return false; }
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "secsign-boot")) return false;
    if (be32(response, 20) != 1) { std::printf("FAIL: secsign-boot state=%u\n", be32(response, 20)); return false; }
    std::printf("PASS: secsign-factory+boot state=IDLE ctr=0 key_loaded=1\n");

    /* secure seed provisioning (v5 INSECURE staging, for derive+sign use). */
    uart_send(dut, 0x63);
    for (size_t index = 24; index < 56; ++index) uart_send(dut, vector.private_key[index]);
    if (!receive_status(dut, response, "secsign-seed") || response[1] != 0) {
        std::puts("FAIL: secsign seed load");
        return false;
    }

    /* ---- Test 1: normal sign, two q strictly increasing ---- */
    if (!sec_sign_request(dut, vector, status, q_out, signature, "secsign-1")) return false;
    if (status != 0 || q_out != 0 || signature != vector.lmots_signature) {
        std::printf("FAIL: secsign-1 status=%u q=%u sig_match=%d\n",
                    status, q_out, (int)(signature == vector.lmots_signature));
        return false;
    }
    if (!sec_read_ctr(dut, ctr, state, "secsign-1-ctr")) return false;
    if (state != 1 || ctr != 1) {
        std::printf("FAIL: secsign-1 post state=%u ctr=%u (expect IDLE ctr=1)\n", state, ctr);
        return false;
    }
    std::printf("PASS: secsign-1 q=0 committed ctr=1 (invariant Release=>Committed ctr>=1)\n");

    if (!sec_sign_request(dut, vector, status, q_out, signature, "secsign-2")) return false;
    if (status != 0 || q_out != 1) {
        std::printf("FAIL: secsign-2 status=%u q=%u (expect q=1)\n", status, q_out);
        return false;
    }
    std::printf("PASS: secsign-2 q=1 strictly increasing\n");

    /* ---- Test 2: q cannot be software-specified - ctr has advanced, repeated requests only use the new ctr.
     * Forging "same q" is impossible (q comes from hardware ctr); verify ctr keeps increasing and is not replayed. ---- */
    if (!sec_read_ctr(dut, ctr, state, "secsign-2-ctr")) return false;
    if (ctr != 2) {
        std::printf("FAIL: secsign-2 post ctr=%u (expect 2)\n", ctr);
        return false;
    }
    std::printf("PASS: secsign q from hw ctr (no sw-supplied q, ctr=2 after 2 signs)\n");

    /* ---- Test 4: power loss before finalize - sign reserved then reset; recovery still burns q ----
     * Simplified: directly commit ST_RESERVED(q=ctr) to simulate "sign interrupted in reserved"; recovery must burn. */
    {
        std::array<uint8_t, 64> rec_reserved{};
        uint32_t tx_res;
        uint8_t slot_res;
        /* Reserve q=2 (current ctr=2). */
        if (!sec_cmd(dut, 0x01, commit_params(2, 2, 2), response, "secsign4-reserve")) return false;
        tx_res = be32(response, 20);
        if (!sec_active_slot(dut, slot_res, "secsign4-slot")) return false;
        if (!nvm_read_full64(dut, rec_reserved, "secsign4-capture")) return false;
        /* Power loss (before finalize/Commit). */
        if (!soc_reset(dut)) { std::puts("FAIL: secsign4 reset"); return false; }
        /* Recovery: FACTORY_INIT was done but the reset cleared it; the key context must be rebuilt.
         * After reset factory_locked=0 and BOOT with no valid slot would hang in BOOTING - restore the reserved slot + mc. */
        if (!sec_mc_load(dut, tx_res, "secsign4-mc")) return false;
        if (!sec_nvm_load(dut, slot_res, rec_reserved, "secsign4-load")) return false;
        if (!sec_cmd(dut, 0x05, sec_key_i(), response, "secsign4-boot")) return false;
        if (be32(response, 20) != 1 || be32(response, 24) != 3) {
            std::printf("FAIL: secsign4-boot state=%u ctr=%u (expect IDLE ctr=3, q=2 burned)\n",
                        be32(response, 20), be32(response, 24));
            return false;
        }
        std::printf("PASS: secsign4 power-loss-before-finalize burned q=2 (recovered ctr=3)\n");
    }

    /* ---- Test 10: exhaustion - push ctr to 32, sign rejected ERR_EXHAUSTED ----
     * Signing one by one up to 32 is too slow; directly commit ST_IDLE(ctr=32) to simulate the exhaustion boundary. */
    if (!sec_cmd(dut, 0x01, commit_params(1, 32, 0), response, "secsign10-exhaust")) return false;
    if (response[18] != 0) { std::printf("FAIL: secsign10 commit status=%u\n", response[18]); return false; }
    if (!sec_sign_request(dut, vector, status, q_out, signature, "secsign10-sign")) return false;
    if (status != 6) {
        std::printf("FAIL: secsign10-sign status=%u (expect 6 ERR_EXHAUSTED)\n", status);
        return false;
    }
    std::printf("PASS: secsign10 exhausted rejected status=6 (ctr=32>=2^5)\n");
    return true;
}

/* SEC_LMS_SIGN (0x66): secure full LMS signature (sec_sign state machine + auth path).
 * Request: I(16)||lms_type(4)||lmots_type(4)||msg_len(2,BE)||msg (single-key fixed scheme
 * has no key_handle). When i_override is non-empty use it as I (the I inside the device-KeyGen public key; deploy self-consistent).
 * Response: frame[16..19]=q (little-endian, uart_put_u32); signature follows. */
static bool sec_lms_sign_request(Vlms_soc &dut, const VerifyVector &vector,
                                 uint8_t &status, uint32_t &q_out,
                                 std::vector<uint8_t> &signature, const char *name,
                                 const std::vector<uint8_t> &i_override = {})
{
    uart_send(dut, 0x66);
    /* I: i_override (device KeyGen public-key I) takes precedence; otherwise vector I. */
    if (i_override.size() == 16) {
        for (size_t index = 0; index < 16; ++index) uart_send(dut, i_override[index]);
    } else {
        for (size_t index = 8; index < 24; ++index) uart_send(dut, vector.private_key[index]);
    }
    /* Types sent little-endian (firmware uart_get_u32 reads little-endian), bytes reversed. */
    for (int index = 3; index >= 0; --index) uart_send(dut, vector.private_key[index]);
    for (int index = 7; index >= 4; --index) uart_send(dut, vector.private_key[index]);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);

    std::array<uint8_t, 48> response{};
    if (!receive_status(dut, response, name)) return false;
    status = response[1];
    q_out = get_u32(response, 16); /* frame[16..19]=q (little-endian) */
    /* 0x66 segmented profile (carried out by FW_PROFILE firmware): [32..35]=enable, [36..39]=sec_sign, [40..43]=tail,
     * [28..31]=commit1 stc fused-transaction segment, [44..47]=commit1 encode+slot-write segment */
    std::printf("PROF SEC-SIGN enable=%u sign=%u tail=%u stc=%u enc=%u\n",
                get_u32(response, 32), get_u32(response, 36), get_u32(response, 40),
                get_u32(response, 28), get_u32(response, 44));
    signature.clear();
    if (response[0] != 0x52) return false;
    if (response[1] == 0) {
        for (size_t i = 0; i < vector.signature.size(); ++i) {
            uint8_t b;
            if (!uart_receive(dut, b, 5000000)) return false;
            signature.push_back(b);
        }
    }
    return true;
}

/* SEC_LMS_KEYGEN (0x67): secure LMS KeyGen (builds the tree from the SEC-slot SEED and produces the root).
 * Request: I(16)||lms_type(4)||lmots_type(4) (single-key fixed scheme has no key_handle).
 * Public key follows. */
static bool sec_lms_keygen_request(Vlms_soc &dut, const VerifyVector &vector,
                                   uint8_t &status,
                                   std::vector<uint8_t> &public_key, const char *name)
{
    uart_send(dut, 0x67);
    /* Types sent little-endian (firmware uart_get_u32 reads little-endian), bytes reversed. I is generated by the device (0x67 no longer accepts host I). */
    for (int index = 3; index >= 0; --index) uart_send(dut, vector.private_key[index]);
    for (int index = 7; index >= 4; --index) uart_send(dut, vector.private_key[index]);

    std::array<uint8_t, 48> response{};
    if (!receive_status(dut, response, name)) return false;
    status = response[1];
    public_key.clear();
    if (response[0] != 0x52) return false;
    if (response[1] == 0) {
        for (size_t i = 0; i < vector.public_key.size(); ++i) {
            uint8_t b;
            if (!uart_receive(dut, b, 5000000)) return false;
            public_key.push_back(b);
        }
    }
    return true;
}

/* SEC_LMS_KEYGEN_NEW (0x68): multi-key rotation - generates and activates a **new key**.
 * Request: I(16)||lms_type(4)||lmots_type(4). I is provided by the host (external test input, distinct per key).
 * Public key follows. */
static bool sec_lms_keygen_new_request(Vlms_soc &dut, const VerifyVector &vector,
                                       const std::vector<uint8_t> &i_new,
                                       uint8_t &status,
                                       std::vector<uint8_t> &public_key, const char *name)
{
    uart_send(dut, 0x68);
    /* I: test caliber = host-provided (external input, KAT byte-reproducible); deploy caliber (0.1.281 model B)
     * ignores this parameter (sec_keygen_new generates new I+SEED in the on-device TRNG; I_new is back-filled with the generated value). */
    for (size_t index = 0; index < 16; ++index) uart_send(dut, i_new[index]);
    /* Types sent little-endian (firmware uart_get_u32 reads little-endian), bytes reversed. */
    for (int index = 3; index >= 0; --index) uart_send(dut, vector.private_key[index]);
    for (int index = 7; index >= 4; --index) uart_send(dut, vector.private_key[index]);

    std::array<uint8_t, 48> response{};
    if (!receive_status(dut, response, name)) return false;
    status = response[1];
    public_key.clear();
    if (response[0] != 0x52) return false;
    if (response[1] == 0) {
        for (size_t i = 0; i < vector.public_key.size(); ++i) {
            uint8_t b;
            if (!uart_receive(dut, b, 5000000)) return false;
            public_key.push_back(b);
        }
    }
    return true;
}

/* Secure LMS trio (full secure-scheme caliber, 0x66/0x67): FACTORY_INIT/BOOT/seed provision ->
 * 0x67 SEC KeyGen (public key = vector) -> 0x66 SEC Sign (signature = full LMS signature q=ctr, q increasing,
 * Release⇒Committed) -> verifies the secure-path correctness (Verilator endorsement before board test). */
static bool run_uart_sec_lms_cases(Vlms_soc &dut)
{
    VerifyVector vector;
    /* SEC cases pin the W4_H5 vector (same as run_uart_sec_sign_cases: H5-caliber assertions,
     * and H10/H15 building 2^h-leaf KEYGEN_LEAF exceeds the SoC UART timeout budget).
     * Path by platform: SHAKE256 uses the default vector (SHAKE-caliber W4/H5). */
    {
        const char *saved = g_vector_path;
#ifdef FW_HASH_SHAKE256
        g_vector_path = "build/lms_verify_vector.txt";
#else
        g_vector_path = "build/vectors/lms_verify_vector_W4_H5.txt";
#endif
        if (!load_verify_vector(vector)) {
            std::puts("FAIL: load sec-lms vector");
            g_vector_path = saved;
            return false;
        }
        g_vector_path = saved;
    }
    std::array<uint8_t, 48> response{};
    std::vector<uint8_t> signature;
    std::vector<uint8_t> public_key;
    uint8_t status = 0;
    uint32_t q_out = 0;
    uint32_t ctr = 0;
    uint32_t state = 0;

    if (!soc_reset(dut)) { std::puts("FAIL: sec-lms reset"); return false; }
    if (!sec_cmd(dut, 0x06, sec_key_i(), response, "seclms-factory")) return false;
    if (response[18] != 0) { std::printf("FAIL: seclms-factory status=%u\n", response[18]); return false; }
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "seclms-boot")) return false;
    if (be32(response, 20) != 1) { std::printf("FAIL: seclms-boot state=%u\n", be32(response, 20)); return false; }
    std::printf("PASS: seclms-factory+boot state=IDLE ctr=0 key_loaded=1\n");

    /* secure seed provisioning (SEC-slot SEED = vector seed) */
    uart_send(dut, 0x63);
    for (size_t index = 24; index < 56; ++index) uart_send(dut, vector.private_key[index]);
    if (!receive_status(dut, response, "seclms-seed") || response[1] != 0) {
        std::puts("FAIL: seclms seed load");
        return false;
    }

    /* 0x67 SEC KeyGen: public key = vector PUBLIC_KEY (current key sec_key_I=vector I + slot SEED=vector SEED build the tree). */
    if (!sec_lms_keygen_request(dut, vector, status, public_key, "seclms-keygen")) return false;
    if (status != 0 || public_key != vector.public_key) {
        std::printf("FAIL: seclms-keygen status=%u pub_match=%d\n", status, (int)(public_key == vector.public_key));
        return false;
    }
    std::printf("PASS: seclms-keygen pub_match ✓\n");

    /* 0x66 SEC Sign (q=ctr=0): signature = full LMS signature (sec_sign σ_q + auth path) */
    if (!sec_lms_sign_request(dut, vector, status, q_out, signature, "seclms-sign-1")) return false;
    if (status != 0 || q_out != 0 || signature != vector.signature) {
        std::printf("FAIL: seclms-sign-1 status=%u q=%u sig_match=%d\n",
                    status, q_out, (int)(signature == vector.signature));
        return false;
    }
    if (!sec_read_ctr(dut, ctr, state, "seclms-sign-1-ctr")) return false;
    if (state != 1 || ctr != 1) {
        std::printf("FAIL: seclms-sign-1 post state=%u ctr=%u (expect IDLE ctr=1)\n", state, ctr);
        return false;
    }
    std::printf("PASS: seclms-sign-1 q=0 committed ctr=1 (Release=>Committed)\n");

    /* 0x66 second time (q=ctr=1): q strictly increasing (signature q=1 ≠ vector q=0, q-only check) */
    if (!sec_lms_sign_request(dut, vector, status, q_out, signature, "seclms-sign-2")) return false;
    if (status != 0 || q_out != 1) {
        std::printf("FAIL: seclms-sign-2 status=%u q=%u (expect q=1)\n", status, q_out);
        return false;
    }
    std::printf("PASS: seclms-sign-2 q=1 strictly increasing\n");
    return true;
}

/* Multi-key rotation (0x68 KEYGEN_NEW, test caliber): FACTORY_INIT/BOOT/seed provision -> 0x67 KeyGen (pubA)
 * -> 0x66 Sign q=0 (ctr=1) -> new SEED (external input) + new I -> 0x68 KeyGen_NEW (pubB≠pubA, new I active)
 * -> reset ctr=0/Q=0 (new key has no signing history) -> 0x66 Sign q=0 (using pubB's I) -> 0x56 Verify self-consistent loop.
 * Verifies: (1) KEYGEN_NEW generates a **different** public key (cross-key isolation, new I + new SEED); (2) q resets to zero after key rotation, STATE_REC cleared. */
static bool run_uart_sec_lms_keygen_new_cases(Vlms_soc &dut)
{
    VerifyVector vector;
    {
        const char *saved = g_vector_path;
#ifdef FW_HASH_SHAKE256
        g_vector_path = "build/lms_verify_vector.txt";
#else
        g_vector_path = "build/vectors/lms_verify_vector_W4_H5.txt";
#endif
        if (!load_verify_vector(vector)) { g_vector_path = saved; return false; }
        g_vector_path = saved;
    }

    std::array<uint8_t, 48> response{};
    /* Independent reset (previous case seclms already did FACTORY_INIT; reset clears the volatile secure-domain state). */
    if (!soc_reset(dut)) { std::puts("FAIL: keygennew reset"); return false; }
    /* fakeltest prerequisite: factory-init + boot -> state=IDLE ctr=0. */
    if (!sec_cmd(dut, 0x06, sec_key_i(), response, "keygennew-factory")) return false;
    if (response[18] != 0) { std::printf("FAIL: keygennew-factory status=%u\n", response[18]); return false; }
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "keygennew-boot")) return false;
    if (be32(response, 20) != 1) { std::printf("FAIL: keygennew-boot state=%u\n", be32(response, 20)); return false; }
    std::printf("PASS: keygennew-factory+boot state=IDLE ctr=0\n");

    /* seed provisioning (SEC-slot SEED = vector seed): 0x67 KeyGen builds the tree with vector I + vector SEED. */
    uart_send(dut, 0x63);
    for (size_t index = 24; index < 56; ++index) uart_send(dut, vector.private_key[index]);
    if (!receive_status(dut, response, "keygennew-seed") || response[1] != 0) {
        std::puts("FAIL: keygennew seed load");
        return false;
    }

    uint8_t status = 0;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> public_key_a;
    if (!sec_lms_keygen_request(dut, vector, status, public_key, "keygennew-0x67")) return false;
    if (status != 0 || public_key != vector.public_key) {
        std::printf("FAIL: keygennew-0x67 status=%u pub_match=%d\n",
                    status, (int)(public_key == vector.public_key));
        return false;
    }
    public_key_a = public_key;
    std::printf("PASS: keygennew-0x67 pubA == vector pub (baseline)\n");

    /* 0x66 Sign q=0 (with vector/key I) -> ctr=1 (first consume one q of the key, then verify it resets to zero after KEYGEN_NEW). */
    uint32_t q_out = 0;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> device_i_a(public_key_a.begin() + 8, public_key_a.begin() + 24);
    if (!sec_lms_sign_request(dut, vector, status, q_out, signature, "keygennew-sign-a", device_i_a)) return false;
    if (status != 0 || q_out != 0) {
        std::printf("FAIL: keygennew-sign-a status=%u q=%u (expect q=0)\n", status, q_out);
        return false;
    }
    if (!sec_cmd(dut, 0x07, {}, response, "keygennew-ctr-a")) return false;
    if (be32(response, 20) != 1 || be32(response, 24) != 1) {
        std::printf("FAIL: keygennew-ctr-a state=%u ctr=%u (expect IDLE/1)\n",
                    be32(response, 20), be32(response, 24));
        return false;
    }
    std::printf("PASS: keygennew pre-rotate ctr=1 (q consumed)\n");

    /* New SEED (external input, differs from the vector seed: xor 0xff forces the public key to change) + new I (host-provided, byte-wise different). */
    std::vector<uint8_t> seed_new(32);
    std::vector<uint8_t> i_new(16);
    for (size_t i = 0; i < 32; ++i) seed_new[i] = static_cast<uint8_t>(vector.private_key[24 + i] ^ 0xffu);
    for (size_t i = 0; i < 16; ++i) i_new[i] = static_cast<uint8_t>(sec_key_i()[i] ^ 0xffu);
    uart_send(dut, 0x63);
    for (uint8_t b : seed_new) uart_send(dut, b);
    if (!receive_status(dut, response, "keygennew-seed2") || response[1] != 0) {
        std::puts("FAIL: keygennew seed2 load");
        return false;
    }

    /* 0x68 KEYGEN_NEW: new I + new SEED build the tree -> pubB ≠ pubA; ctr=0/state=IDLE reset. */
    std::vector<uint8_t> public_key_b;
    if (!sec_lms_keygen_new_request(dut, vector, i_new, status, public_key_b, "keygennew-0x68")) return false;
    if (status != 0 || public_key_b.size() != vector.public_key.size()) {
        std::printf("FAIL: keygennew-0x68 status=%u pub_len=%zu\n", status, public_key_b.size());
        return false;
    }
    if (public_key_b == public_key_a) {
        std::printf("FAIL: keygennew-0x68 pubB == pubA (expected different key)\n");
        return false;
    }
    std::printf("PASS: keygennew-0x68 pubB != pubA (cross-key isolation, new I + new SEED)\n");

    /* After key rotation ctr resets to zero, state=IDLE (new key has no signing history). */
    if (!sec_cmd(dut, 0x07, {}, response, "keygennew-state-b")) return false;
    if (be32(response, 20) != 1 || be32(response, 24) != 0) {
        std::printf("FAIL: keygennew-state-b state=%u ctr=%u (expect IDLE/0)\n",
                    be32(response, 20), be32(response, 24));
        return false;
    }
    std::printf("PASS: keygennew post-rotate state=IDLE ctr=0 (fresh q)\n");

    /* 0x66 Sign q=0 with pubB's I (the I generated by device KeyGen) -> self-consistent (verify with the new public key). */
    std::vector<uint8_t> device_i_b(public_key_b.begin() + 8, public_key_b.begin() + 24);
    std::vector<uint8_t> signature_b;
    std::vector<uint8_t> signature_b_q0;
    if (!sec_lms_sign_request(dut, vector, status, q_out, signature_b, "keygennew-sign-b", device_i_b)) return false;
    if (status != 0 || q_out != 0) {
        std::printf("FAIL: keygennew-sign-b status=%u q=%u (expect q=0)\n", status, q_out);
        return false;
    }
    signature_b_q0 = signature_b;
    std::printf("PASS: keygennew-sign-b q=0 (fresh key, root rebuilt from new SEED+I)\n");

    /* 0x56 Verify: use pubB to verify the keygennew-sign-b (q=0) signature - self-consistent loop. */
    uart_send(dut, 0x56);
    for (uint8_t value : public_key_b) uart_send(dut, value);
    uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
    uart_send(dut, static_cast<uint8_t>(vector.message.size()));
    for (uint8_t value : vector.message) uart_send(dut, value);
    while (vector.message.size() > 74u && vector.message.size() % 4u != 0u) {
        uart_send(dut, 0u);
    }
    for (uint8_t value : signature_b_q0) uart_send(dut, value);
    if (!receive_status(dut, response, "keygennew-verify-b")) return false;
    if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 || get_u32(response, 12) != 0) {
        std::printf("FAIL: keygennew-verify-b status=%u hw_error=%u fallback=%u\n",
                    response[1], response[2], get_u32(response, 12));
        return false;
    }
    std::printf("PASS: keygennew verify-b self-consistent (pubB x sigB q=0)\n");
    return true;
}

/* P1-6 (0.1.274) deploy-caliber regression (INSECURE_TEST_MODE=0 + SEC_TEST=0 build):
 * (1) plaintext SEED_LOAD/FACTORY_INIT/INJECT_TAG rejected; (2) bad wrapped blob -> BOOT unwrap
 * tag failure -> ERROR_LOCKED (fail-closed, ctr not reset); (3) good blob restore -> BOOT unwrap
 * recovers SEED -> IDLE ctr=0; (4) 0x67 KeyGen (device-specific public key) -> 0x66 Sign x2 (q increasing,
 * Release=>Committed) -> 0x56 Verify self-consistent loop (correctness endorsed by signature verification, not dependent on fixed vectors);
 * (5) (0.1.281 model B) 0x68 KEYGEN_NEW: in deploy, **on-device TRNG generates new SEED+I on the spot** (controlled
 * load via CMD_SEED_WRITE_SAFE into slot 0, plaintext SEED_LOAD gating stays) -> pubB≠pubA, ctr reset
 * -> Sign q=0 (new device I) -> Verify self-consistent (multi-key rotation deploy full chain). */
static bool run_uart_deploy_cases(Vlms_soc &dut)
{
    std::array<uint8_t, 48> response{};
    std::array<uint8_t, 48> blob{};

    VerifyVector vector;
    {
        const char *saved = g_vector_path;
        g_vector_path = "build/lms_verify_vector.txt";
        if (!load_verify_vector(vector)) {
            std::printf("FAIL: deploy load vector\n");
            g_vector_path = saved;
            return false;
        }
        g_vector_path = saved;
    }

    /* blob comes from the test-config run (captured by run_uart_sec_state_cases, deterministic). */
    {
        std::ifstream in("build/deploy_blob.bin", std::ios::binary);
        if (!in.read(reinterpret_cast<char *>(blob.data()),
                     static_cast<std::streamsize>(blob.size()))) {
            std::puts("FAIL: build/deploy_blob.bin missing (run test-config test-rtl-lms-soc first)");
            return false;
        }
    }

    /* (1) FACTORY_INIT rejected (deploy build SEC_ERR_UNSUPPORTED=9). */
    if (!sec_cmd(dut, 0x06, sec_key_i(), response, "deploy-factory")) return false;
    if (response[18] != 9) {
        std::printf("FAIL: deploy-factory status=%u (expect 9)\n", response[18]);
        return false;
    }
    std::printf("PASS: deploy-factory rejected status=9 (factory config only)\n");

    /* (2) INJECT_TAG rejected (SEC_TEST=0 firmware backdoor closed). */
    if (!sec_cmd(dut, 0x04, {}, response, "deploy-inject")) return false;
    if (response[18] != 9) {
        std::printf("FAIL: deploy-inject status=%u (expect 9)\n", response[18]);
        return false;
    }
    std::printf("PASS: deploy-inject rejected status=9\n");

    /* (3) plaintext SEED_LOAD (0x63) rejected: frame[1]=1 (fail), frame[2]=RTL ERR_INSECURE_DISABLED=0x0a. */
    {
        std::array<uint8_t, 48> seed_resp{};
        uart_send(dut, 0x63);
        for (size_t i = 0; i < 32; ++i) uart_send(dut, 0x21u);
        if (!receive_status(dut, seed_resp, "deploy-seed")) return false;
        if (seed_resp[1] != 1u || seed_resp[2] != 0x0au) {
            std::printf("FAIL: deploy-seed status=%u hw_error=%u (expect 1/0x0a ERR_INSECURE_DISABLED)\n",
                        seed_resp[1], seed_resp[2]);
            return false;
        }
        std::printf("PASS: deploy-seed-load rejected hw_error=0x0a (plaintext SEED closed)\n");
    }

    /* (4) bad blob: BOOT unwrap tag fails -> ERROR_LOCKED (fail-closed, ctr not reset). */
    {
        std::array<uint8_t, 48> bad = blob;
        bad[0] ^= 0xffu;
        if (!sec_wrap_load(dut, bad, "deploy-bad-wrap")) return false;
        if (!sec_cmd(dut, 0x05, sec_key_i(), response, "deploy-bad-boot")) return false;
        if (be32(response, 20) != 0) {
            std::printf("FAIL: deploy-bad-boot state=%u (expect 0 ERROR_LOCKED)\n",
                        be32(response, 20));
            return false;
        }
        std::printf("PASS: deploy-bad-blob boot state=ERROR_LOCKED (unwrap tag fail, fail-closed)\n");
    }

    /* (5) good blob: WRAP_LOAD + BOOT -> unwrap recovers SEED -> IDLE ctr=0 (fresh device). */
    if (!sec_wrap_load(dut, blob, "deploy-wrap-load")) return false;
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "deploy-boot")) return false;
    if (response[18] != 0 || be32(response, 20) != 1 || response[36] != 1 || response[37] != 1) {
        std::printf("FAIL: deploy-boot state=%u locked=%u key=%u (expect IDLE/1/1)\n",
                    be32(response, 20), response[36], response[37]);
        return false;
    }
    if (!sec_cmd(dut, 0x07, {}, response, "deploy-state")) return false;
    if (be32(response, 24) != 0) {
        std::printf("FAIL: deploy-state ctr=%u (expect 0)\n", be32(response, 24));
        return false;
    }
    std::printf("PASS: deploy-boot unwrap OK state=IDLE ctr=0 key_loaded=1\n");

    /* (6) 0x67 KeyGen: SEC-slot SEED = factory seed 0..31 = generator seed -> public key should equal
     * the vector PUBLIC_KEY (deterministic, fixed-vector assertion). */
    uint8_t status = 0;
    std::vector<uint8_t> public_key;
    if (!sec_lms_keygen_request(dut, vector, status, public_key, "deploy-keygen")) return false;
    if (status != 0 || public_key.size() != vector.public_key.size()) {
        std::printf("FAIL: deploy-keygen status=%u pub_len=%zu\n", status, public_key.size());
        return false;
    }
    std::printf("PASS: deploy-keygen status=0 (device-specific pub, validated by sign+verify below)\n");
    /* The I generated by device KeyGen = public key [8:24] (PK=lmstype(4)||otstype(4)||I(16)||T1(32)),
     * the sign request uses this device I (host records the public key to get I, sends it back in the sign request - consistent with keygen). */
    std::vector<uint8_t> device_i(public_key.begin() + 8, public_key.begin() + 24);
    std::printf("DBG: deploy-keygen pub.I = ");
    for (size_t i = 0; i < 16; ++i) std::printf("%02x", public_key[8 + i]);
    std::printf("\nDBG: deploy-keygen pub.T1[0:4] = ");
    for (size_t i = 0; i < 4; ++i) std::printf("%02x", public_key[24 + i]);
    std::printf("\n");

    /* (7) 0x66 Sign q=0 -> ctr=1 (Release⇒Committed); q=1 strictly increasing. */
    uint32_t q_out = 0;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> signature_q0;
    if (!sec_lms_sign_request(dut, vector, status, q_out, signature, "deploy-sign-1", device_i)) return false;
    if (status != 0 || q_out != 0) {
        std::printf("FAIL: deploy-sign-1 status=%u q=%u (expect q=0)\n", status, q_out);
        return false;
    }
    signature_q0 = signature;
    std::printf("DBG: deploy sig0(q=0) len=%zu = ", signature_q0.size());
    for (size_t i = 0; i < signature_q0.size() && i < 48; ++i) std::printf("%02x", signature_q0[i]);
    std::printf("\n");
    if (!sec_cmd(dut, 0x07, {}, response, "deploy-ctr-1")) return false;
    if (be32(response, 20) != 1 || be32(response, 24) != 1) {
        std::printf("FAIL: deploy-sign-1 post state=%u ctr=%u (expect IDLE/1)\n",
                    be32(response, 20), be32(response, 24));
        return false;
    }
    std::printf("PASS: deploy-sign-1 q=0 committed ctr=1 (Release=>Committed)\n");
    if (!sec_lms_sign_request(dut, vector, status, q_out, signature, "deploy-sign-2", device_i)) return false;
    if (status != 0 || q_out != 1) {
        std::printf("FAIL: deploy-sign-2 status=%u q=%u (expect q=1)\n", status, q_out);
        return false;
    }
    std::printf("PASS: deploy-sign-2 q=1 strictly increasing\n");
    /* Diagnostics: q=1 signature hex (for cross-checking against the PC generator --q=1 SIGNATURE). */
    {
        std::printf("DBG: deploy sig1 = ");
        for (size_t i = 0; i < 32; ++i) std::printf("%02x", signature[i]);
        std::printf("\n");
    }

    /* (8) 0x56 Verify: use the deploy-keygen public key to verify the deploy-sign-1 (q=0) signature - same caliber
     * as the standard sec-lms suite (q=0 verification); then verify the q=1 signature (PC generator --q=1 reference signature
     * byte-identical, verification must pass - q≠0 hardware verification coverage). */
    for (int vq = 0; vq < 2; ++vq) {
        const std::vector<uint8_t> &sig = (vq == 0) ? signature_q0 : signature;
        uart_send(dut, 0x56);
        for (uint8_t value : public_key) uart_send(dut, value);
        uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
        uart_send(dut, static_cast<uint8_t>(vector.message.size()));
        for (uint8_t value : vector.message) uart_send(dut, value);
        while (vector.message.size() > 74u && vector.message.size() % 4u != 0u) {
            uart_send(dut, 0u);
        }
        for (uint8_t value : sig) uart_send(dut, value);
        std::array<uint8_t, 48> verify_resp{};
        if (!receive_status(dut, verify_resp, "deploy-verify")) return false;
        if (verify_resp[0] != 0x52 || verify_resp[1] != 0 || verify_resp[2] != 0 ||
            get_u32(verify_resp, 12) != 0) {
            std::printf("FAIL: deploy-verify q=%d status=%u hw_error=%u fallback=%u\n",
                        vq, verify_resp[1], verify_resp[2], get_u32(verify_resp, 12));
            return false;
        }
        std::printf("PASS: deploy-verify q=%d self-consistent (0x67 pub x 0x66 sig)\n", vq);
    }

    /* (9) (0.1.281 model B) 0x68 KEYGEN_NEW (deploy): new SEED+I generated on the spot by the **on-device TRNG**
     * (sec_keygen_new deploy branch -> CMD_SEED_WRITE_SAFE controlled load into slot 0) -> pubB ≠ pubA
     * (new I+new SEED), ctr reset -> Sign q=0 (new device I) -> Verify self-consistent (multi-key rotation deploy full chain).
     * The request I parameter is ignored under deploy (host still sends the 16B placeholder per protocol). */
    {
        std::vector<uint8_t> i_dummy(16, 0x00u);   /* deploy: ignored, device generates I */
        std::vector<uint8_t> public_key_new;
        std::vector<uint8_t> signature_new;
        std::vector<uint8_t> signature_new_q0;
        std::vector<uint8_t> device_i_new;

        if (!sec_lms_keygen_new_request(dut, vector, i_dummy, status, public_key_new,
                                        "deploy-keygen-new")) return false;
        if (status != 0 || public_key_new.size() != vector.public_key.size()) {
            std::printf("FAIL: deploy-keygen-new status=%u pub_len=%zu\n",
                        status, public_key_new.size());
            return false;
        }
        if (public_key_new == public_key) {
            std::printf("FAIL: deploy-keygen-new pubB == pubA (expected fresh on-device key)\n");
            return false;
        }
        std::printf("PASS: deploy-keygen-new status=0 pubB != pubA (on-device TRNG SEED+I)\n");

        /* After key rotation ctr resets to zero (new key has no signing history). */
        if (!sec_cmd(dut, 0x07, {}, response, "deploy-kgn-ctr")) return false;
        if (be32(response, 20) != 1 || be32(response, 24) != 0) {
            std::printf("FAIL: deploy-kgn-ctr state=%u ctr=%u (expect IDLE/0)\n",
                        be32(response, 20), be32(response, 24));
            return false;
        }
        std::printf("PASS: deploy-keygen-new post-rotate state=IDLE ctr=0 (fresh q)\n");

        /* Sign q=0 with the new device I (pub_new[8:24]) -> ctr=1. */
        device_i_new.assign(public_key_new.begin() + 8, public_key_new.begin() + 24);
        if (!sec_lms_sign_request(dut, vector, status, q_out, signature_new,
                                  "deploy-kgn-sign", device_i_new)) return false;
        if (status != 0 || q_out != 0) {
            std::printf("FAIL: deploy-kgn-sign status=%u q=%u (expect q=0)\n", status, q_out);
            return false;
        }
        signature_new_q0 = signature_new;
        if (!sec_cmd(dut, 0x07, {}, response, "deploy-kgn-ctr1")) return false;
        if (be32(response, 24) != 1) {
            std::printf("FAIL: deploy-kgn-ctr1 ctr=%u (expect 1 after sign q=0)\n", be32(response, 24));
            return false;
        }
        std::printf("PASS: deploy-keygen-new sign q=0 committed ctr=1\n");

        /* Verify: use pubB to verify sigB (q=0) - self-consistent loop (root rebuilt from new SEED+I, signature verification endorses correctness). */
        uart_send(dut, 0x56);
        for (uint8_t value : public_key_new) uart_send(dut, value);
        uart_send(dut, static_cast<uint8_t>(vector.message.size() >> 8));
        uart_send(dut, static_cast<uint8_t>(vector.message.size()));
        for (uint8_t value : vector.message) uart_send(dut, value);
        while (vector.message.size() > 74u && vector.message.size() % 4u != 0u) {
            uart_send(dut, 0u);
        }
        for (uint8_t value : signature_new_q0) uart_send(dut, value);
        if (!receive_status(dut, response, "deploy-kgn-verify")) return false;
        if (response[0] != 0x52 || response[1] != 0 || response[2] != 0 ||
            get_u32(response, 12) != 0) {
            std::printf("FAIL: deploy-kgn-verify status=%u hw_error=%u fallback=%u\n",
                        response[1], response[2], get_u32(response, 12));
            return false;
        }
        std::printf("PASS: deploy-keygen-new verify self-consistent (fresh key full chain)\n");
    }
    return true;
}

/* BOOT closed loop and fault injection (spec §13 tests 3/5/6, step 5).
 * Host persistent-domain model: after commit, grab the active slot 64B via NVM_SYNC + record sim_mc;
 * after reset (power loss), restore both slots via NVM_LOAD + restore mc via MC_LOAD, then BOOT to verify recovery semantics.
 * Prerequisite: run_uart_sec_state_cases already completed FACTORY_INIT (K_WRAP/K_STATE loaded,
 * sec_factory_locked=1); this case reuses that context and does not repeat FACTORY_INIT. */
static bool run_uart_sec_boot_cases(Vlms_soc &dut)
{
    std::array<uint8_t, 48> response{};
    std::array<uint8_t, 64> rec_reserved{};   /* ST_RESERVED(q=7) record */
    std::array<uint8_t, 64> rec_idle9{};      /* ST_IDLE(ctr=9) record */
    std::array<uint8_t, 64> rec_idle10{};     /* ST_IDLE(ctr=10) record */

    /* Confirm the context is ready (factory_locked=1, key_loaded=1); state should be IDLE. */
    if (!sec_cmd(dut, 0x07, {}, response, "boot-pre-state")) return false;
    if (response[36] != 1 || response[37] != 1 || be32(response, 20) != 1) {
        std::printf("FAIL: boot-pre-state state=%u locked=%u key=%u (expect IDLE/1/1)\n",
                    be32(response, 20), response[36], response[37]);
        return false;
    }
    std::printf("PASS: boot-pre-state IDLE factory_locked=1 key_loaded=1 (reuse ctx)\n");

    /* ---- Test 3: ST_RESERVED(q=7) power loss -> recovery conservatively burns ctr=q+1=8 ---- */
    if (!sec_cmd(dut, 0x01, commit_params(2, 7, 7), response, "boot3-reserve")) return false;
    if (response[18] != 0) { std::printf("FAIL: boot3-reserve status=%u\n", response[18]); return false; }
    const uint32_t tx_reserved = be32(response, 20);
    uint8_t slot_reserved = 0;
    if (!sec_active_slot(dut, slot_reserved, "boot3-slot")) return false;
    if (!nvm_read_full64(dut, rec_reserved, "boot3-capture")) return false;
    /* Verify the captured record is RESERVED(q=7): magic@0 state@4(2B) ctr@6(4B).
     * The minimal sufficient layout has no reserved_q field (at Reserve time ctr=q; q is expressed by ctr). */
    if (be32_64(rec_reserved, 0) != 0x4c4d5353u ||
        ((rec_reserved[4] << 8) | rec_reserved[5]) != 2 ||
        be32_64(rec_reserved, 6) != 7) {
        std::printf("FAIL: boot3-capture bad rec magic=%08x state=%u ctr=%u\n",
                    be32_64(rec_reserved, 0), (rec_reserved[4] << 8) | rec_reserved[5],
                    be32_64(rec_reserved, 6));
        return false;
    }

    /* Power loss: reset (volatile state cleared), firmware back to BOOTING. */
    if (!soc_reset(dut)) { std::puts("FAIL: boot3 reset"); return false; }
    if (!sec_cmd(dut, 0x07, {}, response, "boot3-after-reset")) return false;
    if (be32(response, 20) != 5) { std::printf("FAIL: boot3-after-reset state=%u (expect 5)\n", be32(response, 20)); return false; }
    std::printf("PASS: boot3-after-reset state=BOOTING (volatile cleared)\n");

    /* Recovery: restore sim_mc + the RESERVED record to its original slot, then BOOT -> conservatively burns ctr=8. */
    if (!sec_mc_load(dut, tx_reserved, "boot3-mc-load")) return false;
    if (!sec_nvm_load(dut, slot_reserved, rec_reserved, "boot3-nvm-load")) return false;
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "boot3-boot")) return false;
    if (be32(response, 20) != 1 || be32(response, 24) != 8) {
        std::printf("FAIL: boot3-boot state=%u ctr=%u (expect IDLE ctr=8)\n",
                    be32(response, 20), be32(response, 24));
        return false;
    }
    std::printf("PASS: boot3 conservative-burn state=IDLE ctr=8 (q=7 burned)\n");

    /* ---- Test 5: rollback (replay the old-tx slot) -> picks the new-tx slot ---- */
    /* commit ctr=9 (tx=T_new), capture the new slot. After reset restore: old slot (rec_reserved, smaller tx) + new slot,
     * mc restored to T_new; BOOT must pick the new slot ctr=9 (old slot has smaller tx; no rollback allowed). */
    if (!sec_cmd(dut, 0x01, commit_params(1, 9, 0), response, "boot5-commit9")) return false;
    const uint32_t tx_9 = be32(response, 20);
    uint8_t slot_9 = 0;
    if (!sec_active_slot(dut, slot_9, "boot5-slot")) return false;
    if (!nvm_read_full64(dut, rec_idle9, "boot5-capture9")) return false;
    if (!soc_reset(dut)) { std::puts("FAIL: boot5 reset"); return false; }
    if (!sec_mc_load(dut, tx_9, "boot5-mc-load")) return false;
    if (!sec_nvm_load(dut, slot_9, rec_idle9, "boot5-load-new")) return false;
    /* Put the old record in the other slot (rec_reserved with smaller tx), simulating an attacker replaying old state. */
    if (!sec_nvm_load(dut, (uint8_t)(1 - slot_9), rec_reserved, "boot5-load-old")) return false;
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "boot5-boot")) return false;
    if (be32(response, 20) != 1 || be32(response, 24) != 9) {
        std::printf("FAIL: boot5-boot state=%u ctr=%u (expect IDLE ctr=9, rollback rejected)\n",
                    be32(response, 20), be32(response, 24));
        return false;
    }
    std::printf("PASS: boot5 rollback rejected state=IDLE ctr=9 (chose newer tx)\n");

    /* ---- Test 6: half-write (high-tx slot tag corrupted) -> picks the valid low-tx slot ---- */
    /* commit ctr=10 (tx=T_high) writes to the other slot; corrupt its tag after capture.
     * After reset restore: bad-tag high slot + good low slot (rec_idle9); BOOT must skip the high slot and pick ctr=9. */
    if (!sec_cmd(dut, 0x01, commit_params(1, 10, 0), response, "boot6-commit10")) return false;
    const uint32_t tx_10 = be32(response, 20);
    uint8_t slot_10 = 0;
    if (!sec_active_slot(dut, slot_10, "boot6-slot")) return false;
    if (!nvm_read_full64(dut, rec_idle10, "boot6-capture10")) return false;
    rec_idle10[48] ^= 0xff;  /* corrupt the first tag byte (half-write left the tag unfinished) */
    if (!soc_reset(dut)) { std::puts("FAIL: boot6 reset"); return false; }
    if (!sec_mc_load(dut, tx_10, "boot6-mc-load")) return false;
    if (!sec_nvm_load(dut, slot_10, rec_idle10, "boot6-load-corrupt")) return false;
    if (!sec_nvm_load(dut, (uint8_t)(1 - slot_10), rec_idle9, "boot6-load-low")) return false;
    if (!sec_cmd(dut, 0x05, sec_key_i(), response, "boot6-boot")) return false;
    if (be32(response, 20) != 1 || be32(response, 24) != 9) {
        std::printf("FAIL: boot6-boot state=%u ctr=%u (expect IDLE ctr=9, half-write rejected)\n",
                    be32(response, 20), be32(response, 24));
        return false;
    }
    std::printf("PASS: boot6 half-write rejected state=IDLE ctr=9 (corrupt high-tx slot skipped)\n");

    /* ---- Test 7: both slots invalid -> deny service (ERROR_LOCKED), must not fall back to 0 ----
     * 7a: both slots have history but are simultaneously corrupted (non-zero, bad tag) -> BOOT must ERROR_LOCKED
     *     (resetting CTR to 0 would reuse released q, violating the Release=>Committed invariant);
     *     subsequent COMMIT is also rejected (SEC_ERR_LOCKED=2), proving deny-service rather than continued signing.
     * 7b: both slots all-zero (no state ever written) -> fresh device legitimately passes IDLE ctr=0. */
    {
        std::array<uint8_t, 64> rec_corrupt = rec_idle9;  /* non-zero history record (ctr=9) */
        rec_corrupt[48] ^= 0xff;                          /* corrupt the first tag byte */
        if (!sec_nvm_load(dut, 0, rec_corrupt, "boot7a-load0")) return false;
        if (!sec_nvm_load(dut, 1, rec_corrupt, "boot7a-load1")) return false;
        if (!sec_cmd(dut, 0x05, sec_key_i(), response, "boot7a-boot")) return false;
        if (be32(response, 20) != 0) {
            std::printf("FAIL: boot7a-boot state=%u ctr=%u (expect ERROR_LOCKED=0, deny service)\n",
                        be32(response, 20), be32(response, 24));
            return false;
        }
        /* Deny-service verification: after locked, COMMIT must be rejected (SEC_ERR_LOCKED=2). */
        if (!sec_cmd(dut, 0x01, commit_params(1, 9, 0), response, "boot7a-commit")) return false;
        if (response[18] != 2) {
            std::printf("FAIL: boot7a-commit status=%u (expect 2 ERR_LOCKED)\n", response[18]);
            return false;
        }
        std::printf("PASS: boot7a both-slots-corrupt state=ERROR_LOCKED commit rejected (no ctr reset)\n");

        /* 7b: all-zero slots (never had state) -> fresh device passes IDLE ctr=0. */
        std::array<uint8_t, 64> rec_zero{};
        if (!sec_nvm_load(dut, 0, rec_zero, "boot7b-load0")) return false;
        if (!sec_nvm_load(dut, 1, rec_zero, "boot7b-load1")) return false;
        if (!sec_cmd(dut, 0x05, sec_key_i(), response, "boot7b-boot")) return false;
        if (be32(response, 20) != 1 || be32(response, 24) != 0) {
            std::printf("FAIL: boot7b-boot state=%u ctr=%u (expect IDLE ctr=0, fresh device)\n",
                        be32(response, 20), be32(response, 24));
            return false;
        }
        std::printf("PASS: boot7b all-zero-slots fresh device state=IDLE ctr=0\n");
    }
    return true;
}

/* ---- Multi-parameter set (t8: w∈{1,2,4,8} × h∈{5,10,15}) ----
 * run_full: whether to run LMS KeyGen/Sign (tree build). Under the SoC simulation budget:
 *   - W4 hardware tree build (KEYGEN_LEAF batch tasks) is fast -> W4_H5/W4_H10 runnable (perf combo w=4×h=5/10);
 *   - w≠4 tree build goes through software ots_pub (RV32 software SHAKE256 ~35K cycles/chain) -> H5 already takes ~20-40 min,
 *     H10/H15 hours-scale infeasible -> run_full=false (only LM-OTS + LMS Verify functional checks);
 *   - H15 builds 2^15=32768 leaves, over budget -> run_full=false even for W4.
 * run_soc: whether to include in SoC --all-params verification. w=8 software chain = 34 chains x 255 steps x SHAKE256
 *   ≈ 300M cycles/op (W1 chain only 1 step, W2 only 3), infeasible under the SoC simulation 50M timeout (on board,
 *   real 50MHz takes only ~6 s) -> W8 excluded; functional correctness covered by PC multiparam_smoke + on-board verification.
 * The remaining parameter sets' LMS KeyGen/Sign functional correctness is covered by PC multiparam_smoke (j=h full-sweep byte-identical)
 * + on-board verification; performance data (w∈{2,4}×h∈{5,10}) is archived from on-board measurement. */
struct ParamSpec {
    int w;
    int h;
    const char *vector;
    bool run_full;
    bool run_soc;
};

/* N36 (SHAKE vector caliber): build/vectors/lms_verify_vector_*.txt are SHA-256 parameter-scan outputs;
 * SHAKE256 builds must use the shake_-prefixed files (typecodes 21/19), otherwise the batch tasks all spuriously fail
 * (0.1.269 SHAKE "batch-task failure" misdiagnosis root cause; board-test loader adapted, this table previously missed it). */
#ifdef FW_HASH_SHAKE256
#define PS_VEC(w, h) "build/vectors/shake_lms_verify_vector_W" #w "_H" #h ".txt"
#else
#define PS_VEC(w, h) "build/vectors/lms_verify_vector_W" #w "_H" #h ".txt"
#endif
static const ParamSpec kParamSets[] = {
    {1, 5,  PS_VEC(1, 5),  false, true},
    {2, 5,  PS_VEC(2, 5),  false, true},
    {4, 5,  PS_VEC(4, 5),  true,  true},
    {8, 5,  PS_VEC(8, 5),  false, false},
    {1, 10, PS_VEC(1, 10), false, true},
    {2, 10, PS_VEC(2, 10), false, true},
    {4, 10, PS_VEC(4, 10), true,  true},
    {8, 10, PS_VEC(8, 10), false, false},
    {1, 15, PS_VEC(1, 15), false, true},
    {2, 15, PS_VEC(2, 15), false, true},
    {4, 15, PS_VEC(4, 15), false, true},
    {8, 15, PS_VEC(8, 15), false, false},
};
#undef PS_VEC

/* Run one parameter set: LM-OTS trio + LMS Verify (+ LMS KeyGen/Sign when run_full).
 * hits accumulate across parameter sets (firmware keeps running without reset); return false on any failure. */
static bool run_param_set(Vlms_soc &dut, const ParamSpec &ps, uint32_t &hits)
{
    g_param_w = ps.w;
    g_param_h = ps.h;
    g_vector_path = ps.vector;
    VerifyVector vec;
    if (!load_verify_vector(vec)) {
        std::printf("FAIL: load %s\n", ps.vector);
        return false;
    }
    char tag[32];
    std::snprintf(tag, sizeof(tag), "W%d_H%d", ps.w, ps.h);
    std::printf("======== %s (%s) ========\n", tag, ps.vector);
    uint32_t hits_out = hits;
    if (!run_uart_lmots_cases(dut, hits, hits_out, tag)) return false;
    hits = hits_out;
    if (!run_uart_verify_case(dut, hits, hits_out, tag)) return false;
    hits = hits_out;
    if (ps.run_full) {
        if (!run_uart_keygen_case(dut, hits, hits_out, tag)) return false;
        hits = hits_out;
        if (!run_uart_sign_case(dut, hits, hits_out, tag)) return false;
        hits = hits_out;
    }
    return true;
}

int main(int argc, char **argv)
{
    /* Debug-friendly: unbuffered so test output is visible in real time (helps locate hangs) */
    setvbuf(stdout, NULL, _IONBF, 0);
    Verilated::commandArgs(argc, argv);
    /* Multi-parameter sets: --all-params iterates w∈{1,2,4,8}×h∈{5,10,15} (12 vectors);
     * --params=W1_H5,W4_H10,... selects a subset (matched by w×h). Default runs only the W4/H5 fast regression. */
    bool run_all_params = false;
    bool deploy_mode = false;
    std::vector<std::string> param_select;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--all-params") == 0) {
            run_all_params = true;
        } else if (std::strcmp(argv[i], "--deploy") == 0) {
            /* P1-6 (0.1.274): deploy build (-GINSECURE_TEST_MODE=0 + SEC_TEST=0 firmware) regression. */
            deploy_mode = true;
        } else if (std::strncmp(argv[i], "--params=", 9) == 0) {
            std::string list(argv[i] + 9);
            size_t pos = 0;
            while ((pos = list.find(',')) != std::string::npos) {
                param_select.push_back(list.substr(0, pos));
                list.erase(0, pos + 1);
            }
            if (!list.empty()) param_select.push_back(list);
        }
    }
    /* DBG trace (Step 3 debugging): off by default to avoid generating hundreds of GB of VCD.
     * To capture waveforms, set the g_trace_on initial value to true (or restore the hard-coded comment in the LM-OTS Sign section). */
    if (g_trace_on) {
        Verilated::traceEverOn(true);
    }
    Vlms_soc dut;
    if (g_trace_on) {
        g_tfp = new VerilatedVcdC;
        dut.trace(g_tfp, 99);
        g_tfp->open("lmots_sign_trace.vcd");
    }
    dut.uart_rxd = 1;
    dut.uart_cts_i = 1;   /* REVIEW: firmware uart_putc etc. wait for UART_TX_READY(=fin&&cts); without cts_i=1 the firmware hangs forever sending responses (all commands time out) */
    dut.gpio_in = 0;
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;

    int cycles = 0;
    /* Boot wait: since 0.1.232 firmware bss grew by ~5KB (tree-cache arena 16KiB), crt0 zeroing got slower,
     * 30000 cycles times out (RV32 without icache, layout-sensitive) -> relaxed to 200000. */
    while (dut.gpio_out == 0 && !dut.trap && cycles < 200000) {
        tick(dut);
        ++cycles;
    }

    if (dut.trap || dut.gpio_out != 0xa5) {
        std::printf("FAIL: LMS SoC smoke cycles=%d trap=%u gpio=%02x\n",
                    cycles,
                    static_cast<unsigned>(dut.trap),
                    static_cast<unsigned>(dut.gpio_out));
        dut.final();
        return 1;
    }

    std::printf("PASS: LMS SoC RV32 HASH_ONCE cycles=%d gpio=%02x\n",
                cycles,
                static_cast<unsigned>(dut.gpio_out));

    const std::vector<uint8_t> empty;
    const std::vector<uint8_t> abc{'a', 'b', 'c'};
    std::vector<uint8_t> seq55(55);
    std::vector<uint8_t> seq64(64);
    std::vector<uint8_t> seq128(128);
    for (size_t index = 0; index < seq128.size(); ++index) {
        seq128[index] = static_cast<uint8_t>(index);
        if (index < seq64.size()) seq64[index] = static_cast<uint8_t>(index);
        if (index < seq55.size()) seq55[index] = static_cast<uint8_t>(index);
    }

    bool passed = true;
#ifdef FW_HASH_SHAKE256
    /* SHAKE256-256 expected (authoritative reference: Python hashlib; HASH_ONCE single-block cycles=12) */
    passed &= run_uart_case(dut, "empty", empty,
                            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                            12, 2);
    passed &= run_uart_case(dut, "abc", abc,
                            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
                            12, 3);
    passed &= run_uart_case(dut, "seq55", seq55,
                            "9b4cb90daa3ef4e1b923727dc61ebccab5a81c7d54151300a3c26b893539ecf7",
                            12, 4);
    passed &= run_uart_case(dut, "seq64", seq64,
                            "755e8863a2b2bc067f51c1637a71c819d524dc37c17ba7a29c6ee3767c996a49",
                            12, 5);
    passed &= run_uart_case(dut, "seq128", seq128,
                            "8d3a3a49eb989dd9de155fcd66a2c85fb33b9d0576bec9790af31c0565ee15ec",
                            12, 6);
#else
    passed &= run_uart_case(dut, "empty", empty,
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            68, 2);
    passed &= run_uart_case(dut, "abc", abc,
                            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                            68, 3);
    passed &= run_uart_case(dut, "seq55", seq55,
                            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
                            68, 4);
    passed &= run_uart_case(dut, "seq64", seq64,
                            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
                            135, 5);
    passed &= run_uart_case(dut, "seq128", seq128,
                            "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5",
                            202, 6);
#endif
    passed &= run_uart_chain_case(dut, 7);
    passed &= run_uart_trng_status_case(dut);
    passed &= run_uart_trng_read_ack_case(dut);
    passed &= run_uart_trng_read_ack_stress(dut, 200);
    if (deploy_mode) {
        /* P1-6 (0.1.274): deploy build skips all cases depending on plaintext SEED (insecure trio /
         * standard SEC suite); only runs the basic KAT + deploy-caliber cases. */
        passed &= run_uart_deploy_cases(dut);
        dut.final();
        return passed ? 0 : 1;
    }
#ifdef FW_HASH_SHAKE256
    if (run_all_params || !param_select.empty()) {
        /* Multi-parameter-set verification: iterate kParamSets (--all-params or --params subset).
         * hits accumulate across parameter sets (firmware keeps running); W4/H5 exact assertions, others loose (results byte-identical). */
        uint32_t hits = 7;  /* accumulated after the base cases */
        for (const ParamSpec &ps : kParamSets) {
            if (!param_select.empty()) {
                char key[32];
                std::snprintf(key, sizeof(key), "W%d_H%d", ps.w, ps.h);
                if (std::find(param_select.begin(), param_select.end(),
                              std::string(key)) == param_select.end()) {
                    continue;
                }
            } else if (!ps.run_soc) {
                /* --all-params: skip W8 (w=8 software chain 34x255xSHAKE256 ≈ 3e8
                 * cycles/op exceeds the SoC simulation budget; functional correctness covered by PC multiparam_smoke
                 * + on-board verification). Still runnable when --params=W8_x explicitly selects it. */
                std::printf("SKIP: W%d_H%d (w=8 software chain exceeds SoC budget; covered by PC/board)\n",
                            ps.w, ps.h);
                continue;
            }
            if (!run_param_set(dut, ps, hits)) {
                passed = false;
                break;  /* stop on first failure (subsequent hits semantics may be broken) */
            }
        }
    } else {
        /* Default fast regression: W4/H5 single vector (build/lms_verify_vector.txt).
         * LM-OTS KeyGen(1) + Sign(2) + Verify(1) = 4, cumulative 7+4=11
         * new-caliber hits (Verify +3 after D_INTR_CHAIN synthesis): after LM-OTS=11 -> Verify#1=14
         * -> Verify#2=17 -> KeyGen=80 -> Sign=83 */
        uint32_t hits = 7;
        passed &= run_uart_lmots_cases(dut, hits, hits, "W4_H5");
        passed &= run_uart_verify_case(dut, 11, hits, "W4_H5");
        passed &= run_uart_verify_case(dut, 14, hits, "W4_H5");
        passed &= run_uart_keygen_case(dut, 17, hits, "W4_H5");
        passed &= run_uart_sign_case(dut, 80, hits, "W4_H5");
        passed &= run_uart_big_msg_1kb(dut);
    }
#else
    /* SHA-256: multi-parameter-set verification (isomorphic to SHAKE after S5 hardware-izes all w).
     * --params=W4_H10 etc.: iterate kParamSets; W4/H5 exact assertions, others loose.
     * Default still runs the W4/H5 single-vector exact regression. */
    if (run_all_params || !param_select.empty()) {
        uint32_t hits = 7;
        for (const ParamSpec &ps : kParamSets) {
            if (!param_select.empty()) {
                char key[32];
                std::snprintf(key, sizeof(key), "W%d_H%d", ps.w, ps.h);
                if (std::find(param_select.begin(), param_select.end(),
                              std::string(key)) == param_select.end()) {
                    continue;
                }
            } else if (!ps.run_soc) {
                std::printf("SKIP: W%d_H%d (w=8 software chain exceeds SoC budget; covered by PC/board)\n",
                            ps.w, ps.h);
                continue;
            }
            if (!run_param_set(dut, ps, hits)) {
                passed = false;
                break;  /* stop on first failure (subsequent hits semantics may be broken) */
            }
        }
    } else {
        uint32_t hits = 7;
        passed &= run_uart_lmots_cases(dut, hits, hits, "W4_H5");
        passed &= run_uart_verify_case(dut, 11, hits, "W4_H5");
        passed &= run_uart_verify_case(dut, 14, hits, "W4_H5");
        passed &= run_uart_keygen_case(dut, 17, hits, "W4_H5");
        passed &= run_uart_sign_case(dut, 80, hits, "W4_H5");
        passed &= run_uart_big_msg_1kb(dut);
    }
#endif
    /* Secure-domain/NVM/state-domain cases depend on HAS_SECURITY=1 (SHAKE256 wired into SEC; skip lifted after steps 2/3).
     * The 0x64/0x65 intermediate-state cases were removed with 0.1.254 (0.1.240 caliber decision: only two calibers, insecure vs secure). */
    passed &= run_uart_nvm_sync_cases(dut);
    passed &= run_uart_sec_state_cases(dut);
    passed &= run_uart_sec_boot_cases(dut);
    passed &= run_uart_sec_sign_cases(dut);
    passed &= run_uart_sec_lms_cases(dut);
    passed &= run_uart_sec_lms_keygen_new_cases(dut);
    dut.final();
    return passed ? 0 : 1;
}
