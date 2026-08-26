/* Classic algorithm benchmark firmware (fw/lms_bench.c) SoC smoke test: verifies RV32
 * firmware boot + bare-metal allocator + UART protocol + RSA/ECDSA command paths
 * (correctness itself is vouched for by the bench-native PC self-check).
 * Cases:
 *   1 'S' SHA-256(0..63) -> digest must equal fixed value fdeab9ac... (checkable
 *     across implementations).
 *   2 'E' ECDSA P-256 sign -> DER sig read-back.
 *   3 'D' feed the signature back for verify -> status=0 (self-consistent in firmware).
 * read_frame scans at most 64 bytes until the 0x52 marker (defensive; after the
 * uart_tx.v 0.1.282 pending-buffer fix, the first frame should be 0x52 directly).
 * RSA signing ('R') is too slow under Verilator (~20M+ cycles); left for on-board
 * board test (bench_classic).
 */
#include "Vlms_soc.h"
#include "Vlms_soc___024root.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static constexpr int UART_BIT_CYCLES = 50000000 / 115200;

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

static bool uart_receive(Vlms_soc &dut, uint8_t &value, int64_t timeout)
{
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

static bool read_frame(Vlms_soc &dut, uint8_t &status, uint32_t &cycles, int64_t timeout)
{
    uint8_t marker = 0;
    /* scan at most 64 bytes until the 0x52 marker (defends against leading garbage bytes) */
    for (int scan = 0; scan < 64; ++scan) {
        if (!uart_receive(dut, marker, timeout)) {
            std::printf("FAIL: frame timeout (scan=%d gpio_out=0x%02x trap=%d)\n",
                        scan, (int)dut.gpio_out, (int)dut.trap);
            return false;
        }
        if (marker == 0x52u) {
            break;
        }
        timeout = UART_BIT_CYCLES * 4000ll;
    }
    if (marker != 0x52u) {
        std::printf("FAIL: marker not found (last=0x%02x) gpio_out=0x%02x trap=%d\n",
                    marker, (int)dut.gpio_out, (int)dut.trap);
        return false;
    }
    if (!uart_receive(dut, status, UART_BIT_CYCLES * 2000)) {
        return false;
    }
    cycles = 0;
    for (int i = 0; i < 4; ++i) {
        uint8_t b;
        if (!uart_receive(dut, b, UART_BIT_CYCLES * 2000)) {
            return false;
        }
        cycles |= static_cast<uint32_t>(b) << (8 * i);
    }
    return true;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_soc dut;

    /* Same as test_lms_soc.cpp:2288-2291: rxd must be explicitly set to 1 (idle
     * high), otherwise after Verilator construction rxd=X/0 -> uart_rx fabricates
     * bytes during startup -> firmware reads a garbage first command. Same for cts. */
    dut.uart_rxd = 1;
    dut.uart_cts_i = 1;
    dut.gpio_in = 0;
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    /* While waiting for firmware bss clear + bench_crypto_init (RSA/EC key parsing,
     * ~0.5M cycles), the sent command bytes are buffered by the uart_rx register
     * (rdy set) and read once the firmware is ready. */
    ticks(dut, 2000);

    uint8_t status = 0;
    uint32_t cycles = 0;

    /* 1 'S' SHA-256 smoke: digest(bytes 0..63) = fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108 */
    uart_send(dut, 0x53u);
    if (!read_frame(dut, status, cycles, 300000000ll)) {
        std::printf("FAIL: S frame\n");
        return 1;
    }
    if (status != 0) {
        std::printf("FAIL: S status=%u\n", status);
        return 1;
    }
    {
        uint8_t digest[32];
        bool ok = true;
        for (int i = 0; i < 32; ++i) {
            if (!uart_receive(dut, digest[i], UART_BIT_CYCLES * 2000)) {
                ok = false;
                break;
            }
        }
        static const uint8_t expected[32] = {
            0xfd, 0xea, 0xb9, 0xac, 0xf3, 0x71, 0x03, 0x62, 0xbd, 0x26, 0x58,
            0xcd, 0xc9, 0xa2, 0x9e, 0x8f, 0x9c, 0x75, 0x7f, 0xcf, 0x98, 0x11,
            0x60, 0x3a, 0x8c, 0x44, 0x7c, 0xd1, 0xd9, 0x15, 0x11, 0x08};
        if (!ok || std::memcmp(digest, expected, 32) != 0) {
            std::printf("FAIL: S digest mismatch\n");
            return 1;
        }
        std::printf("PASS: S sha256 digest match (cycles=%u, trap=%d)\n", cycles, (int)dut.trap);
    }

    /* 2 'E' ECDSA P-256 deterministic signature -> DER read-back */
    uart_send(dut, 0x45u);
    if (!read_frame(dut, status, cycles, 400000000ll)) {
        std::printf("FAIL: E frame\n");
        return 1;
    }
    if (status != 0) {
        std::printf("FAIL: E status=%u\n", status);
        return 1;
    }
    std::vector<uint8_t> sig;
    {
        uint8_t len = 0;
        if (!uart_receive(dut, len, UART_BIT_CYCLES * 2000)) {
            std::printf("FAIL: E len timeout\n");
            return 1;
        }
        for (int i = 0; i < len; ++i) {
            uint8_t b;
            if (!uart_receive(dut, b, UART_BIT_CYCLES * 2000)) {
                std::printf("FAIL: E sig timeout\n");
                return 1;
            }
            sig.push_back(b);
        }
        std::printf("PASS: E ecdsa sign (cycles=%u, sig_len=%zu, trap=%d)\n",
                    cycles, sig.size(), (int)dut.trap);
    }

    /* 3 'D' ECDSA verify: feed back the same DER signature -> status=0 */
    uart_send(dut, 0x44u);
    uart_send(dut, static_cast<uint8_t>(sig.size()));
    for (uint8_t b : sig) {
        uart_send(dut, b);
    }
    if (!read_frame(dut, status, cycles, 500000000ll)) {
        std::printf("FAIL: D frame\n");
        return 1;
    }
    if (status != 0) {
        std::printf("FAIL: D status=%u (verify rejected own sig)\n", status);
        return 1;
    }
    std::printf("PASS: D ecdsa verify self-consistent (cycles=%u, trap=%d)\n", cycles, (int)dut.trap);

    if (dut.trap) {
        std::printf("FAIL: firmware trap\n");
        return 1;
    }
    std::printf("BENCH SOC SMOKE PASSED\n");
    return 0;
}
