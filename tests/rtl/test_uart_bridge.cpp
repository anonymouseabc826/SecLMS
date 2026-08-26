#include "Vlms_uart_bridge.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>
#include <vector>

static constexpr uint32_t BRIDGE_BASE = 0x18000000;
static constexpr uint32_t REG_CTRL = 0x000;
static constexpr uint32_t REG_ADDR = 0x004;
static constexpr uint32_t REG_LEN = 0x008;
static constexpr uint32_t CTRL_START = 1u;
static constexpr uint32_t CTRL_CLEAR = 2u;
static constexpr uint32_t DIR_RX_RAM = 0u;
static constexpr uint32_t DIR_RAM_TX = 2u;   /* bit1 */
static constexpr uint32_t STATUS_BUSY = 1u;
static constexpr uint32_t STATUS_DONE = 2u;
static constexpr uint32_t STATUS_ERROR = 4u;

double sc_time_stamp() { return 0.0; }

static std::vector<uint32_t> g_ram(568, 0);

static int g_pend_rd = -1;
static uint32_t g_pend_data = 0;
static std::vector<uint8_t> g_tx_out;
static int g_tx_busy = 0;

/* After posedge: capture the bridge outputs (equivalent to the tail of tick(), shared
 * by manual loops with inlined phases).
 * Must always be called, or the simulated peripheral state for stream write/read and
 * uart_tx is not updated. */
static void collect(Vlms_uart_bridge &dut)
{
    if (dut.stream_rd_en) {
        g_pend_rd = dut.stream_rd_addr;
        g_pend_data = g_ram[static_cast<size_t>(g_pend_rd)];
    } else {
        g_pend_rd = -1;
    }
    if (dut.stream_wr_en) {
        g_ram[static_cast<size_t>(dut.stream_wr_addr)] = dut.stream_wr_data;
    }
    if (dut.tx_send) {
        g_tx_out.push_back(static_cast<uint8_t>(dut.tx_data));
        g_tx_busy = 6;   /* simulate UART transmit of 6 ticks */
    }
    if (g_tx_busy > 0) {
        g_tx_busy--;
    }
}

static void tick(Vlms_uart_bridge &dut)
{
    /* Phase 0: clk low. Combinational inputs (stream read data, uart_tx ready) */
    dut.clk = 0;
    if (g_pend_rd >= 0) {
        dut.stream_rd_valid = 1;
        dut.stream_rd_data = g_pend_data;
    } else {
        dut.stream_rd_valid = 0;
        dut.stream_rd_data = 0;
    }
    dut.tx_ready = (g_tx_busy > 0) ? 0 : 1;
    dut.eval();
    /* Phase 1: clk high (posedge) */
    dut.clk = 1;
    dut.eval();
    collect(dut);
}

static void reset(Vlms_uart_bridge &dut)
{
    dut.rst = 1;
    dut.mem_valid = 0;
    dut.mem_write = 0;
    dut.mem_addr = 0;
    dut.mem_wdata = 0;
    dut.mem_wstrb = 0;
    dut.rx_data = 0;
    dut.rx_rdy = 0;
    dut.stream_busy = 0;
    g_ram.assign(568, 0);
    g_pend_rd = -1;
    g_tx_out.clear();
    g_tx_busy = 0;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
}

static void write_reg(Vlms_uart_bridge &dut, uint32_t addr, uint32_t value)
{
    dut.mem_valid = 1;
    dut.mem_write = 1;
    dut.mem_addr = BRIDGE_BASE + addr;
    dut.mem_wdata = value;
    dut.mem_wstrb = 0xf;
    tick(dut);
    dut.mem_valid = 0;
    dut.mem_write = 0;
    tick(dut);
}

static uint32_t read_reg(Vlms_uart_bridge &dut, uint32_t addr)
{
    dut.mem_valid = 1;
    dut.mem_write = 0;
    dut.mem_addr = BRIDGE_BASE + addr;
    tick(dut);
    const uint32_t value = dut.mem_rdata;
    dut.mem_valid = 0;
    tick(dut);
    return value;
}

static void rx_push_bytes(Vlms_uart_bridge &dut, const std::vector<uint8_t> &bytes)
{
    /* Simulate the combinational ack handshake between a real uart_rx and the bridge
     * (rx_ack = S_RX_BYTE && rx_rdy): ack is a combinational output, valid before the
     * consuming posedge (phase 0); on that same posedge the bridge samples the data and
     * uart_rx pops. So the tick that detects the ack rising edge already completes the
     * consumption, no extra idle tick is needed; prev_ack is reset at the end of each
     * byte loop so a leftover ack from the previous byte is not misread.
     * collect() must be called after every posedge to capture peripheral state such as stream writes. */
    bool prev_ack = false;
    for (size_t i = 0; i < bytes.size(); ++i) {
        dut.rx_data = bytes[i];
        dut.rx_rdy = 1;
        bool acked = false;
        int guard = 0;
        while (!acked && guard++ < 200000) {
            dut.clk = 0;
            dut.eval();   /* phase 0: combinational ack (before posedge) */
            const bool cur_ack = dut.rx_ack;
            if (cur_ack && !prev_ack) {
                acked = true;
            }
            prev_ack = cur_ack;
            dut.clk = 1;
            dut.eval();   /* phase 1 (posedge): bridge samples + uart_rx pops */
            collect(dut);
        }
        if (!acked) {
            std::printf("FAIL: rx byte %zu timeout (ack never)\n", i);
        }
        dut.rx_rdy = 0;
        prev_ack = false;
    }
}

static bool wait_done(Vlms_uart_bridge &dut, int max_ticks = 400000)
{
    int guard = 0;
    while (guard++ < max_ticks) {
        if (read_reg(dut, REG_CTRL) & STATUS_DONE) {
            return true;
        }
        if (dut.mem_rdata & STATUS_ERROR) {
            return false;
        }
    }
    std::puts("FAIL: bridge timeout");
    return false;
}

/* ---------- Test cases ---------- */

static int test_rx_to_ram(Vlms_uart_bridge &dut)
{
    int failures = 0;
    reset(dut);
    /* 8 bytes -> task RAM words 32/33 (little-endian packed into words) */
    const std::vector<uint8_t> bytes = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    write_reg(dut, REG_ADDR, 32);
    write_reg(dut, REG_LEN, 8);
    write_reg(dut, REG_CTRL, CTRL_START | DIR_RX_RAM);
    rx_push_bytes(dut, bytes);   /* bridge receives bytes from uart_rx and writes them straight through to task RAM */
    if (!wait_done(dut)) {
        std::printf("FAIL: RX→RAM not done, status=%u wr=%u waddr=%u ram32=%08x\n",
                    read_reg(dut, REG_CTRL),
                    static_cast<unsigned>(dut.stream_wr_en),
                    static_cast<unsigned>(dut.stream_wr_addr),
                    g_ram[32]);
        return 1;
    }
    if (g_ram[32] != 0x44332211u) {
        std::printf("FAIL: RX→RAM word32 got %08x want 44332211\n", g_ram[32]);
        ++failures;
    } else {
        std::puts("PASS: RX→RAM word32");
    }
    if (g_ram[33] != 0x88776655u) {
        std::printf("FAIL: RX→RAM word33 got %08x want 88776655\n", g_ram[33]);
        ++failures;
    } else {
        std::puts("PASS: RX→RAM word33");
    }
    /* clear status */
    write_reg(dut, REG_CTRL, CTRL_CLEAR);
    if (read_reg(dut, REG_CTRL) & (STATUS_DONE | STATUS_ERROR)) {
        std::puts("FAIL: clear did not clear status");
        ++failures;
    }
    return failures;
}

static int test_ram_to_tx(Vlms_uart_bridge &dut)
{
    int failures = 0;
    reset(dut);
    /* prefill task RAM words 40/41 */
    g_ram[40] = 0xddccbbaa;
    g_ram[41] = 0x44332211;
    write_reg(dut, REG_ADDR, 40);
    write_reg(dut, REG_LEN, 8);
    write_reg(dut, REG_CTRL, CTRL_START | DIR_RAM_TX);
    if (!wait_done(dut)) {
        std::printf("FAIL: RAM→TX not done, status=%u\n", read_reg(dut, REG_CTRL));
        return 1;
    }
    const std::vector<uint8_t> expect = {
        0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
    if (g_tx_out.size() != expect.size()) {
        std::printf("FAIL: RAM→TX bytes=%zu want %zu\n", g_tx_out.size(), expect.size());
        ++failures;
    } else {
        bool ok = true;
        for (size_t i = 0; i < expect.size(); ++i) {
            if (g_tx_out[i] != expect[i]) {
                ok = false;
                std::printf("  byte %zu got %02x want %02x\n",
                            i, g_tx_out[i], expect[i]);
            }
        }
        if (ok) {
            std::puts("PASS: RAM→TX byte order");
        } else {
            ++failures;
        }
    }
    return failures;
}

static int test_errors(Vlms_uart_bridge &dut)
{
    int failures = 0;
    reset(dut);
    /* start while core is busy -> error */
    dut.stream_busy = 1;
    write_reg(dut, REG_ADDR, 32);
    write_reg(dut, REG_LEN, 8);
    write_reg(dut, REG_CTRL, CTRL_START | DIR_RX_RAM);
    dut.stream_busy = 0;
    if (!(read_reg(dut, REG_CTRL) & STATUS_ERROR)) {
        std::puts("FAIL: start while stream_busy did not set error");
        ++failures;
    } else {
        std::puts("PASS: busy-start rejected");
    }
    write_reg(dut, REG_CTRL, CTRL_CLEAR);

    /* LEN not a multiple of 4 -> error */
    write_reg(dut, REG_ADDR, 32);
    write_reg(dut, REG_LEN, 6);
    write_reg(dut, REG_CTRL, CTRL_START | DIR_RX_RAM);
    if (!(read_reg(dut, REG_CTRL) & STATUS_ERROR)) {
        std::puts("FAIL: non-multiple-of-4 LEN did not set error");
        ++failures;
    } else {
        std::puts("PASS: bad LEN rejected");
    }
    write_reg(dut, REG_CTRL, CTRL_CLEAR);
    return failures;
}

static int test_ram_to_tx_2144(Vlms_uart_bridge &dut)
{
    int failures = 0;
    reset(dut);
    /* prefill task RAM words 32..567 (536 words = 2144B), verifying the bridge can transmit a full signature y */
    for (int w = 0; w < 536; ++w) {
        g_ram[32 + w] = 0x04030201u + static_cast<uint32_t>(w) * 0x11111111u;
    }
    write_reg(dut, REG_ADDR, 32);
    write_reg(dut, REG_LEN, 2144);
    write_reg(dut, REG_CTRL, CTRL_START | DIR_RAM_TX);
    if (!wait_done(dut)) {
        std::printf("FAIL: RAM→TX 2144 not done, status=%u tx=%zu\n",
                    read_reg(dut, REG_CTRL), g_tx_out.size());
        return 1;
    }
    const size_t expect = 2144u;
    if (g_tx_out.size() != expect) {
        std::printf("FAIL: RAM→TX 2144 bytes=%zu want %zu\n",
                    g_tx_out.size(), expect);
        return 1;
    }
    bool ok = true;
    for (int w = 0; w < 536; ++w) {
        const uint32_t word = g_ram[32 + w];
        const uint8_t b0 = static_cast<uint8_t>(word);
        const uint8_t b1 = static_cast<uint8_t>(word >> 8);
        const uint8_t b2 = static_cast<uint8_t>(word >> 16);
        const uint8_t b3 = static_cast<uint8_t>(word >> 24);
        if (g_tx_out[4 * w + 0] != b0 || g_tx_out[4 * w + 1] != b1 ||
            g_tx_out[4 * w + 2] != b2 || g_tx_out[4 * w + 3] != b3) {
            ok = false;
            std::printf("  word %d mismatch at byte %d\n", w, 4 * w);
            break;
        }
    }
    if (ok) {
        std::puts("PASS: RAM→TX 2144B full");
    } else {
        ++failures;
    }
    return failures;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_uart_bridge dut;

    int failures = 0;
    failures += test_rx_to_ram(dut);
    failures += test_ram_to_tx(dut);
    failures += test_ram_to_tx_2144(dut);
    failures += test_errors(dut);

    std::printf("UART bridge tests: %d failed\n", failures);
    return failures == 0 ? 0 : 1;
}
