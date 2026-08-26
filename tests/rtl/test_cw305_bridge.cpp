// test_cw305_bridge.cpp - lms_cw305_usb_uart bridge simulation test
//
// Covers:
//   1) Register read path (IDENTIFY/CRYPT_TYPE/CRYPT_REV/STATUS/USER_LED)
//   2) TX path: emulate SoC UART sending bytes -> TX FIFO -> host reads REG_TX_IDX/REG_TX_BYTE
//   3) RX path: host writes REG_RX_BYTE -> UART transmits -> verify decoding of soc_uart_rxd waveform
//   4) End-to-end loopback: host writes "ping!" -> (UART TX -> external loopback -> UART RX) -> host reads back
//   5) trap status bit (REG_STATUS bit0)
//
// Speed up with -GUART_BITCLKS=64 (passed in via the Makefile target).

#include "Vlms_cw305_usb_uart.h"
#include "verilated.h"
#ifdef CW305_TRACE
#include "verilated_vcd_c.h"
#endif

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#ifndef TEST_BITCLKS
#define TEST_BITCLKS 64
#endif
static constexpr int BITCLKS = TEST_BITCLKS; /* matches -GUART_BITCLKS (make target 64; real 434) */

double sc_time_stamp() { return 0.0; }

/* Loopback switch: when 1, feed the bridge's UART TX output back into its UART RX input (end-to-end test) */
static bool g_loopback = false;

/* Register addresses (match rtl/lms_cw305_regs.vh) */
enum {
    REG_CLKSETTINGS = 0x00, REG_USER_LED = 0x01, REG_CRYPT_TYPE = 0x02,
    REG_CRYPT_REV = 0x03, REG_IDENTIFY = 0x04, REG_TX_BYTE = 0x05,
    REG_TX_IDX = 0x06, REG_RX_BYTE = 0x07, REG_RX_IDX = 0x08,
    REG_RX_POS = 0x09, REG_STATUS = 0x0a, REG_BUILDTIME = 0x0b,
};

static int g_fails = 0;
static vluint64_t g_simtime = 0;

#ifdef CW305_TRACE
static VerilatedVcdC *g_tfp = nullptr;
#endif

static void check(bool cond, const char *what)
{
    if (!cond) {
        g_fails++;
        printf("FAIL: %s\n", what);
    }
}

/* Single tick: advance both clocks in phase (required for the CDC synchronizers to work) */
static void tick(Vlms_cw305_usb_uart &dut)
{
    dut.usb_clk = 0;
    dut.iut_clk = 0;
    if (g_loopback) {
        /* Loopback: feed UART TX output back to UART RX input (settled before the edge) */
        dut.soc_uart_txd = dut.soc_uart_rxd;
    }
    dut.eval();
    dut.usb_clk = 1;
    dut.eval();
    dut.iut_clk = 1;
    dut.eval();
#ifdef CW305_TRACE
    if (g_tfp) {
        g_tfp->dump(g_simtime);
        g_simtime += 2;
    }
#endif
}

static void reset(Vlms_cw305_usb_uart &dut)
{
    dut.rst = 1;
    dut.usb_addr = 0;
    dut.usb_rdn = 1;
    dut.usb_wrn = 1;
    dut.usb_cen = 1;
    dut.usb_alen = 0;
    dut.usb_din = 0;
    dut.soc_uart_txd = 1; /* UART idle high */
    dut.trap_in = 0;
    for (int i = 0; i < 8; i++) {
        tick(dut);
    }
    dut.rst = 0;
    for (int i = 0; i < 8; i++) {
        tick(dut);
    }
}

/* Host register read (emulates a single-byte cmdReadMem): address = reg<<7, RD# pulse.
 * Sample point = 1 tick after reg_read asserts (official convention: "read_data is valid
 * one tick after reg_read goes high"):
 *   tick1: reg_fe registers the input -> reg_read=1; tick2: the bridge latches/updates
 *   read_data on the pop edge -> sample. Sampling 5 ticks earlier masked the issue of
 *   read_data lagging one tick on the TX_BYTE pop edge (root cause of the 0x2f leading
 *   byte on the board, reproduced and confirmed 2026-08-18). */
static uint8_t host_read(Vlms_cw305_usb_uart &dut, int reg)
{
    uint8_t v = 0;
    dut.usb_addr = (reg << 7);
    dut.usb_cen = 0;
    dut.usb_rdn = 0;
    for (int i = 0; i < 2; i++) {
        tick(dut);
    }
    v = static_cast<uint8_t>(dut.usb_dout);
    dut.usb_rdn = 1;
    tick(dut);
    dut.usb_cen = 1;
    tick(dut);
    return v;
}

/* Host register write: address = reg<<7, data on usb_din, WR# pulse */
static void host_write(Vlms_cw305_usb_uart &dut, int reg, uint8_t data)
{
    dut.usb_addr = (reg << 7);
    dut.usb_din = data;
    dut.usb_cen = 0;
    dut.usb_wrn = 0;
    for (int i = 0; i < 5; i++) {
        tick(dut);
    }
    dut.usb_wrn = 1;
    tick(dut);
    dut.usb_cen = 1;
    dut.usb_din = 0;
    tick(dut);
}

/* Emulate the SoC UART sending one byte (8-N-1, LSB first) on soc_uart_txd */
static void uart_send_byte(Vlms_cw305_usb_uart &dut, uint8_t byte)
{
    dut.soc_uart_txd = 0; /* start */
    for (int i = 0; i < BITCLKS; i++) tick(dut);
    for (int b = 0; b < 8; b++) {
        dut.soc_uart_txd = (byte >> b) & 1;
        for (int i = 0; i < BITCLKS; i++) tick(dut);
    }
    dut.soc_uart_txd = 1; /* stop */
    for (int i = 0; i < BITCLKS; i++) tick(dut);
}

/* Wait for depth bytes to appear in the host-side TX FIFO (with timeout) */
static bool wait_tx_count(Vlms_cw305_usb_uart &dut, int depth)
{
    for (int t = 0; t < 20000; t++) {
        if (host_read(dut, REG_TX_IDX) == depth) return true;
    }
    return false;
}

/* Decode one byte from soc_uart_rxd (wait for the start bit falling edge, center-sample each bit) */
static bool uart_recv_byte(Vlms_cw305_usb_uart &dut, uint8_t &out)
{
    /* Wait for start bit (low) */
    int t = 0;
    while (dut.soc_uart_rxd != 0) {
        tick(dut);
        if (++t > 20000) return false;
    }
    /* Sample: start center (0.5 bit) + 8 data bit centers (1.5, 2.5, ... bit) */
    for (int i = 0; i < BITCLKS / 2; i++) tick(dut); /* to start center */
    uint8_t v = 0;
    for (int b = 0; b < 8; b++) {
        for (int i = 0; i < BITCLKS; i++) tick(dut); /* to next bit center */
        v |= static_cast<uint8_t>(dut.soc_uart_rxd) << b;
    }
    for (int i = 0; i < BITCLKS; i++) tick(dut); /* stop bit center */
    out = v;
    return true;
}

int main()
{
    Verilated::debug(0);
    Vlms_cw305_usb_uart dut;
#ifdef CW305_TRACE
    Verilated::traceEverOn(true);
    static VerilatedVcdC tfp;
    g_tfp = &tfp;
    dut.trace(&tfp, 99);
    tfp.open("build/rtl_cw305_bridge/cw305_bridge.vcd");
#endif
    reset(dut);

    /* ---- 1. read-only registers ---- */
    check(host_read(dut, REG_IDENTIFY) == 0x4C, "IDENTIFY == 'L'");
    check(host_read(dut, REG_CRYPT_TYPE) == 0x4D, "CRYPT_TYPE == 'M'");
    check(host_read(dut, REG_CRYPT_REV) == 0x01, "CRYPT_REV == 1");
    check(host_read(dut, REG_STATUS) == 0x00, "STATUS trap=0");
    check(host_read(dut, REG_TX_IDX) == 0x00, "TX_IDX initial 0");
    check(host_read(dut, REG_RX_POS) == 0x00, "RX_POS initial 0");
    check(host_read(dut, REG_BUILDTIME) == 0x00, "BUILDTIME non-Vivado = 0");

    /* ---- 2. USER_LED write/read ---- */
    host_write(dut, REG_USER_LED, 1);
    check(host_read(dut, REG_USER_LED) == 1, "USER_LED write 1 read back 1");
    host_write(dut, REG_USER_LED, 0);
    check(host_read(dut, REG_USER_LED) == 0, "USER_LED write 0 read back 0");

    /* ---- 3. TX path: SoC sends 3 bytes -> host reads back ---- */
    const uint8_t txpat[3] = {0x48, 0xAB, 0x7F};
    for (uint8_t b : txpat) {
        uart_send_byte(dut, b);
    }
    check(wait_tx_count(dut, 3), "TX FIFO depth 3");
    for (uint8_t exp : txpat) {
        check(host_read(dut, REG_TX_BYTE) == exp, "TX_BYTE popped byte matches");
    }
    check(host_read(dut, REG_TX_IDX) == 0, "TX FIFO depth 0 after pop empty");

    /* ---- 4. RX path: host writes 2 bytes -> UART decode ---- */
    host_write(dut, REG_RX_BYTE, 0xC3);
    host_write(dut, REG_RX_BYTE, 0x3C);
    uint8_t r0 = 0, r1 = 0;
    check(uart_recv_byte(dut, r0) && r0 == 0xC3, "UART decoded byte0 == 0xC3");
    check(uart_recv_byte(dut, r1) && r1 == 0x3C, "UART decoded byte1 == 0x3C");
    /* RX FIFO should now be drained */
    check(host_read(dut, REG_RX_POS) == 0, "RX_POS drained");

    /* ---- 5. end-to-end loopback: host writes "ping!" -> (UART TX -> loopback -> UART RX) -> host reads back ---- */
    g_loopback = true;
    const char msg[] = "ping!";
    const size_t msg_len = sizeof(msg) - 1;   /* excluding '\0' */
    for (size_t i = 0; i < msg_len; i++) {
        host_write(dut, REG_RX_BYTE, static_cast<uint8_t>(msg[i]));
    }
    check(wait_tx_count(dut, static_cast<int>(msg_len)), "loopback TX FIFO depth 5");
    for (size_t i = 0; i < msg_len; i++) {
        uint8_t got = host_read(dut, REG_TX_BYTE);
        check(got == static_cast<uint8_t>(msg[i]),
              "loopback byte matches");
        if (got != static_cast<uint8_t>(msg[i])) {
            printf("        (loopback expected 0x%02X got 0x%02X)\n",
                   static_cast<uint8_t>(msg[i]), got);
        }
    }
    g_loopback = false;

    /* ---- 6. trap status ---- */
    dut.trap_in = 1;
    for (int i = 0; i < 10; i++) tick(dut);
    check((host_read(dut, REG_STATUS) & 0x01) == 1, "STATUS trap=1");
    dut.trap_in = 0;
    for (int i = 0; i < 10; i++) tick(dut);
    check((host_read(dut, REG_STATUS) & 0x01) == 0, "STATUS trap falls back to 0");

    /* ---- 7. 48-byte back-to-back long frame (emulating a firmware response frame) ---- */
    {
        uint8_t frame[48];
        for (int i = 0; i < 48; i++) {
            frame[i] = (i == 0) ? 0x52 : ((i < 4) ? 0x00 : static_cast<uint8_t>(i));
        }
        for (uint8_t b : frame) {
            uart_send_byte(dut, b);
        }
        check(wait_tx_count(dut, 48), "long frame TX FIFO depth 48");
        for (int i = 0; i < 48; i++) {
            uint8_t got = host_read(dut, REG_TX_BYTE);
            check(got == frame[i], "long frame byte matches");
            if (got != frame[i]) {
                printf("        (long frame[%d] expected 0x%02X got 0x%02X)\n", i, frame[i], got);
            }
        }
    }

#ifdef CW305_TRACE
    g_tfp->close();
    g_tfp = nullptr;
#endif
    dut.final();

    if (g_fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", g_fails);
    return 1;
}
