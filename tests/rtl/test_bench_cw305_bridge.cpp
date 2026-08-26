// test_bench_cw305_bridge.cpp - full-chain simulation: bench firmware + USB<->UART bridge
//
// Purpose: reproduce the on-board "command processed twice" issue (a single
// REG_RX_BYTE write -> double response 76B).
// Path: host (USB register protocol) -> bridge -> UART -> SoC bench firmware ->
// response -> bridge -> host.
// Uses real BITCLKS=434 (Makefile target passes -GUART_BITCLKS=434).

#include "Vsim_cw305_soc_bridge.h"
#include "Vsim_cw305_soc_bridge___024root.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>
#include <vector>

double sc_time_stamp() { return 0.0; }

enum {
    REG_CLKSETTINGS = 0x00, REG_USER_LED = 0x01, REG_CRYPT_TYPE = 0x02,
    REG_CRYPT_REV = 0x03, REG_IDENTIFY = 0x04, REG_TX_BYTE = 0x05,
    REG_TX_IDX = 0x06, REG_RX_BYTE = 0x07, REG_RX_IDX = 0x08,
    REG_RX_POS = 0x09, REG_STATUS = 0x0a, REG_BUILDTIME = 0x0b,
};

static void tick(Vsim_cw305_soc_bridge &dut)
{
    dut.usb_clk = 0;
    dut.clk50 = 0;
    dut.eval();
    dut.usb_clk = 1;
    dut.eval();
    dut.clk50 = 1;
    dut.eval();
}

static void ticks(Vsim_cw305_soc_bridge &dut, int n)
{
    for (int i = 0; i < n; i++) tick(dut);
}

static void reset(Vsim_cw305_soc_bridge &dut)
{
    dut.rst = 1;
    dut.usb_addr = 0;
    dut.usb_rdn = 1;
    dut.usb_wrn = 1;
    dut.usb_cen = 1;
    dut.usb_alen = 0;
    dut.usb_din = 0;
    ticks(dut, 50);
    dut.rst = 0;
    /* wait for firmware boot (bench firmware gpio 0xa5 = command loop ready) */
    for (int i = 0; i < 5000000; i++) {
        tick(dut);
        if (dut.rootp->sim_cw305_soc_bridge__DOT__soc__DOT__gpio_out == 0xa5u) {
            break;
        }
    }
    std::printf("DBG: firmware boot done (gpio=0x%02x)\n",
                (int)dut.rootp->sim_cw305_soc_bridge__DOT__soc__DOT__gpio_out);
}

static uint8_t host_read(Vsim_cw305_soc_bridge &dut, int reg)
{
    uint8_t v = 0;
    dut.usb_addr = (reg << 7);
    dut.usb_cen = 0;
    dut.usb_rdn = 0;
    for (int i = 0; i < 2; i++) tick(dut);
    v = static_cast<uint8_t>(dut.usb_dout);
    dut.usb_rdn = 1;
    tick(dut);
    dut.usb_cen = 1;
    tick(dut);
    return v;
}

static void host_write(Vsim_cw305_soc_bridge &dut, int reg, uint8_t data)
{
    dut.usb_addr = (reg << 7);
    dut.usb_din = data;
    dut.usb_cen = 0;
    dut.usb_wrn = 0;
    for (int i = 0; i < 5; i++) tick(dut);
    dut.usb_wrn = 1;
    tick(dut);
    dut.usb_cen = 1;
    dut.usb_din = 0;
    tick(dut);
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vsim_cw305_soc_bridge dut;

    reset(dut);

    /* single write of 0x53 ('S') */
    std::printf("DBG: pushing 0x53 via REG_RX_BYTE\n");
    host_write(dut, REG_RX_BYTE, 0x53);

    /* focused trace of STX uart_tx internal signals (where the second frame comes from) */
    auto *r = dut.rootp;
    int prev_fin = -1;
    for (int t = 0; t < 15000; t++) {
        tick(dut);
        int fin = r->sim_cw305_soc_bridge__DOT__bridge__DOT__stx_unit__DOT__fin;
        int send = r->sim_cw305_soc_bridge__DOT__bridge__DOT__stx_unit__DOT__send;
        int pend = r->sim_cw305_soc_bridge__DOT__bridge__DOT__stx_unit__DOT__pending;
        int idx = r->sim_cw305_soc_bridge__DOT__bridge__DOT__stx_unit__DOT__idx;
        unsigned tdata = r->sim_cw305_soc_bridge__DOT__bridge__DOT__stx_unit__DOT__tdata;
        if (fin != prev_fin || (send && t > 4000 && t < 9000)) {
            std::printf("DBG: t=%d stx: fin=%d send=%d pend=%d idx=%d tdata=0x%03x\n",
                        t, fin, send, pend, (int)idx, tdata);
            prev_fin = fin;
        }
    }

    /* wait for TX FIFO to have bytes (response starts) - 'S' processing takes ~700K ticks */
    bool got = false;
    for (int t = 0; t < 8000000; t++) {
        if (host_read(dut, REG_TX_IDX) != 0) {
            got = true;
            break;
        }
        tick(dut);
    }
    if (!got) {
        std::printf("FAIL: no TX response\n");
        return 1;
    }

    /* pop all TX bytes (response arrives byte by byte; FIFO is empty between bytes - keep waiting for a window) */
    std::vector<uint8_t> resp;
    int idle = 0;
    for (int t = 0; t < 2000000 && idle < 20000; t++) {
        int cnt = host_read(dut, REG_TX_IDX);
        if (cnt > 0) {
            resp.push_back(host_read(dut, REG_TX_BYTE));
            idle = 0;
        } else {
            idle++;
        }
    }
    std::printf("RESPONSE %zu bytes: ", resp.size());
    for (size_t i = 0; i < resp.size(); i++) {
        std::printf("%02x", resp[i]);
    }
    std::printf("\n");
    if (resp.size() == 38) {
        std::printf("RESULT: single response (38B) — no double\n");
    } else if (resp.size() == 76) {
        std::printf("RESULT: DOUBLE response (76B) — REPRODUCED on-board artifact\n");
    } else {
        std::printf("RESULT: unexpected size %zu\n", resp.size());
        return 1;
    }
    std::printf("CW305 BRIDGE BENCH SMOKE PASSED\n");
    return 0;
}
