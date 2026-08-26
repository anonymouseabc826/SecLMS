// test_cw305_soc_bridge.cpp - full-chain simulation: real SoC firmware + USB<->UART bridge
//
// Path: host (USB register protocol) -> bridge -> UART -> SoC firmware -> response -> bridge -> host
// Coverage: HASH_ONCE request/response frame integrity (decisive experiment reproducing the on-board 0x2f leading-byte problem).
//
// Uses the real BITCLKS=434 (Makefile target passes -GUART_BITCLKS=434); simulation is slower but faithful.

#include "Vsim_cw305_soc_bridge.h"
#include "Vsim_cw305_soc_bridge___024root.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

double sc_time_stamp() { return 0.0; }

/* Register addresses (rtl/lms_cw305_regs.vh) */
enum {
    REG_CLKSETTINGS = 0x00, REG_USER_LED = 0x01, REG_CRYPT_TYPE = 0x02,
    REG_CRYPT_REV = 0x03, REG_IDENTIFY = 0x04, REG_TX_BYTE = 0x05,
    REG_TX_IDX = 0x06, REG_RX_BYTE = 0x07, REG_RX_IDX = 0x08,
    REG_RX_POS = 0x09, REG_STATUS = 0x0a, REG_BUILDTIME = 0x0b,
};

static int g_fails = 0;

static void check(bool cond, const char *what)
{
    if (!cond) {
        g_fails++;
        printf("FAIL: %s\n", what);
    }
}

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
    /* Firmware startup self-test: record STATUS/CYCLE read sequence and GPIO write timing */
    uint32_t stat_reads[16] = {0};
    int stat_rcnt = 0;
    uint32_t cyc_reads[8] = {0};
    int cyc_rcnt = 0;
    int fail_tick = -1;
    uint32_t first_gpio_val = 0xFFFFFFFF;
    for (int i = 0; i < 500000; i++) {
        tick(dut);
        auto *r = dut.rootp;
        if (r->sim_cw305_soc_bridge__DOT__soc__DOT__lms_bridge__DOT__accelerator__DOT__g_shake256_only__DOT__u_shake256__DOT__bus_valid &&
            !r->sim_cw305_soc_bridge__DOT__soc__DOT__lms_bridge__DOT__accelerator__DOT__g_shake256_only__DOT__u_shake256__DOT__bus_write) {
            uint32_t off = r->sim_cw305_soc_bridge__DOT__soc__DOT__lms_bridge__DOT__accelerator__DOT__g_shake256_only__DOT__u_shake256__DOT__bus_addr & 0x3FF;
            uint32_t rd = r->sim_cw305_soc_bridge__DOT__soc__DOT__lms_bridge__DOT__accelerator__DOT__g_shake256_only__DOT__u_shake256__DOT__bus_rdata;
            if (off == 0x010 && stat_rcnt < 16) stat_reads[stat_rcnt++] = rd;
            if (off == 0x020 && cyc_rcnt < 8) cyc_reads[cyc_rcnt++] = rd;
        }
        if (fail_tick < 0 &&
            r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_valid &&
            r->sim_cw305_soc_bridge__DOT__soc__DOT__ibex_data_we &&
            r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_addr == 0x10000018u) {
            fail_tick = i;
            first_gpio_val = r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_wdata;
        }
    }
    printf("    [reset] STATUS reads[%d]=[%u %u %u %u %u %u] CYCLE reads[%d]=[%u %u %u] first GPIO write@tick=%d val=0x%x\n",
           stat_rcnt, stat_reads[0], stat_reads[1], stat_reads[2], stat_reads[3], stat_reads[4], stat_reads[5],
           cyc_rcnt, cyc_reads[0], cyc_reads[1], cyc_reads[2], fail_tick, first_gpio_val);
    /* Verify the firmware is the SHAKE256 variant: main's expected_cycles compare point
     * must be c.li a5,12 (0x47b1); the SHA256 variant has addi a5,x0,68 (0x04400793)
     * or c.li a5,68 (0x5791) there.
     * Compressed instructions occupy half a word, so compare with a 16-bit mask; the
     * firmware layout drifts with compilation, so scan for the marker within 0x3000-0x4000
     * (2026-08-18: 0.1.275 firmware marker measured at 0x3b2c). */
    {
        auto &mem = dut.rootp->sim_cw305_soc_bridge__DOT__soc__DOT__ram__DOT__mem;
        bool is12 = false, is68 = false;
        int at12 = -1;
        for (int off = 0x3000; off < 0x4000; off += 2) {
            uint32_t w = mem[off >> 2];
            uint16_t lo = w & 0xffffu;
            uint16_t hi = w >> 16;
            if ((off & 2) == 0) { /* the low half-word of this word is the instruction at this offset */
                if (lo == 0x47b1u) { is12 = true; at12 = off; break; }
                if (lo == 0x5791u || lo == 0x0440u) is68 = true; /* addi's high 16 bits appearing as 0x0440 in the low half-word is unrealistic; see below */
            } else {
                if (hi == 0x47b1u) { is12 = true; at12 = off; break; }
                if (hi == 0x5791u) is68 = true;
            }
            /* full 32-bit addi a5,x0,68 */
            if (w == 0x04400793u) is68 = true;
        }
        printf("    [ram] SHAKE256 marker (c.li a5,12) @0x%x -> %s\n", at12,
               is12 ? "FOUND" : (is68 ? "SHA256 marker" : "not found"));
        check(is12, "firmware is indeed the SHAKE256 variant (expected_cycles=12)");
    }
}

/* Host register read (1 byte). Sample point = 1 tick after reg_read asserts (official
 * convention); see the host_read note in test_cw305_bridge.cpp (on-board 0x2f leading
 * byte root-cause reproduction). */
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

/* Host bulk read of n bytes (DEPRECATED 2026-08-19: simulating "reg_read held high for
 * N ticks, popping 1 per tick" does not match the real cmdReadMem per-byte RD pulses;
 * the level-pop scheme failed on hardware and was rolled back to rising-edge single
 * pops. Kept for reference only; tests now always read byte-by-byte with host_read). */
static void host_read_bulk(Vsim_cw305_soc_bridge &dut, int reg, int n,
                           std::vector<uint8_t> &out)
{
    out.clear();
    dut.usb_addr = (reg << 7);
    dut.usb_cen = 0;
    dut.usb_rdn = 0;
    tick(dut); /* posedge: reg_read<=1 */
    tick(dut); /* posedge: pop B0, read_data<=B0 */
    for (int i = 0; i < n; i++) {
        out.push_back(static_cast<uint8_t>(dut.usb_dout)); /* sample read_data=byte i */
        tick(dut);                                         /* posedge: pop byte i+1 */
    }
    dut.usb_rdn = 1;
    dut.usb_cen = 1;
    tick(dut);
}

/* Host register write (1 byte) */
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

/* Wait until the TX FIFO depth reaches n (with timeout) */
static bool wait_tx_count(Vsim_cw305_soc_bridge &dut, int n, int timeout_ticks)
{
    for (int t = 0; t < timeout_ticks; t++) {
        if (host_read(dut, REG_TX_IDX) == n) return true;
        tick(dut);
    }
    return false;
}

/* Drive the SoC mem0 bus directly (simulates a CPU store, bypassing the firmware) */
static void soc_mmio_write(Vsim_cw305_soc_bridge &dut, uint32_t addr, uint32_t data)
{
    auto *r = dut.rootp;
    r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_valid = 1;
    r->sim_cw305_soc_bridge__DOT__soc__DOT__ibex_data_we = 1;
    r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_addr = addr;
    r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_wdata = data;
    r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_wstrb = 0xF;
    tick(dut);
    r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_valid = 0;
    r->sim_cw305_soc_bridge__DOT__soc__DOT__ibex_data_we = 0;
    r->sim_cw305_soc_bridge__DOT__soc__DOT__mem0_wstrb = 0;
    tick(dut);
}

int main()
{
    Verilated::debug(0);
    Vsim_cw305_soc_bridge dut;

    printf("[1] reset + firmware startup ...\n");
    reset(dut);

    printf("[2] gpio_out=0x%02x (0xa5=firmware entered serve_uart) trap=%d\n",
           (int)dut.gpio_out_o, (int)dut.soc_trap);
    check(host_read(dut, REG_IDENTIFY) == 0x4C, "IDENTIFY == 'L'");

    printf("[3] send HASH_ONCE(empty) ...\n");
    host_write(dut, REG_RX_BYTE, 0x48); /* UART request: 0x48 0x00 */
    host_write(dut, REG_RX_BYTE, 0x00);
    /* SCA trigger observation: firmware handles the request -> engine busy falling edge
     * (completion edge) -> sca_trigger wide pulse (512 ticks; v5 2026-08-18 switched
     * from rising to falling edge so Husky presamples cover the whole operation).
     * Must sample every tick; host_read's internal ticks would miss it. */
    int sca_ticks[8] = {0};
    int sca_cnt = 0;
    bool sca_prev = false;
    for (int t = 0; t < 200000; t++) {
        bool now = dut.sca_trigger_o != 0;
        if (now && !sca_prev && sca_cnt < 8) sca_ticks[sca_cnt++] = t;
        sca_prev = now;
        tick(dut);
    }
    if (sca_cnt > 0) {
        printf("    SCA trigger edges %d, first @tick=%d\n", sca_cnt, sca_ticks[0]);
    } else {
        printf("    SCA trigger edges 0\n");
    }
    check(sca_cnt >= 1, "SCA trigger (engine busy completion edge) at least once");

    printf("[4] read response frame ...\n");
    if (!wait_tx_count(dut, 48, 600000)) {
        printf("    TX FIFO did not reach 48 (actual %d)\n", host_read(dut, REG_TX_IDX));
        g_fails++;
    } else {
        std::vector<uint8_t> frame;
        /* 2026-08-19 rollback: read byte-by-byte (one RD# pulse per byte), matching the
         * rising-edge single-pop RTL. The level-pop bulk read failed on hardware and was
         * dropped (see the host_read_bulk comment). */
        for (int i = 0; i < 48; i++) {
            frame.push_back(host_read(dut, REG_TX_BYTE));
        }
        printf("    frame: ");
        for (int i = 0; i < 48; i++) printf("%02x ", frame[i]);
        printf("\n");
        /* Expected: 0x52 0x00 0x00 0x00 + cycles(4) + hits(4) + fallback(4) + digest(32) */
        check(frame[0] == 0x52, "frame[0] == 0x52 (marker)");
        check(frame[1] == 0x00 && frame[2] == 0x00 && frame[3] == 0x00,
              "frame[1..3] == 0");
        uint32_t cycles = frame[4] | (frame[5] << 8) | (frame[6] << 16) | (frame[7] << 24);
        printf("    cycles=%u\n", cycles);
        check(cycles == 12, "cycles == 12 (SHAKE256 empty message)");
        uint8_t exp_digest[32] = {
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
            0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
            0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
            0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f
        };
        bool digest_ok = true;
        for (int i = 0; i < 32; i++) {
            if (frame[16 + i] != exp_digest[i]) digest_ok = false;
        }
        check(digest_ok, "digest == SHAKE256(\"\")");
    }

    printf("[5] send 0x63 SEED_LOAD + 0x6D DERIVE_RANDOMIZER (single PRF isolation) ...\n");
    /* 0x63: SEED = 00..1f (INSECURE_TEST_MODE plaintext load) */
    host_write(dut, REG_RX_BYTE, 0x63);
    for (int i = 0; i < 32; i++) host_write(dut, REG_RX_BYTE, (uint8_t)i);
    if (!wait_tx_count(dut, 48, 600000)) {
        printf("    0x63 no response (TX=%d)\n", host_read(dut, REG_TX_IDX));
        g_fails++;
    } else {
        for (int i = 0; i < 48; i++) host_read(dut, REG_TX_BYTE);
    }
    /* 0x6D: I = 00..0f, q = 2 -> C = SHAKE256(I||q||0x8585||SEED)
     * (host oracle: 9e68e9f072f125846683e626f32694194f42c2ef2c1de086b40310c3e9df5442) */
    host_write(dut, REG_RX_BYTE, 0x6d);
    for (int i = 0; i < 16; i++) host_write(dut, REG_RX_BYTE, (uint8_t)i);
    host_write(dut, REG_RX_BYTE, 0x02); host_write(dut, REG_RX_BYTE, 0x00);
    host_write(dut, REG_RX_BYTE, 0x00); host_write(dut, REG_RX_BYTE, 0x00);
    if (!wait_tx_count(dut, 48, 600000)) {
        printf("    0x6D no response (TX=%d)\n", host_read(dut, REG_TX_IDX));
        g_fails++;
    } else {
        /* 2026-08-19 rollback: read byte-by-byte (matching the rising-edge single-pop RTL). */
        std::vector<uint8_t> frame;
        for (int i = 0; i < 48; i++) frame.push_back(host_read(dut, REG_TX_BYTE));
        check(frame.size() == 48, "0x6D read 48 bytes");
        check(frame[0] == 0x52 && frame[1] == 0x00, "0x6D frame[0..1] == 0x52 0x00");
        uint32_t cyc = frame[4] | (frame[5] << 8) | (frame[6] << 16) | (frame[7] << 24);
        printf("    0x6D cycles=%u hits=%u\n", cyc,
               frame[8] | (frame[9] << 8) | (frame[10] << 16) | (frame[11] << 24));
        check(cyc > 0 && cyc < 1000, "0x6D cycles reasonable (single PRF call)");
        uint8_t exp_c[32] = {
            0x9e, 0x68, 0xe9, 0xf0, 0x72, 0xf1, 0x25, 0x84,
            0x66, 0x83, 0xe6, 0x26, 0xf3, 0x26, 0x94, 0x19,
            0x4f, 0x42, 0xc2, 0xef, 0x2c, 0x1d, 0xe0, 0x86,
            0xb4, 0x03, 0x10, 0xc3, 0xe9, 0xdf, 0x54, 0x42
        };
        bool c_ok = true;
        for (int i = 0; i < 32; i++) {
            if (frame[16 + i] != exp_c[i]) c_ok = false;
        }
        check(c_ok, "0x6D C == SHAKE256(I||q||0x8585||SEED) oracle");
    }

    printf("[6] send 0x53 full LMS Sign (W4H5 shake256, RTS flow control verifies y passthrough without stalling) ...\n");
    {
        /* Fixed KAT private key (lms_verify_vector_shake_W4_H5.txt): lms_type=0x15
         * lmots_type=0x13 I SEED q=0. Full signature ~= 2236B (q4+type4+C16+y2048+
         * lms_type4+path160); response = 48-byte frame header + 2236 = 2284B. */
        const uint8_t priv[60] = {
            0x00,0x00,0x00,0x15, 0x00,0x00,0x00,0x13,
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
            0x00,0x00,0x00,0x00
        };
        host_write(dut, REG_RX_BYTE, 0x53);
        for (int i = 0; i < 60; i++) host_write(dut, REG_RX_BYTE, priv[i]);
        host_write(dut, REG_RX_BYTE, 0x00); host_write(dut, REG_RX_BYTE, 0x00); /* u16 msg len 0 */
        /* Tree build + sign + y passthrough output. Poll the depth and pop byte by byte
         * until the FIFO drains and the response is stable.
         * If RTS flow control fails (reproduced on real hardware stalling at 260B),
         * resp stops at ~260B. */
        std::vector<uint8_t> resp;
        bool saw_marker = false;
        int stall = 0;
        for (int t = 0; t < 6000000 && stall < 400000; t++) {
            int cnt = host_read(dut, REG_TX_IDX);
            if (cnt > 0) {
                for (int i = 0; i < cnt; i++) {
                    uint8_t b = host_read(dut, REG_TX_BYTE);
                    if (resp.empty() && b == 0x52) saw_marker = true;
                    resp.push_back(b);
                }
                stall = 0;
            } else {
                if (resp.size() >= 48) stall++;
                tick(dut);
            }
        }
        printf("    0x53 response %zu B marker=%d head=%02x%02x%02x%02x sig@48=%02x%02x%02x%02x\n",
               resp.size(), (int)saw_marker, resp[0], resp[1], resp[2], resp[3],
               resp.size() > 52 ? resp[48] : 0, resp.size() > 52 ? resp[49] : 0,
               resp.size() > 52 ? resp[50] : 0, resp.size() > 52 ? resp[51] : 0);
        check(saw_marker && resp.size() >= 2200, "0x53 full signature output (RTS flow control, no 260B stall)");
        /* Frame header first 16B: 52 00 00 00 + status/err/cycles */
        check(resp[0] == 0x52 && resp[1] == 0x00 && resp[2] == 0x00 && resp[3] == 0x00,
              "0x53 frame header marker + status OK");
    }

    dut.final();

    if (g_fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", g_fails);
    return 1;
}
