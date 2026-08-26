#include "Vlms_sha256_mmio_bridge.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>

static constexpr uint32_t LMS_BASE = 0x16000000;
static constexpr uint32_t REG_VERSION = 0x000;
static constexpr uint32_t REG_CAPABILITY = 0x004;
static constexpr uint32_t REG_COMMAND = 0x008;
static constexpr uint32_t REG_CONTROL = 0x00c;
static constexpr uint32_t REG_STATUS = 0x010;
static constexpr uint32_t REG_INPUT_LENGTH = 0x018;
static constexpr uint32_t REG_OUTPUT_LENGTH = 0x01c;
static constexpr uint32_t REG_CYCLE_COUNT = 0x020;
static constexpr uint32_t REG_INPUT = 0x100;
static constexpr uint32_t REG_OUTPUT = 0x200;

static constexpr uint32_t CMD_HASH_ONCE = 1;
static constexpr uint32_t CTRL_START = 1;
static constexpr uint32_t STATUS_BUSY = 1;
static constexpr uint32_t STATUS_DONE = 2;

double sc_time_stamp()
{
    return 0.0;
}

static void tick(Vlms_sha256_mmio_bridge &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_sha256_mmio_bridge &dut)
{
    dut.mem_valid = 0;
    dut.mem_addr = 0;
    dut.mem_wdata = 0;
    dut.mem_wstrb = 0;
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
}

static void write_word(Vlms_sha256_mmio_bridge &dut,
                       uint32_t address,
                       uint32_t value,
                       uint8_t strobes = 0x0f)
{
    dut.mem_valid = 1;
    dut.mem_addr = address;
    dut.mem_wdata = value;
    dut.mem_wstrb = strobes;
    tick(dut);
    dut.mem_valid = 0;
    dut.mem_wstrb = 0;
    dut.eval();
}

static uint32_t read_word(Vlms_sha256_mmio_bridge &dut, uint32_t address)
{
    dut.mem_valid = 1;
    dut.mem_addr = address;
    dut.mem_wstrb = 0;
    tick(dut);
    const uint32_t value = dut.mem_rdata;
    dut.mem_valid = 0;
    dut.eval();
    return value;
}

static int test_decode(Vlms_sha256_mmio_bridge &dut)
{
    dut.mem_valid = 1;
    dut.mem_addr = LMS_BASE + REG_VERSION;
    dut.mem_wstrb = 0;
    dut.eval();
    if (!dut.mem_hit || !dut.mem_ready || dut.mem_rdata != 7) {
        std::puts("FAIL: LMS base decode (VERSION mismatch)");
        return 1;
    }

    /* The decode window has been extended to 2KB ([31:11]): 0x400 is inside the
     * window, and with HASH_SEL=0 the sha256 wrapper responds (low 10 bits wrap
     * to 0x000 = REG_VERSION=7). */
    dut.mem_addr = LMS_BASE + 0x400;
    dut.eval();
    if (!dut.mem_hit || !dut.mem_ready || dut.mem_rdata != 7) {
        std::puts("FAIL: LMS window in-window 0x400");
        return 1;
    }

    /* Outside the window: 0x800 (beyond the 2KB upper bound) does not hit */
    dut.mem_addr = LMS_BASE + 0x800;
    dut.eval();
    if (dut.mem_hit || dut.mem_ready || dut.mem_rdata != 0) {
        std::puts("FAIL: LMS window bounds");
        return 1;
    }

    dut.mem_valid = 0;
    dut.eval();
    return 0;
}

static int test_partial_write(Vlms_sha256_mmio_bridge &dut)
{
    write_word(dut, LMS_BASE + REG_COMMAND, CMD_HASH_ONCE, 0x01);
    if (read_word(dut, LMS_BASE + REG_COMMAND) != 0) {
        std::puts("FAIL: partial MMIO write was accepted");
        return 1;
    }
    return 0;
}

static int test_abc(Vlms_sha256_mmio_bridge &dut)
{
    write_word(dut, LMS_BASE + REG_COMMAND, CMD_HASH_ONCE);
    write_word(dut, LMS_BASE + REG_INPUT_LENGTH, 3);
    write_word(dut, LMS_BASE + REG_OUTPUT_LENGTH, 32);
    write_word(dut, LMS_BASE + REG_INPUT, 0x00636261);
    write_word(dut, LMS_BASE + REG_CONTROL, CTRL_START);

    uint32_t status = 0;
    for (int poll = 0; poll < 80; ++poll) {
        status = read_word(dut, LMS_BASE + REG_STATUS);
        if ((status & STATUS_BUSY) == 0) {
            break;
        }
    }
    if (status != STATUS_DONE ||
        read_word(dut, LMS_BASE + REG_CYCLE_COUNT) != 68 ||
        read_word(dut, LMS_BASE + REG_OUTPUT) != 0xbf1678ba) {
        std::printf("FAIL: bridge HASH_ONCE status=%u cycles=%u output=%08x\n",
                    status,
                    read_word(dut, LMS_BASE + REG_CYCLE_COUNT),
                    read_word(dut, LMS_BASE + REG_OUTPUT));
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_sha256_mmio_bridge dut;
    reset(dut);

    int failures = 0;
    failures += test_decode(dut);
    /* CAPABILITY = 0xef | 0x300(SIM_MC|WRAP) | 0x400(HMAC_KSTATE) | 0x800(KEYGEN_LEAF)
     * | 0x2000(D_INTR_CHAIN,S6) | 0x4000(MSG_Q_COEF,S8) | 0x8000(STATE_COMMIT,S9).
     * The bridge target does not pass -GINSECURE_TEST_MODE (default 0, bit 0x10 not
     * set), HAS_SECURITY defaults to 1, hence 0xefef (see rtl/lms_sha256_mmio.v). */
    if (read_word(dut, LMS_BASE + REG_CAPABILITY) != 0xefef) {
        std::puts("FAIL: capability bits through bridge");
        ++failures;
    }
    failures += test_partial_write(dut);
    failures += test_abc(dut);

    dut.final();
    if (failures != 0) {
        std::printf("LMS mmio bridge tests failed: %d\n", failures);
        return 1;
    }
    std::puts("LMS mmio bridge tests passed");
    return 0;
}