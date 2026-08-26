#include "Vlms_trng_mmio.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>

/* C1 standalone TRNG MMIO peripheral test (protocol v1).
 * SIM_MODE=1 uses LFSR pseudo-noise cells; only interface/gating semantics
 * are checked here, not physical entropy. */

static constexpr uint16_t REG_VERSION = 0x00;
static constexpr uint16_t REG_CAP     = 0x04;
static constexpr uint16_t REG_CTRL    = 0x08;
static constexpr uint16_t REG_STAT    = 0x0c;
static constexpr uint16_t REG_RND     = 0x10;
static constexpr uint16_t REG_APT     = 0x14;

double sc_time_stamp() { return 0.0; }

static void tick(Vlms_trng_mmio &dut)
{
    dut.clk = 0;
    dut.eval();
    dut.clk = 1;
    dut.eval();
}

static void reset(Vlms_trng_mmio &dut)
{
    dut.mem_valid = 0;
    dut.mem_wstrb = 0;
    dut.mem_addr = 0;
    dut.mem_wdata = 0;
    dut.rst = 1;
    tick(dut);
    tick(dut);
    dut.rst = 0;
    tick(dut);
}

static void write_reg(Vlms_trng_mmio &dut, uint32_t offset, uint32_t value)
{
    dut.mem_valid = 1;
    dut.mem_wstrb = 0xf;
    dut.mem_addr = 0x17000000u + offset;
    dut.mem_wdata = value;
    tick(dut);
    dut.mem_valid = 0;
    dut.mem_wstrb = 0;
    dut.eval();
}

static uint32_t read_reg(Vlms_trng_mmio &dut, uint32_t offset)
{
    dut.mem_valid = 1;
    dut.mem_wstrb = 0;
    dut.mem_addr = 0x17000000u + offset;
    dut.eval();
    const uint32_t value = dut.mem_rdata;
    dut.mem_valid = 0;
    dut.eval();
    return value;
}

int main(int argc, char **argv)
{
    Verilated::commandArgs(argc, argv);
    Vlms_trng_mmio dut;
    int failures = 0;
    reset(dut);

    /* VERSION / CAPABILITY */
    if (read_reg(dut, REG_VERSION) != 1) {
        std::printf("FAIL: VERSION=%u\n", read_reg(dut, REG_VERSION));
        ++failures;
    }
    if (read_reg(dut, REG_CAP) != 1) {
        std::printf("FAIL: CAPABILITY=%u\n", read_reg(dut, REG_CAP));
        ++failures;
    }

    /* default CTRL: enable=1, rct=64, apt=650 */
    const uint32_t ctrl = read_reg(dut, REG_CTRL);
    if ((ctrl & 1u) != 1u || ((ctrl >> 8) & 0xffu) != 64u || ((ctrl >> 16) & 0x7ffu) != 650u) {
        std::printf("FAIL: default CTRL=%08x\n", ctrl);
        ++failures;
    }

    /* let TRNG run */
    for (int i = 0; i < 4000; ++i) tick(dut);

    /* STAT: health_fail (bit0) should be 0 on a normal pseudo-random stream */
    if ((read_reg(dut, REG_STAT) & 1u) != 0u) {
        std::printf("FAIL: unexpected health_fail STAT=%08x\n", read_reg(dut, REG_STAT));
        ++failures;
    }

    /* RND: several words, must be non-constant and pairwise different */
    uint32_t words[4];
    bool all_same = true;
    bool all_zero = true;
    for (int w = 0; w < 4; ++w) {
        words[w] = read_reg(dut, REG_RND);
        if (words[w] != 0) all_zero = false;
        if (w > 0 && words[w] != words[0]) all_same = false;
        for (int i = 0; i < 300; ++i) tick(dut);
    }
    if (all_zero) { std::puts("FAIL: RND all-zero"); ++failures; }
    if (all_same) { std::puts("FAIL: RND all-identical"); ++failures; }

    /* fault injection: rct_cutoff=1 trips RCT quickly -> health_fail, RND gated to 0 */
    write_reg(dut, REG_CTRL, (11u << 16) | (1u << 8) | 1u);
    for (int i = 0; i < 200; ++i) tick(dut);
    if ((read_reg(dut, REG_STAT) & 1u) != 1u) {
        std::printf("FAIL: RCT injection did not set health_fail STAT=%08x\n",
                    read_reg(dut, REG_STAT));
        ++failures;
    }
    if (read_reg(dut, REG_RND) != 0) {
        std::puts("FAIL: RND not gated to 0 on health_fail");
        ++failures;
    }

    /* clear_fail pulse + restore thresholds -> fail clears, RND works again */
    write_reg(dut, REG_CTRL, (650u << 16) | (64u << 8) | (1u << 1) | 1u);
    write_reg(dut, REG_CTRL, (650u << 16) | (64u << 8) | 1u);
    for (int i = 0; i < 300; ++i) tick(dut);
    if ((read_reg(dut, REG_STAT) & 1u) != 0u) {
        std::printf("FAIL: clear_fail did not clear STAT=%08x\n", read_reg(dut, REG_STAT));
        ++failures;
    }
    if (read_reg(dut, REG_RND) == 0) {
        std::puts("FAIL: RND still 0 after clear_fail");
        ++failures;
    }

    /* address decode: a non-TRNG address must not hit */
    dut.mem_valid = 1;
    dut.mem_wstrb = 0;
    dut.mem_addr = 0x16000000u;
    dut.eval();
    if (dut.mem_hit) {
        std::puts("FAIL: address decode aliasing to LMS window");
        ++failures;
    }
    dut.mem_valid = 0;
    dut.eval();

    if (failures == 0) {
        std::puts("PASS: trng_mmio (standalone peripheral) functional + health injection");
    } else {
        std::printf("trng_mmio tests failed: %d\n", failures);
    }
    return failures;
}
