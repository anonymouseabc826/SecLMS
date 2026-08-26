// test_cw305_afifo.cpp - lms_cw305_afifo standalone test
//
// Covers: write 3 bytes -> read-side count/empty -> pop byte by byte -> count
// returns to zero; full flag (write 256 bytes); reset clears everything.

#include "Vlms_cw305_afifo.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>

double sc_time_stamp() { return 0.0; }

static int g_fails = 0;

static void check(bool cond, const char *what)
{
    if (!cond) {
        g_fails++;
        printf("FAIL: %s\n", what);
    }
}

static void tick(Vlms_cw305_afifo &dut)
{
    dut.wclk = 0;
    dut.rclk = 0;
    dut.eval();
    dut.wclk = 1;
    dut.eval();
    dut.rclk = 1;
    dut.eval();
}

static void reset(Vlms_cw305_afifo &dut)
{
    dut.rst = 1;
    dut.wren = 0;
    dut.wdata = 0;
    dut.rden = 0;
    for (int i = 0; i < 6; i++) tick(dut);
    dut.rst = 0;
    for (int i = 0; i < 6; i++) tick(dut);
}

int main()
{
    Verilated::debug(0);
    Vlms_cw305_afifo dut;
    reset(dut);

    check(dut.empty == 1, "initial empty");
    check(dut.full == 0, "initial full");
    check(dut.count_rd == 0, "initial count_rd=0");
    check(dut.count_wr == 0, "initial count_wr=0");

    /* write 3 bytes (one wren pulse per byte) */
    for (int i = 0; i < 3; i++) {
        dut.wdata = static_cast<uint8_t>(0x40 + i);
        dut.wren = 1;
        tick(dut);
        dut.wren = 0;
        for (int j = 0; j < 3; j++) tick(dut);
        /* after the sync delay the read side should see the count */
        for (int j = 0; j < 8; j++) tick(dut);
    }
    printf("after 3 writes: empty=%d full=%d count_rd=%u count_wr=%u\n",
           dut.empty, dut.full, dut.count_rd, dut.count_wr);
    check(dut.empty == 0, "empty=0 after 3 writes");
    check(dut.count_rd == 3, "count_rd=3 after 3 writes");
    check(dut.count_wr == 3, "count_wr=3 after 3 writes");

    /* pop 3 bytes, verify data and counts */
    for (int i = 0; i < 3; i++) {
        uint8_t exp = static_cast<uint8_t>(0x40 + i);
        check(dut.rdata == exp, "rdata in correct order");
        dut.rden = 1;
        tick(dut);
        dut.rden = 0;
        for (int j = 0; j < 6; j++) tick(dut);
    }
    printf("after 3 pops: empty=%d count_rd=%u count_wr=%u\n",
           dut.empty, dut.count_rd, dut.count_wr);
    check(dut.empty == 1, "empty=1 after emptying");
    check(dut.count_rd == 0, "count_rd=0 after emptying");

    /* full flag: write 256 bytes */
    for (int i = 0; i < 256; i++) {
        dut.wdata = static_cast<uint8_t>(i);
        dut.wren = 1;
        tick(dut);
        dut.wren = 0;
    }
    for (int j = 0; j < 10; j++) tick(dut);
    printf("after 256 writes: full=%d empty=%d count_wr=%u count_rd=%u\n",
           dut.full, dut.empty, dut.count_wr, dut.count_rd);
    check(dut.full == 1, "full=1 after filling");
    check(dut.count_wr == 256, "count_wr=256 after filling");

    /* reset clears everything */
    reset(dut);
    check(dut.empty == 1, "empty=1 after reset");
    check(dut.full == 0, "full=0 after reset");
    check(dut.count_rd == 0 && dut.count_wr == 0, "counts 0 after reset");

    dut.final();

    if (g_fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", g_fails);
    return 1;
}
