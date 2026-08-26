// Focused unit test: behavior of lms_hash_cmd_check's M3 gate under ALLOW_XQ_DERIVE.
// Drives the combinational-logic (always @*) model: set inputs, tick one cycle, check valid/error/action.
// Build (Makefile --cc --exe style, avoids the inliner env issue with --binary):
//   verilator --cc --exe --top-module tb ... test_cmd_check_allow_xq.cpp rtl/lms_hash_cmd_check.v
#include "Vtb.h"
#include "verilated.h"
#include <cstdio>
#include <cstring>

static const uint32_t CMD_DERIVE_CHAIN = 0x00000004;
static const uint32_t ERR_CHAIN_RANGE  = 0x00000006;
static const uint8_t  ACT_START        = 0;
static int failures = 0;

// Verilator timing (#1 delay) requires defining sc_time_stamp (standard requirement)
double sc_time_stamp() { return 0; }

static void tick(Vtb* t) { t->eval(); }

static void drive(Vtb* t, uint32_t steps) {
    t->command = CMD_DERIVE_CHAIN;
    t->input_length = 0;
    t->output_length = 32;
    t->arg_i = 0;
    t->arg_start = 0;
    t->arg_steps = steps;
    t->arg_key = 0;
    t->seed_valid = 1;
    t->k_wrap_valid = 1;
    t->k_state_valid = 1;
    t->lmots_sign_y_len = 2144;
    tick(t);
}

static void check(const char* name, Vtb* t, uint32_t want_err, uint32_t want_act) {
    bool ok = (t->error_code == want_err) && (t->action == want_act);
    if (!ok) {
        ++failures;
        std::printf("FAIL %-32s error=%08x (want %08x) action=%d (want %d)\n",
                    name, t->error_code, want_err, t->action, want_act);
    } else {
        std::printf("PASS %s\n", name);
    }
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    Vtb* t = new Vtb;
    t->command = 0; t->input_length = 0; t->output_length = 0;
    t->arg_i = 0; t->arg_start = 0; t->arg_steps = 0; t->arg_key = 0;
    t->seed_valid = 0; t->k_wrap_valid = 0; t->k_state_valid = 0;
    t->lmots_sign_y_len = 2144;
    tick(t);

#ifdef ALLOW_TEST
    // ALLOW_XQ_DERIVE=1 (via -DALLOW_TEST and the Verilator parameter ALLOW_XQ_DERIVE=1)
    drive(t, 0);
    check("derive steps=0 (ALLOW=1) -> pass", t, 0, ACT_START);
    drive(t, 1);
    check("derive steps=1 (ALLOW=1) -> reject", t, ERR_CHAIN_RANGE, ACT_START);
#else
    // ALLOW_XQ_DERIVE=0
    drive(t, 0);
    check("derive steps=0 (ALLOW=0) -> reject", t, ERR_CHAIN_RANGE, ACT_START);
    drive(t, 1);
    check("derive steps=1 (ALLOW=0) -> reject", t, ERR_CHAIN_RANGE, ACT_START);
#endif

    std::printf(failures == 0 ? "ALL PASS\n" : "FAILURES: %d\n", failures);
    delete t;
    return failures == 0 ? 0 : 1;
}
