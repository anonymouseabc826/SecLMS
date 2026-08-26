// Minimal prim_assert stub for Vivado synthesis and Verilator simulation.
// All assertion macros are defined as empty (no SVA dependency).
// Based on lowRISC prim_assert.sv (Apache 2.0 licensed).

`ifndef PRIM_ASSERT_SV
`define PRIM_ASSERT_SV

`define ASSERT_DEFAULT_CLK clk_i
`define ASSERT_DEFAULT_RST !rst_ni
`define PRIM_STRINGIFY(__x) `"__x`"

`define ASSERT_ERROR(__name)

// Immediate assertion
`define ASSERT_I(__name, __prop)

// Initial block assertion
`define ASSERT_INIT(__name, __prop)

// Initial block assertion for nets
`define ASSERT_INIT_NET(__name, __prop)

// Final block assertion
`define ASSERT_FINAL(__name, __prop)

// Assertion just before reset
`define ASSERT_AT_RESET(__name, __prop, __rst = `ASSERT_DEFAULT_RST)

// Assertion before reset and in final block
`define ASSERT_AT_RESET_AND_FINAL(__name, __prop, __rst = `ASSERT_DEFAULT_RST)

// Concurrent assertion
`define ASSERT(__name, __prop, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Concurrent assertion NEVER
`define ASSERT_NEVER(__name, __prop, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Known value assertion
`define ASSERT_KNOWN(__name, __sig, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Cover
`define COVER(__name, __prop, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Assume
`define ASSUME(__name, __prop, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)
`define ASSUME_I(__name, __prop)

// Pulse assertion
`define ASSERT_PULSE(__name, __sig, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Conditional assertion
`define ASSERT_IF(__name, __prop, __enable, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Known value with enable
`define ASSERT_KNOWN_IF(__name, __sig, __enable, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Formal-only macros
`define ASSUME_FPV(__name, __prop, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)
`define ASSUME_I_FPV(__name, __prop)
`define COVER_FPV(__name, __prop, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)
`define ASSERT_FPV_LINEAR_FSM(__name, __state, __type, __clk = `ASSERT_DEFAULT_CLK, __rst = `ASSERT_DEFAULT_RST)

// Static lint error
`define ASSERT_STATIC_LINT_ERROR(__name, __prop)

// Static assertion in package
`define ASSERT_STATIC_IN_PACKAGE(__name, __prop)

`endif // PRIM_ASSERT_SV
