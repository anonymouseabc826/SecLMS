`ifndef LMS_SOC_CONFIG_VH
`define LMS_SOC_CONFIG_VH

`timescale 1 ns / 1 ps
`default_nettype none

`define LMS_SOC_CLK 50000000
`define LMS_SOC_RAM_XADR 17

/* Hash core compile selection (independent enable flags of the top thin shell lms_hash_mmio.v):
 *   Each flag can be enabled independently (comma-separated HASH_IMPL spec); adding a new hash
 *   only requires a new define.
 *   * Accounting (REVIEW P1-1, unified 2026-08-16): the defines in this file are only
 *     "documentation-nature defaults"; the actual platform selection is explicitly overridden by
 *     two build paths -- Vivado uses the verilog_define in flow/impl_lms_davinci_pro.tcl (fed by
 *     Makefile HASH_IMPL/HAS_SECURITY); Verilator uses the -GENABLE_SHA256, -GENABLE_SHAKE256,
 *     -GHAS_SECURITY arguments in the Makefile.
 *     To change the platform use make impl-davinci-pro HASH_IMPL=... HAS_SECURITY=...,
 *     do not just edit this file.
 *   Current on-board default accounting (2026-08-16): SHAKE256 + security domain (0.1.271 bitstream). */
`define LMS_SOC_ENABLE_SHA256   1'b0
`define LMS_SOC_ENABLE_SHAKE256 1'b1

/* Security hardening compile selection:
 *   1 = includes WRAP/UNWRAP/HMAC/MC/key slots (full feature set)
 *   0 = pure LMS algorithm hardware (no security domain)
 *   Also documentation-nature defaults; actually overridden by impl tcl / -GHAS_SECURITY
 *   (current on-board accounting = 1). */
`define LMS_SOC_HAS_SECURITY    1'b1

/* Ibex core features are configured via ibex_top parameters (RV32M single-cycle, RegFileFF,
 * no ICache); the pug-era CORE_COMPRESSED/CORE_MULDIV/CORE_TRAP_UNALIGNED are no longer needed. */

`endif
