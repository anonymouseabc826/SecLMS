// Stub for lowRISC dv_fcov_macros.svh (functional coverage macros).
// All coverage macros disabled for synthesis/Verilator.
// Based on lowRISC dv_fcov_macros.svh (Apache 2.0 licensed).

`ifndef DV_FCOV_MACROS_SVH
`define DV_FCOV_MACROS_SVH

`define DV_FCOV_DISABLE
`define DV_FCOV_DISABLE_CP

// Coverage macro stubs (all empty when DV_FCOV_DISABLE is defined)
`define DV_FCOV_INSTANTIATE_CG(NAME_, COND_ = 1'b1, ARGS_ = ())
`define DV_FCOV_EXPR_SEEN(NAME_, EXPR_)
`define DV_FCOV_SVA(EV_NAME_, PROP_, CLK_ = clk_i, RST_ = rst_ni)
`define DV_FCOV_MARK_UNUSED(TYPE_, NAME_)
`define DV_FCOV_SIGNAL(TYPE_, NAME_, EXPR_)
`define DV_FCOV_SIGNAL_GEN_IF(TYPE_, NAME_, EXPR_, GEN_COND_, DEFAULT_ = '0)

`endif
