// Minimal prim_ram_1p_pkg stub for Ibex integration.
// Defines ram_1p_cfg_t type needed by ibex_top.
// Based on lowRISC prim_ram_1p_pkg.sv (Apache 2.0 licensed).

package prim_ram_1p_pkg;

  typedef struct packed {
    logic       cfg_en;
    logic [3:0] cfg;
  } cfg_t;

  typedef struct packed {
    cfg_t ram_cfg;
    cfg_t rf_cfg;
  } ram_1p_cfg_t;

  parameter ram_1p_cfg_t RAM_1P_CFG_DEFAULT = '0;

endpackage
