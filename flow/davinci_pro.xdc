create_clock -period 20.000 -name sys_clk [get_ports sys_clk]
# 2026-08-12: firmware layout-sensitive DEAD (RV32 has no icache, WHS was once +0.011, extremely small; random placement
# easily triggers Hold violations → CPU unresponsive). Add clock uncertainty so implementation keeps more setup/hold
# margin, raising the on-board alive probability (cost: WNS ~-0.5 ns; current +1.4 still meets).
set_clock_uncertainty 0.5 [get_clocks sys_clk]

set_property -dict { PACKAGE_PIN R4 IOSTANDARD LVCMOS15 } [get_ports sys_clk]
set_property -dict { PACKAGE_PIN U7 IOSTANDARD LVCMOS15 } [get_ports sys_rst_n]
set_property CLOCK_DEDICATED_ROUTE FALSE [get_nets sys_clk]

set_property -dict { PACKAGE_PIN E14 IOSTANDARD LVCMOS33 } [get_ports uart_rxd]
set_property -dict { PACKAGE_PIN D17 IOSTANDARD LVCMOS33 } [get_ports uart_txd]

set_property -dict { PACKAGE_PIN V9 IOSTANDARD LVCMOS15 } [get_ports {led[0]}]
set_property -dict { PACKAGE_PIN Y8 IOSTANDARD LVCMOS15 } [get_ports {led[1]}]
set_property -dict { PACKAGE_PIN Y7 IOSTANDARD LVCMOS15 } [get_ports {led[2]}]
set_property -dict { PACKAGE_PIN W7 IOSTANDARD LVCMOS15 } [get_ports {led[3]}]

set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]

# TRNG RO loop: allow combinatorial loops (free-running inverter chain), otherwise DRC errors out.
# Standalone peripheral architecture hierarchy: soc/trng_periph/trng_inst/g_cells[*].u_cell
# Note: ALLOW_COMBINATORIAL_LOOPS can only be set on net/pin, not on cell.
set_property ALLOW_COMBINATORIAL_LOOPS TRUE [get_nets -of_objects [get_cells -hierarchical -filter {NAME =~ *trng_inst*}]]
