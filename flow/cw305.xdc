# ============================================================================
# cw305.xdc — CW305 (xc7a100tftg256-2) pin/clock constraints
# ----------------------------------------------------------------------------
# Pin sources: Sloth-verified CW305 pins
#           (100 MHz crystal N13, button R1, LEDs T2/T3/T4, USB parallel-bus pins)
# Timing convention source: this project's flow/davinci_pro.xdc (50 MHz timing convention + DEAD countermeasure + TRNG RO exemption)
# Matching top level: rtl/lms_cw305_top.v (100 MHz → divide-by-2 → 50 MHz + USB↔UART bridge)
# Note: A12/A14 (FTDI UART pins) are no longer used — the CW305 has no COM port; UART goes through USB registers
#     (mailbox, lms_cw305_usb_uart.v) to communicate with the host.
# ============================================================================

# ---- Clocks ----
# On-board 100 MHz crystal (N13) → top-level divide-by-2 → 50 MHz SoC clock
create_clock -period 10.000 -name clk100 [get_ports sys_clk]
create_generated_clock -name clk50 -source [get_ports sys_clk] -divide_by 2 [get_nets clk50]

# USB bus clock (FTDI CLKOUT = 60 MHz, period 16.667 ns).
# 2026-08-22 fix: previously constrained conservatively to 10 ns (100 MHz) per Sloth's convention — when I/O was
# unconstrained (no set_input/output_delay) it passed; after the 0x72 fix added I/O delay constraints, the usb_isout
# enable combinational path (usb_rdn_r→LUT→OBUFT) and the read_data load path (rdata_mux→IOB FF) need the
# real 60 MHz budget to meet (WNS=-3.5 at 10 ns). All pass after switching to the real period.
create_clock -period 16.667 -name usb_clk [get_ports usb_clk]

# 2026-08-12: firmware layout-sensitive DEAD countermeasure (same convention as davinci_pro.xdc: RV32 has no icache,
# random placement easily triggers Hold violations → CPU unresponsive; clock uncertainty leaves more setup/hold margin)
set_clock_uncertainty 0.5 [get_clocks clk50]

# ---- Pins ----
set_property -dict { PACKAGE_PIN N13 IOSTANDARD LVCMOS33 } [get_ports sys_clk]
set_property -dict { PACKAGE_PIN R1  IOSTANDARD LVCMOS33 } [get_ports sys_rst_n]

# USB parallel bus (FTDI channel B, FT245 synchronous FIFO)
set_property -dict { PACKAGE_PIN F5  IOSTANDARD LVCMOS33 } [get_ports usb_clk]
set_property -dict { PACKAGE_PIN A7  IOSTANDARD LVCMOS33 } [get_ports {usb_data[0]}]
set_property -dict { PACKAGE_PIN B6  IOSTANDARD LVCMOS33 } [get_ports {usb_data[1]}]
set_property -dict { PACKAGE_PIN D3  IOSTANDARD LVCMOS33 } [get_ports {usb_data[2]}]
set_property -dict { PACKAGE_PIN E3  IOSTANDARD LVCMOS33 } [get_ports {usb_data[3]}]
set_property -dict { PACKAGE_PIN F3  IOSTANDARD LVCMOS33 } [get_ports {usb_data[4]}]
set_property -dict { PACKAGE_PIN B5  IOSTANDARD LVCMOS33 } [get_ports {usb_data[5]}]
set_property -dict { PACKAGE_PIN K1  IOSTANDARD LVCMOS33 } [get_ports {usb_data[6]}]
set_property -dict { PACKAGE_PIN K2  IOSTANDARD LVCMOS33 } [get_ports {usb_data[7]}]
set_property -dict { PACKAGE_PIN F4  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[0]}]
set_property -dict { PACKAGE_PIN G5  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[1]}]
set_property -dict { PACKAGE_PIN J1  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[2]}]
set_property -dict { PACKAGE_PIN H1  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[3]}]
set_property -dict { PACKAGE_PIN H2  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[4]}]
set_property -dict { PACKAGE_PIN G1  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[5]}]
set_property -dict { PACKAGE_PIN G2  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[6]}]
set_property -dict { PACKAGE_PIN F2  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[7]}]
set_property -dict { PACKAGE_PIN E1  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[8]}]
set_property -dict { PACKAGE_PIN E2  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[9]}]
set_property -dict { PACKAGE_PIN D1  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[10]}]
set_property -dict { PACKAGE_PIN C1  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[11]}]
set_property -dict { PACKAGE_PIN K3  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[12]}]
set_property -dict { PACKAGE_PIN L2  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[13]}]
set_property -dict { PACKAGE_PIN J3  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[14]}]
set_property -dict { PACKAGE_PIN B2  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[15]}]
set_property -dict { PACKAGE_PIN C7  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[16]}]
set_property -dict { PACKAGE_PIN C6  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[17]}]
set_property -dict { PACKAGE_PIN D6  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[18]}]
set_property -dict { PACKAGE_PIN C4  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[19]}]
set_property -dict { PACKAGE_PIN D5  IOSTANDARD LVCMOS33 } [get_ports {usb_addr[20]}]
set_property -dict { PACKAGE_PIN A4  IOSTANDARD LVCMOS33 } [get_ports usb_rdn]
set_property -dict { PACKAGE_PIN C2  IOSTANDARD LVCMOS33 } [get_ports usb_wrn]
set_property -dict { PACKAGE_PIN A3  IOSTANDARD LVCMOS33 } [get_ports usb_cen]
set_property -dict { PACKAGE_PIN A5  IOSTANDARD LVCMOS33 } [get_ports usb_trigger]

# ---- USB parallel-bus output timing (2026-08-22 fix: root cause of 0x72 intermittent odd-bit flips) ----
# Root cause: the FTDI channel B parallel interface previously had no set_output_delay → the output (device→host) pad
# delay was decided by placement luck → the shuffle build happened to put usb_data D1/D3/D5 (pins B6/E3/B5) at the
# FTDI sample edge → intermittent odd-bit flips (old bit layout differed so it was fine; measured clean, old bits 0/5).
# Fix convention (FT245 synchronous FIFO, usb_clk = FTDI CLKOUT 60 MHz = 16.667 ns):
#   - Output (FPGA→FTDI): FTDI samples on the CLKOUT rising edge (setup≈2 ns) → set_output_delay max 2
#   - Input (FTDI→FPGA): never broken, left unconstrained (input constraints/packing change the reg_fe pipeline
#     timing → stale TX_IDX count → phantom 0x00 prefix before large responses, a measured pitfall).
set_output_delay -clock [get_clocks usb_clk] -max 2.000 [get_ports {usb_data[*]}]
set_output_delay -clock [get_clocks usb_clk] -min 0.000 [get_ports {usb_data[*]}]

# ---- Async FIFO CDC exemption (2026-08-22): all clk50↔usb_clk cross-domain paths are gray code + 2-stage
# synchronization (lms_cw305_afifo dual-clock FIFO + ASYNC_REG sync chains), safe per CDC conventions,
# so the timing tool's literal setup/hold check does not apply — exempted (literal check -6.3 ns at 16.667 ns period).
set_false_path -from [get_clocks usb_clk] -to [get_clocks clk50]
set_false_path -from [get_clocks clk50] -to [get_clocks usb_clk]

set_property -dict { PACKAGE_PIN T2  IOSTANDARD LVCMOS33 } [get_ports {led[0]}]
set_property -dict { PACKAGE_PIN T3  IOSTANDARD LVCMOS33 } [get_ports {led[1]}]
set_property -dict { PACKAGE_PIN T4  IOSTANDARD LVCMOS33 } [get_ports {led[2]}]

# SCA trigger output (20-pin tio_trigger, for TVLA side-channel; same pin T14 as Sloth).
# Decoupled from crypto compute control (observes only the CONTROL START write edge), cycle-aligned; constant 0 when SCA_TEST=0.
set_property -dict { PACKAGE_PIN T14 IOSTANDARD LVCMOS33 } [get_ports sca_trigger]
set_false_path -to [get_ports sca_trigger]

# Synchronous sampling clock output (20-pin CLKOUT, for TVLA; same pin M16 as Sloth).
# clk50 output via ODDR → Husky HS1 (clkgen_src=extclk, 1 samp/cycle); constant 0 when SCA_TEST=0.
set_property -dict { PACKAGE_PIN M16 IOSTANDARD LVCMOS33 } [get_ports tio_clkout]
set_false_path -to [get_ports tio_clkout]

# ---- SPI flash (M1 access verification, on-board SPI NOR) ----
# Routing source: line-by-line tracing of NAE-CW305-Schematic.pdf page 3 + NewAE spiflash_feedthrough xdc
#   flash SCK runs on the CCLK pad (STARTUPE2, no external pin); SI=J13, CS=L12 confirmed via shim;
#   SO is on the SAM_MOSI net; B4 is the candidate read pin; K12/J14/K15/L13 are backup candidates (measured by simultaneous sampling).
set_property -dict { PACKAGE_PIN J13 IOSTANDARD LVCMOS33 } [get_ports flash_mosi]
set_property -dict { PACKAGE_PIN L12 IOSTANDARD LVCMOS33 } [get_ports flash_cs_n]
set_property -dict { PACKAGE_PIN B4  IOSTANDARD LVCMOS33 } [get_ports flash_miso_b4]
set_property -dict { PACKAGE_PIN K12 IOSTANDARD LVCMOS33 } [get_ports flash_miso_k12]
set_property -dict { PACKAGE_PIN J14 IOSTANDARD LVCMOS33 } [get_ports flash_miso_j14]
set_property -dict { PACKAGE_PIN K15 IOSTANDARD LVCMOS33 } [get_ports flash_miso_k15]
set_property -dict { PACKAGE_PIN L13 IOSTANDARD LVCMOS33 } [get_ports flash_miso_l13]
# SPI slow async signals (2 MHz): no timing closure required (flash pins left unconstrained)
set_false_path -to [get_ports {flash_*}]

set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]

# TRNG RO loop: allow combinatorial loops (free-running inverter chain), otherwise DRC errors out.
# Architecture hierarchy same as DaVinci Pro (SoC unchanged): soc/trng_periph/trng_inst/g_cells[*].u_cell
set_property ALLOW_COMBINATORIAL_LOOPS TRUE [get_nets -of_objects [get_cells -hierarchical -filter {NAME =~ *trng_inst*}]]
