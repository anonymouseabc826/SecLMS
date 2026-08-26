# ============================================================================
# impl_lms_cw305.tcl — CW305 (xc7a100tftg256-2) synthesis/implementation script
# ----------------------------------------------------------------------------
# Differences from impl_lms_davinci_pro.tcl (the DaVinci Pro version is kept unchanged):
#   - part xc7a100tfgg484-2 → xc7a100tftg256-2 (CW305-100T, FTG256 package)
#   - top lms_davinci_pro_top → lms_cw305_top (100 MHz divide-by-2, see rtl/lms_cw305_top.v)
#   - constraints davinci_pro.xdc → cw305.xdc
#   - output dir/bitstream name lms_davinci_pro → lms_cw305 (build/vivado_lms_cw305/)
# Everything else (tclargs parameterization, layout-sensitive DEAD single-threading, UART bridge dont_touch) same as
# DaVinci Pro. Usage (via Makefile): make impl-cw305 VIVADO="<vivado.bat>" HASH_IMPL=shake256 ...
# ============================================================================
set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set output_dir [file join $project_dir build vivado_lms_cw305]
set firmware_hex [file normalize [file join $project_dir build lms_soc_smoke firmware.hex]]

if {![file exists $firmware_hex]} {
    error "Missing firmware image: $firmware_hex"
}

file mkdir $output_dir

# HAS_SECURITY compile switch (same as DaVinci Pro: 1=add security (default); 0=pure LMS algorithm hardware)
set has_sec 1
if {[llength $argv] > 0} { set has_sec [lindex $argv 0] }
# ENABLE_SHA256/ENABLE_SHAKE256 overridden via -tclargs (same as DaVinci Pro)
set ena_sha256 0
if {[llength $argv] > 1} { set ena_sha256 [lindex $argv 1] }
set ena_shake256 0
if {[llength $argv] > 2} { set ena_shake256 [lindex $argv 2] }
# INSECURE_TEST_MODE 4th tclarg (1=test config default; 0=deploy config, DEPLOY=1 passed in)
set ins_test_mode 1
if {[llength $argv] > 3} { set ins_test_mode [lindex $argv 3] }
# SCA_TEST 5th tclarg (1=enable SCA trigger output T14, dedicated to TVLA side-channel evaluation;
# default 0=deploy/normal builds have no trigger interface, red line memory.md §12)
set sca_test 0
if {[llength $argv] > 4} { set sca_test [lindex $argv 4] }
# RANDOM_DELAY 6th tclarg (random delay inside the TVLA engine, default 0=off;
# 2026-08-19 measured ineffective for TVLA — phase-misalignment artifact; parameter kept for future work)
set random_delay 0
if {[llength $argv] > 5} { set random_delay [lindex $argv 5] }
# DERIVE_SHUFFLE 7th tclarg (DERIVE phase shuffle level 1, 2026-08-21; default 0=off;
# batch task-block parameters rotate a random start offset per trace, zero-cycle cost; TVLA builds set it to 1)
set derive_shuffle 0
if {[llength $argv] > 6} { set derive_shuffle [lindex $argv 6] }
# ALLOW_XQ_DERIVE 8th tclarg (TVLA isolates a single x_q[i]: allows DERIVE_CHAIN steps=0,
# for side-channel SEED leak characterization; default 0=deploy keeps the M3 gate.
# Only TVLA builds set it to 1)
set allow_xq_derive 0
if {[llength $argv] > 7} { set allow_xq_derive [lindex $argv 7] }
set_property verilog_define "LMS_SOC_HAS_SECURITY=$has_sec LMS_SOC_ENABLE_SHA256=$ena_sha256 LMS_SOC_ENABLE_SHAKE256=$ena_shake256" [current_fileset]

set ibex_dir [file join $project_dir rtl ibex]

read_verilog -sv [file join $ibex_dir prim_assert.sv]
read_verilog -sv [file join $ibex_dir prim_ram_1p_pkg.sv]
read_verilog -sv [file join $ibex_dir prim_secded_pkg.sv]
read_verilog -sv [file join $ibex_dir prim_clock_gating.sv]
read_verilog -sv [file join $ibex_dir prim_buf.sv]
read_verilog -sv [file join $ibex_dir prim_flop.sv]
read_verilog -sv [file join $ibex_dir ibex_pkg.sv]
read_verilog -sv [file join $ibex_dir ibex_alu.sv]
read_verilog -sv [file join $ibex_dir ibex_compressed_decoder.sv]
read_verilog -sv [file join $ibex_dir ibex_controller.sv]
read_verilog -sv [file join $ibex_dir ibex_counter.sv]
read_verilog -sv [file join $ibex_dir ibex_cs_registers.sv]
read_verilog -sv [file join $ibex_dir ibex_csr.sv]
read_verilog -sv [file join $ibex_dir ibex_decoder.sv]
read_verilog -sv [file join $ibex_dir ibex_dummy_instr.sv]
read_verilog -sv [file join $ibex_dir ibex_ex_block.sv]
read_verilog -sv [file join $ibex_dir ibex_fetch_fifo.sv]
read_verilog -sv [file join $ibex_dir ibex_id_stage.sv]
read_verilog -sv [file join $ibex_dir ibex_if_stage.sv]
read_verilog -sv [file join $ibex_dir ibex_load_store_unit.sv]
read_verilog -sv [file join $ibex_dir ibex_multdiv_slow.sv]
read_verilog -sv [file join $ibex_dir ibex_multdiv_fast.sv]
read_verilog -sv [file join $ibex_dir ibex_prefetch_buffer.sv]
read_verilog -sv [file join $ibex_dir ibex_register_file_ff.sv]
read_verilog -sv [file join $ibex_dir ibex_branch_predict.sv]
read_verilog -sv [file join $ibex_dir ibex_wb_stage.sv]
read_verilog -sv [file join $ibex_dir ibex_core.sv]
read_verilog -sv [file join $ibex_dir ibex_top.sv]
read_verilog [file join $project_dir rtl uart_tx.v]
read_verilog [file join $project_dir rtl uart_rx.v]
read_verilog [file join $project_dir rtl lms_fpga_ram.v]
read_verilog [file join $project_dir rtl lms_sha256_round.v]
read_verilog [file join $project_dir rtl lms_sha256_core.v]
read_verilog -sv [file join $project_dir rtl lms_keccak_round.v]
read_verilog [file join $project_dir rtl lms_keccak_core.v]
read_verilog [file join $project_dir rtl lms_hash_cmd_check.v]
read_verilog -sv [file join $project_dir rtl lms_sha256_blockgen.v]
read_verilog -sv [file join $project_dir rtl lms_shake256_blockgen.v]
read_verilog -sv [file join $project_dir rtl lms_hash_engine.v]
read_verilog [file join $project_dir rtl lms_trng.v]
read_verilog [file join $project_dir rtl lms_trng_mmio.v]
read_verilog [file join $project_dir rtl lms_flash_spi.v]
read_verilog [file join $project_dir rtl lms_sha256_mmio.v]
read_verilog [file join $project_dir rtl lms_sha256_sec.v]
read_verilog [file join $project_dir rtl lms_shake256_mmio.v]
read_verilog [file join $project_dir rtl lms_hash_mmio.v]
read_verilog [file join $project_dir rtl lms_sha256_mmio_bridge.v]
read_verilog [file join $project_dir rtl lms_uart_bridge.v]
read_verilog [file join $project_dir rtl lms_cw305_afifo.v]
read_verilog [file join $project_dir rtl lms_cw305_usb_uart.v]
read_verilog -sv [file join $project_dir rtl lms_soc.v]
read_verilog [file join $project_dir rtl lms_cw305_top.v]
read_mem $firmware_hex
read_xdc [file join $project_dir flow cw305.xdc]

synth_design -top lms_cw305_top -part xc7a100tftg256-2 \
    -flatten_hierarchy none -no_lc -directive RuntimeOptimized \
    -generic FIRMWARE_HEX=$firmware_hex -generic INSECURE_TEST_MODE=$ins_test_mode -generic TRNG_SIM_MODE=0 \
    -generic SCA_TEST=$sca_test -generic RANDOM_DELAY=$random_delay -generic DERIVE_SHUFFLE=$derive_shuffle \
    -generic ALLOW_XQ_DERIVE=$allow_xq_derive \
    -generic ENABLE_SHA256=$ena_sha256 -generic ENABLE_SHAKE256=$ena_shake256 -generic HAS_SECURITY=$has_sec
write_checkpoint -force [file join $output_dir lms_cw305_synth.dcp]
report_utilization -file [file join $output_dir utilization_synth.txt]
report_timing_summary -file [file join $output_dir timing_synth.txt]

# UART bridge: opt/place misjudge the bridge RX/TX paths as unreachable (same as DaVinci Pro, see impl_lms_davinci_pro.tcl comment)
opt_design
# Layout-sensitive DEAD (RV32 has no icache): single-threaded placement is deterministic (reproducible, same as DaVinci Pro)
set_param general.maxThreads 1
place_design
phys_opt_design
# route_design -directive AggressiveExplore (2026-08-25 fix: usb_data D1/D5 placement lottery)
#   previously plain route made the SHA-256 bitstream put usb_data D1/D5 (B6/B5) at the FTDI sample edge →
#   intermittent odd-bit flips in the on-board digest (same root cause as 0x72 frame corruption). AggressiveExplore
#   keeps D1/D5 off the edge → on-board digest byte-correct (verified at 15.625/50 MHz), clk50 WNS +0.563 → +0.783.
route_design -directive AggressiveExplore

write_checkpoint -force [file join $output_dir lms_cw305_routed.dcp]
report_utilization -file [file join $output_dir utilization_routed.txt]
report_timing_summary -file [file join $output_dir timing_routed.txt]
report_io -file [file join $output_dir io_routed.txt]
report_drc -file [file join $output_dir drc_routed.txt]
write_bitstream -force [file join $output_dir lms_cw305.bit]
