set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set output_dir [file join $project_dir build vivado_lms_davinci_pro]
set firmware_hex [file normalize [file join $project_dir build lms_soc_smoke firmware.hex]]

if {![file exists $firmware_hex]} {
    error "Missing firmware image: $firmware_hex"
}

file mkdir $output_dir

# HAS_SECURITY compile switch (0.1.241 parameterization): passed via Makefile HAS_SECURITY → -tclargs.
# 1=add security (default, includes WRAP/UNWRAP/HMAC/MC); 0=pure LMS algorithm hardware (saves ~3.7K LUT;
# note: the 4 DSPs are the RV32IMC M-extension fast multiplier inside the SoC, same count in both configs, not SEC
# cost — confirmed via 2026-08-15 DCP query of soc/cpu/u_ibex_core/ex_block_i/gen_multdiv_fast.multdiv_i).
set has_sec 1
if {[llength $argv] > 0} { set has_sec [lindex $argv 0] }
# ENABLE_SHA256/ENABLE_SHAKE256 likewise overridden via -tclargs (0.1.269 fix: after S10
# config.vh is fixed to the SHA-256 config; SHAKE synthesis was previously not covered → engine mismatched firmware → on-board DEAD).
set ena_sha256 0
if {[llength $argv] > 1} { set ena_sha256 [lindex $argv 1] }
set ena_shake256 0
if {[llength $argv] > 2} { set ena_shake256 [lindex $argv 2] }
# INSECURE_TEST_MODE 4th tclarg (P1-6, 0.1.274): 1=test config (default, research prototype;
# plaintext SEED_LOAD allowed); 0=deploy config (plaintext SEED gating enabled, DEPLOY=1 passed via Makefile).
set ins_test_mode 1
if {[llength $argv] > 3} { set ins_test_mode [lindex $argv 3] }
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
read_verilog [file join $project_dir rtl lms_sha256_mmio.v]
read_verilog [file join $project_dir rtl lms_sha256_sec.v]
read_verilog [file join $project_dir rtl lms_shake256_mmio.v]
read_verilog [file join $project_dir rtl lms_hash_mmio.v]
read_verilog [file join $project_dir rtl lms_sha256_mmio_bridge.v]
read_verilog [file join $project_dir rtl lms_uart_bridge.v]
read_verilog -sv [file join $project_dir rtl lms_soc.v]
read_verilog [file join $project_dir rtl lms_davinci_pro_top.v]
read_mem $firmware_hex
read_xdc [file join $project_dir flow davinci_pro.xdc]

synth_design -top lms_davinci_pro_top -part xc7a100tfgg484-2 \
    -flatten_hierarchy none -no_lc -directive RuntimeOptimized \
    -generic FIRMWARE_HEX=$firmware_hex -generic INSECURE_TEST_MODE=$ins_test_mode -generic TRNG_SIM_MODE=0
write_checkpoint -force [file join $output_dir lms_davinci_pro_synth.dcp]
report_utilization -file [file join $output_dir utilization_synth.txt]
report_timing_summary -file [file join $output_dir timing_synth.txt]

# UART bridge (Step 3): opt_design/place_design misjudge the bridge's RX/TX paths as unreachable,
# deleting the data buffer and collapsing concat/read-back logic to constants (post-gate simulation: RX concatenated
# words all 0, TX stuck, yet Verilator PASSes). Cannot DONT_TOUCH the whole bridge — that freezes opt's timing
# optimization (WNS 0.858→0.450), making the SoC CPU unresponsive (basic KAT 0/48, firmware DEAD); also cannot use an
# RTL module-level dont_touch attribute (same SoC unresponsiveness). Correct approach: inside the bridge RTL, add a
# dont_touch wire on mem_valid to block constant propagation (see lms_uart_bridge.v), so opt cannot decide start_req
# is always false; bridge logic is kept and opt can still optimize timing normally.

opt_design
# Layout-sensitive DEAD (RV32 has no icache): Vivado 2020.2 has no place seed parameter; multithreaded placement
# is random (same design, same flow, different runs differ, ~90% DEAD). Single-threaded placement is deterministic (reproducible).
set_param general.maxThreads 1
place_design
phys_opt_design
route_design

write_checkpoint -force [file join $output_dir lms_davinci_pro_routed.dcp]
report_utilization -file [file join $output_dir utilization_routed.txt]
report_timing_summary -file [file join $output_dir timing_routed.txt]
report_io -file [file join $output_dir io_routed.txt]
report_drc -file [file join $output_dir drc_routed.txt]
write_bitstream -force [file join $output_dir lms_davinci_pro.bit]
