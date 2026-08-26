set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set output_dir [file join $project_dir build vivado_sha256_mmio]

file mkdir $output_dir

read_verilog [file join $project_dir rtl lms_sha256_round.v]
read_verilog [file join $project_dir rtl lms_sha256_core.v]
read_verilog [file join $project_dir rtl lms_hash_cmd_check.v]
read_verilog -sv [file join $project_dir rtl lms_sha256_blockgen.v]
read_verilog -sv [file join $project_dir rtl lms_hash_engine.v]
read_verilog [file join $project_dir rtl lms_sha256_sec.v]
read_verilog [file join $project_dir rtl lms_sha256_mmio.v]

synth_design -top lms_sha256_mmio -part xc7a100tfgg484-2
create_clock -name sha256_mmio_clk -period 10.000 [get_ports clk]
write_checkpoint -force [file join $output_dir lms_sha256_mmio_synth.dcp]
report_utilization -file [file join $output_dir utilization.txt]
report_timing_summary -file [file join $output_dir timing_summary.txt]
report_utilization -hierarchical -hierarchical_depth 5 -file [file join $output_dir hier_util.txt]