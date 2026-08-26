set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set output_dir [file join $project_dir build vivado_sha256]

file mkdir $output_dir

read_verilog [file join $project_dir rtl lms_sha256_round.v]
read_verilog [file join $project_dir rtl lms_sha256_core.v]

synth_design -top lms_sha256_core -part xc7a100tfgg484-2
create_clock -name sha256_clk -period 10.000 [get_ports clk]
write_checkpoint -force [file join $output_dir lms_sha256_core_synth.dcp]
report_utilization -file [file join $output_dir utilization.txt]
report_timing_summary -file [file join $output_dir timing_summary.txt]