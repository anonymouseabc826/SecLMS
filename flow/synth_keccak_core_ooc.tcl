set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set output_dir [file join $project_dir build vivado_keccak_ooc]

file mkdir $output_dir

read_verilog -sv [file join $project_dir rtl lms_keccak_round.v]
read_verilog [file join $project_dir rtl lms_keccak_core.v]

synth_design -top lms_keccak_core -part xc7a100tfgg484-2 -mode out_of_context
create_clock -name ooc_clk -period 20.000 [get_ports clk]
write_checkpoint -force [file join $output_dir lms_keccak_core_ooc.dcp]
report_utilization -file [file join $output_dir utilization.txt]
report_timing_summary -file [file join $output_dir timing_summary.txt]
