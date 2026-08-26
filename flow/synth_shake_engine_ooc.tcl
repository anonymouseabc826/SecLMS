set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set output_dir [file join $project_dir build vivado_shake_engine_ooc]

file mkdir $output_dir

read_verilog -sv [file join $project_dir rtl lms_keccak_round.v]
read_verilog [file join $project_dir rtl lms_keccak_core.v]
read_verilog -sv [file join $project_dir rtl lms_shake256_blockgen.v]
read_verilog -sv [file join $project_dir rtl lms_hash_engine.v]

synth_design -top lms_hash_engine -part xc7a100tfgg484-2 -mode out_of_context \
    -generic HASH_TYPE=1 -generic INSECURE_TEST_MODE=1
create_clock -name ooc_clk -period 20.000 [get_ports clk]
write_checkpoint -force [file join $output_dir lms_hash_engine_ooc.dcp]
report_utilization -file [file join $output_dir utilization.txt]
report_utilization -hierarchical -hierarchical_depth 6 -file [file join $output_dir utilization_hierarchical.txt]
