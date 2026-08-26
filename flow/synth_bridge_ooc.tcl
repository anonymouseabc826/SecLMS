# Bridge OOC synthesis (verify -fsm_extraction off preserves data registers)
set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
read_verilog [file join $project_dir rtl lms_uart_bridge.v]
synth_design -top lms_uart_bridge -part xc7a100tfgg484-2 \
    -flatten_hierarchy none -no_lc -directive RuntimeOptimized -fsm_extraction off
write_verilog -mode funcsim -force [file join $project_dir build bridge_ooc_funcsim.v]
puts "OOC bridge funcsim written"
