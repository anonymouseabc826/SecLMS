set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set bitstream [file normalize [file join $project_dir build vivado_lms_davinci_pro lms_davinci_pro.bit]]

if {![file exists $bitstream]} {
    error "Missing bitstream: $bitstream"
}

open_hw_manager
connect_hw_server

set targets [get_hw_targets]
if {[llength $targets] == 0} {
    error "No Vivado hardware target detected"
}

current_hw_target [lindex $targets 0]
open_hw_target

set device ""
foreach candidate [get_hw_devices] {
    if {[string match -nocase "xc7a100t*" [get_property PART $candidate]]} {
        set device $candidate
        break
    }
}
if {$device eq ""} {
    error "No XC7A100T device detected on [current_hw_target]"
}

current_hw_device $device
refresh_hw_device $device
set_property PROGRAM.FILE $bitstream $device
program_hw_devices $device
refresh_hw_device $device

puts "PROGRAMMED [get_property PART $device] with $bitstream"
close_hw_target
disconnect_hw_server
close_hw_manager
