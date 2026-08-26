# flow/program_bit.tcl - program an arbitrary bitstream (diagnostics; path passed via -tclargs).
# Usage: vivado -mode batch -source flow/program_bit.tcl -tclargs <bitpath>
set bitstream [lindex $argv 0]
if {$bitstream eq ""} {
    error "usage: vivado -mode batch -source flow/program_bit.tcl -tclargs <bitpath>"
}
set bitstream [file normalize $bitstream]
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
