//  lms_cw305_regs.vh — CW305 USB register map (companion to lms_cw305_usb_uart.v)
//  ----------------------------------------------------------------------------
//  Register layout matches the NewAE CW305 reference design (cw305_regs.vh style):
//  12 REG_ defines, parsed by chipwhisperer's slurp_defines (CW305 class expects 12).
//  Semantics (differences from the Sloth/NewAE reference):
//    REG_TX_BYTE read  = pop one byte from TX FIFO (device→host, real FIFO, no byte loss)
//    REG_TX_IDX  read  = current TX FIFO depth (bytes pending for the host to read)
//    REG_RX_BYTE write = push one byte into RX FIFO (host→device)
//    REG_RX_IDX / REG_RX_POS read = current RX FIFO depth (0 = device has consumed all)
//  ----------------------------------------------------------------------------

`define REG_CLKSETTINGS     'h00
`define REG_USER_LED        'h01
`define REG_CRYPT_TYPE      'h02
`define REG_CRYPT_REV       'h03
`define REG_IDENTIFY        'h04
`define REG_TX_BYTE         'h05
`define REG_TX_IDX          'h06
`define REG_RX_BYTE         'h07
`define REG_RX_IDX          'h08
`define REG_RX_POS          'h09
`define REG_STATUS          'h0a
`define REG_BUILDTIME       'h0b
