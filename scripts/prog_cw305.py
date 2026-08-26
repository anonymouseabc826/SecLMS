#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CW305 programming script (ChipWhisperer API; Vivado Hardware Manager cannot see the CW305)

Usage: python scripts/prog_cw305.py [bitstream path]
Default bitstream: build/vivado_lms_cw305/lms_cw305.bit

Notes:
- Requires chipwhisperer>=6.0.
- force=True: reprogram regardless of whether the FPGA is already programmed (the default behavior skips the programmed state).
- Programming is done by the on-board USB controller (NewAE firmware) over JTAG, independent of whether the FPGA
  contains the usb_reg_fe register frontend — after programming this project's bitstream, the fpga_read/write register
  path being unavailable is expected (to be restored after the UART bridge port; see the CW305 migration.md §5).
- TMP/TEMP redirected to build/cw305/ (the sandbox's system TEMP is not writable).
"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_LOG = os.path.normpath(os.path.join(_WS, "..", "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ["TMP"] = _LOG
os.environ["TEMP"] = _LOG

import cw_boot  # noqa: E402  (under the sandbox the mkdtemp dir is not writable; patch first, then import chipwhisperer)


def main():
    if len(sys.argv) > 1:
        bsfile = sys.argv[1]
    else:
        bsfile = os.path.normpath(os.path.join(_WS, "..", "build", "vivado_lms_cw305", "lms_cw305.bit"))
    bsfile = os.path.abspath(bsfile)
    if not os.path.isfile(bsfile):
        print("ERROR: bitstream not found: %s" % bsfile)
        sys.exit(1)

    import chipwhisperer as cw

    print("programming %s ..." % bsfile, flush=True)
    t0 = time.time()
    cw305 = cw.target(None, cw.targets.CW305, bsfile=bsfile, force=True)
    print("programmed OK in %.1fs" % (time.time() - t0))
    try:
        cw305.dis()
    except Exception:
        pass


if __name__ == "__main__":
    main()
