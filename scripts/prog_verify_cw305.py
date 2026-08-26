#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prog_verify_cw305.py — program + verify immediately (for diagnostics)"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, ".."))
_LOG = os.path.normpath(os.path.join(_ROOT, "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ["TMP"] = _LOG
os.environ["TEMP"] = _LOG

BS = os.path.normpath(os.path.join(_ROOT, "build", "vivado_lms_cw305", "lms_cw305.bit"))
DEFS = os.path.normpath(os.path.join(_ROOT, "rtl", "lms_cw305_regs.vh"))

import chipwhisperer as cw

print("bitstream:", BS, os.path.getsize(BS), "bytes")
print("programming ...", flush=True)
t0 = time.time()
cw305 = cw.target(None, cw.targets.CW305, bsfile=BS, force=True,
                  defines_files=[DEFS], prog_speed=20E6)
print("programmed in %.1fs" % (time.time() - t0))
print("isFPGAProgrammed:", cw305.fpga.isFPGAProgrammed())
print("INITB:", cw305.fpga.INITBState())
for reg in ("REG_IDENTIFY", "REG_CRYPT_TYPE", "REG_CRYPT_REV", "REG_STATUS", "REG_TX_IDX"):
    try:
        print(reg, "=", list(cw305.fpga_read(getattr(cw305, reg), 1)))
    except Exception as e:
        print(reg, "ERR", repr(e))
try:
    print("buildtime:", cw305.get_fpga_buildtime())
except Exception as e:
    print("buildtime ERR", repr(e))
cw305.dis()
