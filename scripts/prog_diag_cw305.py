#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prog_diag_cw305.py — programming-path diagnostics (step by step: erase / download / DONE)"""
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

import chipwhisperer as cw

# 1. connect only (no programming)
cw305 = cw.target(None, cw.targets.CW305, defines_files=[])
print("1. connected; isFPGAProgrammed =", cw305.fpga.isFPGAProgrammed())
print("   buildtime =", cw305.get_fpga_buildtime())

# 2. explicit erase (PROGRAM_B pulse)
print("2. erasing ...", flush=True)
cw305.fpga.eraseFPGA()
time.sleep(0.2)
print("   after erase: isFPGAProgrammed =", cw305.fpga.isFPGAProgrammed(),
      " INITB =", cw305.fpga.INITBState())

# 3. program (low speed 1E6, serial mode)
print("3. programming @1MHz ...", flush=True)
t0 = time.time()
status = cw305.fpga.FPGAProgram(open(BS, "rb"), exceptOnDoneFailure=True, prog_speed=1E6)
print("   FPGAProgram returned", status, "in %.1fs" % (time.time() - t0))
print("   isFPGAProgrammed =", cw305.fpga.isFPGAProgrammed())
print("   INITB =", cw305.fpga.INITBState())
try:
    print("   buildtime =", cw305.get_fpga_buildtime())
except Exception as e:
    print("   buildtime ERR", repr(e))
cw305.dis()
