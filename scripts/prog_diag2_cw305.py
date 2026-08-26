#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prog_diag2_cw305.py — deep dive into programming state: raw status / repeated erase"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, ".."))
_LOG = os.path.normpath(os.path.join(_ROOT, "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ["TMP"] = _LOG
os.environ["TEMP"] = _LOG

import chipwhisperer as cw

cw305 = cw.target(None, cw.targets.CW305, defines_files=[])

def raw_status(tag):
    s = cw305._naeusb.readCtrl(0x15, dlen=4)
    print("%s: status=%s  bit0=%d  INITB=%d" % (tag, list(s), s[0] & 1, s[1] & 1))

raw_status("initial")

# repeated erase + long waits
for i in range(3):
    print("--- erase attempt %d ---" % i)
    cw305._naeusb.sendCtrl(0x16, 0xA0)
    time.sleep(0.01)
    cw305._naeusb.sendCtrl(0x16, 0xA1)
    time.sleep(0.5)
    raw_status("after erase pulse")
    time.sleep(1.0)
    raw_status("after 1s")

# try different subcommand combinations (0xA2 = exit programming mode?)
print("--- try 0xA2 sequence ---")
cw305._naeusb.sendCtrl(0x16, 0xA0)
time.sleep(0.01)
cw305._naeusb.sendCtrl(0x16, 0xA2)
time.sleep(0.5)
raw_status("after 0xA0/0xA2")

cw305.dis()
