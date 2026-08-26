#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""set_pll.py - configure CW305 CDCE906 PLL output 1 frequency (2026-08-18)

CW305's N13 = CDCE906 PLL output 1 (ref 12 MHz crystal). Default output 1 = 10 MHz
(divide by 2 -> clk50=5 MHz, stable); set 100 MHz -> clk50=50 MHz.
50 MHz physical status (2026-08-28, after Vivado re-synthesis with
flow/impl_lms_cw305_tight50.tcl): HASH_ONCE/CHAIN are stable at 50 MHz; long
batch tasks (LM-OTS keygen/sign, LMS verify) have a hold-timing edge on the
SHAKE engine batch path (verify wrong above ~41.7 MHz, timeouts at 48/50 MHz).
The paper's 50 MHz is the design clock (ms-conversion basis); cycle counts are
clock-frequency independent. See RESULTS.md for the full validation matrix.
Usage: python scripts/set_pll.py 100e6    # output 1 = 100 MHz
      python scripts/set_pll.py 10e6     # restore default 10 MHz
The bit must be reflashed afterwards.
"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_LOG = os.path.normpath(os.path.join(_WS, "..", "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ.setdefault("TMP", _LOG)
os.environ.setdefault("TEMP", _LOG)

import cw_boot  # noqa: E402  (under the sandbox the mkdtemp dir is not writable; patch first, then import chipwhisperer)

import chipwhisperer as cw  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/set_pll.py <freq_hz>  e.g. 100e6 / 10e6")
        return
    freq = float(sys.argv[1])
    t0 = time.time()
    cw305 = cw.target(None, cw.targets.CW305, fpga_id="100t")
    print("[OK] connected in %.1fs, current output1 = %r Hz" % (time.time() - t0, cw305.pll.pll_outfreq_get(1)))
    pll = cw305.pll
    pll.pll_enable_set(True)
    pll.pll_outenable_set(False, 0)
    pll.pll_outenable_set(True, 1)
    pll.pll_outenable_set(False, 2)
    pll.pll_outfreq_set(freq, 1)
    time.sleep(0.2)
    f = pll.pll_outfreq_get(1)
    ok = abs(f - freq) < max(1e5, freq * 0.01)
    print("[%s] output1 = %r Hz (target %r)" % ("OK" if ok else "WARN", f, freq))
    print("Next: reflash the bit so the FPGA configures under the new clock.")


if __name__ == "__main__":
    main()
