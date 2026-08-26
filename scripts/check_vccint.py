#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_vccint.py - read-only check of CW305 VCC-INT power status (2026-08-18)

Read-only check: does not modify VCCINT settings, reprogram, or touch the on-board bitstream.
Checks:
  1) CW305 connection
  2) vccint_get()  - current VCCINT setting/feedback value (Artix-7 xc7a100t nominal 1.0 V)
  3) FPGA DONE     - isFPGAProgrammed() (hard flag: power OK + bitstream loaded)
  4) buildtime     - register read path (proves the FPGA is running normally)
  5) PLL CDCE906   - clock output (optional, corroborates the power chain)

Note: vccint_get returns the on-board DC-DC regulator's setting register value;
to measure the actual VCCINT pin voltage, use a multimeter on the VCCINT test point near X4 (nominal 1.0 V).
"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_LOG = os.path.normpath(os.path.join(_WS, "..", "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ["TMP"] = _LOG
os.environ["TEMP"] = _LOG

def main():
    import chipwhisperer as cw
    print("chipwhisperer version:", getattr(cw, "__version__", "?"))

    t0 = time.time()
    cw305 = cw.target(None, cw.targets.CW305, fpga_id="100t")
    print("[OK] CW305 connected in %.1fs" % (time.time() - t0))

    # 1) VCC-INT setting value
    try:
        v = cw305.vccint_get()
        print("[INFO] vccint_get() = %r" % (v,))
        if isinstance(v, (list, tuple)):
            vv = v[0] | (v[1] << 8)
            print("[INFO] VCCINT register value = %d mV" % vv)
            ok = 900 <= vv <= 1100
            print("[%s] VCCINT setting within 0.9-1.1 V nominal window" % ("OK" if ok else "WARN"))
        else:
            print("[WARN] unknown vccint_get return format: %r" % (v,))
    except Exception as e:
        print("[FAIL] vccint_get: %r" % (e,))

    # 2) FPGA DONE
    try:
        prog = cw305.fpga.isFPGAProgrammed()
        print("[%s] FPGA programmed (DONE) = %s  <-- hard flag: power OK + bitstream loaded"
              % ("OK" if prog else "WARN", prog))
    except Exception as e:
        print("[FAIL] isFPGAProgrammed: %r" % (e,))

    # 3) buildtime (register read path)
    try:
        bt = cw305.get_fpga_buildtime()
        print("[%s] fpga buildtime = %s" % ("OK" if bt else "WARN", bt))
    except Exception as e:
        print("[FAIL] get_fpga_buildtime: %r" % (e,))

    # 4) PLL clock (corroborates the power chain)
    try:
        f = cw305.pll.pll_outfreq_get(1)
        print("[INFO] PLL outfreq(1) = %r MHz" % (f,))
    except Exception as e:
        print("[INFO] PLL read skipped: %r" % (e,))

    print("done. (note: read-only check above; measure actual VCCINT pin voltage with a multimeter, nominal 1.0 V)")

if __name__ == "__main__":
    main()
