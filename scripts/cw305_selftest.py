#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CW305 connectivity self-test script (2026-08-18)

Purpose: verify the full ChipWhisperer env + CW305/Husky USB enumeration + CW305 API chain
         (connect → JTAG programming (auto-program bundled AES_100t.bit) → DONE → register read → buildtime → PLL).

Run: python scripts/cw305_selftest.py

Notes:
- Depends on chipwhisperer>=6.0 (requires chipwhisperer>=6.0).
- TMP/TEMP redirected to build/cw305/ to avoid an unwritable system TEMP directory.
- If CW305 is unprogrammed, fpga_id='100t' auto-programs NewAE's bundled AES bitstream (reversible;
  a later program of this project's bitstream overwrites it); skipped if already programmed.
"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_LOG = os.path.normpath(os.path.join(_WS, "..", "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ["TMP"] = _LOG
os.environ["TEMP"] = _LOG

PASSED = []
FAILED = []


def report(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name)
    print("[%s] %s: %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def main():
    # ---- 1. import ----
    try:
        import chipwhisperer as cw
        report("chipwhisperer import", True, "version=%s" % getattr(cw, "__version__", "?"))
    except Exception as e:
        report("chipwhisperer import", False, repr(e))
        sys.exit(1)

    # ---- 2. USB enumeration (usb1 direct enumeration, real VID/PID) ----
    found = {}
    try:
        import usb1
        ctx = usb1.USBContext()
        for d in ctx.getDeviceList():
            vid, pid = d.getVendorID(), d.getProductID()
            if vid == 0x2B3E:
                try:
                    sn = d.getSerialNumber()
                except Exception:
                    sn = None
                found.setdefault(pid, []).append((d.getBusNumber(), d.getDeviceAddress(), sn))
                print("   NewAE USB: PID=%04X bus=%d addr=%d sn=%r"
                      % (pid, d.getBusNumber(), d.getDeviceAddress(), sn))
        report("NewAE device enumeration (VID_2B3E)", len(found) > 0,
               str({hex(k): v for k, v in found.items()}))
        report("CW305 present (PID C305)", 0xC305 in found, str(found.get(0xC305)))
        report("Husky present (PID ACE5)", 0xACE5 in found, str(found.get(0xACE5)))
    except Exception as e:
        report("USB enumeration (usb1)", False, repr(e))
    # Extra: chipwhisperer's built-in named enumeration (name/sn/hw_loc, for cross-reference)
    try:
        devs = cw.list_devices()
        print("   cw.list_devices(): %s" % devs)
    except Exception as e:
        print("   cw.list_devices() failed: %r" % (e,))

    # ---- 3. CW305 connection + auto-programming ----
    cw305 = None
    try:
        t0 = time.time()
        cw305 = cw.target(None, cw.targets.CW305, fpga_id="100t")
        report("CW305 connection (cw.target)", True, "took %.1fs" % (time.time() - t0))
    except Exception as e:
        report("CW305 connection (cw.target)", False, repr(e))
        _summary()
        sys.exit(1)

    # ---- 4. FPGA status ----
    try:
        prog = cw305.fpga.isFPGAProgrammed()
        report("FPGA programmed (DONE)", bool(prog), "isFPGAProgrammed=%s" % prog)
    except Exception as e:
        report("FPGA DONE check", False, repr(e))

    # ---- 5. Register read path ----
    try:
        bt = cw305.get_fpga_buildtime()
        report("get_fpga_buildtime (register read)", True, "buildtime=%s" % bt)
    except Exception as e:
        report("get_fpga_buildtime", False, repr(e))

    for regname in ("REG_CRYPT_TYPE", "REG_CRYPT_REV"):
        try:
            reg = getattr(cw305, regname)
            val = cw305.fpga_read(reg, 4)
            report("fpga_read %s" % regname, True, "addr=0x%02X val=%s" % (reg, list(val)))
        except Exception as e:
            report("fpga_read %s" % regname, False, repr(e))

    # ---- 6. User LED blink (visual confirmation, non-fatal) ----
    try:
        if getattr(cw305, "REG_USER_LED", None) is not None:
            cw305.fpga_write(cw305.REG_USER_LED, [1])
            time.sleep(0.3)
            cw305.fpga_write(cw305.REG_USER_LED, [0])
            report("user LED write (REG_USER_LED)", True, "toggled 0.3s on/off")
        else:
            report("user LED write (REG_USER_LED)", False, "REG_USER_LED not defined")
    except Exception as e:
        report("user LED write", False, repr(e))

    # ---- 7. PLL (CDCE906) ----
    try:
        f = cw305.pll.pll_outfreq_get(1)
        report("PLL CDCE906 read frequency", True, "outfreq(1)=%r" % f)
    except Exception as e:
        report("PLL CDCE906 read frequency", False, repr(e))

    # ---- Disconnect ----
    try:
        cw305.dis()
        report("disconnect (dis)", True, "")
    except Exception as e:
        report("disconnect (dis)", False, repr(e))

    _summary()


def _summary():
    print("\n==== self-test summary: %d PASS / %d FAIL ====" % (len(PASSED), len(FAILED)))
    for n in PASSED:
        print("  PASS  %s" % n)
    for n in FAILED:
        print("  FAIL  %s" % n)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
