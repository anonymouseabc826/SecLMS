#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fw_update_cw305.py — CW305 SAM3U firmware upgrade 0.51.0 → 0.53.0 (bundled)

Flow: connect → enterBootloader (erase firmware) → wait for AT91 serial port enumeration →
      program mcufw.bin → wait for device recovery → verify. Fully software-driven; no JP5 jumper needed.
Risk: low (protected by the SAM3U ROM bootloader; on failure retry or recover via JP5).
"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, ".."))
_LOG = os.path.normpath(os.path.join(_ROOT, "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ["TMP"] = _LOG
os.environ["TEMP"] = _LOG


def wait_for(fn, timeout, what):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = fn()
            if r:
                return r
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError("timeout waiting for %s" % what)


def main():
    import chipwhisperer as cw
    from chipwhisperer.capture.scopes.cwhardware.ChipWhispererSAM3Update import (
        get_at91_ports,
    )

    # 1. connect and enter bootloader
    print("[1/5] connecting to CW305 ...", flush=True)
    cw305 = cw.target(None, cw.targets.CW305, defines_files=[])
    print("      isFPGAProgrammed:", cw305.fpga.isFPGAProgrammed())
    print("[2/5] enterBootloader (erase SAM3U firmware) ...", flush=True)
    cw305._naeusb.enterBootloader(True)
    try:
        cw305.dis()
    except Exception:
        pass
    print("      bootloader entered, waiting for AT91 serial port ...", flush=True)

    # 2. wait for AT91 serial port (bootloader enumeration)
    ports = wait_for(lambda: get_at91_ports() or None, 40,
                     "AT91 bootloader serial port")
    port = ports[0] if isinstance(ports, (list, tuple)) else ports
    print("      bootloader on: %s" % port, flush=True)

    # 3. program firmware
    print("[3/5] programming firmware 0.53.0 ...", flush=True)
    from chipwhisperer.capture.scopes.cwhardware.ChipWhispererSAM3Update import (
        SAMFWLoader,
    )
    loader = SAMFWLoader(None)
    ok = loader.program(port, hardware_type="cw305")
    print("      program returned:", ok, flush=True)
    if not ok:
        raise RuntimeError("firmware programming failed")

    # 4. wait for device recovery (bootloader exits → WinUSB re-enumerates)
    print("[4/5] waiting for CW305 to re-enumerate ...", flush=True)
    time.sleep(3)
    wait_for(lambda: cw.list_devices() or None, 40, "CW305 re-enumeration")
    print("      re-enumerated", flush=True)

    # 5. verify firmware version (NAEUSB prints a firmware-version warning on connect)
    print("[5/5] verifying ...", flush=True)
    t = cw.target(None, cw.targets.CW305, defines_files=[])
    print("      connected; isFPGAProgrammed:", t.fpga.isFPGAProgrammed())
    try:
        print("      buildtime:", t.get_fpga_buildtime())
    except Exception as e:
        print("      buildtime ERR:", repr(e))
    t.dis()
    print("DONE")


if __name__ == "__main__":
    main()
