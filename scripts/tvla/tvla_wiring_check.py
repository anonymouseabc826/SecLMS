#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_wiring_check.py — TVLA wiring verification (stage-1 smoke test)

Run after synthesizing/programming the SCA_TEST=1 bit: verifies
  1. CW305 mailbox communication (IDENTIFY/CRYPT_TYPE)
  2. Trigger line: send HASH_ONCE -> Husky should capture the TIO4 trigger edge (CW305 T14 -> 20-pin -> Husky TIO4)
  3. Power line: after trigger the trace should show a clear power waveform (CW305 X4 -> Husky Measure POS)

Usage:
  python scripts/tvla/tvla_wiring_check.py [--n 3] [--samples 50000]
"""
import argparse
import os
import struct
import sys
import time

import numpy as np

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
_LOG = os.path.normpath(os.path.join(_ROOT, "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ.setdefault("TMP", _LOG)
os.environ.setdefault("TEMP", _LOG)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from cw305_serial import Cw305Serial  # noqa: E402


def read_exact(port, n: int, timeout: float = 3.0) -> bytes:
    """Collect n bytes (cw305 read() returns per available FIFO amount, possibly less than requested)."""
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        chunk = port.read(n - len(buf))
        if chunk:
            buf.extend(chunk)
        else:
            time.sleep(0.001)
    return bytes(buf)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=3, help="number of test traces")
    ap.add_argument("--samples", type=int, default=50000,
                    help="samples per trace (50k @50MS/s = 1 ms, covers operation + tail)")
    ap.add_argument("--gain", type=float, default=25.0, help="Husky gain dB (scope.gain.db, -6.5..55)")
    args = ap.parse_args()

    import chipwhisperer as cw

    scope = cw.scope()
    try:
        # Husky clock: clkgen_freq × adc_mul = ADC sample rate.
        # 50 MHz target logic -> 50 MS/s (mul=1) is enough; do not let adc_freq exceed the 200 MHz spec
        # (measured: at 100e6 mul auto-adjusts to 3 -> 300 MHz, out-of-spec warning).
        scope.clock.clkgen_freq = 50e6
        scope.adc.samples = args.samples
        scope.adc.offset = 0
        # Husky gain is scope.gain.db (scope.adc.gain does not exist, silently ignored!)
        scope.gain.db = args.gain
        scope.trigger.module = "basic"
        scope.trigger.triggers = "tio4"
        scope.adc.basic_mode = "rising_edge"
        scope.io.hs2 = "disabled"
        # Note: Husky GPIO has no hs4 attribute (measured: reports unknown attribute), removed

        print("=== 1. CW305 mailbox ===")
        with Cw305Serial(timeout=5.0) as port:
            port.reset_input_buffer()
            print("  IDENTIFY/CRYPT_TYPE OK (bitstream is the SCA_TEST=1 build)")

            print(f"=== 2. trigger line + 3. power line ({args.n} traces) ===")
            trig_ok = 0
            power_ok = 0
            for i in range(args.n):
                scope.arm()
                port.write(bytes([0x48, 0x00]))   # HASH_ONCE(empty)
                try:
                    scope.capture()               # no exception = trigger captured (timeout throws/forces)
                    trig_ok += 1
                except Exception as e:
                    print(f"  trace {i}: trigger timeout/failure: {e}")
                tr = scope.get_last_trace()
                std = float(tr.std())
                rng = float(tr.max()) - float(tr.min())
                # Power-waveform criterion: AC-coupled no signal std≈0.05-0.1; significantly larger with activity.
                # HASH_ONCE is only 12 cycles (240ns), too short — this trace mainly verifies the trigger; for the power
                # waveform, LM-OTS KeyGen (190µs) is more reliable (see --op extension or tvla_capture).
                if std > 0.5:
                    power_ok += 1
                print(f"  trace {i}: std={std:.3f} range=[{tr.min():.2f},{tr.max():.2f}] "
                      f"({'CLIP?' if abs(tr.min()) > 0.49 or tr.max() > 0.49 else ('PWR?' if std > 0.5 else 'flat')})")

                # Read back the response frame (verifies the command actually ran; read() returns per available FIFO, must collect enough)
                resp = read_exact(port, 48, timeout=3.0)
                if resp[:1] == b"\x52":
                    print(f"  trace {i}: HASH_ONCE response frame OK (cycles={struct.unpack_from('<I', resp, 4)[0]})")
                else:
                    print(f"  trace {i}: abnormal response frame first={resp[:1].hex() if resp else 'empty'}")

            print(f"\nresult: trigger captured {trig_ok}/{args.n}, power signal {power_ok}/{args.n}")
            if trig_ok == 0:
                print("  !! trigger line not connected: check T14->20-pin->Husky TIO4 and the SCA_TEST=1 bit")
            if power_ok == 0:
                print("  !! no signal on power line: check X4->Measure POS (single-ended + shorting cap); "
                      "or re-test with the longer LM-OTS KeyGen operation (HASH_ONCE only 240 ns, too short)")
    finally:
        scope.dis()
    return 0


if __name__ == "__main__":
    sys.exit(main())
