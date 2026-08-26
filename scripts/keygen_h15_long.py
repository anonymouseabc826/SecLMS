#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keygen_h15_long.py - H15 keygen long-duration listen (distinguish very slow vs hung)

After sending the 0x4B W4_H15 keygen command, keep listening on the FIFO for up to 360s:
  - receiving the 48B frame (marker 0x52) + 56B public key -> done, record elapsed time
  - any sporadic data in between -> firmware is still emitting/progressing (slow but alive)
  - no data at all -> truly hung (infinite loop / waiting on hardware)
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
os.environ.setdefault("TMP", "build/cw305")
os.environ.setdefault("TEMP", "build/cw305")
from cw305_serial import Cw305Serial  # noqa: E402

OP_KEYGEN = 0x4B
VEC = "build/vectors/shake_lms_verify_vector_W4_H15.txt"
MAX_WAIT = 360.0


def load_priv():
    with open(VEC, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("PRIVATE_KEY="):
                priv = bytes.fromhex(line.split("=", 1)[1])
                if len(priv) == 60:
                    return priv
    raise SystemExit("no PRIVATE_KEY")


def main():
    priv = load_priv()
    with Cw305Serial(timeout=0.5) as port:
        # drain input
        for _ in range(20):
            w = port.in_waiting
            if w <= 0:
                break
            port.read(w)
        port.reset_input_buffer()
        t0 = time.monotonic()
        port.write(bytes([OP_KEYGEN]) + priv)
        print("H15 keygen issued @ t=0.00s, listening for 360s...")
        buf = bytearray()
        last_print = 0.0
        while time.monotonic() - t0 < MAX_WAIT:
            w = port.in_waiting
            if w > 0:
                data = port.read(w)
                buf.extend(data)
                now = time.monotonic() - t0
                if now - last_print > 5.0:
                    print("  t=%6.1fs: received %d B total: %s" % (now, len(buf), buf[:32].hex()))
                    last_print = now
                if len(buf) >= 48 and buf[:1] == b"\x52":
                    print("  t=%6.1fs: 48B frame arrived (marker=0x52)" % (time.monotonic() - t0))
                    # wait for public key
                    while len(buf) < 104 and time.monotonic() - t0 < MAX_WAIT:
                        w = port.in_waiting
                        if w > 0:
                            buf.extend(port.read(w))
                        else:
                            time.sleep(0.02)
                    print("done: total %.1fs, frame+public key %d B" % (time.monotonic() - t0, len(buf)))
                    return
            else:
                time.sleep(0.05)
        print("timeout after %.0fs: received %d B total -> %s"
              % (MAX_WAIT, len(buf), "very slow (data present)" if len(buf) else "truly hung (zero data)"))


if __name__ == "__main__":
    main()
