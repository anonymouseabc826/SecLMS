#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clock_check.py - verify the actual CW305 clk50 frequency (2026-08-18)

Method: 0x4B H10 keygen, parse the response frame's total_cycles (frame[20..23] little-endian) and wall time,
        f_actual = total_cycles / wall_seconds.
Reference: DaVinci board test W4_H10 keygen total = 14,248,418 cycles (@50MHz = 285ms).
  - f_actual ≈ 50MHz  -> clock OK, problem in firmware/tree cache
  - f_actual ≈ 5MHz   -> clk50 is only ~5MHz (10x slow!) -- clock root cause
Also read hw cycles (frame[4..7]): H10 keygen should be ≈ 9,495,528.
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
os.environ.setdefault("TMP", "build/cw305")
os.environ.setdefault("TEMP", "build/cw305")
from cw305_serial import Cw305Serial  # noqa: E402

OP_KEYGEN = 0x4B
VEC = "build/vectors/shake_lms_verify_vector_W4_H10.txt"


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
    with Cw305Serial(timeout=3.0) as port:
        for _ in range(20):
            w = port.in_waiting
            if w <= 0:
                break
            port.read(w)
        port.reset_input_buffer()
        t0 = time.monotonic()
        port.write(bytes([OP_KEYGEN]) + priv)
        # Read the 48B frame
        buf = bytearray()
        while len(buf) < 48 and time.monotonic() - t0 < 40:
            w = port.in_waiting
            if w > 0:
                buf.extend(port.read(w))
            else:
                time.sleep(0.01)
        wall = time.monotonic() - t0
        if len(buf) < 48 or buf[0] != 0x52:
            print("H10 keygen response abnormal: %d B, marker=%s" % (len(buf), buf[:4].hex()))
            return
        hw = struct.unpack_from("<I", buf, 4)[0]
        total = struct.unpack_from("<I", buf, 20)[0]
        print("H10 keygen: wall=%.3fs  hw_cycles=%d  total_cycles=%d" % (wall, hw, total))
        print("actual clock = total/wall = %.2f MHz" % (total / wall / 1e6))
        print("reference: DaVinci total=14,248,418 @50MHz=285ms; hw should be ≈9,495,528")
        # Drain the public key
        while len(buf) < 104 and time.monotonic() - t0 < 5:
            w = port.in_waiting
            if w > 0:
                buf.extend(port.read(w))
            else:
                time.sleep(0.01)


if __name__ == "__main__":
    main()
