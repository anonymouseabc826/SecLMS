#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vccint_load_test.py - VCC-INT external supply load verification (2026-08-18)

Purpose: confirm whether the external DC supply really powers VCCINT.
Method: after flashing the project bit, run LMOTS_KEYGEN (the heaviest operation) continuously for 30s
       to keep the FPGA at full load; the user watches the DC supply panel current:
        - current rises above 0.5 A  -> external supply genuinely effective (normal)
        - current still ~0.03 A      -> external supply not connected to VCCINT (check DIP switches/banana plugs)
"""
import glob
import os
import struct
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, ".."))
_LOG = os.path.normpath(os.path.join(_ROOT, "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ.setdefault("TMP", _LOG)
os.environ.setdefault("TEMP", _LOG)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from cw305_serial import Cw305Serial  # noqa: E402

OP_LMOTS_KEYGEN = 0x60
DURATION = 30  # seconds


def load_priv() -> bytes:
    for pat in ("build/vectors/*keygen*shake*.txt", "build/vectors/*.txt"):
        for p in glob.glob(pat):
            try:
                with open(p, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("PRIVATE_KEY="):
                            priv = bytes.fromhex(line.split("=", 1)[1])
                            if len(priv) == 60:
                                return priv
            except Exception:
                continue
    raise SystemExit("60B PRIVATE_KEY vector not found; run make vectors first")


def read_exact(port, n, timeout=3.0):
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        c = port.read(n - len(buf))
        if c:
            buf.extend(c)
        else:
            time.sleep(0.001)
    return bytes(buf)


def main():
    priv = load_priv()
    print("PRIVATE_KEY loaded (60B). Starting 30s full load: LMOTS_KEYGEN loop...")
    print(">>> Watch the DC supply panel: current should rise from 0.03A to above 0.5A <<<")
    with Cw305Serial(timeout=5.0) as port:
        port.reset_input_buffer()
        for _ in range(3):
            port.read(4096)
        port.reset_input_buffer()
        frame = bytes([OP_LMOTS_KEYGEN]) + priv
        t0 = time.monotonic()
        n = 0
        while time.monotonic() - t0 < DURATION:
            port.write(frame)
            resp = read_exact(port, 48)
            if resp[:1] == b"\x52":
                read_exact(port, 32)  # public key (drain FIFO, keep bridge state sane)
                n += 1
            else:
                print("!! bad resp marker:", resp[:4].hex(), file=sys.stderr)
            if n % 100 == 0 and n:
                el = time.monotonic() - t0
                print("  %d ops, %.1fs (%.0f ms/op)" % (n, el, el / n * 1000))
        el = time.monotonic() - t0
        print("done: %d LMOTS_KEYGEN ops in %.1fs (%.0f ops/s)"
              % (n, el, n / el if el else 0))
    print("Verdict: current >0.5A => external supply effective; still ~0.03A => check DIP switches/banana plugs")


if __name__ == "__main__":
    main()
