#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vccint_load_h15.py - VCC-INT external supply true full-load verification (2026-08-18 rev2)

Fixes to v1:
  1) Drain now polls in_waiting (v1's read(4096)x3 blocked 35s x3=105s on an empty FIFO; the command was never even sent)
  2) 0x4B KEYGEN response = 48B frame + 56B LMS public key (v1 only drained 32B)

Single LMS KeyGen W4_H15 (456M total cycles @50MHz ~ 9s of hardware full load).
User watches the DC supply panel current: it should rise clearly within 9s (0.3-1.5A).
"""
import os
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

OP_KEYGEN = 0x4B
VEC = os.path.join(_ROOT, "build", "vectors", "shake_lms_verify_vector_W4_H15.txt")
PUB_LEN = 56  # LMS public key = 4 type + 4 otstype + 16 I + 32 root


def load_priv():
    with open(VEC, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("PRIVATE_KEY="):
                priv = bytes.fromhex(line.split("=", 1)[1])
                if len(priv) == 60:
                    return priv
    raise SystemExit("PRIVATE_KEY not found in %s" % VEC)


def drain(port):
    """Non-blocking drain: only read the bytes already in the FIFO, do not wait."""
    for _ in range(20):
        try:
            w = port.in_waiting
        except Exception:
            break
        if w <= 0:
            break
        port.read(w)
    port.reset_input_buffer()


def read_exact(port, n, timeout):
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        c = port.read(n - len(buf))
        if c:
            buf.extend(c)
        else:
            time.sleep(0.005)
    return bytes(buf)


def main():
    priv = load_priv()
    print("PRIVATE_KEY (W4_H15) loaded.")
    print(">>> About to launch LMS KeyGen W4_H15: ~9s of 100% hardware full load <<<")
    print(">>> Watch the DC supply panel: current should rise clearly within 9s <<<")
    time.sleep(2)
    with Cw305Serial(timeout=3.0) as port:
        drain(port)
        port.write(bytes([OP_KEYGEN]) + priv)
        t0 = time.monotonic()
        resp = read_exact(port, 48, timeout=30.0)
        el = time.monotonic() - t0
        print("48B frame took %.2fs, marker=%s" % (el, resp[:1].hex()))
        if resp[:1] == b"\x52":
            pub = read_exact(port, PUB_LEN, timeout=5.0)
            print("public key %d/%d B read within %.2fs" % (len(pub), PUB_LEN, time.monotonic() - t0))
            print("LMS KeyGen W4_H15 done (normal 0x52). Total time %.1fs" % (time.monotonic() - t0))
        else:
            print("abnormal response:", resp[:8].hex())
    print("Verdict: current clearly rising within 9s => external supply works; barely moving => check DIP switches/banana plugs")


if __name__ == "__main__":
    main()
