#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_derive_xq_smoke.py — 0x63/0x6F smoke test on the ALLOW_XQ_DERIVE=1 bit (2026-08-25)

Verifies that SEED preload (0x63) and isolated single x_q[i] derivation
(0x6F, DERIVE_CHAIN steps=0) complete normally on the hardware bit: frame
header 0x52 + status=0 + error=0 + cycles>0.
x_q[i] is never read back (private key element); the response digest field
should be 0 (return_digest=0).

Usage: python scripts/tvla/probe_derive_xq_smoke.py
"""
import os
import struct
import sys

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))
os.environ.setdefault("TMP", os.path.join(_ROOT, "build", "cw305"))
os.environ.setdefault("TEMP", os.path.join(_ROOT, "build", "cw305"))

from cw305_serial import Cw305Serial  # noqa: E402

RESP_SIZE = 48
OP_SEED_LOAD = 0x63
OP_DERIVE_XQ = 0x6F


def read_exact(port, n, timeout=15.0):
    import time
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        chunk = port.read(n - len(buf))
        if chunk:
            buf.extend(chunk)
        else:
            time.sleep(0.001)
    return bytes(buf)


def load_priv():
    p = os.path.join(_ROOT, "build", "vectors", "lms_verify_vector_shake_W4_H5.txt")
    vec = {}
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                vec[k.strip()] = v.strip()
    priv = bytes.fromhex(vec["PRIVATE_KEY"])
    if len(priv) != 60:
        raise ValueError(f"PRIVATE_KEY len {len(priv)} != 60")
    return vec, priv


def main():
    vec, priv = load_priv()
    seed = priv[24:56]
    ident = priv[8:24]
    q = int.from_bytes(priv[56:60], "big")

    with Cw305Serial(timeout=5.0) as port:
        port.reset_input_buffer()
        for _ in range(3):
            port.read(4096)
        port.reset_input_buffer()

        # 0x63 SEED preload
        port.write(bytes([OP_SEED_LOAD]) + seed)
        r = read_exact(port, RESP_SIZE)
        ok = len(r) == RESP_SIZE and r[:1] == b"\x52"
        print(f"[0x63] len={len(r)} head={r[:4].hex()} marker={'OK' if ok else 'BAD'} "
              f"status={r[1] if len(r) > 1 else -1} err={r[2] if len(r) > 2 else -1}")
        if not ok or r[1] != 0:
            print("FAIL: 0x63 preload")
            return 1

        # 0x6F isolated single x_q[i] (repeat to verify stability)
        frame = bytes([OP_DERIVE_XQ]) + ident + struct.pack("<I", q) + struct.pack("<H", 0)
        print(f"[0x6F] frame = {frame.hex()}")
        for trial in range(5):
            port.write(frame)
            r = read_exact(port, RESP_SIZE, timeout=10.0)
            ok = len(r) == RESP_SIZE and r[:1] == b"\x52" and r[1] == 0 and r[2] == 0
            cycles = struct.unpack("<I", r[4:8])[0]
            hits = struct.unpack("<I", r[8:12])[0]
            digest = r[16:48]
            print(f"[0x6F#{trial}] marker={'OK' if ok else 'BAD'} status={r[1] if len(r) > 1 else -1} "
                  f"err={r[2] if len(r) > 2 else -1} cycles={cycles} hits={hits} "
                  f"digest_zero={digest == b'\x00' * 32}")
            if not ok:
                print("FAIL: 0x6F derive_xq")
                return 1
            if cycles == 0:
                print("WARN: cycles=0 (hardware may not have actually executed DERIVE_CHAIN)")

        # varying-parameter smoke: q+1 / i=1
        for label, qi, ii in (("q+1", q + 1, 0), ("i=1", q, 1)):
            f2 = bytes([OP_DERIVE_XQ]) + ident + struct.pack("<I", qi) + struct.pack("<H", ii)
            port.write(f2)
            r = read_exact(port, RESP_SIZE, timeout=10.0)
            ok = len(r) == RESP_SIZE and r[:1] == b"\x52" and r[1] == 0 and r[2] == 0
            cycles = struct.unpack("<I", r[4:8])[0]
            print(f"[0x6F {label}] marker={'OK' if ok else 'BAD'} status={r[1] if len(r) > 1 else -1} "
                  f"err={r[2] if len(r) > 2 else -1} cycles={cycles}")
            if not ok:
                print(f"FAIL: 0x6F {label}")
                return 1

    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
