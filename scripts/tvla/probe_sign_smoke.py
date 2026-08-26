#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_sign_smoke.py — 0x63/0x4B/0x53 smoke test on the shuffle bit (2026-08-21 evening)
Verifies that keygen/sign commands complete normally on the hardware bit and the
marker is clean (does not check digest correctness; only confirms command
completion + frame header 0x52 + status=0), as a pre-acquisition smoke test for
Sign TVLA.
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
KEYGEN_PUB_LEN = 56
SIGN_LEN_W4H5 = 44 + 67 * 32 + 5 * 32  # 2348


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
    seed = bytes(range(32))
    msg = b""
    with Cw305Serial(timeout=5.0) as port:
        port.reset_input_buffer()
        for _ in range(3):
            port.read(4096)
        port.reset_input_buffer()

        # 0x63 preload
        port.write(bytes([0x63]) + seed)
        r = read_exact(port, RESP_SIZE)
        print(f"[0x63] len={len(r)} head={r[:4].hex()} marker={'OK' if r[:1]==b'\x52' else 'BAD'}")

        # 0x4B keygen (60B priv)
        port.write(bytes([0x4B]) + priv)
        kr = read_exact(port, RESP_SIZE, timeout=20.0)
        pub = read_exact(port, KEYGEN_PUB_LEN, timeout=5.0) if len(kr) >= RESP_SIZE else b""
        print(f"[0x4B] head={kr[:4].hex()} marker={'OK' if kr[:1]==b'\x52' else 'BAD'} "
              f"status={kr[1]} err={kr[2]} pub_len={len(pub)}")

        # 0x53 sign (60B priv + u16 len + msg)
        port.write(bytes([0x53]) + priv + struct.pack(">H", len(msg)) + msg)
        sr = read_exact(port, RESP_SIZE, timeout=20.0)
        sig = read_exact(port, SIGN_LEN_W4H5, timeout=10.0) if len(sr) >= RESP_SIZE else b""
        print(f"[0x53] head={sr[:4].hex()} marker={'OK' if sr[:1]==b'\x52' else 'BAD'} "
              f"status={sr[1]} err={sr[2]} sig_len={len(sig)}")

        # repeat 0x53 to check stability
        port.write(bytes([0x53]) + priv + struct.pack(">H", len(msg)) + msg)
        sr2 = read_exact(port, RESP_SIZE, timeout=20.0)
        sig2 = read_exact(port, SIGN_LEN_W4H5, timeout=10.0) if len(sr2) >= RESP_SIZE else b""
        print(f"[0x53#2] head={sr2[:4].hex()} marker={'OK' if sr2[:1]==b'\x52' else 'BAD'} "
              f"status={sr2[1]} err={sr2[2]} sig_len={len(sig2)}")
        if len(sig) and len(sig2):
            print(f"[sig] sig==sig2 (deterministic) = {sig == sig2}")

    print("DONE")


if __name__ == "__main__":
    main()
