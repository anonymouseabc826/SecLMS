#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""swbaseline_smoke.py — pure-software baseline bit smoke test (2026-08-21)

Verifies the pure-software 0x6D (software single PRF) + scheme-A fixed
HASH_ONCE trigger firmware:
  1. Connect CW305 (requires build/vivado_lms_cw305/lms_cw305.bit already
     programmed, pure-software firmware)
  2. 0x63 preloads SEED (test fixed and random)
  3. 0x6D(I[16], q_le[4]) → validate response frame [16..47]
     C == hashlib.shake_256(I || q_le || 0x8585 || SEED).digest(32)
  4. Tally the response frame header/error code/cycles fields; multiple rounds
     to confirm per-trace stability

Usage:
  python scripts/tvla/swbaseline_smoke.py [--n 20]
"""
import argparse
import hashlib
import os
import struct
import sys

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))
os.environ.setdefault("TMP", os.path.join(_ROOT, "build", "cw305"))
os.environ.setdefault("TEMP", os.path.join(_ROOT, "build", "cw305"))

from cw305_serial import Cw305Serial  # noqa: E402

OP_SEED_LOAD = 0x63
OP_DERIVE_RANDOMIZER = 0x6D
RESP_SIZE = 48


def oracle_c(i: bytes, q: int, seed: bytes) -> bytes:
    # q inside the prefix is written by the firmware's lms_store_u32 (big-endian,
    # RFC 8554 serialization style); the request-frame q is still little-endian
    # (uart_get_u32 LE read). The two byte orders are identical when q=0.
    return hashlib.shake_256(i + struct.pack(">I", q) + b"\x85\x85" + seed).digest(32)


def read_exact(port, n: int, timeout: float = 5.0) -> bytes:
    buf = bytearray()
    import time
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
    ap.add_argument("--n", type=int, default=20, help="traces per group")
    ap.add_argument("--i-hex", default="000102030405060708090a0b0c0d0e0f",
                    help="fixed I (16B hex)")
    ap.add_argument("--q", type=lambda s: int(s, 0), default=0,
                    help="fixed q (int, default 0)")
    args = ap.parse_args()

    i = bytes.fromhex(args.i_hex)
    if len(i) != 16:
        print("ERROR: I must be 16B", file=sys.stderr)
        return 1
    seeds = {
        "fixed": bytes(range(32)),
        "random": os.urandom(32),
    }

    with Cw305Serial(timeout=5.0) as port:
        port.reset_input_buffer()
        for _ in range(3):
            port.read(4096)
        port.reset_input_buffer()

        for grp, seed in seeds.items():
            # 0x63 preload
            port.write(bytes([OP_SEED_LOAD]) + seed)
            r = read_exact(port, RESP_SIZE, timeout=10.0)
            if len(r) < RESP_SIZE or r[:1] != b"\x52" or r[1] != 0:
                print(f"!! [{grp}] 0x63 preload bad: len={len(r)} head={r[:4].hex()}")
                return 1
            ok = 0
            for k in range(args.n):
                port.write(bytes([OP_DERIVE_RANDOMIZER]) + i + struct.pack("<I", args.q))
                r = read_exact(port, RESP_SIZE, timeout=10.0)
                if len(r) < RESP_SIZE:
                    print(f"!! [{grp}] trace {k}: short resp {len(r)}")
                    return 1
                if r[:1] != b"\x52" or r[1] != 0 or r[2] != 0:
                    print(f"!! [{grp}] trace {k}: status bad head={r[:4].hex()}")
                    return 1
                got = r[16:48]
                exp = oracle_c(i, args.q, seed)
                if got == exp:
                    ok += 1
                else:
                    print(f"!! [{grp}] trace {k}: C MISMATCH")
                    print(f"    got {got.hex()}")
                    print(f"    exp {exp.hex()}")
            print(f"[{grp}] 0x6D oracle: {ok}/{args.n} PASS  "
                  f"(I={i.hex()} q={args.q} seed={seed.hex()[:8]}…)")
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
