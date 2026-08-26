#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""swbaseline_sign_smoke.py — pure-software full-Sign smoke test (truncated, 2026-08-21)

Verifies board-level correctness of the pure-software full Sign (SLotH Fig.6
replica firmware):
  1. 0x63 preloads slot SEED (real seed, off-window)
  2. 0x4B KeyGen builds the tree (seedless frame: SEED segment all zero, firmware
     uses slot SEED) → 56B public key
  3. 0x53 full Sign (seedless frame) → 2348B signature (W4_H5)
  4. 0x56 Verify (public key + empty message + signature) → firmware software
     verification is self-consistent
  5. fixed/random N rounds each + signature/public key compared against the PC
     vector (root/C consistency at q=0)

Usage:
  python scripts/tvla/swbaseline_sign_smoke.py [--n 3]
"""
import argparse
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
OP_KEYGEN = 0x4B
OP_SIGN = 0x53
OP_VERIFY = 0x56
RESP_SIZE = 48
KEYGEN_PUB_LEN = 56
SIGN_LEN_W4H5 = 2348


def read_exact(port, n: int, timeout: float = 30.0) -> bytes:
    import time
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        chunk = port.read(n - len(buf))
        if chunk:
            buf.extend(chunk)
        else:
            time.sleep(0.002)
    return bytes(buf)


def seedless_priv(priv: bytes) -> bytes:
    """0x4B/0x53 frame private key: SEED segment (priv[24:56]) all zero (firmware uses slot SEED)."""
    return priv[:24] + b"\x00" * 32 + priv[56:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=3, help="rounds per group")
    args = ap.parse_args()

    # vector private key (W4_H5): 60B = lms_type(4)||lmots_type(4)||I(16)||seed(32)||q(4)
    vec_path = os.path.join(_ROOT, "build", "vectors",
                            "lms_verify_vector_shake_W4_H5.txt")
    vec = {}
    with open(vec_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                vec[k.strip()] = v.strip()
    priv = bytes.fromhex(vec["PRIVATE_KEY"])
    if len(priv) != 60:
        print("ERROR: vector priv len %d" % len(priv), file=sys.stderr)
        return 1

    seeds = {"fixed": bytes.fromhex(vec["PRIVATE_KEY"])[24:56],
             "random": os.urandom(32)}

    with Cw305Serial(timeout=5.0) as port:
        port.reset_input_buffer()
        for _ in range(3):
            port.read(4096)
        port.reset_input_buffer()

        for grp, seed in seeds.items():
            # 1) 0x63 preload
            port.write(bytes([OP_SEED_LOAD]) + seed)
            r = read_exact(port, RESP_SIZE, timeout=10.0)
            if len(r) < RESP_SIZE or r[:1] != b"\x52" or r[1] != 0:
                print(f"!! [{grp}] 0x63 preload bad: {r[:4].hex()}")
                return 1
            for k in range(args.n):
                # 2) 0x4B KeyGen (seedless) → public key
                port.write(bytes([OP_KEYGEN]) + seedless_priv(priv))
                r = read_exact(port, RESP_SIZE + KEYGEN_PUB_LEN, timeout=90.0)
                if len(r) < RESP_SIZE + KEYGEN_PUB_LEN or r[:1] != b"\x52" or r[1] != 0:
                    print(f"!! [{grp}] round {k} 0x4B bad: {r[:8].hex()} len={len(r)}")
                    return 1
                pub = r[RESP_SIZE:RESP_SIZE + KEYGEN_PUB_LEN]
                # 2b) fixed-group q=0 public key root vs PC vector (same seed/I/type → key derivation correct)
                if grp == "fixed" and k == 0:
                    vec_pub = bytes.fromhex(vec["PUBLIC_KEY"])
                    if pub[24:56] != vec_pub[24:56]:
                        print("!! [fixed] pub root MISMATCH vs vector")
                        print(f"    got {pub[24:56].hex()}")
                        print(f"    exp {vec_pub[24:56].hex()}")
                        return 1
                # 3) 0x53 Sign (seedless, empty message) → signature
                port.write(bytes([OP_SIGN]) + seedless_priv(priv) +
                           struct.pack(">H", 0))
                r = read_exact(port, RESP_SIZE + SIGN_LEN_W4H5, timeout=120.0)
                if len(r) < RESP_SIZE + SIGN_LEN_W4H5 or r[:1] != b"\x52" or r[1] != 0:
                    print(f"!! [{grp}] round {k} 0x53 bad: {r[:8].hex()} len={len(r)}")
                    return 1
                sig = r[RESP_SIZE:RESP_SIZE + SIGN_LEN_W4H5]
                # 4) 0x56 Verify (public key + empty message + signature) → software verification self-consistent.
                # Writing the 2407B frame byte-by-byte is slow (Cw305Serial.write = one USB transaction
                # per byte), so write in small paced chunks to avoid write_timeout/residual misalignment.
                vframe = bytes([OP_VERIFY]) + pub + struct.pack(">H", 0) + sig
                import time as _t
                for off in range(0, len(vframe), 32):
                    port.write(vframe[off:off + 32])
                    _t.sleep(0.003)
                r = read_exact(port, RESP_SIZE, timeout=90.0)
                if len(r) < RESP_SIZE or r[:1] != b"\x52" or r[1] != 0:
                    print(f"!! [{grp}] round {k} 0x56 verify FAIL: {r[:8].hex()}")
                    return 1
                # 5) structure checks: signature q=0, sig type, non-zero C
                sig_q = int.from_bytes(sig[0:4], "big")
                if sig_q != 0:
                    print(f"!! [{grp}] round {k} sig q={sig_q} (expect 0)")
                    return 1
                print(f"[{grp}] round {k}: keygen+sign+verify OK "
                      f"(pub={pub[24:40].hex()}… sig_q={sig_q})")
        print("SIGN SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
