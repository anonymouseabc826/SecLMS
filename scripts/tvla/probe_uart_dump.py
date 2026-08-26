#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_uart_dump.py — on-board UART response byte-by-byte dump diagnostics (2026-08-21 evening)
Purpose: locate the root cause of the 0x72 marker corruption. Sends 0x63 /
HASH_ONCE(empty) / 0x6D once each, dumps the full 48B response, and compares it
against the expectation.
"""
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

RESP_SIZE = 48


def read_exact(port, n, timeout=8.0):
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


def dump(port, name, req, expect_digest=None):
    port.reset_input_buffer()
    port.write(req)
    r = read_exact(port, RESP_SIZE)
    print(f"[{name}] len={len(r)}")
    print(f"  full = {r.hex()}")
    print(f"  head = {r[:4].hex()}  (marker 0x{r[0]:02x} status {r[1]} err {r[2]} rsv {r[3]})")
    if expect_digest is not None and len(r) >= 48:
        got = r[16:48]
        same = got == expect_digest
        diff = [i for i in range(32) if got[i] != expect_digest[i]]
        print(f"  digest {'==EXP' if same else 'MISMATCH'} ({len(diff)}/32 bytes differ)")
        if diff:
            print(f"  diff bytes idx={diff}")
            for i in diff[:8]:
                print(f"    [{i}] got={got[i]:02x} exp={expect_digest[i]:02x} xor={got[i]^expect_digest[i]:02x}")
    return r


def main():
    i = bytes(range(16))  # 00..0f
    q = 0
    seed = bytes(range(32))
    with Cw305Serial(timeout=5.0) as port:
        print("=== buildtime:", end=" ")
        try:
            print(port.get_buildtime())
        except Exception as e:
            print("ERR", e)
        port.reset_input_buffer()
        for _ in range(3):
            port.read(4096)
        port.reset_input_buffer()

        # 0x63 seed load (fixed seed)
        dump(port, "0x63 seedload", bytes([0x63]) + seed)

        # HASH_ONCE empty (0x48 len=0)
        dump(port, "0x48 empty", bytes([0x48, 0x00]))

        # 0x6D derive_randomizer (needs seed preloaded)
        dump(port, "0x6D derive", bytes([0x6D]) + i + struct.pack("<I", q),
             expect_digest=hashlib.shake_256(i + struct.pack(">I", q) + b"\x85\x85" + seed).digest(32))

        # HASH_ONCE empty again
        dump(port, "0x48 empty#2", bytes([0x48, 0x00]))

    print("DONE")


if __name__ == "__main__":
    main()
