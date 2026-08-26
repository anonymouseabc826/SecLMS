#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_read_path.py — read-path isolation (batch read vs byte-by-byte read, 2026-08-22 morning)
Determine whether the 0x72/bit5 corruption is a read-path (Python/batch read)
issue or a genuine hardware issue:
  1. Byte-by-byte read: fpga_read(TX_BYTE, 1) pops 1 byte at a time × 48
  2. Batch read: fpga_read(TX_BYTE, take) pops take bytes at once
  Both run HASH_ONCE(empty) and compare against hashlib.shake_256(b'').
  - Byte-by-byte clean + batch bad → batch read/bridge bug (script/RTL)
  - Both bad → genuine hardware (FTDI electrical)
"""
import hashlib
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))
os.environ.setdefault("TMP", os.path.join(_ROOT, "build", "cw305"))
os.environ.setdefault("TEMP", os.path.join(_ROOT, "build", "cw305"))

import cw_boot  # noqa: E402
import chipwhisperer as cw  # noqa: E402

_REGS = os.path.join(_ROOT, "rtl", "lms_cw305_regs.vh")
EXP = hashlib.shake_256(b"").digest(32)


def fpga_read(cw305, reg, n):
    return cw305.fpga_read(getattr(cw305, reg), n)


def fpga_write(cw305, reg, data):
    cw305.fpga_write(getattr(cw305, reg), data)


def send_hash_once(cw305):
    # request = 0x48 | len(0)  → write RX_BYTE byte-by-byte
    for b in (0x48, 0x00):
        fpga_write(cw305, "REG_RX_BYTE", [b])
    # wait until the device consumes the request (RX_POS == 0)
    t0 = time.monotonic()
    while fpga_read(cw305, "REG_RX_POS", 1)[0] != 0:
        if time.monotonic() - t0 > 3:
            return False
        time.sleep(0.001)
    return True


def drain(cw305):
    # drain the TX FIFO
    cnt = fpga_read(cw305, "REG_TX_IDX", 1)[0]
    if cnt:
        fpga_read(cw305, "REG_TX_BYTE", cnt)


def read_byte_by_byte(cw305, n, timeout=5.0):
    """Byte-by-byte read: each fpga_read(TX_BYTE, 1) pops 1 byte."""
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        cnt = fpga_read(cw305, "REG_TX_IDX", 1)[0]
        if cnt > 0:
            buf.append(fpga_read(cw305, "REG_TX_BYTE", 1)[0])
        else:
            time.sleep(0.0005)
    return bytes(buf)


def read_batch(cw305, n, timeout=5.0):
    """Batch read: after reading TX_IDX, one fpga_read(TX_BYTE, take) pops take bytes."""
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        cnt = fpga_read(cw305, "REG_TX_IDX", 1)[0]
        if cnt > 0:
            take = min(cnt, n - len(buf))
            buf.extend(fpga_read(cw305, "REG_TX_BYTE", take))
        else:
            time.sleep(0.0005)
    return bytes(buf)


def main():
    cw305 = cw.target(None, cw.targets.CW305, defines_files=[_REGS])
    print("EXP SHAKE256(empty) =", EXP.hex())

    for mode, reader in (("byte-by-byte", read_byte_by_byte),
                         ("batch", read_batch)):
        bad = 0
        digests = []
        for k in range(5):
            drain(cw305)
            time.sleep(0.02)
            if not send_hash_once(cw305):
                print(f"[{mode}] send failed at {k}")
                break
            r = reader(cw305, 48)
            if len(r) < 48:
                print(f"[{mode}] {k}: short resp {len(r)}")
                continue
            marker = r[0]
            digest = r[16:48]
            digests.append(digest.hex())
            diff = [i for i in range(32) if digest[i] != EXP[i]]
            if marker != 0x52 or diff:
                bad += 1
            print(f"[{mode}] {k}: marker=0x{marker:02x} diff={len(diff)} "
                  f"digest={digest[:8].hex()}")
        uniq = len(set(digests))
        print(f"[{mode}] bad={bad}/5 unique={uniq}")
    cw305.dis()
    print("DONE")


if __name__ == "__main__":
    main()
