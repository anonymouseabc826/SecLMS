#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""flash_write_test_cw305.py — M1b SPI flash write-path verification (CW305)

The FPGA writes 8 bytes to flash starting at 0x100000 through the on-board SPI path
(CS=L12/SI=J13/SCK=CCLK); each byte clears one distinct bit
(0xFE/0xFD/0xFB/0xF7/0xEF/0xDF/0xBF/0x7F, demonstrating the monotonic "bit programming" style),
then reads back via the SAM3U path (shim) and compares — verifying that the FPGA→flash write direction is truly reachable.

Usage (program the M1b bitstream first):
  python scripts/flash_write_test_cw305.py
"""
import os
import sys
import time
import struct

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, ".."))
sys.path.insert(0, _WS)
from cw305_serial import Cw305Serial  # noqa: E402

FLASH_PROG = 0x5C
RESPONSE_SIZE = 48
BASE = 0x100000
PATTERN = [0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F]
SHIM_BITSTREAM = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(cw.__file__)),
                 "hardware", "firmware", "cw305", "SPI_flash_100t.bit"))
PROJECT_BITSTREAM = os.path.normpath(
    os.path.join(_ROOT, "build", "vivado_lms_cw305", "lms_cw305.bit"))


def read_exact(port, n, timeout=5.0):
    buf = b""
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        chunk = port.read(n - len(buf))
        if chunk:
            buf += chunk
        else:
            time.sleep(0.002)
    return buf


def send_prog(port, addr, data):
    req = bytes([FLASH_PROG, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF,
                 addr & 0xFF, data])
    port.reset_input_buffer()
    port.write(req)
    resp = read_exact(port, RESPONSE_SIZE)
    if len(resp) < RESPONSE_SIZE:
        return None
    return resp


def parse_prog(resp):
    """Response frame: payload=nvm_response[0..31] lives in frame[16..47];
    addr is echoed in nvm_response[16..18]=frame[32..34], data in frame[35], STATUS in frame[47]."""
    echo = (resp[32] << 16) | (resp[33] << 8) | resp[34]
    data = resp[35]
    stat = resp[47]
    return resp[2], echo, data, stat


def main():
    # 1) write via FPGA path
    with Cw305Serial(timeout=4.0, write_timeout=4.0) as port:
        print("writing via FPGA path (0x%06X..0x%06X):" %
              (BASE, BASE + len(PATTERN) - 1), flush=True)
        for i, val in enumerate(PATTERN):
            addr = BASE + i
            resp = send_prog(port, addr, val)
            if resp is None:
                print("  @0x%06X <- 0x%02X : NO RESPONSE" % (addr, val))
                sys.exit(1)
            err, echo, data, stat = parse_prog(resp)
            ok = err == 0 and echo == addr and data == val
            print("  @0x%06X <- 0x%02X : %s (status=%02X echo=%06X data=%02X)" %
                  (addr, val, "OK" if ok else "FAIL", stat, echo, data), flush=True)
            if not ok:
                print("FAIL at write ack")
                sys.exit(1)
        print("all writes acked")

    # 2) read back via SAM3U path
    import chipwhisperer as cw
    if not os.path.isfile(SHIM_BITSTREAM):
        print("ERROR: shim bitstream missing: %s" % SHIM_BITSTREAM)
        sys.exit(1)
    print("loading shim for SAM3U read-back ...", flush=True)
    fpga = cw.target(None, cw.targets.CW305)
    spi = fpga.spi_mode(bsfile=SHIM_BITSTREAM)
    ok_all = True
    for i, val in enumerate(PATTERN):
        addr = BASE + i
        d = spi.cmd_read_mem(1, addr)
        got = d[0]
        match = "MATCH" if got == val else "MISMATCH"
        if got != val:
            ok_all = False
        print("  readback @0x%06X = 0x%02X (expect 0x%02X) %s" %
              (addr, got, val, match))
    try:
        fpga.dis()
    except Exception:
        pass
    if ok_all:
        print("M1b PASS: FPGA→flash write path verified (8/8 bytes checked bit by bit)")
    else:
        print("M1b FAIL: readback mismatch")

    # 3) restore project bitstream
    print("restoring project bitstream ...", flush=True)
    if os.path.isfile(PROJECT_BITSTREAM):
        tgt = cw.target(None, cw.targets.CW305, bsfile=PROJECT_BITSTREAM, force=True)
        try:
            tgt.dis()
        except Exception:
            pass
        print("restored")


if __name__ == "__main__":
    main()
