#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""flash_wel_diag_cw305.py — M1b WEL diagnostics (CW305)

The FPGA sends WREN (0x06) through the on-board SPI path, then the SAM3U path (shim) reads the flash STATUS register:
  - If WEL=1 (STATUS bit1): the FPGA's SCK/CS/SI genuinely reach the flash → the write path works (0x5C should be programmable);
  - If WEL=0: the FPGA's SPI command did not reach the flash (SCK or CS/SI clamped/not connected) → hardware-level problem.

Usage (program the bitstream containing 0x5D first):
  python scripts/flash_wel_diag_cw305.py
"""
import os
import sys
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, ".."))
sys.path.insert(0, _WS)
from cw305_serial import Cw305Serial  # noqa: E402

FLASH_CMD = 0x5D
WREN = 0x06
WRDI = 0x04
RESPONSE_SIZE = 48
SHIM_BITSTREAM = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(cw.__file__)),
                 "hardware", "firmware", "cw305", "SPI_flash_100t.bit"))
PROJECT_BITSTREAM = os.path.normpath(
    os.path.join(_ROOT, "build", "vivado_lms_cw305", "lms_cw305.bit"))


def read_exact(port, n, timeout=4.0):
    buf = b""
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        c = port.read(n - len(buf))
        if c:
            buf += c
        else:
            time.sleep(0.002)
    return buf


def fpga_send_cmd(port, byte):
    port.reset_input_buffer()
    port.write(bytes([FLASH_CMD, byte]))
    resp = read_exact(port, RESPONSE_SIZE)
    if len(resp) < RESPONSE_SIZE:
        return None
    return resp


def read_status_sam3u(spi):
    spi.set_cs_pin(False)
    spi.spi_tx_rx([0x05])
    sr = spi.spi_tx_rx([0x00])[0]
    spi.set_cs_pin(True)
    return sr


def main():
    import chipwhisperer as cw

    # 0) baseline: clear WEL via SAM3U, confirm the SAM3U path can read/write STATUS (rule out stale WEL interference)
    print("loading shim for baseline WRDI ...", flush=True)
    fpga = cw.target(None, cw.targets.CW305)
    spi = fpga.spi_mode(bsfile=SHIM_BITSTREAM)
    spi.enable_write(True)          # WREN
    spi.enable_write(False)         # WRDI (clear WEL)
    sr = read_status_sam3u(spi)
    print("SAM3U baseline: WRDI -> STATUS 0x%02X (WEL=%d), expect WEL=0" %
          (sr, (sr >> 1) & 1))
    try:
        fpga.dis()
    except Exception:
        pass
    if (sr >> 1) & 1:
        print("ERROR: baseline WEL not cleared (SAM3U path abnormal?)")
        sys.exit(1)

    # 1) reload project bitstream, FPGA sends WREN
    print("reloading project bitstream ...", flush=True)
    tgt = cw.target(None, cw.targets.CW305, bsfile=PROJECT_BITSTREAM, force=True)
    try:
        tgt.dis()
    except Exception:
        pass
    time.sleep(0.5)
    with Cw305Serial(timeout=4.0, write_timeout=4.0) as port:
        resp = fpga_send_cmd(port, WREN)
        if resp is None:
            print("ERROR: no response to WREN")
            sys.exit(1)
        print("FPGA WREN ack: status=%02X (busy=%d done=%d)" %
              (resp[47], resp[47] & 1, (resp[47] >> 1) & 1))
        time.sleep(0.2)

    # 2) read STATUS via SAM3U to verify WEL
    print("loading shim for STATUS read ...", flush=True)
    fpga = cw.target(None, cw.targets.CW305)
    spi = fpga.spi_mode(bsfile=SHIM_BITSTREAM)
    sr = read_status_sam3u(spi)
    print("STATUS after FPGA WREN (expect WEL=1): 0x%02X (WEL=%d)" % (sr, (sr >> 1) & 1))
    if (sr >> 1) & 1:
        print("M1b WEL DIAG PASS: FPGA→flash write path confirmed reachable (SCK/CS/SI all active)")
    else:
        print("M1b WEL DIAG FAIL: WREN did not reach flash (SCK or CS/SI link down)")
    try:
        fpga.dis()
    except Exception:
        pass

    # 3) restore
    print("restoring project bitstream ...", flush=True)
    tgt = cw.target(None, cw.targets.CW305, bsfile=PROJECT_BITSTREAM, force=True)
    try:
        tgt.dis()
    except Exception:
        pass


if __name__ == "__main__":
    main()
