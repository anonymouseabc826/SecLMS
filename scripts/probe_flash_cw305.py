#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_flash_cw305.py — M1 SPI flash access verification (CW305)

After (optionally) programming, send the SoC a FLASH_PROBE (0x5B) command and read the
JEDEC-ID readback bytes on 5 MISO candidate pins to determine the FPGA↔flash read path:

  candidate 0 = B4  (SAM_MOSI net, preferred per schematic)
  candidate 1 = K12 (D00/MOSI dual-function pin)
  candidate 2 = J14 (D02)
  candidate 3 = K15 (D03)
  candidate 4 = L13 (FCS_B)

Known device JEDEC IDs: S25FL132K = 01 40 15, AT25SF321 = 1F 86 01, MX25L3233F = C2 5E 16.
If any candidate reads one of the patterns above → the FPGA can read flash SO through that pin (M1 passes; M2 uses this read path).

Usage:
  python scripts/probe_flash_cw305.py [bitstream path] [--no-program]
"""
import os
import sys
import struct
import time

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, ".."))
sys.path.insert(0, _WS)
from cw305_serial import Cw305Serial  # noqa: E402

FLASH_PROBE = 0x5B
RESPONSE = 0x52
RESPONSE_SIZE = 48

KNOWN_IDS = {
    "S25FL132K":  bytes([0x01, 0x40, 0x15]),
    "AT25SF321":  bytes([0x1F, 0x86, 0x01]),
    "MX25L3233F": bytes([0xC2, 0x5E, 0x16]),
}
CAND_NAMES = ["B4(SAM_MOSI)", "K12(D00)", "J14(D02)", "K15(D03)", "L13(FCS_B)"]


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


def main():
    bitstream = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        bitstream = os.path.abspath(sys.argv[1])
    do_program = "--no-program" not in sys.argv

    if do_program:
        if bitstream is None:
            bitstream = os.path.normpath(os.path.join(_ROOT, "build", "vivado_lms_cw305",
                                                      "lms_cw305.bit"))
        if not os.path.isfile(bitstream):
            print("ERROR: bitstream not found: %s" % bitstream)
            sys.exit(1)
        import chipwhisperer as cw
        print("programming %s ..." % bitstream, flush=True)
        t0 = time.time()
        tgt = cw.target(None, cw.targets.CW305, bsfile=bitstream, force=True)
        print("programmed OK in %.1fs" % (time.time() - t0))
        try:
            tgt.dis()
        except Exception:
            pass
        time.sleep(0.5)

    with Cw305Serial(timeout=3.0, write_timeout=3.0) as port:
        print("board identified, probing SPI flash ...")
        port.reset_input_buffer()
        port.write(bytes([FLASH_PROBE]))
        resp = read_exact(port, RESPONSE_SIZE)
        if len(resp) < RESPONSE_SIZE:
            print("ERROR: short response (%d bytes): %s" % (len(resp), resp.hex()))
            sys.exit(1)
        head = struct.unpack_from("<BBBBIII", resp)
        print("frame: op=0x%02X status=%d error=%d cycles=%d hits=%d" % head[:5])
        payload = resp[16:48]
        print("payload[0:16] (header): %s" % payload[0:16].hex())
        cands = []
        for i in range(5):
            b3 = payload[16 + i * 3: 16 + i * 3 + 3]
            cands.append(b3)
        stat = payload[31]
        print("FLASH_STATUS byte: 0x%02X (busy=%d done=%d)" %
              (stat, stat & 1, (stat >> 1) & 1))
        print("---- MISO candidate readback (byte0 first, MSB-first) ----")
        for i, name in enumerate(CAND_NAMES):
            b3 = cands[i]
            match = next((k for k, v in KNOWN_IDS.items() if b3 == v), None)
            tag = " <== MATCH %s" % match if match else ("(prefix %s)" % next(
                (k for k, v in KNOWN_IDS.items() if b3[0] == v[0]), "") if b3[0] != 0xFF else "(idle-FF)")
            print("  [%d] %-14s = %02X %02X %02X%s" % (i, name, b3[0], b3[1], b3[2], tag))
        matched = [i for i, b3 in enumerate(cands) if b3 in KNOWN_IDS.values()]
        if matched:
            print("M1 PASS: FPGA can read flash SO via %s (JEDEC match)" %
                  ", ".join(CAND_NAMES[i] for i in matched))
        else:
            print("M1 FAIL: no candidate read a known JEDEC ID (read path not confirmed)")


if __name__ == "__main__":
    main()
