#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cw305_serial.py — CW305 board-test serial compatibility layer (pyserial duck typing)

CW305 has no COM port: the SoC's 115200 UART talks to the host through the on-board
lms_cw305_usb_uart bridge (register mailbox). This module implements the same interface
as pyserial (read/write/timeout/in_waiting/reset_*) via the chipwhisperer API
(fpga_read/fpga_write), so tests/board/test_lms_uart.py can run on CW305 without
changing the serial logic.

Register semantics (rtl/lms_cw305_regs.vh):
  REG_TX_BYTE read  = pop one byte from TX FIFO (device→host)
  REG_TX_IDX  read  = TX FIFO depth
  REG_RX_BYTE write = push one byte into RX FIFO (host→device)
  REG_RX_POS  read  = RX FIFO depth (0 = device has consumed everything)

Usage (in test_lms_uart.py):
  from cw305_serial import Cw305Serial
  with Cw305Serial(timeout=3.0, write_timeout=3.0) as port: ...

Dependencies: chipwhisperer>=6.0; TMP/TEMP must point to a writable directory (sandbox environment).
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

import cw_boot  # noqa: E402  (mkdtemp dir unwritable under sandbox; patch before importing chipwhisperer)

_REG_DEFS = os.path.normpath(os.path.join(_ROOT, "rtl", "lms_cw305_regs.vh"))
_IDENTIFY_EXPECT = 0x4C  # 'L'
_CRYPT_TYPE_EXPECT = 0x4D  # 'M'


class Cw305Serial:
    """pyserial duck-typed CW305 serial port (register mailbox protocol)."""

    def __init__(self, port="cw305", baud=115200, timeout=3.0, write_timeout=3.0,
                 check_bitstream=True):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.write_timeout = write_timeout
        self.check_bitstream = check_bitstream
        self._cw305 = None
        self._closed = False

    # ---- connection management ----
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def open(self):
        import chipwhisperer as cw
        self._cw305 = cw.target(None, cw.targets.CW305,
                                defines_files=[_REG_DEFS])
        if self.check_bitstream:
            ident = self._fpga_read("REG_IDENTIFY", 1)[0]
            ctype = self._fpga_read("REG_CRYPT_TYPE", 1)[0]
            if ident != _IDENTIFY_EXPECT or ctype != _CRYPT_TYPE_EXPECT:
                raise RuntimeError(
                    "CW305 current bitstream is not this project's (IDENTIFY=0x%02X, TYPE=0x%02X, "
                    "expected 0x%02X/0x%02X). Please program build/vivado_lms_cw305/lms_cw305.bit first"
                    % (ident, ctype, _IDENTIFY_EXPECT, _CRYPT_TYPE_EXPECT))

    def close(self):
        if self._cw305 is not None:
            try:
                self._cw305.dis()
            except Exception:
                pass
            self._cw305 = None
        self._closed = True

    # ---- register access ----
    def _fpga_read(self, regname, n):
        return self._cw305.fpga_read(getattr(self._cw305, regname), n)

    def _fpga_write(self, regname, data):
        self._cw305.fpga_write(getattr(self._cw305, regname), data)

    # ---- pyserial-compatible interface ----
    @property
    def in_waiting(self):
        """Number of bytes pending read (TX FIFO depth)."""
        if self._cw305 is None:
            return 0
        return self._fpga_read("REG_TX_IDX", 1)[0]

    def read(self, n=1):
        """Read at most n bytes; returns immediately with available data (may be fewer than n), returns b'' on timeout.

        2026-08-19 decision (RTS/CTS flow control v9): REG_TX_BYTE uses **bulk reads**. The RTL
        does a single pop on the rising edge (one RD pulse per byte); cmdReadMem(addr, take)
        issues take RD pulses over take consecutive addresses → pops take bytes. With v7 (no
        flow control), bulk reads only popped part (FIFO-full backpressure drops bytes;
        measured fpga_read(TX_BYTE,16) popped only 10); with v9 RTS/CTS flow control (SoC
        passthrough paused by RTS while waiting to read), bulk reads are fully correct
        (measured fpga_read(TX_BYTE,48) pops 48, head=52 00 00 00 0c…). Each batch of take
        bytes (≤FIFO depth 256) is 1 USB transaction, ~10x faster than byte-by-byte (2
        transactions per byte; 2396B measured 23s/trace).
        """
        if self._cw305 is None or n <= 0:
            return b""
        deadline = time.monotonic() + self.timeout
        while True:
            cnt = self._fpga_read("REG_TX_IDX", 1)[0]
            if cnt > 0:
                take = min(cnt, n)
                data = bytes(self._fpga_read("REG_TX_BYTE", take))
                return data
            if time.monotonic() >= deadline:
                return b""
            time.sleep(0.0005)

    def write(self, data):
        """Write bytes (push all into RX FIFO, then wait until the device consumes them). Returns the number of bytes written."""
        if self._cw305 is None:
            raise OSError("port not open")
        data = bytes(data)
        if not data:
            return 0
        # Push byte-by-byte (RX FIFO is 256 deep; request frames are far smaller, so it won't fill)
        for b in data:
            self._fpga_write("REG_RX_BYTE", [b])
        # Wait until the device consumes everything (flow control)
        deadline = time.monotonic() + self.write_timeout
        while self._fpga_read("REG_RX_POS", 1)[0] != 0:
            if time.monotonic() >= deadline:
                raise TimeoutError("CW305 RX FIFO not drained within write_timeout")
            time.sleep(0.0005)
        return len(data)

    def flush(self):
        pass

    def reset_input_buffer(self):
        """Discard pending device→host bytes (pop the TX FIFO)."""
        if self._cw305 is None:
            return
        cnt = self._fpga_read("REG_TX_IDX", 1)[0]
        if cnt > 0:
            self._fpga_read("REG_TX_BYTE", cnt)

    def reset_output_buffer(self):
        pass

    # ---- convenience diagnostics ----
    def get_status(self):
        st = self._fpga_read("REG_STATUS", 1)[0]
        return {"trap": bool(st & 0x01)}

    def get_buildtime(self):
        return self._cw305.get_fpga_buildtime()


if __name__ == "__main__":
    # Self-test: connect + read identify + loopback (write "ping" and read back? firmware has no loopback -- only identity check)
    s = Cw305Serial(timeout=2.0)
    with s:
        print("buildtime:", s.get_buildtime())
        print("status:", s.get_status())
    print("OK")
