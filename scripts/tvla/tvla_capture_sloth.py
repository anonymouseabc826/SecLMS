#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_capture_sloth.py — SLotH open-source fixed-caliber TVLA capture (2026-08-20)

Runs the official SLotH implementation on CW305 (test_leak loop, fixed-caliber modification:
SK.other/message/ADRS fixed, grouped only by SK.seed, rando[0]&1 decides fixed/random),
capturing power traces with Husky, to verify
"SLotH unmasked 4.80 flat line = missed detection due to public-component randomization".

Communication (SLotH official prog_cw305.py mechanism, register mailbox, not COM port):
  - cw.target(None, cw.targets.CW305, defines_files=[cw305_regs.vh], bsfile=bit)
    auto-programs the SLotH bit; pll_outfreq_set(31.25MHz) configures CDCE906
  - iut_write/read: fpga_write(REG_RX_BYTE)/fpga_read(REG_TX_BYTE) talks to the firmware UART bridge

Per-trace protocol (firmware test_leak.c):
  1. Host iut_write(1 byte) -> firmware runs one round: TRIG_PULSE(GPIO bit0 32-beat pulse, before signing)
     -> slh_do_sign(4.9M cycles @31.25MHz ≈ 157ms) -> TRIG_PULSE(END) -> sio_puts("[STAT] trig=...")
  2. Husky arm + capture (trigger=TRIG_PULSE rising edge, routed to T14 -> TIO4)
  3. iut_read parses [STAT] trig -> TRIG_SIGNAL_F=0x94A44891 assigned to fixed, R=0x92444891 to random

Trigger = pre-signing pulse -> post-trigger window covers the pre-signing segment (PRF region).
Synchronous sampling needs HS1=M16 (tio_clkout, ODDR drives iut_clk, needs cclk_output_ext enabled —
default DIP k16_sel or register; if freq_ctr unreadable, fall back to async 50MS/s).

Usage:
  python scripts/tvla/tvla_capture_sloth.py --bit <sloth-cw305.bit> \
      --n 1000 --out build/tvla/sloth_1k_fixed [--sync] [--samples 200000] [--presamples 2000]
"""
import argparse
import json
import os
import re
import sys
import time

import numpy as np

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
_LOG = os.path.normpath(os.path.join(_ROOT, "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ.setdefault("TMP", _LOG)
os.environ.setdefault("TEMP", _LOG)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))
import cw_boot  # noqa: E402  (under sandbox the mkdtemp dir is unwritable; must patch before importing chipwhisperer)

TRIG_SIGNAL_F = 0x94A44891  # fixed-group trigger value (firmware-encoded)
TRIG_SIGNAL_R = 0x92444891  # random-group trigger value


def parse_trig(resp):
    m = re.search(r"trig=\s*([0-9a-fA-F]+)", resp)
    if not m:
        return None
    v = int(m.group(1), 16)
    if v == TRIG_SIGNAL_F:
        return "fixed"
    if v == TRIG_SIGNAL_R:
        return "random"
    return None


class SlothIut:
    """SLotH firmware UART bridge (register mailbox, modeled on the official prog_cw305.py)."""

    def __init__(self, target):
        self._t = target
        self.tx_idx = 0
        self.rx_idx = 0

    def read_available(self):
        s = ""
        tx_idx = self._t.fpga_read(self._t.REG_TX_IDX, 1)[0]
        while tx_idx != self.tx_idx:
            ch = self._t.fpga_read(self._t.REG_TX_BYTE, 1)[0]
            s += chr(ch)
            self.tx_idx = tx_idx
            tx_idx = self._t.fpga_read(self._t.REG_TX_IDX, 1)[0]
        return s

    def read_until(self, needle="[STAT]", timeout=20.0):
        # Wait for a complete [STAT] line (trig= followed by a full 8-digit hex): "[STAT]" or "trig=" alone
        # may be truncated before the value
        buf = ""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            buf += self.read_available()
            if re.search(r"trig=\s*[0-9a-fA-F]{8}", buf):
                return buf
            time.sleep(0.005)
        return buf

    def write(self, s):
        # Official protocol: write REG_RX_BYTE + REG_RX_IDX (incremented) — writing only BYTE, firmware won't receive
        for ch in s:
            self.rx_idx = (self.rx_idx + 1) & 0xFF
            self._t.fpga_write(self._t.REG_RX_BYTE, [ord(ch)])
            self._t.fpga_write(self._t.REG_RX_IDX, [self.rx_idx])
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                rx_pos = self._t.fpga_read(self._t.REG_RX_POS, 1)[0]
                if rx_pos == self.rx_idx:
                    break
                time.sleep(0.002)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bit", required=True, help="SLotH CW305 bitstream path")
    ap.add_argument("--sloth-dir", default="sloth", help="SLotH source dir containing rtl/cw305_regs.vh (external dependency)")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--out", required=True)
    ap.add_argument("--samples", type=int, default=200000, help="samples per trace")
    ap.add_argument("--presamples", type=int, default=2000)
    ap.add_argument("--gain", type=float, default=5.0)
    ap.add_argument("--sync", action="store_true", help="synchronous sampling (HS1=M16 clock, must be enabled)")
    ap.add_argument("--clk-mhz", type=float, default=50.0,
                    help="clock MHz (firmware compiles UART baud rate per config.vh SLOTH_CLK=50MHz, "
                         "PLL must be set to 50MHz; with sync = expected HS1 frequency)")
    ap.add_argument("--verify-every", type=int, default=100)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    import chipwhisperer as cw

    regs = os.path.normpath(os.path.join(
        _ROOT, args.sloth_dir, "rtl", "cw305_regs.vh"))

    # CW305 target: auto-program SLotH bit
    print("programming %s ..." % args.bit, flush=True)
    t0 = time.time()
    tgt = cw.target(None, cw.targets.CW305,
                    defines_files=[regs], bsfile=args.bit, force=True)
    print("programmed OK in %.1fs" % (time.time() - t0), flush=True)
    tgt.pll.pll_outfreq_set(args.clk_mhz * 1e6, 1)
    print("PLL channel1 freq = %.2f MHz" % (tgt.pll.pll_outfreq_get(1) / 1e6))

    iut = SlothIut(tgt)
    # Drain startup output (self-test log)
    iut.read_until("[STAT]", timeout=30.0)

    scope = cw.scope()
    try:
        if args.sync:
            scope.clock.clkgen_freq = args.clk_mhz * 1e6
            scope.clock.clkgen_src = "extclk"
            fc = scope.clock.freq_ctr
            if not (fc and fc > 1e6):
                print("!! freq_ctr=%r (HS1 external clock not locked; try DIP k16_sel or enable tio_clkout via register)"
                      % fc, file=sys.stderr)
                return 1
            scope.clock.adc_mul = 1
            print("sync: freq_ctr=%.3f MHz" % (fc / 1e6))
        else:
            scope.clock.clkgen_freq = 50e6
        scope.adc.samples = args.samples
        if args.presamples:
            scope.adc.presamples = args.presamples
        scope.gain.db = args.gain
        scope.trigger.module = "basic"
        scope.trigger.triggers = "tio4"
        scope.adc.basic_mode = "rising_edge"
        scope.io.hs2 = "disabled"

        traces_f, traces_r = [], []
        metas_f, metas_r = [], []
        n_f = n_r = 0
        t_start = time.monotonic()
        for i in range(args.n):
            scope.arm()
            iut.write("\x01")
            scope.capture()
            trace = scope.get_last_trace()
            resp = iut.read_until("[STAT]", timeout=10.0)
            grp = parse_trig(resp)
            if grp is None:
                print("!! trace %d: cannot parse group (resp tail=%r)"
                      % (i, resp[-60:]), file=sys.stderr)
                continue
            meta = {"i": i, "group": grp, "trig": resp}
            if grp == "fixed":
                traces_f.append(trace); metas_f.append(meta); n_f += 1
            else:
                traces_r.append(trace); metas_r.append(meta); n_r += 1
            if (i + 1) % 100 == 0 or i == args.n - 1:
                el = time.monotonic() - t_start
                print("  %d/%d  fixed=%d random=%d  (%.1fs, %.0f ms/trace)"
                      % (i + 1, args.n, n_f, n_r, el, 1000 * el / (i + 1)))

        def save_group(g, tg, mg):
            if not tg:
                print("  !! %s group has no traces, skipping" % g)
                return
            arr = np.asarray(tg, dtype=np.float32)
            np.save(os.path.join(args.out, "%s.npy" % g), arr)
            with open(os.path.join(args.out, "%s_meta.json" % g), "w",
                      encoding="utf-8") as f:
                json.dump({
                    "op": "sloth_slh_dsa_shake_128f_sign",
                    "group": g, "n": len(tg), "trace_len": int(arr.shape[1]),
                    "presamples": args.presamples, "sync": args.sync,
                    "samples_per_cycle": 1.0 if args.sync else 50.0 / args.clk_mhz,
                    "clk_mhz": args.clk_mhz,
                    "caliber": "sloth-fixed (SK.other/msg/ADRS fixed, SK.seed grouped)",
                    "platform": "SLotH official source on CW305 (xc7a100tftg256-2)",
                    "bit": os.path.basename(args.bit),
                    "meta": mg,
                }, f, ensure_ascii=False, indent=1)
            print("  saved %s -> %s/%s.npy" % (arr.shape, args.out, g))

        save_group("fixed", traces_f, metas_f)
        save_group("random", traces_r, metas_r)
    finally:
        scope.dis()
        try:
            tgt.dis()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
