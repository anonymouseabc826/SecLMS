#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""interleave_two_fixed.py - interleaved two-seed fixed-group discrimination experiment (2026-08-25)

Goal: determine whether the t~40 of the fixed busy+8 event (abs 20008) in fixed-vs-random is
(a) an interleaved-capture structure artifact, or (b) a seed statistical effect.
Method: alternate two different constant SEEDs in blocks within one capture (A=default vector, B=seed2 vector);
the only difference between groups = seed content. If t at 20008 is large -> seed statistical effect; if ~baseline -> interleaving artifact.
"""
import os
import struct
import sys

import numpy as np

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))
os.environ.setdefault("TMP", os.path.join(_ROOT, "build", "cw305"))
os.environ.setdefault("TEMP", os.path.join(_ROOT, "build", "cw305"))

from cw305_serial import Cw305Serial  # noqa: E402
from tvla_capture import (OP_SEED_LOAD, OP_DERIVE_XQ, RESP_SIZE,  # noqa: E402
                          read_exact, load_vector)

VEC_B = os.path.join(_ROOT, "build", "vectors",
                     "lms_verify_vector_shake_W4_H5_seed2.txt")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--vec-b", default=None, help="B-group vector path (default seed2)")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--blk", type=int, default=250)
    args = ap.parse_args()
    _, privA = load_vector(4, 5, None)
    _, privB = load_vector(4, 5, args.vec_b or VEC_B)
    assert privA[24:56] != privB[24:56], "seeds identical!"

    import chipwhisperer as cw
    scope = cw.scope()
    try:
        scope.clock.clkgen_freq = 15.625e6
        scope.clock.clkgen_src = "extclk"
        fc = scope.clock.freq_ctr
        if not (fc and fc > 1e6):
            print("!! external clock not locked", file=sys.stderr)
            return 1
        scope.clock.adc_mul = 1
        scope.adc.samples = 26000
        scope.adc.presamples = 20000
        scope.gain.db = 5.0
        scope.trigger.module = "basic"
        scope.trigger.triggers = "tio4"
        scope.adc.basic_mode = "rising_edge"
        scope.io.hs2 = "disabled"

        BLK = args.blk
        N = args.n
        with Cw305Serial(timeout=5.0) as port:
            port.reset_input_buffer()
            for _ in range(3):
                port.read(4096)
            port.reset_input_buffer()
            traces = {"A": [], "B": []}
            for i in range(N):
                grp = "A" if (i // BLK) % 2 == 0 else "B"
                priv = privA if grp == "A" else privB
                seed = priv[24:56]
                ident = priv[8:24]
                q = int.from_bytes(priv[56:60], "big")
                # 0x63 preload (outside window)
                port.write(bytes([OP_SEED_LOAD]) + seed)
                r = read_exact(port, RESP_SIZE, timeout=10.0)
                if r[:1] != b"\x52":
                    print(f"!! {i} preload bad", file=sys.stderr)
                    return 1
                frame = (bytes([OP_DERIVE_XQ]) + ident +
                         struct.pack("<I", q) + struct.pack("<H", 0))
                scope.arm()
                port.write(frame)
                scope.capture()
                tr = scope.get_last_trace()
                traces[grp].append(tr)
                resp = read_exact(port, RESP_SIZE, timeout=3.0)
                if resp[:1] != b"\x52":
                    print(f"!! {i} resp bad", file=sys.stderr)
                    return 1
                if (i + 1) % 100 == 0:
                    print(f"  {i+1}/{N} [{grp}]", flush=True)

        a = np.asarray(traces["A"], dtype=np.float32)
        b = np.asarray(traces["B"], dtype=np.float32)
        na, nb = a.shape[0], b.shape[0]
        t = (a.mean(0) - b.mean(0)) / np.sqrt(
            a.var(0, ddof=1) / na + b.var(0, ddof=1) / nb)
        from scipy.stats import norm
        C = norm.ppf(1 - 1e-5 / (2 * t.shape[0]))
        i = int(np.argmax(np.abs(t)))
        print(f"interleaved fixedA vs fixedB: nA={na} nB={nb}")
        print(f"  max|t| = {abs(t[i]):.2f} @ abs {i}  C={C:.2f}")
        print(f"  t@20008 = {t[20008]:.2f}")
        for lo, hi, name in ((19990, 20020, 'busy+8 [19990:20020]'),
                             (20020, 20100, 'absorb region'), (0, 20000, 'pre-trig')):
            seg = np.abs(t[lo:hi]); j = int(np.argmax(seg))
            print(f"  {name}: max|t|={seg.max():6.2f} @ abs {lo+j}")
    finally:
        scope.dis()
    return 0


if __name__ == "__main__":
    sys.exit(main())
