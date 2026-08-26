#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""diag_derive_xq.py - locate the position and leakage of the x_q[i] hash in the derive_xq 1k traces

Compare against the known peak (abs 19992) of the 0x6D (derive_randomizer) 1k capture:
1. print max|t| of each window segment (coarse sweep in 500-pt segments)
2. fine sweep of pointwise |t| near the trigger point [19800:20200]
3. print the structure of the fixed/random mean traces near the trigger point (locate the busy segment)
4. compare against the same region of the 0x6D prf_1k_sync capture
"""
import os
import sys

import numpy as np

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))


def welch_t(a, b):
    a = a.astype(np.float64)
    b = b.astype(np.float64)
    na, nb = a.shape[0], b.shape[0]
    ma, mb = a.mean(axis=0), b.mean(axis=0)
    va, vb = a.var(axis=0, ddof=1), b.var(axis=0, ddof=1)
    t = (ma - mb) / np.sqrt(va / na + vb / nb)
    return t


def main():
    d_xq = os.path.join(_ROOT, "build", "tvla", "derive_xq_1k")
    d_6d = os.path.join(_ROOT, "build", "tvla", "prf_1k_sync")

    for name, d in (("derive_xq_1k", d_xq), ("prf_1k_sync(0x6D)", d_6d)):
        print(f"\n=== {name} ===")
        f = np.load(os.path.join(d, "fixed.npy"))
        r = np.load(os.path.join(d, "random.npy"))
        print(f"  fixed {f.shape} random {r.shape}")

        t = welch_t(f, r)
        # coarse sweep in 500-pt segments
        print("  coarse max|t| per 500-pt segment (seg:max@off):")
        for seg in range(0, t.shape[0], 500):
            ts = t[seg:seg + 500]
            i = int(np.argmax(np.abs(ts)))
            print(f"    [{seg}:{seg + 500}] max|t|={abs(ts[i]):7.2f} @ abs {seg + i}")
        # fine sweep near the trigger point
        for lo, hi in ((19800, 20200), (18000, 20000)):
            ts = t[lo:hi]
            i = int(np.argmax(np.abs(ts)))
            print(f"  fine [{lo}:{hi}] max|t|={abs(ts[i]):7.2f} @ abs {lo + i}")
        # mean-trace structure (locate busy segment): adjacent-difference energy
        mf = f.mean(axis=0)
        mr = r.mean(axis=0)
        d1 = np.abs(np.diff(mf))
        top = np.argsort(d1)[-8:]
        print(f"  mean-trace diff top positions (fixed): {sorted(top.tolist())}")
        print(f"  mean(fixed)@{19980:20300}: ...")
        # print the fixed group's mean near the trigger point to check for a 12-cycle structure
        win = mf[19970:20040]
        print("  fixed mean [19970:20040]:", np.round(win, 3).tolist())


if __name__ == "__main__":
    main()
