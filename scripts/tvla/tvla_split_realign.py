#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_split_realign.py — 130.58 attribution purity discrimination (systematics vs seed leakage)

Background: even/odd split within the fixed group (same SEED, same operation) shows a strong t in the
absorption region (73.88@20034 at 10k), suggesting trace-index-dependent acquisition systematics.
If that difference is "operation-related", RANDOM_DELAY re-alignment recovers it together with the real
seed leakage -> 130.58 attribution impure; if the even/odd split is flat after re-alignment, 130.58 is pure seed leakage.

Method: split the delay-data fixed group by trace index (even/odd, or front/back half); each half is
re-aligned with the delay-free reference template (identical to realign_analyze.py), then Welch t after alignment:
  --mode evenodd   even/odd (trace-index structure)
  --mode frontback front 50% / back 50% (time drift)

Expected (discrimination):
  significant -> systematics are operation-related and recovered by re-alignment -> 130.58 needs re-attribution
  flat        -> 130.58 is seed leakage; even/odd difference flattened by interleaved capture under fixed trace order / does not enter between-group difference

Usage:
  python scripts/tvla/tvla_split_realign.py \
      --dir build/tvla/derive_xq_delay_100k --template-dir build/tvla/derive_xq_100k \
      --mode evenodd
"""
import argparse
import json
import os
import sys

import numpy as np

from realign_analyze import load_mean_var
from tvla_analyze import welch_t, critical_value

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))


def hp(x, w):
    if w <= 1:
        return x
    k = np.ones(w) / w
    xm = np.apply_along_axis(lambda a: np.convolve(a, k, mode="same"), 1, x)
    return x - xm


def make_template(td, group, t0, tlen, hp_w):
    tm, _, _ = load_mean_var(os.path.join(td, group + ".npy"), 0, 100000)
    t = tm[t0:t0 + tlen]
    if hp_w > 1:
        t = hp(t.reshape(1, -1), hp_w)[0]
    return t - t.mean()


def realign(mem, tmpl, wstart, search, max_shift, pre, tlen, hp_w, idx):
    """Per-trace cross-correlation alignment for the given trace subset (idx). Returns the aligned array."""
    N = idx.shape[0]
    L = mem.shape[1]
    aligned = np.zeros((N, pre + tlen + 256), dtype=np.float64)
    w1 = min(wstart + search, L)
    nlag_max = max_shift + 1
    for s in range(0, N, 4096):
        sub = idx[s:min(s + 4096, N)]
        x = np.asarray(mem[sub, :], dtype=np.float64)
        seg = x[:, wstart:w1]
        if hp_w > 1:
            seg = hp(seg, hp_w)
        nlag = min(seg.shape[1] - tlen + 1, nlag_max)
        corr = np.zeros((seg.shape[0], nlag))
        for k in range(nlag):
            ss = seg[:, k:k + tlen]
            ss = ss - ss.mean(axis=1, keepdims=True)
            corr[:, k] = (ss * tmpl).sum(axis=1)
        best = np.argmax(corr, axis=1)
        for j in range(x.shape[0]):
            src_abs = max(0, wstart + best[j] - pre)
            src = x[j, src_abs:min(src_abs + aligned.shape[1], L)]
            aligned[s + j, :src.shape[0]] = src
    return aligned


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="delay data directory")
    ap.add_argument("--template-dir", required=True, help="delay-free reference directory")
    ap.add_argument("--mode", default="evenodd", choices=["evenodd", "frontback"])
    ap.add_argument("--group", default="fixed",
                    help="which group to split (default fixed: same SEED, cleanest)")
    ap.add_argument("--t0", type=int, default=20012)
    ap.add_argument("--tlen", type=int, default=64)
    ap.add_argument("--search", type=int, default=1200)
    ap.add_argument("--wstart", type=int, default=20004)
    ap.add_argument("--max-shift", type=int, default=1100)
    ap.add_argument("--pre", type=int, default=16)
    ap.add_argument("--hp", type=int, default=32)
    ap.add_argument("--alpha", type=float, default=1e-5)
    args = ap.parse_args()

    d = os.path.normpath(os.path.join(_ROOT, args.dir))
    td = os.path.normpath(os.path.join(_ROOT, args.template_dir))
    mem = np.load(os.path.join(d, args.group + ".npy"), mmap_mode="r")
    N = mem.shape[0]

    if args.mode == "evenodd":
        idx0 = np.arange(0, N, 2)
        idx1 = np.arange(1, N, 2)
        label = f"{args.group} even/odd split"
    else:
        h = N // 2
        idx0 = np.arange(0, h)
        idx1 = np.arange(h, 2 * h)
        label = f"{args.group} front/back split"

    tmpl = make_template(td, args.group, args.t0, args.tlen, args.hp)
    a0 = realign(mem, tmpl, args.wstart, args.search, args.max_shift,
                 args.pre, args.tlen, args.hp, idx0)
    a1 = realign(mem, tmpl, args.wstart, args.search, args.max_shift,
                 args.pre, args.tlen, args.hp, idx1)

    t, _ = welch_t(a0, a1)
    t = np.nan_to_num(t, nan=0.0, posinf=0.0, neginf=0.0)
    C = critical_value(args.alpha, t.shape[0],
                       np.full(t.shape[0], min(a0.shape[0], a1.shape[0]) - 1))
    i = int(np.argmax(np.abs(t)))
    at = np.abs(t)
    above = int((at > C).sum())
    seg = slice(args.pre - 8, args.pre + 64)  # absorption region (near the match point)
    absorb_t = float(at[seg].max()) if seg.stop <= t.shape[0] else 0.0
    print(f"[{label}] re-aligned: max|t|={at[i]:.2f} @aligned-pt {i} "
          f"(C={C:.2f}, above={above}, L={t.shape[0]})")
    print(f"    absorb region (aligned {seg.start}:{seg.stop}) max|t|={absorb_t:.2f}")
    res = {"label": label, "mode": args.mode, "group": args.group,
           "n0": int(a0.shape[0]), "n1": int(a1.shape[0]),
           "max_abs_t": float(at[i]), "argmax_aligned": int(i),
           "critical_C": float(C), "n_above_C": above,
           "absorb_max_abs_t": absorb_t, "L": int(t.shape[0])}
    with open(os.path.join(d, f"split_realign_{args.mode}.json"), "w",
              encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
