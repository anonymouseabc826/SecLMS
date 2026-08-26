#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_cpa_realign.py — SEED value-level attribution on re-aligned delay data (130.58 purity test)

130.58 = the fixed-vs-random recovered value on re-aligned delay data. If acquisition systematics
(time drift / even-odd structure) are mixed in, the fixed/random group difference cannot be fully
attributed to the seed. This script uses **grouping-independent** seed value functions
(corr(power, HW(SEED)) etc.) to attribute on the "re-aligned delay random group":

  - if corr is significant in the absorption region after re-alignment -> 130.58 contains real seed leakage
  - if corr is not significant after re-alignment -> 130.58 mostly comes from systematics (fixed/random
    temporal separation drift + even-odd structure residue), seed attribution is doubtful

Control: same-caliber corr on delay-free data (naturally aligned) -> if also not significant, the seed
leakage itself is weak, and the large fixed-vs-random t values are mostly acquisition-structure differences.

Usage:
  python scripts/tvla/tvla_cpa_realign.py \
      --dir build/tvla/derive_xq_delay_100k --template-dir build/tvla/derive_xq_100k \
      --mode corr-hw [--align]
"""
import argparse
import json
import os
import sys

import numpy as np

from realign_analyze import load_mean_var
from tvla_analyze import welch_t

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
ABSORB = (20012, 20080)
ARTIFACT = 20008


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


def realign(mem, tmpl, wstart, search, max_shift, pre, tlen, hp_w):
    N = mem.shape[0]
    L = mem.shape[1]
    aligned = np.zeros((N, pre + tlen + 256), dtype=np.float64)
    w1 = min(wstart + search, L)
    nlag_max = max_shift + 1
    for s in range(0, N, 4096):
        x = np.asarray(mem[s:min(s + 4096, N), :], dtype=np.float64)
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


def corr_series(mem, f, w0, w1, blk=4000):
    n = mem.shape[0]
    fm = f - f.mean()
    fstd = np.sqrt((fm * fm).sum())
    L = w1 - w0
    num = np.zeros(L, dtype=np.float64)
    den = np.zeros(L, dtype=np.float64)
    for s in range(w0, w1, blk):
        e = min(s + blk, w1)
        xb = np.asarray(mem[:, s:e], dtype=np.float64)
        xm = xb - xb.mean(axis=0, keepdims=True)
        num[s - w0:e - w0] = (xm * fm[:, None]).sum(axis=0)
        den[s - w0:e - w0] = np.sqrt((xm * xm).sum(axis=0))
    corr = num / (fstd * den)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = corr * np.sqrt((n - 2) / np.maximum(1e-12, 1 - corr * corr))
    return corr, t


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--template-dir", required=True)
    ap.add_argument("--mode", default="corr-hw",
                    choices=["corr-hw", "corr-byte0"])
    ap.add_argument("--align", action="store_true",
                    help="re-align the delay data before corr (default off = unaligned corr)")
    ap.add_argument("--t0", type=int, default=20012)
    ap.add_argument("--tlen", type=int, default=64)
    ap.add_argument("--search", type=int, default=1200)
    ap.add_argument("--wstart", type=int, default=20004)
    ap.add_argument("--max-shift", type=int, default=1100)
    ap.add_argument("--pre", type=int, default=16)
    ap.add_argument("--hp", type=int, default=32)
    args = ap.parse_args()

    d = os.path.normpath(os.path.join(_ROOT, args.dir))
    td = os.path.normpath(os.path.join(_ROOT, args.template_dir))
    grp = "random"
    npy = os.path.join(d, f"{grp}.npy")
    if not os.path.exists(npy):
        print(f"!! {npy} missing", file=sys.stderr)
        return 1
    mem = np.load(npy, mmap_mode="r")
    with open(os.path.join(d, f"{grp}_meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    seeds = [e.get("seed") for e in meta.get("meta", [])]
    if not seeds:
        print("!! no per-trace seed", file=sys.stderr)
        return 1
    f = np.array([bin(int(s, 16)).count("1") for s in seeds],
                 dtype=np.float64) if args.mode == "corr-hw" \
        else np.array([bytes.fromhex(s)[0] for s in seeds], dtype=np.float64)

    if args.align:
        tmpl = make_template(td, grp, args.t0, args.tlen, args.hp)
        mem = realign(mem, tmpl, args.wstart, args.search, args.max_shift,
                      args.pre, args.tlen, args.hp)
        w0, w1 = 0, mem.shape[1]
        tag = "re-aligned"
    else:
        w0, w1 = 20000, 26000
        tag = "unaligned"

    corr, t = corr_series(mem, f, w0, w1)
    n = len(f)
    from scipy import stats
    C = float(stats.t.ppf(1 - 1e-5 / (2 * t.size), n - 2))
    at = np.abs(t)
    i = int(at.argmax())
    if args.align:
        seg = slice(8, min(80, t.size))   # aligned indices: near match point (pre=16)
    else:
        seg = slice(max(0, ABSORB[0] - w0), ABSORB[1] - w0)
    absorb = float(at[seg].max()) if seg.stop > seg.start else 0.0
    print(f"[{args.mode} {tag}] N={n} max|t|={at[i]:.2f}@abs {i + w0} "
          f"| absorb[{ABSORB[0]}:{ABSORB[1]}] max|t|={absorb:.2f} "
          f"| C={C:.2f} above={(at > C).sum()}")
    res = {"label": f"{args.mode} {tag}", "N": n, "aligned": args.align,
           "max_abs_t": float(at[i]), "argmax_abs_point": int(i + w0),
           "absorb_max_abs_t": absorb, "critical_C": float(C),
           "n_above_C": int((at > C).sum())}
    out = os.path.join(d, f"cpa_realign_{args.mode}_{'aligned' if args.align else 'raw'}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
