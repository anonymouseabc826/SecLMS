#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""power_noise_check.py - 5V DC Jack power-source switch smoke comparison (2026-08-21)

Compare two software PRF (0x6D, derive_randomizer) captures to evaluate whether noise drops after
switching the power source:
  A = current state (USB powered; can reuse build/tvla/sw_prf_1k_full or sw_prf_10k)
  B = new configuration (USB + 5V DC Jack; re-captured with the same parameters after switching power)

Output metrics (A/B side by side):
  1. idle baseline std (silent segment before trigger, noise floor)
  2. per-trace RMS of the active segment (operation power magnitude)
  3. isomorphism: fixed/random mean-trace correlation, RMS ratio (TVLA prerequisite)
  4. F/R pointwise Welch t: max|t|, C (Bonferroni alpha=1e-5), above-threshold fraction
  5. t/sqrt(N) normalization (N-independent effect measure, A/B directly comparable)
  6. same-seed ff-split max|t| (capture-flow noise floor, should be far below F/R)

Verdict: B's idle std or ff noise floor significantly below A -> DC power supply noise reduction is effective;
         B's t/sqrt(N) >= A -> signal strength does not drop (or SNR improves).

Usage:
  # B capture (after switching power; parameters must match A):
  python scripts/tvla/tvla_capture.py --op derive_randomizer --sync \\
      --n 600 --interleave 100 --presamples 20000 --samples 60000 \\
      --clk-mhz 15.6 --out build/tvla/power_dc5v
  # compare (--a defaults to sw_prf_1k_full):
  python scripts/tvla/tvla_capture.py ...   # capture B first
  python scripts/tvla/power_noise_check.py --b build/tvla/power_dc5v

Dependencies: numpy, scipy (already installed). Large-N data is automatically subsampled to MAXN and sqrt(N)-normalized.
"""
import argparse
import json
import os
import sys

import numpy as np

ALPHA = 1e-5
IDLE = (0, 5000)          # silent segment before trigger (presamples=20000, pre-command segment)
ACT = (20000, 55000)      # active segment (software PRF ~20050..~54000, same window as sw_prf_1k_full)
MAXN = 2000               # subsampling cap for t computation (comparable after sqrt(N) normalization)

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))


def welch_t(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Pointwise Welch t (ddof=1)."""
    n1, n2 = a.shape[0], b.shape[0]
    m1, m2 = a.mean(axis=0), b.mean(axis=0)
    v1, v2 = a.var(axis=0, ddof=1), b.var(axis=0, ddof=1)
    denom = np.sqrt(v1 / n1 + v2 / n2)
    return np.where(denom > 0, (m1 - m2) / np.where(denom > 0, denom, 1.0), 0.0)


def load_traces(d: str):
    """Load fixed/random npy (mmap) + seeds; returns a dict."""
    out = {}
    for grp in ("fixed", "random"):
        p = os.path.join(d, f"{grp}.npy")
        if not os.path.exists(p):
            continue
        out[grp] = np.load(p, mmap_mode="r")
    return out


def reduce_std(traces, w):
    """Compute the mean per-trace std within window w in chunks (memory-efficient)."""
    s, e = w
    chunk = 500
    sums = 0.0
    n = 0
    for i in range(0, traces.shape[0], chunk):
        seg = traces[i:i + chunk, s:e]
        sums += float(np.std(seg, axis=1).sum())
        n += seg.shape[0]
    return sums / n


def reduce_rms(traces, w):
    s, e = w
    chunk = 500
    sums = 0.0
    n = 0
    for i in range(0, traces.shape[0], chunk):
        seg = traces[i:i + chunk, s:e]
        sums += float(np.sqrt(np.mean(seg ** 2, axis=1)).sum())
        n += seg.shape[0]
    return sums / n


def iso_metrics(traces):
    """RMS ratio + mean-trace correlation (full-window subsample)."""
    f, r = traces["fixed"], traces["random"]
    ns = min(f.shape[0], r.shape[0], MAXN)
    f2, r2 = f[:ns], r[:ns]
    fr = np.sqrt(np.mean(f2 ** 2, axis=1))
    rr = np.sqrt(np.mean(r2 ** 2, axis=1))
    fm, rm = f2.mean(axis=0), r2.mean(axis=0)
    c = float(np.corrcoef(fm, rm)[0, 1])
    return rr.mean() / fr.mean(), c


def fr_t(traces, win):
    f, r = traces["fixed"], traces["random"]
    ns = min(f.shape[0], r.shape[0], MAXN)
    f2, r2 = f[:ns, win[0]:win[1]], r[:ns, win[0]:win[1]]
    t = welch_t(f2, r2)
    L = t.size
    from scipy.stats import norm
    C = float(norm.ppf(1 - ALPHA / (2 * L)))
    n_above = int((np.abs(t) > C).sum())
    return (float(np.max(np.abs(t))), int(np.argmax(np.abs(t))) + win[0],
            C, n_above, L, ns)


def ff_split(traces, win):
    f = traces["fixed"]
    ns = min(f.shape[0], MAXN)
    f2 = f[:ns, win[0]:win[1]]
    a, b = f2[0::2], f2[1::2]
    t = welch_t(a, b)
    return float(np.max(np.abs(t))), ns


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--a", default=None,
                    help="A directory (current state/USB; default=build/tvla/sw_prf_1k_full)")
    ap.add_argument("--b", required=True, help="B directory (new DC-powered capture)")
    ap.add_argument("--window", default=None, help="override window 's:e' (default 20000:55000)")
    args = ap.parse_args()

    dirA = args.a or os.path.join(_ROOT, "build", "tvla", "sw_prf_1k_full")
    if args.window:
        s, e = (int(x) for x in args.window.split(":"))
        win = (s, e)
    else:
        win = ACT

    def meta_n(d):
        mp = os.path.join(d, "fixed_meta.json")
        if os.path.exists(mp):
            with open(mp, encoding="utf-8") as f:
                m = json.load(f)
            return m.get("n") or len(m.get("meta", []))
        return None

    print("=" * 78)
    for tag, d in (("A (USB, current)", dirA), ("B (USB+DC5V, new config)", args.b)):
        if not os.path.isdir(d):
            print(f"!! {tag}: directory does not exist {d}"); continue
        tr = load_traces(d)
        if "fixed" not in tr or "random" not in tr:
            print(f"!! {tag}: missing fixed/random.npy"); continue
        nf, nr = tr["fixed"].shape[0], tr["random"].shape[0]
        idle_f = reduce_std(tr["fixed"], IDLE)
        idle_r = reduce_std(tr["random"], IDLE)
        rms_f = reduce_rms(tr["fixed"], win)
        rms_r = reduce_rms(tr["random"], win)
        rms_ratio, corr = iso_metrics(tr)
        tmax, at, C, n_ab, L, ns = fr_t(tr, win)
        ff, ns_ff = ff_split(tr, win)
        print("-" * 78)
        print(f"{tag}   {d}")
        print(f"  N: fixed={nf} random={nr}   (meta n={meta_n(d)})")
        print(f"  idle baseline : fixed={idle_f:.2e} random={idle_r:.2e}   <- noise floor")
        print(f"  active RMS    : fixed={rms_f:.2e} random={rms_r:.2e}  RMS ratio={rms_ratio:.4f}")
        print(f"  isomorphism   : {corr:.5f}")
        print(f"  F/R max|t|    : {tmax:.2f} @{at}   C={C:.2f}(Bonf,alpha=1e-5,L={L})  "
              f"above={100*n_ab/L:.1f}%  (N_eff={ns})")
        print(f"  t/sqrt(N) norm: {tmax/np.sqrt(ns):.3f}   (N-independent effect size, A/B directly comparable)")
        print(f"  ff-split max|t|: {ff:.2f} @N_eff={ns_ff}   <- capture-flow noise floor (same seed should be far lower)")
    print("=" * 78)
    print("Verdict: B idle std / ff noise floor < A -> DC power supply noise reduction is effective;")
    print("         B t/sqrt(N) >= A -> signal strength not reduced (clearly higher if SNR improved).")
    print("Note: if N differs between A and B, t/sqrt(N) normalization already removes the N effect; compare directly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
