#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_sign_smoke.py - smoke isomorphism verification for Scheme B (2026-08-19)

Verify whether Sign Scheme B fixes the "operation asymmetry":
  1. correlation coefficient of the two group mean traces (old data 0.0865 -> expected ~ 1.0)
  2. per-trace RMS / total energy / active-segment length comparison (old data 2.14x / 5.3x / 4.0x -> expected ~ 1.0)
  3. peak position alignment (the two groups' active segments should coincide)
  4. optional: quick TVLA max|t| (N=50 is of limited significance; only look at magnitude/above-threshold distribution)

Usage: python scripts/tvla/check_sign_smoke.py build/tvla/sign_smoke_vB
"""
import json
import os
import sys

import numpy as np


def load_traces(d):
    f = np.load(os.path.join(d, "fixed.npy"), mmap_mode="r")
    r = np.load(os.path.join(d, "random.npy"), mmap_mode="r")
    meta = json.load(open(os.path.join(d, "fixed_meta.json"), encoding="utf-8"))
    return f, r, meta


def group_stats(X, label):
    m = X.mean(axis=1)
    rms = X.std(axis=1)
    en = (X.astype(np.float64) ** 2).sum(axis=1)
    # active segment: per-trace sliding-window energy vs noise floor of the first 1000 points
    noise = np.median(X[:, :1000].std(axis=1))
    act = []
    for t in X:
        w = np.convolve(t.astype(np.float64) ** 2, np.ones(200) / 200, "valid")
        act.append(int((w > (noise ** 2 * 9)).sum() * 200))
    act = np.array(act)
    print(f"[{label}] n={X.shape[0]} mean={m.mean():.5f} rms={rms.mean():.5f} "
          f"energy={en.mean():.1f} act_len={act.mean():.0f}(+/-{act.std():.0f})")
    return dict(mean=m, rms=rms, energy=en, act=act)


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "build/tvla/sign_smoke_vB"
    f, r, meta = load_traces(d)
    print(f"traces: fixed {f.shape} random {r.shape}  meta: op={meta.get('op')} "
          f"presamples={meta.get('presamples')} method={meta.get('method')}")

    n = min(f.shape[0], r.shape[0])
    F = np.array(f[:n], dtype=np.float32)
    R = np.array(r[:n], dtype=np.float32)

    sf = group_stats(F, "fixed ")
    sr = group_stats(R, "random")

    print(f"\nRMS ratio random/fixed   = {sr['rms'].mean() / sf['rms'].mean():.3f}  (old data 2.14)"
          f"\nenergy ratio random/fixed = {sr['energy'].mean() / sf['energy'].mean():.3f}  (old data 5.3)"
          f"\nact_len ratio random/fixed= {sr['act'].mean() / sf['act'].mean():.3f}  (old data 4.0)")

    fm = F.mean(axis=0)
    rm = R.mean(axis=0)
    c = np.corrcoef(fm, rm)[0, 1]
    print(f"\nmean-trace corr = {c:.4f}  (old data 0.0865; fixed expectation >0.99)")

    # intra-group consistency: cross-correlation of the two halves
    half = F[: n // 2].mean(0)
    half2 = F[n // 2:].mean(0)
    print(f"fixed  intra-half corr = {np.corrcoef(half, half2)[0, 1]:.4f}")
    half = R[: n // 2].mean(0)
    half2 = R[n // 2:].mean(0)
    print(f"random intra-half corr = {np.corrcoef(half, half2)[0, 1]:.4f}")

    # quick TVLA (uncorrected; only look at magnitude and above-threshold distribution shape)
    df = n - 1
    var_f = F.var(axis=0, ddof=1)
    var_r = R.var(axis=0, ddof=1)
    se = np.sqrt(var_f / n + var_r / n)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = (fm - rm) / se
        t[~np.isfinite(t)] = 0.0
    tmax = np.nanmax(np.abs(t))
    print(f"\nquick TVLA max|t| = {tmax:.1f} @pt {np.nanargmax(np.abs(t))} "
          f"(N={n}/group, uncorrected, magnitude reference only)")
    over = int((np.abs(t) > 6).sum())
    print(f"points |t|>6: {over} / {t.shape[0]} ({100.0 * over / t.shape[0]:.2f}%)")

    np.save(os.path.join(d, "smoke_t.npy"), t)
    print(f"saved |t| curve -> {d}/smoke_t.npy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
