#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_analyze.py — TVLA trace analysis (pointwise Welch t-test + Bonferroni correction)

Leakage assessment on the fixed/random trace pair captured by tvla_capture.py:
  1. Pointwise Welch's t-test (no equal-variance assumption, Satterthwaite df)
  2. Multiple-comparison correction = **Bonferroni** (p_adj = alpha/L, critical value C = normal/t quantile
     ±alpha/2L). Note: this is Bonferroni, not Mini-p (Westfall-Young);
     the SLotH paper uses Mini-p (C≈7.03@L=5.95M, lower than Bonferroni's 7.06) —
     the paper must state Bonferroni; C is slightly conservative, conclusion direction unaffected.
  3. Output: max|t|, leakage hot spots (top-N |t| positions -> cycle mapping), optional leakage plot

Usage:
  python scripts/tvla/tvla_analyze.py --dir build/tvla/run1 \
      --alpha 1e-5 --top 20 [--plot leak.png]

Input: <dir>/fixed.npy + <dir>/random.npy (N×L float32)
Output: stdout report + <dir>/tvla_report.json + optional <dir>/leak.png
"""
import argparse
import json
import os
import sys

import numpy as np

# t-distribution quantile (df→∞ approximation; with large N the Welch df is huge, so a normal approximation suffices)
from scipy.stats import norm, t as t_dist


def welch_t(fixed: np.ndarray, random: np.ndarray) -> tuple:
    """Pointwise Welch t statistic. Input N×L. Returns (t_arr, df_arr)."""
    n1, n2 = fixed.shape[0], random.shape[0]
    m1, m2 = fixed.mean(axis=0), random.mean(axis=0)
    v1, v2 = fixed.var(axis=0, ddof=1), random.var(axis=0, ddof=1)
    se = np.sqrt(v1 / n1 + v2 / n2)
    # Zero-variance points (both groups constant) -> t=0
    t_arr = np.divide(m1 - m2, se, out=np.zeros_like(se), where=se > 0)
    df = (v1 / n1 + v2 / n2) ** 2 / (
        (v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1)
    )
    df = np.where(np.isfinite(df) & (df > 0), df, 1e6)
    return t_arr, df


def critical_value(alpha: float, L: int, df: np.ndarray) -> float:
    """Mini-p caliber (same as SLotH): L independent tests, corrected overall type-I error rate <= alpha.
    Simplest form = Bonferroni single-point threshold; Mini-p is slightly lower."""
    p_adj = alpha / L
    # Normal approximation with large df, conservatively using the median df
    df_med = float(np.median(df))
    if df_med > 1e4:
        return float(norm.ppf(1 - p_adj / 2))
    return float(t_dist.ppf(1 - p_adj / 2, df_med))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="trace directory (contains fixed/random .npy)")
    ap.add_argument("--alpha", type=float, default=1e-5, help="overall type-I error rate (default 1e-5)")
    ap.add_argument("--top", type=int, default=20, help="output top-N |t| hot spots")
    ap.add_argument("--plot", default=None, help="leakage plot path (requires matplotlib, optional)")
    ap.add_argument("--clk-mhz", type=float, default=50.0, help="clock frequency (cycle mapping)")
    ap.add_argument("--samples-per-cycle", type=float, default=1.0)
    ap.add_argument("--window", default=None,
                    help="analysis sample range 'start:end' (default full window; used to trim UART response-window false positives, "
                         "e.g. LM-OTS KG @15.6MHz uses 0:45000)")
    ap.add_argument("--presamples", type=int, default=None,
                    help="number of pre-trigger samples (scheme 1 trace: whole operation within presamples pre-trigger samples; "
                         "when set, hot-spot cycle remapped to operation start (trigger at presamples), and default window=0:presamples)")
    args = ap.parse_args()

    fixed = np.load(os.path.join(args.dir, "fixed.npy"))
    random = np.load(os.path.join(args.dir, "random.npy"))
    # Read presamples from meta.json (if not given explicitly on the command line)
    if args.presamples is None:
        meta_path = os.path.join(args.dir, "fixed_meta.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta = json.load(f)
                args.presamples = int(meta.get("presamples", 0) or 0)
                # Real clock caliber in meta takes precedence over the command-line default (50MHz)
                if "clk_mhz" in meta and args.clk_mhz == 50.0:
                    args.clk_mhz = float(meta["clk_mhz"])
                if "samples_per_cycle" in meta and args.samples_per_cycle == 1.0:
                    args.samples_per_cycle = float(meta["samples_per_cycle"])
            except Exception:
                args.presamples = 0
        else:
            args.presamples = 0
    # Window: explicit --window takes priority; otherwise scheme 1 (presamples>0) defaults to 0:presamples (whole operation),
    # legacy caliber (presamples=0) defaults to the full window.
    w0, w1 = 0, fixed.shape[1]
    if args.window:
        w0, w1 = (int(x) for x in args.window.split(":"))
    elif args.presamples > 0:
        w0, w1 = 0, args.presamples
        print("presamples=%d -> default analysis window [0:%d] (whole operation before trigger)" % (args.presamples, w1))
    fixed = fixed[:, w0:w1]
    random = random[:, w0:w1]
    if args.window:
        print("window slice: [%d:%d]" % (w0, w1))
    if fixed.shape[1] != random.shape[1]:
        print(f"!! trace length mismatch fixed={fixed.shape[1]} random={random.shape[1]}", file=sys.stderr)
        return 1
    n1, n2, L = fixed.shape[0], random.shape[0], fixed.shape[1]
    print(f"traces: fixed={n1} random={n2}  points(L)={L}")

    t_arr, df = welch_t(fixed, random)
    abs_t = np.abs(t_arr)
    tmax = float(abs_t.max())
    imax = int(abs_t.argmax())
    abs_point = imax + w0   # absolute sample point (includes window offset, used in reports under v5 presamples mode)

    C = critical_value(args.alpha, L, df)
    n_exceed = int((abs_t > C).sum())

    # Hot spots: top-N non-adjacent peaks (simple dedup: take |t| descending, skip points within ±5 of already selected)
    order = np.argsort(abs_t)[::-1]
    peaks = []
    for idx in order:
        if all(abs(idx - p) > 5 for p in peaks):
            peaks.append(int(idx))
        if len(peaks) >= args.top:
            break

    cyc = args.samples_per_cycle
    print(f"\nmax|t| = {tmax:.3f} @ point {imax} (abs {abs_point}) "
          f"(~cycle {imax / cyc:.0f}, ~{imax / cyc / args.clk_mhz:.1f} us)")
    if args.presamples > 0:
        print(f"(scheme 1 presamples={args.presamples}: trigger=busy completion edge at window end, "
              f"whole operation in window front; cycle counted from window start)")
    print(f"critical C(alpha={args.alpha:.0e}, L={L}) = {C:.3f}  "
          f"points above C = {n_exceed} ({100.0 * n_exceed / L:.3f}%)")
    verdict = "LEAKAGE DETECTED" if n_exceed > 0 else "no leakage above threshold"
    print(f"verdict: {verdict}")

    print(f"\ntop {len(peaks)} |t| hot spots (point -> cycle -> time):")
    for p in peaks:
        print(f"  point {p:8d}  cycle {p / cyc:9.1f}  t={abs_t[p]:7.3f}  "
              f"({p / cyc / args.clk_mhz:8.1f} us)")

    report = {
        "n_fixed": n1, "n_random": n2, "L": L,
        "window": [w0, w1],
        "max_abs_t": tmax, "argmax_point": imax, "argmax_abs_point": abs_point,
        "critical_C": C, "alpha": args.alpha,
        "n_above_C": n_exceed, "verdict": verdict,
        "hot_spots": [{"point": p, "abs_point": p + w0, "cycle": p / cyc,
                       "t": float(abs_t[p])} for p in peaks],
    }
    with open(os.path.join(args.dir, "tvla_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    print(f"\nreport -> {args.dir}/tvla_report.json")

    if args.plot:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            print("!! matplotlib not installed, skipping plot", file=sys.stderr)
            return 0
        fig, ax = plt.subplots(2, 1, figsize=(12, 7), sharex=True)
        x = np.arange(L) / cyc
        ax[0].plot(x, t_arr, lw=0.4)
        ax[0].axhline(C, color="r", ls="--", lw=0.8, label=f"+C={C:.2f}")
        ax[0].axhline(-C, color="r", ls="--", lw=0.8)
        ax[0].set_ylabel("t-value"); ax[0].legend()
        ax[0].set_title(f"TVLA |t| (max={tmax:.2f}, {verdict})")
        # Scheme 1 phase annotation: operation start = presamples - engine duration (LM-OTS KeyGen W4 ≈ 8966 cycles)
        if args.presamples > 0:
            eng_cycles = 8966  # LM-OTS KeyGen W4 hw measured (group A)
            op_start_abs = args.presamples - int(eng_cycles * cyc)
            for name, xa in [("DERIVE region (est.)", op_start_abs), ("trigger=completion edge", args.presamples)]:
                xc = (xa - w0) / cyc
                if 0 <= xc <= L / cyc:
                    ax[0].axvline(xc, color="g", ls=":", lw=0.8)
                    ax[0].text(xc, ax[0].get_ylim()[1] * 0.95, name, fontsize=7,
                               color="g", rotation=90, va="top")
        ax[1].plot(x, fixed.mean(axis=0), lw=0.4, label="fixed mean")
        ax[1].plot(x, random.mean(axis=0), lw=0.4, label="random mean")
        ax[1].set_xlabel(f"cycle ({args.clk_mhz} MHz)")
        ax[1].set_ylabel("power (ADC)"); ax[1].legend()
        fig.tight_layout()
        fig.savefig(args.plot, dpi=150)
        print(f"plot -> {args.plot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
