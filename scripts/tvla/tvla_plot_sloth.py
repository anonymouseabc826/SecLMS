#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_plot_sloth.py — SLotH paper-style TVLA t-trace figure (2026-08-18)

Computes pointwise Welch t over the fixed/random trace pair captured by tvla_capture.py, and plots
per the SLotH paper (Accelerating_SLH_DSA.md §7.1) plotting conventions:
  * signed t curve (oscillating around 0), not |t|;
  * y axis clipped near the threshold (default max(C, 6.5)); above-threshold giant peaks are "top-clipped",
    with a red arrow at the clip marking the actual peak value (e.g. "|t| = 42.1");
  * dual threshold lines: ±C (Bonferroni correction, normal/t quantile C=Φ^{-1}(1-α/2L), red dashed)
    + ±4.5 (standard TVLA 5σ, orange dotted, reference);
  * above-threshold regions (|t|>C) highlighted in translucent red;
  * optional bottom subplot: fixed/random mean traces (power waveforms) shown aligned.

Statistically identical to tvla_analyze.py (reuses its welch_t / critical_value),
only the plotting style differs; for analysis numbers, rely on tvla_analyze.py output.

Usage:
  python scripts/tvla/tvla_plot_sloth.py --dir build/tvla/v6_prf_smoke1k \
      --out build/tvla/v6_prf_smoke1k/fig_sloth.png [--window 4000:32767] \
      [--ylim 6.5] [--no-mean] [--clk-mhz 15.6] [--samples-per-cycle 3.2051]
"""
import argparse
import json
import os
import sys

import numpy as np

from tvla_analyze import welch_t, critical_value


def load_pair(d):
    """Read the fixed/random npy pair + read presamples/clk/spc from meta."""
    f = np.load(os.path.join(d, "fixed.npy"))
    r = np.load(os.path.join(d, "random.npy"))
    meta = {}
    for grp in ("fixed", "random"):
        p = os.path.join(d, grp + "_meta.json")
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as fh:
                    meta.update(json.load(fh))
            except Exception:
                pass
    return f, r, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="trace directory (fixed/random .npy)")
    ap.add_argument("--out", required=True, help="output figure path")
    ap.add_argument("--alpha", type=float, default=1e-5)
    ap.add_argument("--window", default=None, help="sample range 'start:end'")
    ap.add_argument("--presamples", type=int, default=None,
                    help="pre-trigger samples (auto from meta if present; default window=0:presamples)")
    ap.add_argument("--clk-mhz", type=float, default=None,
                    help="clock MHz (auto from meta if present; only affects x-axis units)")
    ap.add_argument("--samples-per-cycle", type=float, default=None,
                    help="samples per cycle (auto from meta if present)")
    ap.add_argument("--ylim", type=float, default=None,
                    help="y-axis clip range (default max(C, 6.5); beyond it top-clip + arrow annotation)")
    ap.add_argument("--std-threshold", type=float, default=4.5,
                    help="standard TVLA threshold (default 4.5=common 5σ value, red dashed)")
    ap.add_argument("--center", type=int, default=None,
                    help="symmetric window centered on the max|t| peak (half-width = this many samples), x axis with peak at origin "
                         "(default None=original window; use for SLotH-style centered figures)")
    ap.add_argument("--no-mean", action="store_true",
                    help="do not plot the fixed/random mean-trace subplot")
    ap.add_argument("--legend-loc", default="upper right",
                    help="legend location (matplotlib loc; for peak-centered figures use 'upper left' or "
                         "'center right' to avoid covering the peak-top arrow, default upper right)")
    ap.add_argument("--highlight", default="band",
                    choices=["none", "band", "all"],
                    help="above-threshold red highlight mode: band=highlight only the main peak band "
                         "(|t|>max(C, 0.3*tmax), recommended, avoids solid red over narrow windows); "
                         "all=everything |t|>C (legacy behavior, solid red shadow over narrow windows); "
                         "none=no highlight (threshold lines + peak arrow only, cleanest)")
    ap.add_argument("--decimate", type=int, default=None,
                    help="rendering stride for full-window dense plots (e.g. SLotH 200k-point/sign large windows): plot every "
                         "Nth sample of the curve (peak annotation still computed at full resolution). "
                         "Default None=no decimation; recommend >= 50 for 200k-point windows, "
                         "so the oscillating curve is readable rather than a solid block.")
    ap.add_argument("--exclude", default=None,
                    help="absolute sample range 'start:end' to exclude fixed artifacts (t zeroed, e.g. "
                         "'20007:20011' removes the busy+8 load peak)")
    ap.add_argument("--dpi", type=int, default=150)
    args = ap.parse_args()

    fixed, random, meta = load_pair(args.dir)
    # Auto-fill parameters from meta (explicit command-line values take priority)
    if args.presamples is None:
        args.presamples = int(meta.get("presamples", 0) or 0)
    if args.clk_mhz is None:
        args.clk_mhz = float(meta.get("clk_mhz", 50.0))
    if args.samples_per_cycle is None:
        args.samples_per_cycle = float(meta.get("samples_per_cycle", 1.0))

    tlen_full = fixed.shape[1]

    # Search window (for peak finding): --window first; else --presamples (scheme 1: whole operation before trigger);
    # else the full trace.
    if args.window:
        s0, s1 = (int(x) for x in args.window.split(":"))
    elif args.presamples > 0:
        s0, s1 = 0, args.presamples
    else:
        s0, s1 = 0, tlen_full
    s1 = min(s1, tlen_full)
    if s1 - s0 < 2:
        print(f"!! search window too short [{s0}:{s1}]", file=sys.stderr)
        return 1

    # --center N: find the max|t| peak within the search window, then take a symmetric window centered on the peak (half-width N samples),
    # x axis with peak at origin. For short operations (single PRF ~60 cycles) the waveform body thus lands in the figure center,
    # with pre/post-operation context on both sides — the SLotH paper's "leakage peak centered" shape.
    center_origin = None  # absolute sample position of the peak in the original trace (x=0)
    if args.center is not None:
        ts, dfs = welch_t(np.asarray(fixed[:, s0:s1], dtype=np.float64),
                          np.asarray(random[:, s0:s1], dtype=np.float64))
        # --exclude also applies to peak detection (excludes fixed artifacts, avoids centering on an artifact peak)
        if args.exclude:
            e0, e1 = (int(v) for v in args.exclude.split(":"))
            j0 = max(0, e0 - s0)
            j1 = min(ts.shape[0], e1 - s0)
            if j1 > j0:
                ts[j0:j1] = 0.0
        peak_abs = s0 + int(np.abs(ts).argmax())
        c0 = max(0, peak_abs - args.center)
        c1 = min(tlen_full, peak_abs + args.center)
        # When the peak is too close to the trace start/end for symmetry, snap the window to the edge (keeping width 2N)
        if c0 == 0:
            c1 = min(tlen_full, 2 * args.center)
        elif c1 == tlen_full:
            c0 = max(0, tlen_full - 2 * args.center)
        center_origin = float(peak_abs)
        w0, w1 = c0, c1
        print(f"--center {args.center}: peak at absolute sample {peak_abs}, window [{c0}:{c1}] L={c1 - c0}")
    else:
        w0, w1 = s0, s1

    fixed = np.asarray(fixed[:, w0:w1], dtype=np.float64)
    random = np.asarray(random[:, w0:w1], dtype=np.float64)
    L = fixed.shape[1]
    if fixed.shape[0] < 2 or random.shape[0] < 2:
        print(f"!! too few traces fixed={fixed.shape[0]} random={random.shape[0]}", file=sys.stderr)
        return 1

    t_arr, df = welch_t(fixed, random)
    # --exclude "start:end" (absolute samples): zero t over that range (excludes fixed measurement artifacts,
    # e.g. busy+8 load peak; peak/highlight/threshold all based on the zeroed data)
    if args.exclude:
        e0, e1 = (int(v) for v in args.exclude.split(":"))
        i0 = max(0, e0 - w0)
        i1 = min(L, e1 - w0)
        if i1 > i0:
            t_arr[i0:i1] = 0.0
            print(f"--exclude abs[{e0}:{e1}) -> window idx [{i0}:{i1}) zeroed")
    abs_t = np.abs(t_arr)
    tmax = float(abs_t.max())
    C = critical_value(args.alpha, L, df)
    std_thr = args.std_threshold

    # y-axis clip: default max(C, 6.5), keeping threshold lines and waveform body visible; giant peaks top-clipped
    ylim = args.ylim if args.ylim else max(float(C), 6.5)

    cyc = args.samples_per_cycle
    # x axis: with --center, peak at origin (cycle and us dual axis); otherwise counted from window start
    if center_origin is not None:
        x = (np.arange(L) + w0 - center_origin) / cyc  # cycle, peak=0
    else:
        x = np.arange(L) / cyc
    x_us = x / args.clk_mhz  # us

    # --decimate: rendering stride for full-window dense plots (peak/threshold/highlight still use full-resolution t_arr)
    if args.decimate and args.decimate > 1:
        step = int(args.decimate)
        x_disp = x[::step]
        t_disp = t_arr[::step]
        n_disp = len(x_disp)
        print(f"--decimate {step}: full window {L} points -> displaying {n_disp} points")
    else:
        x_disp, t_disp = x, t_arr
        n_disp = L

    nrows = 1 if args.no_mean else 2
    fig, ax = plt.subplots(nrows, 1, figsize=(11, 3.2 * nrows),
                           sharex=True, dpi=args.dpi)
    if nrows == 1:
        ax = [ax]
    a0 = ax[0]

    # 1) signed t curve (thin blue line; with --decimate drawn at display stride)
    a0.plot(x_disp, t_disp, lw=0.5, color="#1f77b4")

    # 2) above-threshold red highlight: band=highlight only the main peak band (|t|>max(C,0.3*tmax)),
    #    avoiding narrow windows where |t|>C points paint the whole y range as a red shadow; none=off.
    if args.highlight == "band":
        over = abs_t > max(C, 0.3 * tmax)
    elif args.highlight == "all":
        over = abs_t > C
    else:
        over = None
    if over is not None and over.any():
        a0.fill_between(x, -ylim, ylim, where=over, color="red", alpha=0.12,
                        interpolate=True, linewidth=0)
    # Top-clipped giant peaks: draw short red vertical ticks where above threshold and reaching the ylim edge
    clip_hit = (over is not None) & over & ((t_arr >= ylim) | (t_arr <= -ylim))
    if clip_hit.any():
        idx = np.where(clip_hit)[0]
        # Under coarse sampling these may merge into segments; drawing only the first point of each segment keeps it clean
        last = -2
        for k in idx:
            if k - last > 4:
                a0.plot([x[k], x[k]], [-ylim, ylim], color="red", lw=0.6,
                        alpha=0.6)
            last = k

    # 3) dual threshold lines: ±C (Bonferroni, red dashed, paper caliber) + ±4.5 (standard TVLA 5σ, orange dotted)
    a0.axhline(C, color="#d62728", ls="--", lw=1.1,
               label=f"+C={C:.2f} (Bonferroni)")
    a0.axhline(-C, color="#d62728", ls="--", lw=1.1)
    a0.axhline(std_thr, color="#ff7f0e", ls=":", lw=1.1,
               label=f"+{std_thr:.1f} (5σ TVLA)")
    a0.axhline(-std_thr, color="#ff7f0e", ls=":", lw=1.1)
    a0.axhline(0, color="gray", lw=0.5)

    # 4) y-axis clip + top-clip arrow annotating the actual peak
    a0.set_ylim(-ylim, ylim)
    imax = int(abs_t.argmax())
    # Annotate only when the peak really exceeds the threshold: arrow from the peak top to a text box beside it (not flush with the frame top,
    # avoiding text overlapping frame/title; in peak-centered figures the right side is context area, so right side is emptier).
    if tmax > std_thr:
        top = t_arr[imax] > 0
        y_arrow = min(ylim, float(tmax)) * 0.98
        # Place the text to the right of the peak (positive x), connected with a thin line to the peak top
        txt_dx = (x[-1] - x[0]) * 0.06
        a0.annotate(
            f"|t| = {tmax:.1f}", xy=(x[imax], y_arrow),
            xytext=(x[imax] + txt_dx, y_arrow * 0.92),
            arrowprops=dict(arrowstyle="-", color="red", lw=1.0),
            color="red", fontsize=9, ha="left", va="center")
    a0.set_ylabel("t statistic")
    a0.set_title(f"TVLA t-test (N_f={fixed.shape[0]}, N_r={random.shape[0]}, "
                 f"max|t|={tmax:.1f}, C={C:.2f}, L={L})")
    a0.legend(loc=args.legend_loc, fontsize=8, framealpha=0.9)
    a0.grid(alpha=0.2)

    # 5) optional: mean power-waveform subplot
    if not args.no_mean:
        a1 = ax[1]
        a1.plot(x, fixed.mean(axis=0), lw=0.6, color="#1f77b4", label="fixed mean")
        a1.plot(x, random.mean(axis=0), lw=0.6, color="#2ca02c", label="random mean")
        a1.set_ylabel("power (ADC)")
        a1.legend(loc=args.legend_loc, fontsize=8)

    if args.center is not None:
        ax[-1].set_xlabel(
            f"offset from leak peak (cycle @{args.clk_mhz} MHz; "
            f"{args.samples_per_cycle:.2f} samp/cyc; peak=0)")
    else:
        ax[-1].set_xlabel(f"time (cycle @{args.clk_mhz} MHz; "
                          f"{args.samples_per_cycle:.2f} samp/cyc)")
    fig.tight_layout()
    fig.savefig(args.out, dpi=args.dpi)
    print(f"plot -> {args.out}  (ylim=±{ylim:.2f}, max|t|={tmax:.1f} @cycle {imax/cyc:.0f} "
          f"~{imax/cyc/args.clk_mhz:.1f} us, C={C:.2f})")
    return 0


if __name__ == "__main__":
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("!! matplotlib not installed", file=sys.stderr)
        sys.exit(1)
    sys.exit(main())
