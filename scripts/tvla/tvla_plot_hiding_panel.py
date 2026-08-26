#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_plot_hiding_panel.py — two-panel paper figure for the hiding countermeasure (§6.2 appendix)

Top: RANDOM_DELAY dilution (unaligned) |t| — max|t| < C (x_q[i] @100k = 3.80)
Bottom: re-alignment recovery |t| — leakage peak 130.6 ("dilution rather than removal")

Data sources (all already-captured on-disk data, no board time needed):
  --dir           delayed capture directory (fixed/random.npy, e.g. build/tvla/derive_xq_delay_100k)
  --template-dir  delay-free reference directory (template source, uses its random/fixed group means)

Alignment logic identical to realign_analyze.py (template cross-correlation -> per-trace lag -> shift align -> Welch t).
"""
import argparse
import json
import os
import sys

import numpy as np

from realign_analyze import load_mean_var  # chunked mmap mean/var (full trace length)
from tvla_analyze import welch_t

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))


def hp(x, w):
    """Subtract sliding mean along the time axis (no boundary padding; first/last w/2 dropped)."""
    if w <= 1:
        return x
    k = np.ones(w) / w
    xm = np.apply_along_axis(lambda a: np.convolve(a, k, mode="same"), 1, x)
    return x - xm


def load_win_mean_var(path, w0, w1, chunk=8000):
    """Chunked-mmap pointwise mean/var over sample window [w0:w1) (avoids loading 20GB fully)."""
    mem = np.load(path, mmap_mode="r")
    L = w1 - w0
    s = np.zeros(L, dtype=np.float64)
    s2 = np.zeros(L, dtype=np.float64)
    n = 0
    N = mem.shape[0]
    for i in range(0, N, chunk):
        x = np.asarray(mem[i:min(i + chunk, N), w0:w1], dtype=np.float64)
        c = x.shape[0]
        s += x.sum(0)
        s2 += (x * x).sum(0)
        n += c
    mean = s / n
    var = (s2 - n * mean * mean) / (n - 1)
    return mean, var, n


def welch_from_mv(m1, v1, n1, m2, v2, n2):
    se = np.sqrt(v1 / n1 + v2 / n2)
    return np.divide(m1 - m2, se, out=np.zeros_like(se), where=se > 0)


def make_template(td, group, t0, tlen, hp_w):
    tm, _, _ = load_mean_var(os.path.join(td, group + ".npy"), 0, 100000)
    t = tm[t0:t0 + tlen]
    if hp_w > 1:
        t = hp(t.reshape(1, -1), hp_w)[0]
    return t - t.mean()


def realign(path, tmpl, wstart, search, max_shift, pre, tlen, hp_w):
    """Per-trace cross-correlation to find lag -> shift align -> returns (aligned, lag)."""
    mem = np.load(path, mmap_mode="r")
    N, L = mem.shape
    aligned = np.zeros((N, pre + tlen + 256), dtype=np.float64)
    lag = np.zeros(N, dtype=np.int64)
    w1 = min(wstart + search, L)
    nlag_max = max_shift + 1
    for i in range(0, N, 4096):
        x = np.asarray(mem[i:min(i + 4096, N)], dtype=np.float64)
        seg = x[:, wstart:w1]
        if hp_w > 1:
            seg = hp(seg, hp_w)
        nlag = min(seg.shape[1] - tlen + 1, nlag_max)
        corr = np.zeros((seg.shape[0], nlag))
        for k in range(nlag):
            s = seg[:, k:k + tlen]
            s = s - s.mean(axis=1, keepdims=True)
            corr[:, k] = (s * tmpl).sum(axis=1)
        best = np.argmax(corr, axis=1)
        for j in range(x.shape[0]):
            src_abs = max(0, wstart + best[j] - pre)
            src = x[j, src_abs:min(src_abs + aligned.shape[1], L)]
            aligned[i + j, :src.shape[0]] = src
            lag[i + j] = best[j]
    return aligned, lag


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="delayed capture directory (fixed/random.npy)")
    ap.add_argument("--template-dir", required=True, help="delay-free reference directory")
    ap.add_argument("--out", required=True, help="output two-panel figure path")
    ap.add_argument("--window", default="20016:26000",
                    help="dilution-panel analysis sample window (default 20016:26000, excludes busy+8 artifact)")
    ap.add_argument("--t0", type=int, default=20012, help="template start (absolute)")
    ap.add_argument("--tlen", type=int, default=64, help="template length")
    ap.add_argument("--search", type=int, default=1200, help="per-trace search-window length")
    ap.add_argument("--wstart", type=int, default=20004, help="search-window start")
    ap.add_argument("--max-shift", type=int, default=1100)
    ap.add_argument("--pre", type=int, default=16)
    ap.add_argument("--hp", type=int, default=32)
    ap.add_argument("--alpha", type=float, default=1e-5)
    ap.add_argument("--dpi", type=int, default=150)
    args = ap.parse_args()

    d = os.path.normpath(os.path.join(_ROOT, args.dir))
    td = os.path.normpath(os.path.join(_ROOT, args.template_dir))
    w0, w1 = (int(v) for v in args.window.split(":"))

    spc, clk = 1.0, 15.625
    try:
        with open(os.path.join(d, "fixed_meta.json"), encoding="utf-8") as fh:
            m = json.load(fh)
        spc = float(m.get("samples_per_cycle", 1.0))
        clk = float(m.get("clk_mhz", 15.625))
    except Exception:
        pass

    from scipy.stats import norm

    # ===== Top panel: dilution (unaligned) =====
    m1f, v1f, n1f = load_win_mean_var(os.path.join(d, "fixed.npy"), w0, w1)
    m1r, v1r, n1r = load_win_mean_var(os.path.join(d, "random.npy"), w0, w1)
    t1 = welch_from_mv(m1f, v1f, n1f, m1r, v1r, n1r)
    L1 = t1.shape[0]
    C1 = float(norm.ppf(1 - args.alpha / (2 * L1)))
    t1max = float(np.max(np.abs(t1)))

    # ===== Bottom panel: re-alignment recovery =====
    tmpl = {"fixed": make_template(td, "fixed", args.t0, args.tlen, args.hp),
            "random": make_template(td, "random", args.t0, args.tlen, args.hp)}
    af, _ = realign(os.path.join(d, "fixed.npy"), tmpl["fixed"],
                    args.wstart, args.search, args.max_shift, args.pre,
                    args.tlen, args.hp)
    ar, _ = realign(os.path.join(d, "random.npy"), tmpl["random"],
                    args.wstart, args.search, args.max_shift, args.pre,
                    args.tlen, args.hp)
    nf, nr = af.shape[0], ar.shape[0]
    mf, mr = af.mean(0), ar.mean(0)
    vf, vr = af.var(0, ddof=1), ar.var(0, ddof=1)
    t2 = welch_from_mv(mf, vf, nf, mr, vr, nr)
    t2 = np.nan_to_num(t2, nan=0.0, posinf=0.0, neginf=0.0)
    L2 = t2.shape[0]
    C2 = float(norm.ppf(1 - args.alpha / (2 * L2)))
    i2 = int(np.argmax(np.abs(t2)))
    t2max = float(abs(t2[i2]))

    print(f"unaligned: max|t|={t1max:.2f} C={C1:.2f} L={L1} "
          f"({100.0 * (np.abs(t1) > C1).mean():.2f}% above)")
    print(f"re-aligned: max|t|={t2max:.2f} @aligned-pt {i2} C={C2:.2f} L={L2}")

    # ===== Plotting =====
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(2, 1, figsize=(11, 7), sharex=False)

    # Top: dilution (cycle offset within window)
    x1 = (np.arange(L1) + w0) / spc
    ax[0].plot(x1, t1, lw=0.5, color="#1f77b4")
    ax[0].axhline(C1, color="#d62728", ls="--", lw=1.1,
                  label=f"±C={C1:.2f} (Bonferroni)")
    ax[0].axhline(-C1, color="#d62728", ls="--", lw=1.1)
    ax[0].axhline(4.5, color="#ff7f0e", ls=":", lw=1.1, label="±4.5 (5σ TVLA)")
    ax[0].axhline(-4.5, color="#ff7f0e", ls=":", lw=1.1)
    ax[0].axhline(0, color="gray", lw=0.5)
    ax[0].set_ylim(-max(C1, 6.5) * 1.15, max(C1, 6.5) * 1.15)
    ax[0].set_ylabel("t statistic")
    ax[0].set_title(
        f"RANDOM_DELAY, unaligned: max|t|={t1max:.2f} "
        f"(0 points above C; N_f={n1f}, N_r={n1r})")
    ax[0].legend(loc="upper right", fontsize=8)
    ax[0].grid(alpha=0.2)

    # Bottom: re-aligned (peak at origin)
    x2 = (np.arange(L2) - i2) / spc
    ax[1].plot(x2, t2, lw=0.8, color="#1f77b4")
    over = np.abs(t2) > C2
    if over.any():
        ax[1].fill_between(x2, -max(C2, 6.5), max(C2, 6.5), where=over,
                           color="red", alpha=0.12, interpolate=True,
                           linewidth=0)
    ax[1].axhline(C2, color="#d62728", ls="--", lw=1.1,
                  label=f"±C={C2:.2f} (Bonferroni)")
    ax[1].axhline(-C2, color="#d62728", ls="--", lw=1.1)
    ax[1].axhline(4.5, color="#ff7f0e", ls=":", lw=1.1, label="±4.5 (5σ TVLA)")
    ax[1].axhline(-4.5, color="#ff7f0e", ls=":", lw=1.1)
    ax[1].axhline(0, color="gray", lw=0.5)
    ylim2 = max(C2, 6.5) * 1.15
    ax[1].set_ylim(-ylim2, ylim2)
    if t2max > 4.5:
        top = t2[i2] > 0
        y_arrow = max(C2, 6.5) * 0.98 if top else -max(C2, 6.5) * 0.98
        ax[1].annotate(
            f"|t| = {t2max:.1f}", xy=(x2[i2], y_arrow),
            xytext=(x2[i2] + (x2[-1] - x2[0]) * 0.06, y_arrow * 0.92),
            arrowprops=dict(arrowstyle="-", color="red", lw=1.0),
            color="red", fontsize=9, ha="left", va="center")
    ax[1].set_xlim(-30, 150)
    ax[1].set_ylabel("t statistic")
    ax[1].set_xlabel(
        f"offset from leak peak (cycle @ {clk} MHz, {spc:.2f} samp/cyc; peak=0)")
    ax[1].set_title(f"Re-aligned: max|t|={t2max:.2f} "
                    f"(N_f={nf}, N_r={nr})")
    ax[1].legend(loc="upper right", fontsize=8)
    ax[1].grid(alpha=0.2)

    fig.tight_layout()
    fig.savefig(args.out, dpi=args.dpi)
    print(f"plot -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
