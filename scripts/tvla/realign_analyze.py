#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""realign_analyze.py — re-aligned TVLA analysis of randomly delayed (RANDOM_DELAY) traces

Paper methodology (§10 of the TVLA mitigation review): after hiding dilution, align each
trace to its actual DERIVE position → recover the leakage (old C path 170.2@100k).
Applied the same way to x_q[i] (0x6F+RANDOM_DELAY):

- Template: mean DERIVE-segment trace from the delay-free reference run
  (--template-dir). Uses the random-group mean (seed-averaged → DERIVE power
  envelope independent of SEED); t0 is taken after the fixed artifact ~8 cycles
  after busy (not SEED-related), to avoid cross-correlation locking onto the artifact.
- Per trace: cross-correlate with the template within the post-trigger search
  window → best lag L (= that trace's DERIVE shift relative to the reference)
  → shift-align → recompute the pointwise Welch t.

Usage:
  python scripts/tvla/realign_analyze.py --dir build/tvla/derive_xq_delay_100k \
      --template-dir build/tvla/derive_xq_100k
"""
import argparse
import json
import os
import sys

import numpy as np

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))


def load_mean_var(path, i0, i1, chunk=8000):
    """Compute pointwise mean/var of traces [i0:i1) in chunks (avoids memory blow-up at the 100k scale)."""
    mem = np.load(path, mmap_mode="r")
    L = mem.shape[1]
    s = np.zeros(L, dtype=np.float64)
    s2 = np.zeros(L, dtype=np.float64)
    n = 0
    for i in range(i0, i1, chunk):
        x = np.asarray(mem[i:min(i + chunk, i1)], dtype=np.float64)
        c = x.shape[0]
        s += x.sum(0)
        s2 += (x * x).sum(0)
        n += c
    mean = s / n
    var = (s2 - n * mean * mean) / (n - 1)
    return mean, var, n


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True, help="delayed acquisition directory (fixed/random.npy)")
    ap.add_argument("--template-dir", required=True,
                    help="delay-free reference directory (template source; uses its random-group mean)")
    ap.add_argument("--t0", type=int, default=20012,
                    help="template start (absolute; after the busy+8 fixed artifact)")
    ap.add_argument("--tlen", type=int, default=64, help="template length")
    ap.add_argument("--search", type=int, default=1200,
                    help="per-trace search window length (covers rnd 0..1023 + margin)")
    ap.add_argument("--wstart", type=int, default=20004,
                    help="search window start (absolute; slightly before the template start)")
    ap.add_argument("--max-shift", type=int, default=1100,
                    help="maximum allowed lag")
    ap.add_argument("--pre", type=int, default=16,
                    help="output window samples before the template match position (to include "
                         "peak 20008; template starts at 20012, peak is 4 cycles before it)")
    ap.add_argument("--hp", type=int, default=32,
                    help="high-pass window length (subtract sliding mean to emphasize per-cycle structure; 0=off)")
    ap.add_argument("--alpha", type=float, default=1e-5)
    ap.add_argument("--plot", default=None,
                    help="path of the |t| curve plot after realignment (SLotH style: signed t + "
                         "±C + ±4.5 + peak annotation; optional, requires matplotlib)")
    ap.add_argument("--plot-xlim", default=None,
                    help="plot x-axis range (peak at origin, in cycles; e.g. '-30:150' trims the "
                         "flat tails; default full window)")
    args = ap.parse_args()

    d = os.path.normpath(os.path.join(_ROOT, args.dir))
    td = os.path.normpath(os.path.join(_ROOT, args.template_dir))

    def hp(x, w):
        """Subtract the sliding mean along the time axis (no boundary padding; first/last w/2 dropped)."""
        if w <= 1:
            return x
        k = np.ones(w) / w
        # sliding-average each trace with np.convolve (axis=1 is time)
        xm = np.apply_along_axis(
            lambda a: np.convolve(a, k, mode="same"), 1, x)
        return x - xm

    # Template: mean DERIVE-segment trace from the delay-free reference (de-meaned + high-pass).
    # Per-group template: fixed group uses the delay-free fixed mean (same seed → identical
    # structure, near-perfect alignment); random group uses the delay-free random mean (seed-averaged envelope).
    def make_tmpl(group):
        tm, _, _ = load_mean_var(os.path.join(td, group + ".npy"), 0, 100000)
        t = tm[args.t0:args.t0 + args.tlen]
        if args.hp > 1:
            t = hp(t.reshape(1, -1), args.hp)[0]
        return t - t.mean()

    tmpl = {"fixed": make_tmpl("fixed"), "random": make_tmpl("random")}

    nlag_max = args.max_shift + 1

    def realign(path, tmpl):
        mem = np.load(path, mmap_mode="r")
        N, L = mem.shape
        # aligned column k ↔ original abs (wstart + lag_j - pre + k); the template match lands at a fixed slot
        aligned = np.zeros((N, args.pre + args.tlen + 256), dtype=np.float64)
        lag = np.zeros(N, dtype=np.int64)
        w1 = min(args.wstart + args.search, L)
        for i in range(0, N, 4096):
            x = np.asarray(mem[i:min(i + 4096, N)], dtype=np.float64)
            seg = x[:, args.wstart:w1]
            if args.hp > 1:
                seg = hp(seg, args.hp)
            nlag = seg.shape[1] - args.tlen + 1
            nlag = min(nlag, nlag_max)
            corr = np.zeros((seg.shape[0], nlag))
            for k in range(nlag):
                s = seg[:, k:k + args.tlen]
                s = s - s.mean(axis=1, keepdims=True)
                corr[:, k] = (s * tmpl).sum(axis=1)
            best = np.argmax(corr, axis=1)
            for j in range(x.shape[0]):
                src_abs = args.wstart + best[j] - args.pre
                if src_abs < 0:
                    src_abs = 0
                src = x[j, src_abs:min(src_abs + aligned.shape[1], L)]
                aligned[i + j, :src.shape[0]] = src
                lag[i + j] = best[j]
        return aligned, lag

    print(f"re-aligning {d} ...", flush=True)
    af, lagf = realign(os.path.join(d, "fixed.npy"), tmpl["fixed"])
    ar, lagr = realign(os.path.join(d, "random.npy"), tmpl["random"])

    nf, nr = af.shape[0], ar.shape[0]
    mf = af.mean(0)
    mr = ar.mean(0)
    vf = af.var(0, ddof=1)
    vr = ar.var(0, ddof=1)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = (mf - mr) / np.sqrt(vf / nf + vr / nr)
    t = np.nan_to_num(t, nan=0.0, posinf=0.0, neginf=0.0)

    from scipy.stats import norm
    C = norm.ppf(1 - args.alpha / (2 * t.shape[0]))
    i = int(np.argmax(np.abs(t)))
    above = int(np.sum(np.abs(t) > C))
    lag_mid = (lagf.mean() + lagr.mean()) / 2.0
    print(f"re-aligned: max|t| = {abs(t[i]):.2f} @ aligned-pt {i} "
          f"(abs ~{args.wstart + lag_mid - args.pre + i:.0f})")
    print(f"C(Bonf, L={t.shape[0]}) = {C:.3f}  above-C = {above} "
          f"({above / t.shape[0] * 100:.2f}%)")
    print(f"lag: fixed mean={lagf.mean():.1f} max={lagf.max()} | "
          f"random mean={lagr.mean():.1f} max={lagr.max()}")

    out = os.path.join(d, "realign_report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"max_abs_t": float(abs(t[i])), "argmax_aligned": int(i),
                   "C": float(C), "n_above_C": above, "alpha": args.alpha,
                   "lag_fixed_mean": float(lagf.mean()),
                   "lag_random_mean": float(lagr.mean())},
                  f, ensure_ascii=False, indent=1)
    print(f"report -> {out}")

    if args.plot:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            print("!! matplotlib not installed, skipping plot", file=sys.stderr)
        else:
            spc, clk = 1.0, 15.625
            try:
                with open(os.path.join(d, "fixed_meta.json"), encoding="utf-8") as fh:
                    m = json.load(fh)
                spc = float(m.get("samples_per_cycle", 1.0))
                clk = float(m.get("clk_mhz", 15.625))
            except Exception:
                pass
            Lp = t.shape[0]
            x = (np.arange(Lp) - i) / spc  # peak at origin (cycles)
            ylim = max(float(C), 6.5)
            fig, ax = plt.subplots(figsize=(11, 4))
            ax.plot(x, t, lw=0.8, color="#1f77b4",
                    label="re-aligned t (fixed vs random)")
            over = np.abs(t) > C
            if over.any():
                ax.fill_between(x, -ylim, ylim, where=over, color="red",
                                alpha=0.12, interpolate=True, linewidth=0)
            ax.axhline(C, color="#d62728", ls="--", lw=1.1,
                       label=f"±C={C:.2f} (Bonferroni)")
            ax.axhline(-C, color="#d62728", ls="--", lw=1.1)
            ax.axhline(4.5, color="#ff7f0e", ls=":", lw=1.1,
                       label="±4.5 (5σ TVLA)")
            ax.axhline(-4.5, color="#ff7f0e", ls=":", lw=1.1)
            ax.axhline(0, color="gray", lw=0.5)
            ylim2 = ylim * 1.15
            ax.set_ylim(-ylim2, ylim2)
            if args.plot_xlim:
                x0, x1 = (float(v) for v in args.plot_xlim.split(":"))
                ax.set_xlim(x0, x1)
            tmax_p = float(abs(t[i]))
            if tmax_p > 4.5:
                top = t[i] > 0
                y_arrow = ylim * 0.98 if top else -ylim * 0.98
                ax.annotate(
                    f"|t| = {tmax_p:.1f}", xy=(x[i], y_arrow),
                    xytext=(x[i] + (x[-1] - x[0]) * 0.06, y_arrow * 0.92),
                    arrowprops=dict(arrowstyle="-", color="red", lw=1.0),
                    color="red", fontsize=9, ha="left", va="center")
            ax.set_xlabel(f"offset from leak peak (cycle @ {clk} MHz, "
                          f"{spc:.2f} samp/cyc; peak=0)")
            ax.set_ylabel("t statistic")
            ax.set_title(f"Re-aligned TVLA t-test (isolated x_q[i], "
                         f"RANDOM_DELAY, N_f={nf}, N_r={nr}, "
                         f"max|t|={tmax_p:.2f}, C={C:.2f}, L={Lp})")
            ax.legend(loc="upper right", fontsize=8)
            ax.grid(alpha=0.2)
            fig.tight_layout()
            fig.savefig(args.plot, dpi=150)
            print(f"plot -> {args.plot}")


if __name__ == "__main__":
    main()
