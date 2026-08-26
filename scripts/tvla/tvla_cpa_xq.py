#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_cpa_xq.py — SEED value-level attribution for x_q[i] data (mmap chunked, memory friendly)

Goal: SEED value-level analysis of the 0x6F isolated single x_q[i] capture data
(build/tvla/derive_xq_{1k,10k,100k} and their delay versions) that does **not depend on
fixed-vs-random grouping**, to adjudicate "does power really vary with the SEED value":

  --mode corr-hw      pointwise Pearson corr(power, HW(SEED)) (within random group)
  --mode corr-byte0   pointwise Pearson corr(power, SEED[0])
  --mode bitgroup b   Welch t on random group split by SEED bit b
  --mode hw-med       Welch t on random group split by HW median
  --mode split        Welch t on fixed group split by trace-index parity (same SEED, acquisition-systematics control)

For the x_q[i] measurement window (presamples=20000, busy+8 artifact at abs 20008, absorption ~20023):
  - corr ≈ 0 at artifact point 20008 -> artifact unrelated to SEED value (the TVLA giant peak is an
    acquisition-structure difference, not seed-content leakage) — CPA-version discrimination experiment
  - corr significant in absorption region [20012:20080] -> leakage genuinely varies with SEED value (SEED value-level attribution)

Usage:
  python scripts/tvla/tvla_cpa_xq.py --dir build/tvla/derive_xq_100k \
      --mode corr-hw
"""
import argparse
import json
import os
import sys

import numpy as np

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
C_ALPHA = 1e-5
ABSORB = (20012, 20080)   # absorption region (template t0=20012, 64 beats; peak ~20023)
ARTIFACT = 20008          # busy+8 fixed artifact point


def load_meta(dirpath, grp):
    p = os.path.join(dirpath, f"{grp}_meta.json")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        m = json.load(f)
    meta = m.get("meta")
    if not meta:
        return None
    return [e.get("seed") for e in meta]


def hw_of(seed_hex):
    return bin(int(seed_hex, 16)).count("1")


def welch_t_series(a, b):
    n1, n2 = a.shape[0], b.shape[0]
    m1, m2 = a.mean(axis=0), b.mean(axis=0)
    v1, v2 = a.var(axis=0, ddof=1), b.var(axis=0, ddof=1)
    denom = np.sqrt(v1 / n1 + v2 / n2)
    return np.where(denom > 0, (m1 - m2) / np.where(denom > 0, denom, 1.0), 0.0)


def corr_series(mem, f, w0, w1, blk=4000):
    """Pointwise Pearson corr(power, f(seed)), chunked by columns (float32 mmap -> local float64)."""
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


def critical_t(n, L):
    from scipy import stats
    return float(stats.t.ppf(1 - C_ALPHA / (2 * L), n - 2))


def summarize(name, corr, t, w0, C, out_dir):
    at = np.abs(t)
    mx = float(at.max())
    arg = int(at.argmax())
    a0, a1 = ABSORB
    seg = slice(a0 - w0, a1 - w0)
    absorb_t = float(np.abs(t[seg]).max()) if seg.stop > 0 else 0.0
    absorb_arg = int(seg.start + np.abs(t[seg]).argmax()) if seg.stop > 0 else -1
    corr_art = (float(corr[ARTIFACT - w0])
                if corr is not None and w0 <= ARTIFACT < w0 + corr.size
                else None)
    above = int((at > C).sum())
    print(f"[{name}] L={t.size} max|t|={mx:.2f}@{arg} (abs {arg + w0}) "
          f"| absorb[{a0}:{a1}] max|t|={absorb_t:.2f}@{absorb_arg + w0} "
          f"| corr@20008={corr_art if corr_art is not None else 'n/a'}"
          f" | C={C:.2f} above={above}")
    res = {"label": name, "L": int(t.size), "window": [w0, w0 + t.size],
           "max_abs_t": mx, "argmax_abs_point": int(arg + w0),
           "absorb_region": [a0, a1], "absorb_max_abs_t": absorb_t,
           "absorb_argmax_abs_point": int(absorb_arg + w0),
           "corr_at_artifact_20008": corr_art,
           "critical_C": C, "n_above_C": above}
    with open(os.path.join(out_dir, "tvla_cpa_xq_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--mode", required=True,
                    choices=["corr-hw", "corr-byte0", "bitgroup", "hw-med",
                             "split"])
    ap.add_argument("--bit", type=int, default=7)
    ap.add_argument("--window", default="20000:26000")
    args = ap.parse_args()

    d = os.path.normpath(os.path.join(_ROOT, args.dir))
    w0, w1 = (int(v) for v in args.window.split(":"))

    grp = "fixed" if args.mode == "split" else "random"
    npy = os.path.join(d, f"{grp}.npy")
    if not os.path.exists(npy):
        print(f"!! {npy} missing", file=sys.stderr)
        return 1
    mem = np.load(npy, mmap_mode="r")
    seeds = load_meta(d, grp)

    if args.mode in ("corr-hw", "corr-byte0"):
        if not seeds:
            print("!! no per-trace seed in meta", file=sys.stderr)
            return 1
        f = np.array([hw_of(s) for s in seeds], dtype=np.float64) \
            if args.mode == "corr-hw" \
            else np.array([bytes.fromhex(s)[0] for s in seeds],
                          dtype=np.float64)
        corr, t = corr_series(mem, f, w0, w1)
        C = critical_t(len(f), t.size)
        summarize(args.mode, corr, t, w0, C, d)
    elif args.mode in ("bitgroup", "hw-med"):
        if not seeds:
            print("!! no per-trace seed in meta", file=sys.stderr)
            return 1
        if args.mode == "bitgroup":
            g = np.array([(int(s, 16) >> args.bit) & 1 for s in seeds],
                         dtype=np.int64)
        else:
            hw = np.array([hw_of(s) for s in seeds], dtype=np.float64)
            g = (hw > np.median(hw)).astype(np.int64)
        L = w1 - w0
        if args.mode == "bitgroup":
            g = np.array([(int(s, 16) >> args.bit) & 1 for s in seeds],
                         dtype=np.int64)
        else:
            hw = np.array([hw_of(s) for s in seeds], dtype=np.float64)
            g = (hw > np.median(hw)).astype(np.int64)
        idx0 = np.where(g == 0)[0]
        idx1 = np.where(g == 1)[0]
        g0 = np.asarray(mem[idx0, w0:w1], dtype=np.float32)
        g1 = np.asarray(mem[idx1, w0:w1], dtype=np.float32)
        t = welch_t_series(g0, g1)
        from scipy import stats
        C = float(stats.t.ppf(1 - C_ALPHA / (2 * t.size), min(g0.shape[0],
                                                              g1.shape[0]) - 1))
        summarize(args.mode + (f" b{args.bit}" if args.mode == "bitgroup"
                               else ""), None, t, w0, C, d)
    else:  # split: even/odd split within fixed group
        n = mem.shape[0]
        L = w1 - w0
        idx0 = np.arange(0, n, 2)
        idx1 = np.arange(1, n, 2)
        g0 = np.asarray(mem[idx0, w0:w1], dtype=np.float32)
        g1 = np.asarray(mem[idx1, w0:w1], dtype=np.float32)
        t = welch_t_series(g0, g1)
        from scipy import stats
        C = float(stats.t.ppf(1 - C_ALPHA / (2 * t.size), n // 2 - 1))
        summarize("split", None, t, w0, C, d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
