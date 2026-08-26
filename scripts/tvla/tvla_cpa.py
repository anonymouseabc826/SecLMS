#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_cpa.py — SEED value-level adjudication analysis (2026-08-20)

Goal: adjudicate the TVLA-caliber ambiguity — "fixing other values -> true positive vs false positive",
"randomizing other values -> false negative vs true negative". Using analysis that does **not depend on
fixed-vs-random grouping** to directly answer "does power really vary with the SEED value":

  --mode bitgroup <b>  pointwise Welch t on random group split by SEED bit b
                       (SEED value-function grouping, not fixed-vs-random)
  --mode hw            pointwise Welch t on random group split by SEED Hamming-weight median
                       (coarse value function)
  --mode corr <f>      pointwise Pearson correlation corr(power, f(seed)), f∈{hw, byte0}
  --mode split         pointwise Welch t on fixed group split by trace-index parity (same SEED
                       same operation, should be flat -> rules out acquisition-flow/batch systematics)

Adjudication logic:
  E1  bitgroup/hw/corr significant in random group  -> power genuinely varies with SEED value
      -> fixed-caliber positive = true positive (the reverse "fixed caliber manufactures false positives" explanation is excluded)
  E2  split flat -> acquisition flow itself has no systematics (fixed-caliber positive is not a flow artifact)
  E3  bitgroup still significant on sloth-caliber data (I/q already randomized)
      -> SEED value-level leakage remains recoverable under the randomized caliber -> randomized-caliber flat line = confirmed false negative

Usage:
  python scripts/tvla/tvla_cpa.py --dir build/tvla/night_prf_100k \
      --mode bitgroup 7 --clk-mhz 15.6
  python scripts/tvla/tvla_cpa.py --dir build/tvla/night_prf_100k \
      --mode hw --clk-mhz 15.6
  python scripts/tvla/tvla_cpa.py --dir build/tvla/night_prf_100k \
      --mode corr hw --clk-mhz 15.6
  python scripts/tvla/tvla_cpa.py --dir build/tvla/night_prf_100k \
      --mode split --clk-mhz 15.6
"""
import argparse
import json
import os
import sys

import numpy as np

C_ALPHA = 1e-5


def load(dirpath):
    """Load fixed/random npy + per-trace seed."""
    traces = {}
    seeds = {}
    for grp in ("fixed", "random"):
        p = os.path.join(dirpath, f"{grp}.npy")
        if not os.path.exists(p):
            continue
        traces[grp] = np.load(p)
        mp = os.path.join(dirpath, f"{grp}_meta.json")
        if os.path.exists(mp):
            with open(mp, encoding="utf-8") as f:
                m = json.load(f)
            meta = m.get("meta")
            if meta:
                seeds[grp] = [e.get("seed") for e in meta]
    return traces, seeds


def seed_bytes(seed_hex):
    return bytes.fromhex(seed_hex)


def hw_of(seed_hex):
    return bin(int(seed_hex, 16)).count("1")


def welch_t_series(a, b, spc=1.0):
    """Pointwise Welch t (ddof=1, Satterthwaite); returns t array and number of independent points L."""
    n1, n2 = a.shape[0], b.shape[0]
    m1 = a.mean(axis=0)
    m2 = b.mean(axis=0)
    v1 = a.var(axis=0, ddof=1)
    v2 = b.var(axis=0, ddof=1)
    denom = np.sqrt(v1 / n1 + v2 / n2)
    t = np.where(denom > 0, (m1 - m2) / np.where(denom > 0, denom, 1.0), 0.0)
    L = t.size
    C = _critical_C(n1, n2, L, spc)
    return t, C


def _critical_C(n1, n2, L, spc=1.0):
    """Bonferroni: C = t_{1 - alpha/(2*L_eff)} (df~min(n1,n2)-1 conservative)."""
    from scipy import stats
    L_eff = L / spc
    df = min(n1, n2) - 1
    return float(stats.t.ppf(1 - C_ALPHA / (2 * L_eff), df))


def report(t, C, label, out_dir, clk_mhz, extra=None):
    at = np.abs(t)
    mx = at.max()
    arg = int(at.argmax())
    above = int((at > C).sum())
    print(f"[{label}] L={t.size}  max|t|={mx:.2f} @pt {arg} "
          f"({arg / (clk_mhz * 1e6) * 1e6:.1f} us)  C={C:.2f}  "
          f"above={above} ({100.0 * above / t.size:.3f}%)")
    res = {"label": label, "L": int(t.size), "max_abs_t": float(mx),
           "argmax_point": int(arg), "critical_C": C, "n_above_C": above,
           "verdict": "LEAKAGE DETECTED" if mx > C else "no leakage"}
    if extra:
        res.update(extra)
    with open(os.path.join(out_dir, "tvla_cpa_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    return res


def mode_bitgroup(traces, seeds, args, out_dir):
    """Group random traces by SEED bit b."""
    if "random" not in traces:
        print("!! no random group", file=sys.stderr)
        return
    X = traces["random"]
    sd = seeds.get("random")
    if not sd:
        print("!! random meta has no per-trace seed", file=sys.stderr)
        return
    b = args.bit
    bits = np.array([(int(s, 16) >> b) & 1 for s in sd], dtype=np.int64)
    g0 = X[bits == 0]
    g1 = X[bits == 1]
    print(f"bit {b}: 0-group={g0.shape[0]}  1-group={g1.shape[0]}")
    t, C = welch_t_series(g0, g1, args.samples_per_cycle)
    report(t, C, f"random-group by SEED bit{b} (E1)",
           out_dir, args.clk_mhz, extra={"bit": b,
                                         "n0": int(g0.shape[0]),
                                         "n1": int(g1.shape[0])})


def mode_hw(traces, seeds, args, out_dir):
    """Group random traces by SEED Hamming-weight median."""
    if "random" not in traces:
        print("!! no random group", file=sys.stderr)
        return
    X = traces["random"]
    sd = seeds.get("random")
    if not sd:
        print("!! random meta has no per-trace seed", file=sys.stderr)
        return
    hw = np.array([hw_of(s) for s in sd], dtype=np.float64)
    med = np.median(hw)
    g0 = X[hw <= med]
    g1 = X[hw > med]
    print(f"HW median={med}: low={g0.shape[0]}  high={g1.shape[0]}  "
          f"(HW range {hw.min()}-{hw.max()})")
    t, C = welch_t_series(g0, g1, args.samples_per_cycle)
    report(t, C, "random-group by SEED HW-median (E1)",
           out_dir, args.clk_mhz, extra={"hw_median": float(med)})


def mode_corr(traces, seeds, args, out_dir):
    """Pointwise Pearson corr(power, f(seed)), f∈{hw, byte0}."""
    if "random" not in traces:
        print("!! no random group", file=sys.stderr)
        return
    X = traces["random"].astype(np.float64)
    sd = seeds.get("random")
    if not sd:
        print("!! random meta has no per-trace seed", file=sys.stderr)
        return
    if args.func == "hw":
        f = np.array([hw_of(s) for s in sd], dtype=np.float64)
    elif args.func == "byte0":
        f = np.array([seed_bytes(s)[0] for s in sd], dtype=np.float64)
    else:
        raise SystemExit(f"unknown corr func {args.func}")
    n = X.shape[0]
    fm = f - f.mean()
    fstd = np.sqrt((fm * fm).sum())
    # Compute pointwise corr in blocks, avoiding a one-shot float64 conversion of 19 GiB
    L = X.shape[1]
    num = np.zeros(L, dtype=np.float64)
    den = np.zeros(L, dtype=np.float64)
    BLK = 4000
    for s in range(0, L, BLK):
        e = min(s + BLK, L)
        xb = X[:, s:e].astype(np.float64)
        xm = xb - xb.mean(axis=0, keepdims=True)
        num[s:e] = (xm * fm[None, :].T).sum(axis=0)
        den[s:e] = np.sqrt((xm * xm).sum(axis=0, keepdims=True))[0]
    corr = num / (fstd * den)
    # t = corr * sqrt((n-2)/(1-corr^2))
    with np.errstate(divide="ignore", invalid="ignore"):
        t = corr * np.sqrt((n - 2) / np.maximum(1e-12, 1 - corr * corr))
    at = np.abs(t)
    mx = at.max()
    arg = int(at.argmax())
    print(f"[corr {args.func}] N={n}  max|corr|={np.abs(corr).max():.4f} "
          f"@pt {arg}  max|t|={mx:.2f}  "
          f"(r at DERIVE ~19992: {corr[19992]:.4f})")
    res = {"label": f"corr({args.func})", "N": n, "L": int(corr.size),
           "max_abs_corr": float(np.abs(corr).max()),
           "argmax_point": int(arg), "max_abs_t": float(mx),
           "corr_at_19992": float(corr[19992] if corr.size > 19992 else 0.0)}
    with open(os.path.join(out_dir, "tvla_cpa_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)


def mode_split(traces, seeds, args, out_dir):
    """Split fixed group by trace-index parity (same SEED, same operation)."""
    if "fixed" not in traces:
        print("!! no fixed group", file=sys.stderr)
        return
    X = traces["fixed"]
    n = X.shape[0]
    g0 = X[0::2]
    g1 = X[1::2]
    print(f"split: even={g0.shape[0]}  odd={g1.shape[0]}")
    t, C = welch_t_series(g0, g1, args.samples_per_cycle)
    report(t, C, "fixed-group even/odd split (E2, same SEED)",
           out_dir, args.clk_mhz, extra={"n_even": int(g0.shape[0]),
                                         "n_odd": int(g1.shape[0])})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--mode", required=True,
                    choices=["bitgroup", "hw", "corr", "split"])
    ap.add_argument("--bit", type=int, default=0)
    ap.add_argument("--func", default="hw", choices=["hw", "byte0"])
    ap.add_argument("--clk-mhz", type=float, default=15.6)
    ap.add_argument("--samples-per-cycle", type=float, default=1.0)
    args = ap.parse_args()

    traces, seeds = load(args.dir)
    out_dir = args.dir
    if args.mode == "bitgroup":
        mode_bitgroup(traces, seeds, args, out_dir)
    elif args.mode == "hw":
        mode_hw(traces, seeds, args, out_dir)
    elif args.mode == "corr":
        mode_corr(traces, seeds, args, out_dir)
    elif args.mode == "split":
        mode_split(traces, seeds, args, out_dir)


if __name__ == "__main__":
    main()
