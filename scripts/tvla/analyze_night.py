#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""analyze_night.py - automatic analysis of overnight unattended results (2026-08-19)

Runs paper-caliber analysis on the overnight capture directories under build/tvla/:

  P0a  night_sign_10k  full Sign synchronized capture 10k/group (same caliber as SLotH §6.4)
       - full window 0:20000 (Mini-p C)                  -> primary number
       - engine window (trimmed command segment + pre-trigger Keccak) -> reference number
  P0b  night_prf_100k   single isolated PRF 100k/group (SLotH §5-style single peak)
       - full window 0:20000 + peak-region window
  P1   night_base_ff_a/b, night_base_rr_a/b  noise-floor reference (two independent captures merged into fixed/random)

Output:
  - per-directory tvla_report.json / tvla_full.png (already produced by analyze)
  - summary table build/tvla/night_summary.json + console table
  - comparison against the three SLotH paper experiment points (CPU 24.5 / unmasked 4.80 / TI 5.00)
"""
import json
import os
import sys

import numpy as np

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", ".."))
BASE = os.path.join(_ROOT, "build", "tvla")   # capture output directory
ANALYZE = os.path.join(_ROOT, "scripts", "tvla", "tvla_analyze.py")

CLK = 15.6
SPC = 1.0  # synchronized capture 1 samp/clk50-cycle


def run_analyze(directory, window, label):
    """Run tvla_analyze.py, return the report dict."""
    import subprocess
    out_dir = os.path.join(BASE, directory)
    if not (os.path.exists(os.path.join(out_dir, "fixed.npy")) and
            os.path.exists(os.path.join(out_dir, "random.npy"))):
        print(f"!! {directory}: missing fixed/random.npy, skipping", file=sys.stderr)
        return None
    cmd = [sys.executable, ANALYZE, "--dir", out_dir,
           "--clk-mhz", str(CLK), "--samples-per-cycle", str(SPC)]
    if window:
        cmd += ["--window", window]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode not in (0, 1):
        print(f"!! {directory}[{label}]: analyze rc={r.returncode}\n{r.stderr[-800:]}",
              file=sys.stderr)
        return None
    rp = os.path.join(out_dir, "tvla_report.json")
    if not os.path.exists(rp):
        print(f"!! {directory}[{label}]: no report json\n{r.stdout[-800:]}",
              file=sys.stderr)
        return None
    with open(rp, encoding="utf-8") as f:
        rep = json.load(f)
    rep["label"] = label
    print(f"[{directory} | {label}] max|t|={rep['max_abs_t']:.2f} "
          f"@pt {rep['argmax_abs_point']}  C={rep['critical_C']:.2f} "
          f"above={rep['n_above_C']} ({100.0*rep['n_above_C']/rep['L']:.3f}%) "
          f"verdict={rep['verdict']}")
    return rep


def _load_group(src, name):
    """Read traces from a single-group capture directory: --group fixed stores fixed.npy, --group random stores random.npy."""
    p = os.path.join(src, f"{name}.npy")
    if os.path.exists(p):
        return np.load(p)
    return None


def merge_baseline(a_dir, b_dir, out_name):
    """Merge two independent captures (same group) into a fixed/random noise-floor reference.

    ff: two --group fixed captures (each stored as fixed.npy) -> a/fixed vs b/fixed
    rr: two --group random captures (each stored as random.npy) -> a/random vs b/random
    """
    src_a = os.path.join(BASE, a_dir)
    src_b = os.path.join(BASE, b_dir)
    dst = os.path.join(BASE, out_name)
    os.makedirs(dst, exist_ok=True)
    fa = _load_group(src_a, "fixed"); ra = _load_group(src_a, "random")
    fb = _load_group(src_b, "fixed"); rb = _load_group(src_b, "random")
    if fa is not None and ra is not None and fb is not None and rb is not None:
        # both directories contain both groups (should not happen); just concatenate
        fixed = np.concatenate([fa, fb], axis=0)
        random = np.concatenate([ra, rb], axis=0)
    elif fa is not None and fb is not None:
        fixed, random = fa, fb            # ff: two fixed captures
    elif ra is not None and rb is not None:
        fixed, random = ra, rb            # rr: two random captures
    else:
        raise FileNotFoundError(
            f"baseline directory missing npy: {a_dir}(fixed={fa is not None},random={ra is not None}) "
            f"{b_dir}(fixed={fb is not None},random={rb is not None})")
    np.save(os.path.join(dst, "fixed.npy"), fixed)
    np.save(os.path.join(dst, "random.npy"), random)
    meta = {"op": "baseline", "n": fixed.shape[0], "trace_len": int(fixed.shape[1]),
            "presamples": 20000, "sync": True, "samples_per_cycle": 1.0,
            "clk_mhz": CLK}
    with open(os.path.join(dst, "fixed_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    print(f"merged {a_dir} + {b_dir} -> {out_name} ({fixed.shape[0]} traces)")


def main():
    summary = {}

    # ---- P0a: full Sign 10k/group ----
    print("\n=== P0a: full Sign 10k/group ===")
    summary["sign_full"] = run_analyze("night_sign_10k", None, "full 0:20000")
    # Engine window: from after the command segment (0x63 preload + frame header ~3000 pts) to before trigger.
    # sign W4H5 total ~15K cycles @15.6MHz ≈ 15000 pts; trigger=presamples=20000. Engine compute window ~ [3000:17000].
    summary["sign_engine"] = run_analyze("night_sign_10k", "3000:17000",
                                         "engine window 3000:17000")
    # Pre-trigger Keccak compute segment (same-caliber focus as SLotH unmasked): after command segment [3000:15000]
    summary["sign_pre_trigger"] = run_analyze("night_sign_10k", "3000:15000",
                                              "pre-trigger 3000:15000")

    # ---- P0b: single PRF 100k/group ----
    print("\n=== P0b: single PRF 100k/group ===")
    summary["prf_full"] = run_analyze("night_prf_100k", None, "full 0:20000")
    # Single-PRF peak measured ~8 pts before trigger (near presamples=20000, DERIVE completion edge);
    # peak-region window takes 2000 pts before trigger (covers DERIVE + chain tail), excluding the UART command segment.
    summary["prf_peak"] = run_analyze("night_prf_100k", "18000:20000",
                                      "peak 18000:20000")

    # ---- P1: noise-floor reference ----
    print("\n=== P1: baselines ===")
    if all(os.path.exists(os.path.join(BASE, d, f))
           for d in ("night_base_ff_a", "night_base_ff_b")
           for f in ("fixed.npy",)):
        merge_baseline("night_base_ff_a", "night_base_ff_b", "night_base_ff")
        summary["baseline_ff"] = run_analyze("night_base_ff", None,
                                             "fixed-vs-fixed 1k")
    if all(os.path.exists(os.path.join(BASE, d, f))
           for d in ("night_base_rr_a", "night_base_rr_b")
           for f in ("random.npy",)):
        merge_baseline("night_base_rr_a", "night_base_rr_b", "night_base_rr")
        summary["baseline_rr"] = run_analyze("night_base_rr", None,
                                             "random-vs-random 1k")

    # ---- SLotH comparison ----
    sloth = {"cpu_baseline": 24.5, "unmasked_keccak": 4.80, "ti_keccak": 5.00}
    print("\n=== SLotH cross-caliber table ===")
    print(f"{'experiment':<28}{'max|t|':>10}{'C':>8}{'above%':>10}")
    for key in ("sign_full", "sign_engine", "prf_full", "baseline_ff", "baseline_rr"):
        rep = summary.get(key)
        if rep:
            print(f"{key:<28}{rep['max_abs_t']:>10.2f}{rep['critical_C']:>8.2f}"
                  f"{100.0*rep['n_above_C']/rep['L']:>10.3f}")
    print("SLotH refs: CPU=%s, unmasked Keccak=%s (10k, full-sign window, "
          "no plaintext load), TI=%s (100k)" %
          (sloth["cpu_baseline"], sloth["unmasked_keccak"], sloth["ti_keccak"]))

    with open(os.path.join(BASE, "night_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1, default=str)
    print(f"\nsummary -> {BASE}/night_summary.json")


if __name__ == "__main__":
    main()
