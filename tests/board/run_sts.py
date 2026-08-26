"""C1(1) offline NIST STS 2.1.2 characterization driver: feed interactive input to run all 15 tests and parse finalAnalysisReport.

Run the compiled NIST STS 2.1.2 assess.exe on the raw random stream
collected by tests/board/test_trng_characterize.py (binary, e.g. build/trng_raw.bin),
execute all 15 tests, and parse
experiments/AlgorithmTesting/finalAnalysisReport.txt to summarize each test item's P-VALUE/PROPORTION.

Usage:
  python tests/board/run_sts.py --input build/trng_raw.bin \
      --stream-bits 1000000 --num-streams 8

  --stream-bits  bits per stream (assess's <stream length> parameter, e.g. 1_000_000).
  --num-streams  number of bitstreams (How many bitstreams); num*stream_bits/8 bytes <= input file bytes.
  STS recommends >= 1e6 bits per stream; a larger num-streams makes PROPORTION more
  trustworthy (generally >= 10 is statistically meaningful).

STS interactive sequence (utilities.c):
  generatorOptions: 0 (Input File) -> input file path
  chooseTests:      1 (apply all 15 tests)
  fixParameters:    0 (continue, default block length)
  openOutputStreams: num-streams -> 1 (Binary format)
Measurement-based characterization only; no claim of NIST certification (trng_c1_plan §8 scope).
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

STS_DIR = Path(__file__).resolve().parent.parent.parent / "reference" / "tools" / "sts-2.1.2" / "sts-2.1.2"
ASSESS = STS_DIR / "assess.exe"
REPORT = STS_DIR / "experiments" / "AlgorithmTesting" / "finalAnalysisReport.txt"

TEST_NAMES = [
    "Frequency", "BlockFrequency", "CumulativeSums", "Runs", "LongestRun",
    "Rank", "FFT", "NonOverlappingTemplate", "OverlappingTemplate", "Universal",
    "ApproximateEntropy", "RandomExcursions", "RandomExcursionsVariant", "Serial",
    "LinearComplexity",
]


def run_assess(input_file: Path, stream_bits: int, num_streams: int) -> None:
    if not ASSESS.exists():
        raise RuntimeError(f"assess.exe not built: {ASSESS}")
    if not input_file.exists():
        raise RuntimeError(f"input file does not exist: {input_file}")
    need_bytes = stream_bits * num_streams // 8
    actual = input_file.stat().st_size
    if actual < need_bytes:
        raise RuntimeError(
            f"input {actual} B insufficient: {num_streams} streams x {stream_bits} bits need {need_bytes} B"
        )
    # assess accepts relative or absolute paths; interactive input lines: 0, file, 1, 0, num, 1.
    answers = f"0\n{input_file.resolve()}\n1\n0\n{num_streams}\n1\n"
    # Remove the old report; success is judged by whether a new one is generated (assess main has no return 0, exit code is always nonzero).
    if REPORT.exists():
        REPORT.unlink()
    proc = subprocess.run(
        [str(ASSESS), str(stream_bits)],
        input=answers,
        cwd=str(STS_DIR),
        capture_output=True,
        text=True,
        timeout=3600,
    )
    # assess's main lacks a trailing return, so the exit code is meaningless; use report generation as the success criterion.
    if not REPORT.exists():
        raise RuntimeError(f"assess did not generate a report (possibly insufficient input/crash):\n{proc.stdout}\n{proc.stderr}")


def parse_report() -> list[dict]:
    if not REPORT.exists():
        raise RuntimeError(f"report not generated: {REPORT}")
    results = []
    # Line format: C1..C10 (10 columns)  P-VALUE  PROPORTION  STATISTICAL TEST name
    row_re = re.compile(
        r"^\s*(\d+\s+){9}\d+\s+([0-9.]+|----)\s+(\d+/\d+|----)\s+(\S.*?)\s*$"
    )
    for line in REPORT.read_text(errors="replace").splitlines():
        m = row_re.match(line)
        if not m:
            continue
        pvalue, proportion, name = m.group(2), m.group(3), m.group(4).strip()
        # STS prefixes lines whose PROPORTION is out of range with "* " before the test name; strip it when parsing.
        name = name.lstrip("* ").strip()
        if name.upper().startswith("STATISTICAL") or not name:
            continue
        results.append({"pvalue": pvalue, "proportion": proportion, "name": name})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="C1① NIST STS offline characterization")
    parser.add_argument("--input", type=Path, default=Path("build/trng_raw.bin"))
    parser.add_argument("--stream-bits", type=int, default=1_000_000)
    parser.add_argument("--num-streams", type=int, default=8)
    parser.add_argument(
        "--save", type=Path, default=None,
        help="copy finalAnalysisReport.txt to this path for retention (default build/sts_report.txt)",
    )
    args = parser.parse_args()

    print(f"STS: input={args.input} stream_bits={args.stream_bits} num_streams={args.num_streams}")
    run_assess(args.input, args.stream_bits, args.num_streams)

    save = args.save or Path("build/sts_report.txt")
    save.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPORT, save)

    results = parse_report()
    if not results:
        raise RuntimeError("report parsing returned empty (format may have changed; see build/sts_report.txt)")

    import math

    print(f"\n{'P-VALUE':>9}  {'PROPORTION':>11}  TEST")
    print("-" * 60)
    # Flagged lines (STS already marks out-of-range items with "*" in the report), deduplicated by unique test name.
    flagged = set()
    n_streams = args.num_streams
    # min pass rate for significance alpha=0.01 (NIST STS 2.1.2 appendix): 1-a-3*sqrt(a(1-a)/n)
    min_rate = 0.99 - 3.0 * math.sqrt(0.01 * 0.99 / n_streams) if n_streams > 0 else 0.0
    for r in results:
        print(f"{r['pvalue']:>9}  {r['proportion']:>11}  {r['name']}")
        if "/" in r["proportion"]:
            num, den = r["proportion"].split("/")
            if num.isdigit() and den.isdigit() and int(den) > 0:
                if int(num) / int(den) < min_rate:
                    flagged.add(r["name"])
    print("-" * 60)
    print(f"report saved: {save}")
    print(f"min pass rate (alpha=0.01, n={n_streams}) = {min_rate:.4f}")
    if flagged:
        print(f"WARNING: PROPORTION below min pass rate for: {', '.join(sorted(flagged))}")
        return 2
    print("PASS: STS characterization complete, no PROPORTION out-of-range items")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
