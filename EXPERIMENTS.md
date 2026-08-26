# SecLMS Experiment Reproduction Guide

This document maps every quantitative claim in the SecLMS paper to the concrete
artifacts, commands, and scripts needed to reproduce it. All experiments run on
the NewAE CW305 platform (Xilinx Artix-7 xc7a100tftg256-2) at 50 MHz unless
stated otherwise.

> **Clock note (read first):** the paper's 50 MHz is the **design clock** —
> the Vivado timing-closure target and the ms-conversion basis
> (ms = cycles/50e6); it is not a claim that the CW305 physically ran at
> 50 MHz. Measured cycle counts are clock-frequency independent, so board
> re-measurements reproduce the paper's 50 MHz cycle data at any PLL.
> Physical CW305 board tests run at the actual PLL clock (15.625 MHz for the
> TVLA bit). A 50 MHz physical re-validation (2026-08-28, see
> `flow/impl_lms_cw305_tight50.tcl`) makes HASH_ONCE/CHAIN stable at 50 MHz;
> long batch tasks (LM-OTS keygen/sign, LMS verify) retain a hold-timing edge
> on the SHAKE engine batch path (see RESULTS.md for the full matrix). Only
> side-channel acquisition deliberately uses 15.625 MHz.

## Prerequisites

### Hardware

- **NewAE CW305** board (xc7a100tftg256-2) — required for all board-level
  experiments (KAT, performance, fault injection).
- **ChipWhisperer Husky** oscilloscope with the 20-pin TIO connector — required
  for the side-channel TVLA/CPA measurements.
- **NewAE ChipWhisperer** capture hardware (USB register-mailbox harness) for
  the board UART interface at 115200 baud.
- **DaVinci Pro** board — used for the alternate implementation target.

### Toolchain

- RISC-V GNU toolchain (rv32imc) — firmware build.
- Verilator 5.040 — RTL simulation (`bash flow/run_rtl_tests_msys.sh` on MSYS2
  handles the `Program Files` space-path issue).
- Vivado 2020.2 — synthesis and implementation.
- Python 3 with the following packages (pip-installable):
  - `pyserial` — board UART communication (`tests/board/*.py`).
  - `chipwhisperer` (>= 6.0) — CW305 board control and capture.
  - `numpy`, `scipy`, `matplotlib` — TVLA/CPA trace analysis and plotting.
  - `cryptography` — RSA/ECDSA benchmark validation (`scripts/bench_classic.py`).
  - `libusb` Python bindings (`usb1`) — CW305 selftest.

All board scripts are designed to run from the repository root
(`python scripts/...`, `python tests/board/...`); internal modules under
`scripts/` and `scripts/tvla/` are imported via `sys.path` injection.

---

## 1. Correctness / Known-Answer Tests (KAT)

| Paper claim | Reproduction |
|---|---|
| LMS/LM-OTS/HSS encoding conforms to RFC 8554 | `make test` (PC regression: LMS, LM-OTS, tree, HSS, hashes, MMIO client, random source) |
| SHA-256 and SHAKE256 backends both close the loop | `make test-rtl-sha256`, `make test-rtl-shake256-mmio`, `make test-rtl-lms-soc` (Verilator full-SoC) |
| Secure-domain state machine (FACTORY_INIT/BOOT/SEC_SIGN) | `make test-rtl-lms-soc-deploy` (deploy-scope regression; run `test-rtl-lms-soc` first to produce the wrapped-blob input) |
| Board-level KAT | `python tests/board/test_lms_uart.py --port <PORT> --hash shake256` |

## 2. Performance (paper §6.2)

The paper reports hardware-vs-software speedups at W4/H10: SHAKE256
3,002x/2,007x/1,408x and SHA-256 202x/139x/136x for key generation, signing,
and verification, plus the security-domain signing overhead.

| Artifact | Command |
|---|---|
| On-board cycle measurement (UART protocol, `SOC_CYCLE_COUNT`) | `scripts/run_perf_sweep.ps1` (multi-parameter sweep driver) |
| Per-parameter-set runs (0.1.270/0.1.273/0.1.275 baselines) | `scripts/run_multiparam_270.ps1`, `run_multiparam_273.ps1`, `run_multiparam_275.ps1`, `run_multiparam_cw305.ps1` |
| Firmware-side cycle counters | `fw/lms_soc_smoke.c` (response frames carry hw/total/steady cycle counts) |
| Pure-software baseline (same platform) | build firmware with `NO_HW_ACCEL=1` |
| SoC simulation timing | `tests/rtl/test_lms_soc.cpp` (Verilator cycle counts) |

## 3. Resource Utilization (paper §6.3)

Paper: SHAKE256 45,318 LUT (71.5%) / 19,200 FF / 36 BRAM / 4 DSP; SHA-256
32,550 LUT (51.3%); security domain 5,168 LUT (SHAKE256) / 5,063 LUT (SHA-256).

| Artifact | Command |
|---|---|
| SHAKE256 implementation | `make impl-cw305 VIVADO="<vivado>" HASH_IMPL=shake256` (report in `build/vivado_lms_cw305/`) |
| SHA-256 implementation | `make impl-cw305 VIVADO="<vivado>" HASH_IMPL=sha256` |
| DaVinci Pro implementation | `make impl-davinci-pro VIVADO="<vivado>"` |
| RTL-only synthesis (no firmware) | `flow/synth_rtl_*.tcl` via `make synth-rtl-*` targets |

## 4. Side-Channel TVLA/CPA (paper §6.4)

The paper reports leakage characterization with TVLA t-statistics and CPA,
including the PRF single-peak result, hiding dilution (random delay), and
phase shuffling. The capture/analysis pipeline lives in `scripts/tvla/`.
**Clock note:** side-channel acquisitions are the one domain that runs the
FPGA at 15.625 MHz (CDCE906 PLL 31.25 MHz half-rate, synchronous sampling at
one sample per cycle); all performance measurements in §2 use the 50 MHz
paper scope.

| Step | Script |
|---|---|
| Capture power traces (two groups) | `python scripts/tvla/tvla_capture.py --n 1000 --out build/tvla/run1` |
| Hardware wiring self-check | `python scripts/tvla/tvla_wiring_check.py` |
| TVLA analysis (t-statistics) | `python scripts/tvla/tvla_analyze.py --dir build/tvla/run1` |
| CPA analysis | `python scripts/tvla/tvla_cpa.py --dir build/tvla/run1` |
| Single x_q[i] isolation | `python scripts/tvla/tvla_cpa_xq.py --dir build/tvla/derive_xq_100k` |
| Hiding-panel plots | `python scripts/tvla/tvla_plot_hiding_panel.py` |
| Realignment of traces | `python scripts/tvla/realign_analyze.py`, `tvla_split_realign.py`, `tvla_cpa_realign.py` |
| SLotH comparison capture | `python scripts/tvla/tvla_capture_sloth.py --bit <sloth.bit> --sloth-dir <sloth-src>` |
| Random-delay countermeasure firmware | build firmware with `RANDOM_DELAY=1`; RTL with `-GRANDOM_DELAY=1` |
| DERIVE phase shuffling | build RTL with `DERIVE_SHUFFLE=1` (test: `make test-rtl-shake256-batch-shuffle`) |
| Offline NIST STS characterization | `python tests/board/run_sts.py` (needs compiled NIST STS 2.1.2) |
| TRNG characterization | `python tests/board/test_trng_characterize.py` |

## 5. Fault Injection / State Management (paper §6.5)

The paper validates the reserve-sign-commit atomicity with a six-scenario
state-management fault-injection evaluation (power-loss classes: after
reserved, before finalize, rollback, half-write; injection classes; normal flow).

| Artifact | Command |
|---|---|
| Secure-domain board tests (FACTORY_INIT/BOOT/SEC_SIGN/fault injection) | `python tests/board/test_lms_uart.py --port <PORT> --sec-board-test` |
| Verilator power-loss classes | `tests/rtl/test_lms_soc.cpp` (covered by `make test-rtl-lms-soc`) |
| VCCINT glitch injection drivers | `scripts/vccint_load_h15.py`, `scripts/vccint_load_test.py`, `scripts/check_vccint.py` |
| Deploy-scope two-phase board flow | `scripts/deploy_board_two_phase.ps1` |

## 6. Classical-Algorithm Comparison (paper Tables 1/2)

The RSA-2048 (PKCS#1 v1.5) and ECDSA P-256 (RFC 6979) columns are produced by
`bench/` using Mbed TLS 2.28.9 on the same Ibex/CW305 platform. Mbed TLS is an
external dependency (not vendored): point `MBEDTLS_DIR` at a local
mbedtls-2.28.9 checkout.

| Artifact | Command |
|---|---|
| PC self-check (RSA/ECDSA correctness) | `make bench-native MBEDTLS_DIR="<path>"` |
| SoC benchmark firmware | `make bench-fw MBEDTLS_DIR="<path>"` |
| Benchmark timing driver (PC) | `bench/bench_timing_pc.c`, `scripts/bench_classic.py` |
| Benchmark firmware source | `fw/lms_bench.c`, `bench/bench_crypto.c` |

## 7. Board Bring-Up / Programming

| Artifact | Command |
|---|---|
| Program CW305 bitstream | `python scripts/prog_cw305.py <bitstream>` |
| Board boot helper | `python scripts/cw_boot.py` (via `scripts/cw305_serial.py`) |
| Flash access verification | `scripts/flash_wel_diag_cw305.py`, `scripts/flash_write_test_cw305.py`, `scripts/probe_flash_cw305.py` |
| SPI flash programming | `scripts/fw_update_cw305.py` |
| PLL setup | `scripts/set_pll.py` |
| Husky scope diagnostics | `scripts/husky_diag.py` |

---

## Measurement Data

See [RESULTS.md](RESULTS.md) for the authoritative measurement tables (performance, resource utilization, side-channel TVLA, and the RSA/ECDSA comparison), with board-reproduction status marked per row.

## Reference Documents

- `rtl/README.md` — RTL source notes and third-party provenance.

## External Dependencies

- Mbed TLS 2.28.9 (benchmarks only): dual-licensed Apache-2.0 OR
  GPL-2.0-or-later; adopted under Apache-2.0 (see `NOTICE`).
- NIST STS 2.1.2 (entropy characterization, optional): external tool.
- SLotH sources (side-channel comparison, optional): external.
