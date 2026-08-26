# SecLMS Measurement Data (paper scope)

Authoritative measurement data supporting the SecLMS paper. All numbers below
were reproduced on the reference hardware with firmware 0.1.280; the
reproduction status column marks values we re-measured on the board in this
repository's verification pass.

> **Conventions**:
> - Firmware **0.1.280**; **performance scope is a single 50 MHz SoC clock
>   domain** (paper scope: 50 MHz is the design clock — Vivado timing-closure
>   target and ms-conversion basis, ms = cycles/50e6; CW305 physical board
>   tests run at the actual PLL clock, 15.625 MHz for the TVLA bit).
> - Cycle counts are clock-frequency independent (`SOC_CYCLE_COUNT` counts
>   periods), so board re-measurements reproduce the paper's 50 MHz cycle
>   data regardless of the PLL programmed on the physical bitstream.
> - **50 MHz physical validation (2026-08-28, Vivado re-synthesis)**: a
>   tightened build (`flow/impl_lms_cw305_tight50.tcl`, clk100 8.6 ns →
>   clk50 ≈58 MHz constraint) makes HASH_ONCE/CHAIN fully stable at physical
>   50 MHz (originally all bits failed even `empty` at 50 MHz; root cause:
>   Ibex CPU prefetch-FIFO path, WNS 0.661 ns @58 MHz). Long batch tasks
>   (LM-OTS keygen/sign, LMS verify via VERIFY_LEAF/D_INTR_CHAIN) still have
>   a hold-timing edge on the SHAKE engine `batch_block1_r` path (hold slack
>   0.050 ns @58 MHz; verify digests wrong above ≈41.7 MHz, timeouts at
>   48/50 MHz). This is an RTL-level engine path; the cycle counts are
>   unaffected (frequency-independent) and remain identical to the paper.
> - Side-channel acquisition (Section 2) is the only domain that deliberately
>   runs the FPGA at **15.625 MHz** (CDCE906 PLL 31.25 MHz half-rate; rollover
>   correction applied accordingly).
> - SCA trigger edge = **busy rising edge (start edge)**
>   (`rtl/lms_soc.v:122-127`, 2026-08-19 scheme B-RTL fix; all datasets
>   `meta.env.trigger_edge=rising`). "DERIVE completion edge @19992" is the
>   peak phase position at the end of the DERIVE segment, not the trigger edge.
> - Side-channel statistics use **Bonferroni correction** (not Mini-p),
>   α=1e-5; N per group as listed in each table.
> - Parameter sets: W1 p=265 / W2 133 / W4 67 / W8 34 (`src/lms_params.c`).
> - TRNG deployment scope: in the deploy configuration, I, the randomizer C,
>   and SEED are all generated on-device by the TRNG (SEED enters the hardware
>   slot via the controlled-loading path); the test configuration uses fixed
>   vectors (KAT-reproducible).

---

## 1. Performance Data (0.1.280, CW305 board, 9 parameter sets, bit `lms_shake_hw_fixed_0280_20260823.bit`, 9/9 PASS; 50 MHz paper scope — ms conversions use ms = cycles/50e6)

### 1.1 SHAKE256 hardware/software co-design, 9 parameter sets (hw/total; Sign includes steady)

| Parameter set | LMS KeyGen hw/total | LMS Sign hw/total(steady) | LMS Verify hw/total | Reproduced |
|---|---|---|---|---|
| W1_H5 | 290,132/438,299 | 3,495/10,553(9,286) | 9,225/57,803 | |
| W1_H10 | 9,574,728/14,370,787 | 3,495/11,149(9,882) | 9,335/58,795 | |
| W1_H15 | 306,682,172/460,069,558 | 3,495/11,746(10,479) | 9,445/59,787 | |
| W2_H5 | 206,580/354,971 | 3,113/10,024(8,757) | 5,846/11,824 | |
| W2_H10 | 6,817,512/11,620,963 | 3,113/10,620(9,353) | 5,956/12,816 | ✓ LM-OTS verified |
| W2_H15 | 218,367,708/371,991,862 | 3,113/11,217(9,950) | 6,066/13,808 | |
| W4_H5 | 287,732/436,539 | 5,499/12,375(11,108) | 6,614/12,523 | ✓ full LMS verified |
| **W4_H10** | **9,495,528/14,312,707** | **5,499/12,971(11,704)** | **6,724/13,515** | ✓ full LMS verified |
| W4_H15 | 304,145,372/458,209,238 | 5,499/13,568(12,301) | 6,834/14,507 | ✓ full LMS verified |

- LM-OTS layer hw (w-dependent, H-independent): W1 KeyGen 9,041/Sign 3,483/
  Verify 9,079; W2 6,430/3,101/5,700; W4 8,966/5,487/6,468. (W4 values
  re-verified on board.)
- **Paper headline (W4_H10)**: LMS KeyGen 9,495,528/14,312,707; Sign
  5,499/12,971(steady 11,704); Verify 6,724/13,515. — **all re-verified on
  board in this repository.**

### 1.2 Pure-software baseline (NO_HW_ACCEL=1, 0.1.280, rollover-corrected)

| Item | total cycles | Notes |
|---|---:|---|
| LM-OTS W4 KeyGen | 41,880,142 | — |
| LM-OTS W4 Sign | 23,493,113 | — |
| LM-OTS W4 Verify | 18,542,224 | — |
| LMS W4_H5 KeyGen (cached/no-cache) | **1,342,652,831** | <2^32, no rollover |
| LMS W4_H5 Sign no-cache | 1,324,019,972 | <2^32, no rollover |
| LMS W4_H5 Sign cached | 23,494,860 (steady 23,493,842) | — |
| LMS W4_H5 Verify | 18,827,191 | — |
| Pure-software H10 KeyGen | **42,966,115,790** | ≈14 min @50 MHz |
| Pure-software H10 Sign no-cache | **42,946,664,220** | full-tree rebuild |
| Pure-software H10 Sign cached | **23,495,450** (steady 23,494,432) | measured |
| Pure-software H10 Verify (no-cache) | **19,025,958** | measured |
| Pure-software H10 Verify (cached) | **19,025,956** | measured |

> Note: pure-software H10 KeyGen uses the full-tree software construction
> (1024 leaves x 67 chains + tree hash); the paper's M4 H10 15.4B figure uses
> a different single-pass measure. The paper's sw-compare H10 KeyGen/Sign
> values are derived or estimated with the scope noted.

### 1.3 SHA-256 platform (0.1.280, Verilator SoC; the paper uses only the area for SHA-256)

- LMS W4_H5: KeyGen hw=1,246,681 / Sign hw=23,811 (steady 29,640) / Verify hw=28,341.
- LM-OTS layer hw: KeyGen W1 26,867/W2 22,513/W4 38,761; Sign W1 17,178/W2
  14,625/W4 23,584; Verify W1 18,714/W2 16,273/W4 27,327.

### 1.4 Resource utilization and firmware size (0.1.280, DaVinci Pro xc7a100tfgg484-2)

| Configuration | LUT | FF | BRAM | DSP | WNS |
|---|---:|---:|---:|---:|---:|
| SHAKE256 test config | 45,318 | 19,790 | 36 | 4 | see archive |
| SHAKE256 deploy config | 45,336 | 19,548 | 36 | 4 | +0.197 |
| SHA-256 test config | 32,550 | 16,840 | 36 | 4 | +0.563 |

- Firmware size (0.1.280, SHAKE256 test config): text 50,660 / data 4 /
  bss 34,152 (≈49.5/33.4/82.8 KiB).
- Task RAM: `task_words[0:2151]` = 8,608 B (8.4 KiB).
- **Headline speedups (paper, uniform W4/H10 conservative scope)**:
  **3000x/2000x/1400x**. Derivation (pure-software total / hardware total,
  Sign uses steady):
  - KeyGen: 42,966,115,790 / 14,312,707 = **3,002 → 3000x**
  - Sign: 23,494,432 / 11,704 = **2,007 → 2000x**
  - Verify: 19,025,958 / 13,515 = **1,408 → 1400x**
- Deploy-vs-test gate delta: 18 LUT after 0.1.280 re-synthesis.

### 1.5 Classical-algorithm benchmark (Mbed TLS 2.28.9, same Ibex RV32IMC soft core, CW305 board @50 MHz, 0.1.282)

> Purpose: same-platform comparison of classical algorithms (RSA/ECDSA),
> highlighting the order-of-magnitude advantage of hash-based signatures on
> constrained cores. Firmware: `fw/lms_bench.c` (bench config); sources in
> `bench/` (Mbed TLS 2.28.9 minimal config: RSA PKCS#1 v1.5, ECDSA P-256
> deterministic RFC 6979, SHA-256). Cycles via `SOC_CYCLE_COUNT`;
> ms = cycles/50e6 (paper scope; the paper reports the same platform at
> 50 MHz). Board and PC cross-validated byte-for-byte (deterministic).

| Operation | Parameter | cycles | ms @50 MHz | PC cross-check (x86, same config) |
|---|---|---:|---:|---|
| SHA-256 | 64 B input | 12,788 | 0.26 ms | — |
| RSA sign | RSA-2048, PKCS#1 v1.5 | 181,622,782 | 3.63 s | 1.450 ms |
| RSA verify | RSA-2048 | 3,161,439 | 0.063 s | 0.035 ms |
| ECDSA sign | P-256 (RFC 6979) | 119,535,507 | 2.39 s | 1.920 ms |
| ECDSA verify | P-256 | 261,075,889 | 5.22 s | 4.000 ms |

- Verilator SoC smoke (same firmware): SHA 12,976/12,788 (≤1.5%), ECDSA sign
  115,429,248, ECDSA verify 247,544,195 — simulation/board deviation ≤7%.
- Internal consistency: RSA sign/verify ratio 181,622,782/3,161,439 = **57.5x**;
  ECDSA verify/sign ratio 261,075,889/119,535,507 = **2.18x** (same order as
  SEGGER 2.09x, mbedTLS official ≈3.5x).
- RV32/PC cycle ratio ≈ **20–42x** (cycle-accounting scope, same mbedTLS
  config; expected for Ibex RV32IMC without big-integer acceleration).
- Public references (different platforms, order-of-magnitude anchors only):
  - SEGGER emCrypt ECDSA P-256: sign 164.16 ms / verify 78.70 ms
    (verify/sign 2.09x) — kb.segger.com/ECDSA
  - mbedTLS official benchmark: secp256r1 sign 2121/s, verify 612/s
    (verify/sign ≈3.5x) — mbed-tls.readthedocs.io
  - RP2040 Cortex-M0+ @133 MHz: ECDH P-256 tens of ms (arXiv 2603.19340)
- Comparison with SecLMS (paper Table 1, **W4_H5 row** as a concrete example,
  **total cycles as the fair baseline**; the paper's headline set is W4_H10):
  - HW Sign 12,375 (steady 11,108) → vs RSA sign **≈14,700x**,
    vs ECDSA sign **≈9,700x**
  - HW Verify 6,614 → vs RSA verify **≈480x**, vs ECDSA verify **≈39,500x**
  - Pure-software Verify (cached) 18,827,191 → ≈6x slower than RSA verify,
    ≈14x faster than ECDSA verify (same-soft-core internal comparison)

---

## 2. Side-Channel TVLA Data

### 2.1 Main result table (max|t|, Bonferroni α=1e-5; trigger edge = rising)

| Dataset | Content | N/group | max\|t\| | C | Above threshold | Report |
|---|---|---:|---:|---:|---:|---|
| night_prf_100k | unmasked PRF (0x6D isolated) single peak | 100,000 | **776.2** @19992 | 5.85 | 0.165% | `night_prf_100k` |
| prf_1k_sync | PRF sync 1k (sqrt-N check 776.2/sqrt(100)=77.6) | 1,000 | **77.7** @19992 | 6.25 | 0.020% | `prf_1k_sync` |
| night_base_ff / night_base_rr | noise floor (fixed-fixed / random-random) | 1,000 | **17.6 / 10.5** | 6.25 | — | `night_base_ff`/`night_base_rr` |
| sign_10k | unmasked Sign (scheme B steady state, W4_H5) | 10,000 | **250.04** @8361 | 5.80 | 94.2% | `sign_10k` |
| sign_10k_slothcaliber | same but SLotH scope (I/q random, SEED-group only) | 10,000 | **7.0** @18346 | 5.80 | 263 pts | `sign_10k_slothcaliber` |
| sloth_10k_fixed | SLotH official code fixed scope (SK.seed-group only) | 5,072 | **262.1** | 6.58 | 29.1% | `sloth_10k_fixed` |
| sw_prf_1k | pure-software single PRF (NO_HW_ACCEL=1) | 1,000 | **147.3** @22460 | 6.36 | 73.6% | `sw_prf_1k` |
| sw_prf_10k | pure-software single PRF 10k | 10,000 | **468.7** @22460 | 6.31 | 87.2% | `sw_prf_10k` |
| sw_prfchain_trunc1k | pure-software PRF chain truncated (0x6E, SLotH Fig.6 first 73k cycles) | 1,000 | **150.2** | 6.47 | 73.1% | `sw_prfchain_trunc1k` |
| shuffle_sign_1k | Sign after DERIVE phase shuffling (DERIVE segment 7700:9200) | 500 | **22.30** @8901 | 5.85 | 5.73% | `shuffle_sign_1k` |
| shuffle_sign_10k | same, 10k | 10,000 | **104.78** @8901 | 5.80 | 53.1% | `shuffle_sign_10k` |
| shuffle_sign_fix_1k | shuffle-fix recheck 1k | 500 | **15.58** | 5.85 | — | `shuffle_sign_fix_1k` |

### 2.2 Derived conclusions (paper scope)

- **Unmasked structural leakage**: PRF single peak **776.2@100k**; Sign DERIVE
  segment **250.04@10k** (94.2% above threshold) — headline leakage numbers.
- **Software baseline comparison**: software single PRF 147.3@1k / 468.7@10k
  (diffuse across the full window) ≈ 1.9x hardware (same N); vs SLotH CPU
  24.5@1k ≈ 6.0x; truncated 150.2@1k ≈ 6.1x.
- **SLotH flat-line root cause**: official scope 10k=4.80 (missed detection due
  to randomization of the public component); fixed scope 10k=262.1 (same
  implementation, same board) — "flat line = scope miss" decisive evidence (55x).
- **Hiding (RANDOM_DELAY, 0x6D-specific)**: diluted to 2.8/3.5 (1k/100k, <C);
  alignment recovers **170.2@100k** — defense in depth, not elimination;
  masking (TI 3-share) is the fundamental countermeasure (future work,
  infeasible on xc7a100t, +15~24k LUT).
- **DERIVE phase shuffling (DERIVE_SHUFFLE, Sign-level lightweight defense)**:
  DERIVE segment 1k 37.78→**22.30** (−41%), 10k 250.04→**104.78** (−58%);
  above-threshold points 1k 54.3%→5.73% (−89%), 10k 94.2%→53.1% — "raises the
  attacker's alignment cost".
- False-positive clipping (within the Sign window): command segment (UART
  plaintext seed) ~39@1k/168@10k, auth path 86-102@1k/362.8@10k, output
  segment 455@1k/687.7@10k — all clipped in analysis (window 7700:9200 DERIVE
  segment readout).

### 2.3 Capture configuration (required for reproduction)

- Board: CW305 (xc7a100tftg256-2); oscilloscope: NewAE Husky; supply: external
  1.0 V/3 A DC.
- Clock: 15.625 MHz (CDCE906 PLL 31.25 MHz half-rate); synchronous sampling
  1 samp/cycle (M16 tio_clkout→HS1).
- Trigger: busy 512-tick pulse via TIO4; **edge = rising (start edge)**;
  presamples=20000/samples=26000.
- Sign scheme B: per trace `0x63 SEED_LOAD → 0x4B KEYGEN (tree build outside
  the window, drain 48B+56B) → arm → 0x53 steady-state sign`.
- Scripts: `scripts/tvla/tvla_capture.py` (`--op sign/prf_chain/hash_once/...`),
  `tvla_analyze.py` (Bonferroni).
