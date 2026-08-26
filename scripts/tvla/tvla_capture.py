#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tvla_capture.py — CW305 + Husky TVLA trace capture (fixed-vs-random)

Per the TVLA plan stages 2/3: capture two groups of power traces
(fixed group / random group) for the given operation, for pointwise Welch t-test by tvla_analyze.py.

fixed-vs-random semantics (group A/B):
  - Private-key operations (lmots_keygen=0x60 / keygen=0x4b): request = opcode + 60B private key
    (lms_type(4)||lmots_type(4)||I(16)||seed(32)||q(4)).
    fixed group = original vector private key (SEED fixed); random group = only the SEED segment
    priv[24:56] is randomly replaced, the rest (I/type/q) fixed -> leakage difference only from SEED-related paths.
  - hash_once (0x48): fixed group = fixed message; random group = random message.

Usage:
  python scripts/tvla/tvla_capture.py --n 1000 --out build/tvla/run1 \
      --op lmots_keygen --group fixed --w 4 --h 5
  python scripts/tvla/tvla_capture.py --n 1000 --out build/tvla/run1 \
      --op lmots_keygen --group random --w 4 --h 5

Dependencies: Python environment with chipwhisperer>=6.0 (Husky auto-detected via cw.scope()), numpy.
Hardware wiring (TVLA plan §3, measured 2026-08-17):
  X4 (VCCINT 20dB amplified low side) -> Husky Measure POS SMA (single-ended + shorting cap)
  T14 (20-pin tio_trigger) -> Husky CW 20-pin TIO4 (triggers='tio4')
  Clock from Husky internal PLL (clkgen_freq=50e6, async sampling + trigger alignment)
"""
import argparse
import json
import os
import struct
import sys
import time

import numpy as np

_WS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_WS, "..", ".."))
_LOG = os.path.normpath(os.path.join(_ROOT, "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ.setdefault("TMP", _LOG)
os.environ.setdefault("TEMP", _LOG)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from cw305_serial import Cw305Serial  # noqa: E402

# ---- operation -> UART request frame construction (consistent with tests/board/test_lms_uart.py) ----
OP_HASH_ONCE = 0x48
OP_LMOTS_KEYGEN = 0x60
OP_KEYGEN = 0x4B
OP_SIGN = 0x53                # full LMS Sign (SLotH-caliber main experiment: LM-OTS Sign + auth path + assembly)
OP_DERIVE_RANDOMIZER = 0x6D   # TVLA single-PRF isolation (2026-08-18): one DERIVE_RANDOMIZER only
OP_PRF_CHAIN = 0x6E           # multi-PRF chain (2026-08-21, SLotH Fig.6 reproduction): M consecutive software PRFs, trigger at chain head
OP_DERIVE_XQ = 0x6F           # TVLA isolated single x_q[i] (2026-08-25 side-channel SEED leakage characterization fix): single DERIVE_CHAIN steps=0
OP_SEED_LOAD = 0x63           # SEED preload (prerequisite for 0x6D/0x6F, hardware slot load)

RESP_SIZE = 48  # response frame (HASH_ONCE/KeyGen unified 48B frame header)

# 0x4B LMS KeyGen public key length (response = RESP_SIZE frame header + public key).
# LMS_PUBLIC_KEY_LEN = 4(lms_type) + 4(lmots_type) + 16(I) + 32(root) = 56B.
# Note: lmots_keygen(0x60) public key is only 32B (LMS_N), 0x4B is 56B — the old code
# draining only 32B for keygen was a bug (same note in vccint_load_h15.py); scheme B must read 56B.
KEYGEN_PUB_LEN = 56

# Full LMS Sign signature length (0x53 response = RESP_SIZE frame header + signature).
# Consistent with the firmware VERIFY_SIGNATURE_LEN formula (fw/lms_soc_smoke.c):
#   LM-OTS sig = type(4) + C(n=32) + y(p*32), LMS sig = q(4) + lmots_sig + lms_type(4) + h*32(path)
#   = 4 + (4+32+p*32) + 4 + h*32 = 44 + p*32 + h*32
# p taken from the lms_params.c parameter table (SHAKE256_N32_W*): W1=265 W2=133 W4=67 W8=34.
# W4H5 = 44+2144+160 = 2348 ✓ (old hardcoded 2352 was 4B too many -> read_exact wasted a 5s timeout per trace,
# ~8 extra minutes for 100 traces; fixed 2026-08-19 to compute dynamically).
_LMOTS_P_BY_W = {1: 265, 2: 133, 4: 67, 8: 34}


def lms_sign_len(w: int, h: int) -> int:
    return 44 + _LMOTS_P_BY_W[w] * 32 + h * 32


def load_vector(w: int, h: int, vector_path: str | None) -> dict:
    """Load verification vector (PRIVATE_KEY etc. fields)."""
    if vector_path is None:
        cand = os.path.join(_ROOT, "build", "vectors",
                            f"lms_verify_vector_shake_W{w}_H{h}.txt")
        if not os.path.exists(cand):
            cand = os.path.join(_ROOT, "build", "vectors",
                                f"lms_verify_vector_shake_W{w}_H{h}.txt")
        if not os.path.exists(cand):
            # Fallback: any shake vector (as long as w/h match)
            import glob
            cands = sorted(glob.glob(os.path.join(_ROOT, "build", "vectors",
                                                  "lms_verify_vector_shake_*.txt")))
            if not cands:
                raise FileNotFoundError("no verify vector found; run make vectors first")
            cand = cands[0]
        vector_path = cand
    vec = {}
    with open(vector_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                vec[k.strip()] = v.strip()
    priv = bytes.fromhex(vec["PRIVATE_KEY"])
    if len(priv) != 60:
        raise ValueError(f"PRIVATE_KEY len {len(priv)} != 60 (vector {vector_path})")
    return vec, priv


def make_frame(op: str, priv: bytes, msg: bytes, rng: np.random.Generator,
               group: str, sloth_caliber: bool = False,
               seedless: bool = False,
               fixed_seed_b: str | None = None) -> tuple[bytes, str, bytes]:
    """Build request frame + seed description + randomized full private key rpriv.

    seedless=True (pure-software truncated variant, 2026-08-21): the SEED segment
    (priv[24:56]) of 0x4B/0x53 frames is sent all zeros (public); the firmware uses
    the 0x63-preloaded slot SEED (fw pure-software branch coverage) — no SEED plaintext
    in the command-receive segment (aligned with SLotH "without plaintext key load").
    The seed description / 0x63 preload still use the real seed (outside the capture window).

    sloth_caliber=True (SLotH caliber, 2026-08-20 validation experiment): reproduces SLotH's
    "fixed-vs-random against SK.seed, other key components were randomized"
    detection caliber — both groups randomize the non-target components I(16B, priv[8:24])
    and q(priv[56:60], 0..2^h-1), grouping only by SEED (fixed fixed / random random).
    Randomized public components -> large within-group variance -> Welch t suppressed,
    used to verify that the "our 250 vs SLotH 4.80" difference is mainly due to the
    detection caliber, not the implementation. rpriv must be used for the 0x4B warmup frame
    (tree cache fingerprint includes I+seed; after randomizing I, 0x4B and 0x53 must share
    the same I to hit).
    """
    if op == "hash_once":
        if group == "fixed":
            data = msg
        else:
            data = rng.bytes(len(msg))
        return (bytes([OP_HASH_ONCE]) + struct.pack(">H", len(data)) + data,
                data.hex(), priv)
    if op == "derive_randomizer":
        # Single-PRF isolation: request 0x6D | I[16] | q_u32_le. SEED preloaded via 0x63 (outside the main loop).
        # random group randomizes only the SEED segment priv[24:56] (consistent with private-key ops), I/q fixed.
        if group == "random":
            seed = (bytes.fromhex(fixed_seed_b) if fixed_seed_b
                    else rng.bytes(32))
            priv = priv[:24] + seed + priv[56:]
        return (bytes([OP_DERIVE_RANDOMIZER]) + priv[8:24] +
                struct.pack("<I", int.from_bytes(priv[56:60], "big"))), priv[24:56].hex(), priv
    if op == "prf_chain":
        # Multi-PRF chain (0x6E, 2026-08-21): request 0x6E | I[16] | q_u32_le | M_u32_le.
        # SEED preloaded via 0x63 (outside window); I/q fixed, grouped only by SEED; M=4 (4 calls in chain).
        # Window truncated to first 73k cycles -> only first (+ start of second) call (SLotH Fig.6 reproduction).
        if group == "random":
            seed = (bytes.fromhex(fixed_seed_b) if fixed_seed_b
                    else rng.bytes(32))
            priv = priv[:24] + seed + priv[56:]
        return (bytes([OP_PRF_CHAIN]) + priv[8:24] +
                struct.pack("<I", int.from_bytes(priv[56:60], "big")) +
                struct.pack("<I", 4)), priv[24:56].hex(), priv
    if op == "derive_xq":
        # Isolated single x_q[i] (0x6F, 2026-08-25): request 0x6F | I[16] | q_u32_le | i_u16_le.
        # SEED preloaded via 0x63 (outside window); I/q/i fixed, grouped only by SEED. i fixed to 0 (single derivation).
        # Response carries no x_q[i] (private-key element); verification via independent oracle (see analyze/validate).
        if group == "random":
            seed = (bytes.fromhex(fixed_seed_b) if fixed_seed_b
                    else rng.bytes(32))
            priv = priv[:24] + seed + priv[56:]
        return (bytes([OP_DERIVE_XQ]) + priv[8:24] +
                struct.pack("<I", int.from_bytes(priv[56:60], "big")) +
                struct.pack("<H", 0)), priv[24:56].hex(), priv
    if op == "sign":
        # Full LMS Sign (0x53): request = opcode + 60B private key + u16 message length + message.
        # random group randomizes only SEED segment priv[24:56] (I/q/type fixed, SLotH
        # fixed-vs-random against SK.seed caliber). Message uses fixed empty/msg_hex (consistent with SLotH full sign function).
        if sloth_caliber:
            # SLotH caliber: both groups randomize I + q (ADRS equivalent), q limited to [0, 2^h-1]
            priv = (priv[:8] + rng.bytes(16) + priv[24:56] +
                    struct.pack(">I", int(rng.integers(0, 1 << 5))))
        if group == "random":
            seed = (bytes.fromhex(fixed_seed_b) if fixed_seed_b
                    else rng.bytes(32))
            priv = priv[:24] + seed + priv[56:]
        if seedless:
            # Pure-software truncated variant: frame SEED segment all zeros (firmware uses slot SEED); rpriv also all zeros
            # (0x4B warmup frame must be seedless too, otherwise fingerprint mismatch).
            priv = priv[:24] + b"\x00" * 32 + priv[56:]
        return (bytes([OP_SIGN]) + priv +
                struct.pack(">H", len(msg)) + msg), priv[24:56].hex(), priv
    # Private-key operations: random group randomizes only SEED segment priv[24:56]
    if group == "random":
        seed = rng.bytes(32)
        priv = priv[:24] + seed + priv[56:]
    opcode = OP_LMOTS_KEYGEN if op == "lmots_keygen" else OP_KEYGEN
    return bytes([opcode]) + priv, priv[24:56].hex(), priv


def read_exact(port, n: int, timeout: float = 5.0) -> bytes:
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(buf) < n and time.monotonic() < deadline:
        chunk = port.read(n - len(buf))
        if chunk:
            buf.extend(chunk)
        else:
            time.sleep(0.001)
    return bytes(buf)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=1000, help="number of traces")
    ap.add_argument("--out", required=True, help="output directory (each group saved as .npy + meta.json)")
    ap.add_argument("--op", choices=["hash_once", "lmots_keygen", "keygen", "sign",
                                     "derive_randomizer", "prf_chain", "derive_xq"],
                    default="lmots_keygen")
    ap.add_argument("--group", choices=["fixed", "random"], required=True)
    ap.add_argument("--w", type=int, default=4, choices=[1, 2, 4, 8])
    ap.add_argument("--h", type=int, default=5, choices=[5, 10, 15])
    ap.add_argument("--vector", default=None, help="vector file (auto-selected by w/h by default)")
    ap.add_argument("--msg-hex", default=None, help="hash_once fixed message (hex, default empty)")
    ap.add_argument("--samples", type=int, default=200000,
                    help="samples per trace @50MS/s (200k=4ms; LM-OTS KG engine 190us in window front)")
    ap.add_argument("--presamples", type=int, default=0,
                    help="pre-trigger samples (Husky cap 32767≈655us@50MS/s; 2026-08-18 scheme 1: "
                         "SCA trigger changed to engine busy completion edge, presamples covers the whole operation incl. leading DERIVE/PRF segment; "
                         "0=legacy behavior, post-trigger window)")
    ap.add_argument("--offset", type=int, default=0,
                    help="post-trigger offset samples (skip USB command tail noise)")
    ap.add_argument("--gain", type=float, default=5.0,
                    help="Husky gain dB (scope.gain.db; measured 15dB saturates, 0dB too small, recommend 5-10)")
    ap.add_argument("--verify-every", type=int, default=0,
                    help="verify response frame every N traces (0=no verify, saves time; smoke test recommends 10)")
    ap.add_argument("--clk-mhz", type=float, default=15.625,
                    help="CW305 actual design clock MHz (side-channel scope: TVLA PLL 31.25MHz divided by 2 = 15.625; "
                         "pass the actual PLL value; legacy runs used 50)")
    ap.add_argument("--interleave", type=int, default=0,
                    help="interleaved capture: when >0, alternate fixed/random groups within one process (switch every N traces), "
                         "eliminating trigger phase drift between long-capture groups (2026-08-18: sub-sample phase difference between 10k long-capture groups caused artifacts; "
                         "after interleaving, inter-group spacing=N×44ms)")
    ap.add_argument("--fixed-seed-b", default=None,
                    help="discrimination experiment: random group uses this fixed SEED (hex 32B) instead of random "
                         "(forming a fixedA/fixedB alternation with the fixed group, isolating acquisition-structure differences; "
                         "use together with --interleave)")
    ap.add_argument("--sync", action="store_true",
                    help="synchronous sampling (same as SLotH): clkgen_src=extclk (HS1 to CW305 tio_clkout/M16) "
                         "+ adc_mul=1 -> 1 sample/clk50-cycle phase lock; full Sign window ~15K points "
                         "directly covered by presamples. Default off (async clkgen_freq=50e6).")
    ap.add_argument("--sloth-caliber", action="store_true",
                    help="SLotH detection caliber (2026-08-20 validation experiment): on sign, both groups randomize "
                         "non-target components I+q (ADRS equivalent), grouped only by SEED — reproduces SLotH's "
                         "'other key components randomized' within-group variance caliber, verifying t decreases.")
    ap.add_argument("--sw-sign", action="store_true",
                    help="pure-software truncated Sign (2026-08-21, SLotH Fig.6 reproduction): 0x4B/0x53 "
                         "frame SEED segment sent all zeros (firmware uses 0x63-preloaded slot SEED) — no SEED plaintext "
                         "in command-receive segment (aligned with without plaintext key load). Use with "
                         "--presamples 0 --samples 73000 to capture the first 73k cycles before signing.")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    rng = np.random.default_rng(20260817)
    vec, priv = load_vector(args.w, args.h, args.vector)
    msg = bytes.fromhex(args.msg_hex) if args.msg_hex else bytes(0)

    import chipwhisperer as cw

    # ---- Husky acquisition board (2026-08-17 measured parameters) ----
    scope = cw.scope()
    try:
        if args.sync:
            # Synchronous sampling (same as SLotH §6.4): HS1 external clock (CW305 tio_clkout=clk50) into PLL,
            # adc_mul=1 -> 1 sample/clk50-cycle phase lock. freq_ctr=15.63MHz measured.
            # Critical ordering (Husky API): the clkgen_src setter captures the current clkgen_freq as target_freq
            # and triggers auto frequency measurement override — must [set clkgen_freq first (expected=external clock) then clkgen_src],
            # reversed order leaves target_freq=old value (50MHz) causing PLL divide-by-zero / no lock, ADC captures no signal.
            scope.clock.clkgen_freq = args.clk_mhz * 1e6   # expected frequency (--clk-mhz passes the actual value)
            scope.clock.clkgen_src = "extclk"
            fc = scope.clock.freq_ctr
            if not (fc and fc > 1e6):
                print("!! freq_ctr=%r (external clock not locked, check M16->HS1 wiring)" % fc, file=sys.stderr)
                scope.dis()
                return 1
            scope.clock.adc_mul = 1
            print("sync sampling: extclk(HS1) + adc_mul=1 -> 1 samp/cycle")
            print("  freq_ctr=%.3f MHz  clkgen_freq=%.3f MHz" % (fc / 1e6, scope.clock.clkgen_freq / 1e6))
        else:
            scope.clock.clkgen_freq = 50e6      # do not use 100e6 (exceeds ADC 200MHz spec)
        scope.adc.samples = args.samples
        if args.presamples:
            # Scheme 1 (2026-08-18): trigger at operation completion edge (busy falling), presamples covers the whole operation.
            # Husky cap 32767 (~655us@50MS/s); samples must be >= presamples.
            if args.presamples > args.samples:
                raise ValueError("presamples(%d) > samples(%d)" % (args.presamples, args.samples))
            scope.adc.presamples = args.presamples
            print("presamples=%d (whole operation captured before trigger)" % args.presamples)
        scope.adc.offset = args.offset
        scope.gain.db = args.gain               # Husky gain (scope.adc.gain does not exist!)
        scope.trigger.module = "basic"
        scope.trigger.triggers = "tio4"         # CW 20-pin TIO4 (this is the default)
        scope.adc.basic_mode = "rising_edge"
        scope.io.hs2 = "disabled"               # disable HS-IO clock output (noise prevention)
        # Note: Husky GPIO has no hs4 attribute (measured: unknown attribute), not set

        # ---- CW305 target (control channel: USB register mailbox) ----
        with Cw305Serial(timeout=5.0) as port:
            port.reset_input_buffer()
            for _ in range(3):
                port.read(4096)
            port.reset_input_buffer()

            metas = []
            if args.interleave:
                metas_f, metas_r = [], []
            # Streaming save (2026-08-25 fix): large captures (100k scale) use memmap, writing while capturing,
            # avoiding OOM from a large np.asarray allocation at save time (delay-100k once lost 2.65h of data this way).
            _L = args.samples
            _tmp = os.path.join(args.out, "_tmp_")
            if args.interleave:
                mm_f = np.lib.format.open_memmap(_tmp + "fixed.npy", mode="w+",
                                                 dtype=np.float32,
                                                 shape=(args.n, _L))
                mm_r = np.lib.format.open_memmap(_tmp + "random.npy", mode="w+",
                                                 dtype=np.float32,
                                                 shape=(args.n, _L))
                nf = nr = 0
            else:
                mm_g = np.lib.format.open_memmap(_tmp + args.group + ".npy",
                                                 mode="w+", dtype=np.float32,
                                                 shape=(args.n, _L))
                ng = 0

            # Scheme B (finalized 2026-08-19, fix for invalidated Sign data): no longer needs a separate warmup to build the tree.
            # Each trace explicitly sends 0x4B KEYGEN before 0x53, binding the tree cache to this trace's seed (see main loop),
            # so the first trace naturally builds the tree, fixed group hits cache from the second trace on, and both groups are steady-state signatures.
            t0 = time.monotonic()
            for i in range(args.n):
                if args.interleave:
                    grp = "fixed" if (i // args.interleave) % 2 == 0 else "random"
                    frame, seed_hex, rpriv = make_frame(args.op, priv, msg, rng, grp,
                                                        args.sloth_caliber,
                                                        seedless=args.sw_sign,
                                                        fixed_seed_b=args.fixed_seed_b)
                else:
                    grp = args.group
                    frame, seed_hex, rpriv = make_frame(args.op, priv, msg, rng, grp,
                                                        args.sloth_caliber,
                                                        seedless=args.sw_sign,
                                                        fixed_seed_b=args.fixed_seed_b)

                if args.op in ("derive_randomizer", "prf_chain", "sign", "derive_xq"):
                    # Preload SEED (same caliber as SLotH "without plaintext key load", scheme A):
                    # first 0x63 loads the current group's seed into the hardware slot (outside trigger window, not on the trace),
                    # then arm + command. The sign frame still contains plaintext SEED (firmware F2 fingerprint hit skips
                    # MMIO plaintext load), command-receive segment at trace start, trimmed with --window.
                    seed = bytes.fromhex(seed_hex)
                    port.write(bytes([OP_SEED_LOAD]) + seed)
                    r = read_exact(port, RESP_SIZE, timeout=10.0)
                    if len(r) < RESP_SIZE or r[:1] != b"\x52":
                        print("!! trace %d: preload resp bad (len=%d head=%s), retrying"
                              % (i, len(r), r[:1].hex()), file=sys.stderr)
                        port.reset_input_buffer()
                        port.write(bytes([OP_SEED_LOAD]) + seed)
                        r = read_exact(port, RESP_SIZE, timeout=10.0)
                if args.op == "sign":
                    # Scheme B (finalized 2026-08-19, fix for invalidated Sign data): each trace first explicitly 0x4B
                    # KEYGEN builds the tree, binding the tree cache fingerprint (I||seed||type) to this trace's seed —
                    # tree building happens outside the trace window (not armed then), so 0x53 always hits the cache ->
                    # pure steady-state signature. The fixed/random trace surfaces are therefore strictly isomorphic (fixes the
                    # operation asymmetry in old data where "random group builds the tree implicitly every trace vs fixed group steady state",
                    # see the session summary §2.1 and the TVLA mitigation review).
                    # random group has a new seed per trace -> real tree build every trace (~25ms hw); fixed group same seed ->
                    # fingerprint hit from second trace on, no rebuild (nearly free). Under SLotH caliber (--sloth-caliber)
                    # both groups randomize I -> tree built every trace; rpriv with random I/q/seed must be used for 0x4B.
                    keygen_priv = rpriv
                    port.write(bytes([OP_KEYGEN]) + keygen_priv)
                    kr = read_exact(port, RESP_SIZE, timeout=20.0)  # first-trace tree build ~25ms hw
                    if len(kr) < RESP_SIZE or kr[:1] != b"\x52":
                        print("!! trace %d: keygen prebuild resp bad (len=%d head=%s), retrying"
                              % (i, len(kr), kr[:1].hex()), file=sys.stderr)
                        port.reset_input_buffer()
                        port.write(bytes([OP_KEYGEN]) + keygen_priv)
                        kr = read_exact(port, RESP_SIZE, timeout=20.0)
                    # Drain 0x4B response = 48B frame + 56B LMS public key (old code draining only
                    # 32B for keygen was a bug; not reading the full residue leaves TX FIFO -> bridge state corruption).
                    read_exact(port, KEYGEN_PUB_LEN, timeout=5.0)
                scope.arm()
                port.write(frame)
                scope.capture()
                trace = scope.get_last_trace()

                # Response drain: private-key op response = 48B frame + 32B public key. Must read fully each time,
                # otherwise residual TX FIFO -> next command response misaligned -> bridge state corruption (2026-08-17
                # measured: 1k smoke test skipped public key -> CW305 unresponsive, needed re-flash to recover).
                resp = read_exact(port, RESP_SIZE, timeout=3.0)
                if args.verify_every and i % args.verify_every == 0:
                    if resp[:1] != b"\x52":
                        print(f"!! trace {i}: bad resp marker {resp[:1].hex()!r}",
                              file=sys.stderr)
                if args.op == "lmots_keygen":
                    read_exact(port, 32, timeout=3.0)      # 0x60: 32B LM-OTS public key
                elif args.op == "keygen":
                    read_exact(port, KEYGEN_PUB_LEN, timeout=3.0)  # 0x4B: 56B LMS public key
                elif args.op == "sign":
                    # Full LMS Sign response = RESP_SIZE frame header + full signature (lms_sign_len dynamic
                    # by w/h, aligned with firmware VERIFY_SIGNATURE_LEN, W4H5=2348B). Must read fully,
                    # otherwise residual TX FIFO -> bridge state corruption (old hardcoded 2352, 4B too many, wasted a timeout per trace).
                    read_exact(port, lms_sign_len(args.w, args.h), timeout=5.0)
                # Note: derive_randomizer(0x6D)'s C is within the 48B frame [16..47], no extra 32B

                meta = {
                    "i": i, "seed": seed_hex, "op": args.op,
                    "w": args.w, "h": args.h, "group": grp,
                    "prebuild": args.op == "sign",  # scheme B: per-trace 0x4B tree-build warmup, 0x53 steady state
                    "caliber": ("sloth" if args.sloth_caliber else "project"),
                }
                if args.interleave:
                    if grp == "fixed":
                        mm_f[nf] = trace
                        nf += 1
                        metas_f.append(meta)
                    else:
                        mm_r[nr] = trace
                        nr += 1
                        metas_r.append(meta)
                else:
                    mm_g[ng] = trace
                    ng += 1
                    metas.append(meta)
                if (i + 1) % 100 == 0 or i == args.n - 1:
                    el = time.monotonic() - t0
                    print(f"  [{grp}] {i+1}/{args.n}  ({el:.1f}s, "
                          f"{el / (i + 1) * 1000:.0f} ms/trace)")

            # ---- Save (streaming finalize: memmap -> exact-shape chunked write) ----
            def save_group(g, n_actual, mg):
                import numpy.lib.format as npfmt
                mm = np.lib.format.open_memmap(_tmp + g + ".npy", mode="r",
                                               dtype=np.float32,
                                               shape=(args.n, _L))
                p = os.path.join(args.out, f"{g}.npy")
                with open(p, "wb") as f:
                    npfmt.write_array_header_1_0(
                        f, {"descr": np.dtype(np.float32).str,
                            "fortran_order": False,
                            "shape": (n_actual, _L)})
                    _CH = 10000
                    for i in range(0, n_actual, _CH):
                        f.write(np.ascontiguousarray(mm[i:i + _CH]).tobytes())
                del mm
                try:
                    os.remove(_tmp + g + ".npy")
                except OSError:
                    pass
                with open(os.path.join(args.out, f"{g}_meta.json"), "w",
                          encoding="utf-8") as f:
                    json.dump({
                        "op": args.op, "group": g, "w": args.w, "h": args.h,
                        "n": n_actual, "trace_len": _L,
                        "presamples": args.presamples,
                        "sync": args.sync,
                        "samples_per_cycle": 1.0 if args.sync else 50.0 / args.clk_mhz,
                        "clk_mhz": args.clk_mhz,
                        "vector": os.path.basename(args.vector) if args.vector else None,
                        "env": {"trigger_edge": "rising",   # 2026-08-19 v13+: busy rising edge (start edge)
                                "board": "CW305", "scope": "Husky",
                                "probe": "Measure POS SMA (X4)"},
                        "method": ("sign: per-trace 0x4B keygen prebuild then steady 0x53 "
                                   "sign (scheme B, 2026-08-19)" if args.op == "sign"
                                   else "direct op capture"),
                        "meta": mg,
                    }, f, ensure_ascii=False, indent=1)
                print(f"  saved ({n_actual}, {_L}) -> {args.out}/{g}.npy")

            if args.interleave:
                save_group("fixed", nf, metas_f)
                save_group("random", nr, metas_r)
            else:
                save_group(args.group, ng, metas)
    finally:
        scope.dis()

    return 0


if __name__ == "__main__":
    sys.exit(main())
