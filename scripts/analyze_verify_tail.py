#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse verify_tail_trace.vcd to locate the bridge's receive-tail end (byte_left_r→0) and the timing of firmware tail reads.

Usage: python scripts/analyze_verify_tail.py verify_tail_trace.vcd
Output: per-cycle changes of rx_rdy/rx_ack/state_r/byte_left_r/rx_cons_r at bridge tail-end,
        and uart_rx data/rdy and firmware gpio_out after bridge done.
"""
import sys
from collections import defaultdict

VCD = sys.argv[1] if len(sys.argv) > 1 else "verify_tail_trace.vcd"

# ---- 1. Parse header: signal id -> name ($var lines have leading space, $scope nesting, duplicate names disambiguated by width) ----
sig_ids = {}          # vcd code -> full name
name_codes = {}       # name -> [(code, size, scope)]
scope = ""
with open(VCD, "r", errors="replace") as f:
    for line in f:
        s = line.strip()
        if s.startswith("$scope"):
            parts = s.split()
            scope = parts[3] if len(parts) >= 4 else scope
        elif s.startswith("$upscope"):
            scope = ""
        elif s.startswith("$var"):
            parts = s.split()
            # $var wire 16 pE byte_left_r [15:0] $end
            code = parts[3]
            name = parts[4]
            size = 1
            if len(parts) >= 6 and parts[5].startswith("["):
                hi = parts[5].replace("[", "").replace("]", "")
                try:
                    size = int(hi.split(":")[0]) + 1
                except Exception:
                    pass
            sig_ids[code] = name
            name_codes.setdefault(name, []).append((code, size, scope))
        elif s.startswith("$timescale"):
            print("timescale:", s)

def code_for(name, size=None):
    cands = name_codes.get(name, [])
    if not cands:
        return None
    if size is not None:
        for c, sz, sc in cands:
            if sz == size:
                return c
    return cands[-1][0]

# Target signals (depth-6 short names + width filter to avoid collisions with e.g. ibex)
want = {
    "byte_left_r": code_for("byte_left_r", 16),
    "rx_cons_r": code_for("rx_cons_r", 16),
    "bridge_state": code_for("state_r", 3),
    "bridge_rx_rdy": code_for("rx_rdy", 1),
    "bridge_rx_ack": code_for("rx_ack", 1),
    "bridge_owner": code_for("bridge_owner", 1),
    "bridge_active": code_for("bridge_active", 1),
    "bridge_busy": code_for("bridge_busy", 1),
    "uart_rx_data": code_for("uart_rx_data", 8),
    "uart_rx_ready": code_for("uart_rx_ready", 1),
    "gpio_out": code_for("gpio_out", 8),
    "uart_rxd": code_for("uart_rxd", 1),
}
print("=== target code ===")
for k, v in want.items():
    print(f"  {k}: {v}")

valid_codes = set(v for v in want.values() if v)

import re
pat_multi = re.compile(r"^b([01xXzZ]+)\s+(\S+)$")
pat_bit = re.compile(r"^([01xXzZ])(\S+)$")

events = defaultdict(list)
cur_time = 0
with open(VCD, "r", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        if line[0] == "#":
            cur_time = int(line[1:])
            continue
        m = pat_multi.match(line)
        if m and m.group(2) in valid_codes:
            events[m.group(2)].append((cur_time, m.group(1)))
            continue
        m = pat_bit.match(line)
        if m and m.group(2) in valid_codes:
            events[m.group(2)].append((cur_time, m.group(1)))

for name, code in sorted(want.items(), key=lambda kv: (kv[1] is None, kv[0])):
    if code is None:
        print(f"=== {name}: not found ===")
        continue
    ev = events.get(code, [])
    print(f"=== {name} (code={code}): {len(ev)} changes, last 10 ===")
    for t, v in ev[-10:]:
        print(f"    t={t} v={v}")

# Find the first time byte_left_r reaches 0
bl = events.get(want["byte_left_r"], [])
zero_t = None
for i in range(len(bl) - 1):
    if bl[i][1] != "0" and bl[i + 1][1] == "0":
        zero_t = bl[i + 1][0]
        break
print("=== first time byte_left_r reaches 0 ===", zero_t)

# Bridge tail-end window: ±4000 cycles around zero_t
if zero_t:
    t0 = max(0, zero_t - 4000)
    t1 = zero_t + 20000
    window = []
    for name, code in want.items():
        if code is None:
            continue
        for t, v in events.get(code, []):
            if t0 <= t <= t1:
                window.append((t, name, v))
    window.sort()
    cur = {}
    last_t = None
    out_lines = []
    for t, name, v in window:
        if t != last_t:
            if last_t is not None:
                out_lines.append(f"  t={last_t}: {cur}")
            cur = {}
            last_t = t
        cur[name] = v
    if last_t is not None:
        out_lines.append(f"  t={last_t}: {cur}")
    print("=== bridge tail-end window (near byte_left_r->0, first 90 entries) ===")
    for line in out_lines[:90]:
        print(line)

print("=== done ===")
