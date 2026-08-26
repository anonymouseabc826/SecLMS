#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze VCD trace files (standard VCD and Verilator's VerilatedVcd).

Verilator's VerilatedVcd writes 1-bit values as '<bit><id>' (e.g. '1a"') and
multi-bit as 'b<value><id>'; ids are single non-space chars and may be quotes
or punctuation.  Multi-bit $var lines carry a [msb:lsb] range in the name that
the parser must tolerate.

This is the reusable replacement for the former build/analyze_vcd.py +
build/vcd_scopes.py debug tools (see the VCD scope documentation, section 2).

Examples:
  python scripts/analyze_vcd.py trace.vcd --signals
  python scripts/analyze_vcd.py trace.vcd --sig uart_rx_ack --edges
  python scripts/analyze_vcd.py trace.vcd --sig stream_wr_en -t 1000 50000
"""
import argparse
import re
import sys

SCOPE_RE = re.compile(r'^\$scope\s+\S+\s+(\S+)\s*\$end')
UPSCOPE_RE = re.compile(r'^\$upscope\s*\$end')
VAR_RE = re.compile(r'^\$var\s+\S+\s+(\d+)\s+(\S+)\s+(\S+)(?:\s+\[\d+:\d+\])?\s*\$end')
TIME_RE = re.compile(r'^#(\d+)\s*$')
BITVAL_RE = re.compile(r'^([01xzXZ])(\S)$')
BINVAL_RE = re.compile(r'^b([01xzXZ]+)(\S)$')


def main():
    ap = argparse.ArgumentParser(description='Analyze VCD trace files.')
    ap.add_argument('vcd', help='path to VCD file')
    ap.add_argument('--signals', action='store_true',
                    help='list all signals (id, size, scope-qualified name)')
    ap.add_argument('--sig', metavar='NAME',
                    help='signal name to inspect (substring match on scope-qualified name)')
    ap.add_argument('--edges', action='store_true',
                    help='print every change of the selected signal in the window')
    ap.add_argument('-t', nargs=2, type=int, metavar=('T0', 'T1'),
                    help='time window [T0,T1] (default: whole trace)')
    args = ap.parse_args()

    if args.signals:
        return _dump_signals(args.vcd)

    if not args.sig:
        print('--sig NAME is required unless --signals is used', file=sys.stderr)
        return 2

    t0, t1 = (args.t if args.t else (0, 10**12))
    scope = []
    id2name = {}
    id2size = {}
    target_ids = set()
    values = {}
    time = 0
    events = []
    hit = False

    for raw in _lines(args.vcd):
        line = raw.strip()
        m = SCOPE_RE.match(line)
        if m:
            scope.append(m.group(1))
            continue
        if UPSCOPE_RE.match(line):
            if scope:
                scope.pop()
            continue
        m = VAR_RE.match(line)
        if m:
            size, ident, name = m.group(1), m.group(2), m.group(3)
            id2name[ident] = name
            id2size[ident] = int(size)
            full = '.'.join(scope + [name]) if scope else name
            if args.sig in full:
                target_ids.add(ident)
                hit = True
            continue
        m = TIME_RE.match(line)
        if m:
            time = int(m.group(1))
            continue

        bm = BITVAL_RE.match(line)
        if bm:
            val, ident = bm.group(1), bm.group(2)
            if ident in target_ids and t0 <= time <= t1:
                if args.edges or values.get(ident) != val:
                    events.append((time, ident, val))
            if ident in target_ids or ident in values:
                values[ident] = val
            continue
        bv = BINVAL_RE.match(line)
        if bv:
            val, ident = bv.group(1), bv.group(2)
            if ident in target_ids and t0 <= time <= t1:
                if args.edges or values.get(ident) != val:
                    events.append((time, ident, val))
            if ident in target_ids or ident in values:
                values[ident] = val
            continue
        # other value forms (r<real>, etc.) are ignored

    if not hit:
        print('signal not found: %s' % args.sig, file=sys.stderr)
        return 1

    for ident in target_ids:
        print('# %s (id=%r size=%d) final=%s' %
              (id2name[ident], ident, id2size[ident], values.get(ident, '?')))
    if args.edges:
        print('# changes in window [%d,%d]:' % (t0, t1))
        for t, ident, val in events:
            print('%9d  %-3s  %s' % (t, ident, val))
    return 0


def _dump_signals(path):
    scope = []
    for raw in _lines(path):
        line = raw.strip()
        m = SCOPE_RE.match(line)
        if m:
            scope.append(m.group(1))
            continue
        if UPSCOPE_RE.match(line):
            if scope:
                scope.pop()
            continue
        m = VAR_RE.match(line)
        if m:
            size, ident, name = m.group(1), m.group(2), m.group(3)
            full = '.'.join(scope + [name]) if scope else name
            print('%-6s %-4s %s' % (ident, size, full))
    return 0


def _lines(path):
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            yield line


if __name__ == '__main__':
    sys.exit(main())
