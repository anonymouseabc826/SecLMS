"""TRNG_READ_ACK stress test (per-byte idle variant): verify whether the uart_rx sampling-point problem can be eliminated with inter-byte idle.

Write requests byte-by-byte, leaving idle after each byte (default 300us, >2 char times @115200),
so uart_rx idx=9 has ample time to lock onto the start-bit center, avoiding back-to-back
sampling-point drift. Usage: python tests/board/stress_ack_paced.py [--n 3000] [--idle-us 300] [--port COM5]
"""
import argparse
import serial
import struct
import time

def rex(p, n):
    d = bytearray()
    while len(d) < n:
        c = p.read(n - len(d))
        if not c:
            raise TimeoutError(f"{len(d)}/{n}")
        d.extend(c)
    return bytes(d)

def crc8(d):
    c = 0
    for b in d:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--idle-us", type=int, default=300, help="idle microseconds after each byte")
    ap.add_argument("--port", default="COM5")
    args = ap.parse_args()
    idle_s = args.idle_us / 1e6
    p = serial.Serial(args.port, 115200, timeout=2.0, write_timeout=2.0)
    p.reset_input_buffer()
    p.reset_output_buffer()
    time.sleep(0.3)
    ok = fail = to = mm = 0
    firstfail = -1
    t0 = time.time()
    for i in range(args.n):
        for b in (0x5A, 4, i & 0xFF):
            p.write(bytes([b]))
            p.flush()
            time.sleep(idle_s)  # inter-byte idle: time for uart_rx to lock the start bit
        try:
            r = rex(p, 48)
            cnt = struct.unpack_from("<I", r, 36)[0]
            seq = r[40]
            data = rex(p, cnt * 4)
            crc = rex(p, 1)[0]
            if r[0] != 0x52 or cnt != 4 or seq != (i & 0xFF) or crc != crc8(data) or r[1] != 0 or r[2] != 0:
                fail += 1
                mm += 1
                if firstfail < 0:
                    firstfail = i
                    print(f"[{i}] MISMATCH marker={hex(r[0])} cnt={cnt} seq={hex(seq)} exp={hex(i&0xFF)} crcok={crc==crc8(data)}", flush=True)
                continue
            ok += 1
        except TimeoutError as e:
            fail += 1
            to += 1
            if firstfail < 0:
                firstfail = i
                print(f"[{i}] TIMEOUT {e}", flush=True)
        time.sleep(0.001)
    el = time.time() - t0
    rate = args.n / el if el > 0 else 0
    print(f"RESULT[paced idle={args.idle_us}us] ok={ok} fail={fail} timeout={to} mismatch={mm} firstfail={firstfail} ({el:.1f}s {rate:.0f}op/s)", flush=True)
    p.close()
    return 0 if fail == 0 else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
