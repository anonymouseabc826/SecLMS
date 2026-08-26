"""TRNG_READ_ACK high-speed no-gap stress test: verify the uart_rx depth-2 FIFO fix.

Fire N back-to-back 0x5A||count||seq requests (no inter-byte gap) and check
marker/count/seq/CRC8. Covers the previous 12K-batch hang point.
Usage: python tests/board/stress_ack.py [--n 15000] [--port COM5]
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
    ap.add_argument("--n", type=int, default=15000)
    ap.add_argument("--port", default="COM5")
    args = ap.parse_args()
    p = serial.Serial(args.port, 115200, timeout=2.0, write_timeout=2.0)
    p.reset_input_buffer()
    p.reset_output_buffer()
    time.sleep(0.3)
    ok = fail = to = mm = 0
    firstfail = -1
    t0 = time.time()
    for i in range(args.n):
        p.write(bytes([0x5A, 4, i & 0xFF]))
        p.flush()
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
                    print(f"    frame48={r.hex()}", flush=True)
                continue
            ok += 1
        except TimeoutError as e:
            fail += 1
            to += 1
            if firstfail < 0:
                firstfail = i
                print(f"[{i}] TIMEOUT {e}", flush=True)
        if fail and (i - firstfail) < 3:
            # Diagnostic: probe STATUS right after a mismatch/timeout to tell firmware deadlock vs byte-stream misalignment
            try:
                p.reset_input_buffer()
                p.write(bytes([0x59]))
                p.flush()
                sr = rex(p, 48)
                st = struct.unpack_from("<I", sr, 36)[0]
                print(f"    diag STATUS marker={hex(sr[0])} STAT={hex(st)} health_fail={st&1}", flush=True)
            except TimeoutError as e:
                print(f"    diag STATUS DEAD {e}", flush=True)
        if (i + 1) % 3000 == 0:
            print(f"  progress {i+1}/{args.n} ok={ok} fail={fail}", flush=True)
        time.sleep(0.002)
    el = time.time() - t0
    print(f"RESULT[fifo2] ok={ok} fail={fail} timeout={to} mismatch={mm} firstfail={firstfail} ({el:.1f}s)", flush=True)
    p.close()
    return 0 if fail == 0 else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
