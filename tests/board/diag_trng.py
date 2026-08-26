"""Diagnostic: after a collection failure, check whether firmware STATUS/ACK still responds (deadlock vs recoverable)."""
import serial
import struct
import time

def rex(p, n, t=2.0):
    p.timeout = t
    d = bytearray()
    while len(d) < n:
        c = p.read(n - len(d))
        if not c:
            raise TimeoutError(f"{len(d)}/{n}")
        d.extend(c)
    return bytes(d)

p = serial.Serial("COM5", 115200, timeout=2.0, write_timeout=2.0)
p.reset_input_buffer()
p.reset_output_buffer()
time.sleep(0.2)
try:
    p.write(bytes([0x59]))
    p.flush()
    r = rex(p, 48)
    stat = struct.unpack_from("<I", r, 36)[0]
    print(f"STATUS ALIVE marker={hex(r[0])} STAT={hex(stat)} health_fail={stat&1}")
except TimeoutError as e:
    print(f"STATUS DEAD: {e}")

p.reset_input_buffer()
time.sleep(0.1)
try:
    p.write(bytes([0x5A, 4, 0x42]))
    p.flush()
    r = rex(p, 48)
    print(f"ACK ALIVE cnt={struct.unpack_from('<I', r, 36)[0]} seq={hex(r[40])}")
except TimeoutError as e:
    print(f"ACK DEAD: {e}")
p.close()
