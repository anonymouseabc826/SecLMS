"""SHAKE batch-task on-board test special diagnostic (2026-08-16).

Standalone forensics script: issue each request to the on-board SHAKE platform in turn --
0x62 (lmots-verify), 0x61 (lmots-sign), 0x56 (lms-verify KAT), 0x60 (lmots-keygen, run
last, highest hang risk) -- dumping full response frames without PASS/FAIL assertions.
Goal: capture the hw_error codes and byte-by-byte diffs to root-cause the SHAKE hardware
batch-task on-board test failures (Verilator passes fully, single-core paths pass on
board, batch tasks fail).

Usage:
  python tests/board/diag_shake_batch.py --port COM5 [--only verify]
"""

import argparse
import struct
import sys
import time
from pathlib import Path

import serial

REQUEST_HASH = 0x48
REQUEST_VERIFY = 0x56
REQUEST_LMOTS_KEYGEN_TEST = 0x60
REQUEST_LMOTS_SIGN_TEST = 0x61
REQUEST_LMOTS_VERIFY_TEST = 0x62
RESPONSE = 0x52
RESPONSE_SIZE = 48
VERIFY_VECTOR = Path("build/lms_verify_vector.txt")


def load_vector() -> dict:
    vector = {}
    for line in VERIFY_VECTOR.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vector[k.strip()] = v.strip()
    return vector


def read_exact(port: serial.Serial, n: int) -> bytes:
    data = port.read(n)
    if len(data) != n:
        raise TimeoutError(f"read_exact: got {len(data)}/{n} bytes: {data.hex()}")
    return data


def write_paced(port: serial.Serial, data: bytes, chunk_size: int = 4, sleep_time: float = 0.004):
    for i in range(0, len(data), chunk_size):
        port.write(data[i:i + chunk_size])
        time.sleep(sleep_time)


def dump_frame(tag: str, response: bytes):
    marker, status, hw_error, reserved, cycles, hits, fallback = struct.unpack_from(
        "<BBBBIII", response)
    next_q = struct.unpack_from("<I", response, 16)[0]
    total = struct.unpack_from("<I", response, 20)[0]
    parse_cycles = struct.unpack_from("<I", response, 24)[0]
    sign_cycles = struct.unpack_from("<I", response, 28)[0]
    steady = struct.unpack_from("<I", response, 32)[0]
    print(f"[{tag}] marker=0x{marker:02x} status={status} hw_error={hw_error} "
          f"reserved={reserved} cycles={cycles} hits={hits} fallback={fallback}")
    print(f"[{tag}] next_q/value={next_q} total={total} parse={parse_cycles} "
          f"sign_internal={sign_cycles} steady={steady}")
    print(f"[{tag}] raw={response.hex()}")
    return status, hw_error, cycles, hits


def test_hash_once(port: serial.Serial):
    """Single-core path sanity: HASH_ONCE 'abc' expected in 12 cycles."""
    msg = b"abc"
    request = bytes((REQUEST_HASH,)) + struct.pack(">H", len(msg)) + msg
    write_paced(port, request)
    response = read_exact(port, RESPONSE_SIZE)
    dump_frame("once", response)
    try:
        digest = read_exact(port, 32)
        print(f"[once] digest={digest.hex()}")
    except TimeoutError as e:
        print(f"[once] digest timeout: {e}")
        extra = port.read(64)
        print(f"[once] extra bytes after timeout: {extra.hex()}")
    return None


def test_lmots_verify(port: serial.Serial, vector: dict):
    private_key = bytes.fromhex(vector["PRIVATE_KEY"])
    message = bytes.fromhex(vector["MESSAGE"])
    public_key = bytes.fromhex(vector["LMOTS_PUBLIC_KEY"])
    signature = bytes.fromhex(vector["LMOTS_SIGNATURE"])
    request = (
        bytes((REQUEST_LMOTS_VERIFY_TEST,))
        + private_key[8:24]
        + struct.pack("<I", 0)
        + public_key
        + struct.pack(">H", len(message))
        + message
        + signature
    )
    write_paced(port, request)
    response = read_exact(port, RESPONSE_SIZE)
    dump_frame("lmots-verify(0x62)", response)


def test_lmots_sign(port: serial.Serial, vector: dict):
    private_key = bytes.fromhex(vector["PRIVATE_KEY"])
    message = bytes.fromhex(vector["MESSAGE"])
    signature = bytes.fromhex(vector["LMOTS_SIGNATURE"])
    request = bytes((REQUEST_LMOTS_SIGN_TEST,)) + private_key + struct.pack(">H", len(message)) + message
    write_paced(port, request)
    response = read_exact(port, RESPONSE_SIZE)
    dump_frame("lmots-sign(0x61)", response)
    try:
        actual = read_exact(port, len(signature))
    except TimeoutError as e:
        print(f"[lmots-sign] signature read timeout: {e}")
        return
    n = min(len(actual), len(signature))
    first_bad = next((i for i in range(n) if actual[i] != signature[i]), n)
    print(f"[lmots-sign] siglen got={len(actual)} exp={len(signature)} first_bad={first_bad}")
    if first_bad < n:
        lo, hi = max(0, first_bad - 8), min(n, first_bad + 8)
        print(f"[lmots-sign] got[{lo}:{hi}]={actual[lo:hi].hex()}")
        print(f"[lmots-sign] exp[{lo}:{hi}]={signature[lo:hi].hex()}")
        # Compare the first 8B of each 32B chain (y segment starts at 40; W4 is 32B per chain)
        for k in range(8):
            off = 40 + k * 32
            if off + 8 <= n:
                ok = actual[off:off + 8] == signature[off:off + 8]
                print(f"[lmots-sign] y[{off}..{off+7}] match={ok}")
    else:
        print("[lmots-sign] signature matches")


def test_lms_verify(port: serial.Serial, vector: dict):
    public_key = bytes.fromhex(vector["PUBLIC_KEY"])
    message = bytes.fromhex(vector["MESSAGE"])
    signature = bytes.fromhex(vector["SIGNATURE"])
    request = bytearray((REQUEST_VERIFY,))
    request += public_key
    request += struct.pack(">H", len(message)) + message
    if len(message) > 74:
        request += b"\x00" * ((4 - len(message) % 4) % 4)
    request += signature
    write_paced(port, bytes(request))
    response = read_exact(port, RESPONSE_SIZE)
    dump_frame("lms-verify(0x56)", response)


def test_lmots_keygen(port: serial.Serial, vector: dict):
    """Highest hang risk; run last."""
    private_key = bytes.fromhex(vector["PRIVATE_KEY"])
    public_key = bytes.fromhex(vector["LMOTS_PUBLIC_KEY"])
    request = bytes((REQUEST_LMOTS_KEYGEN_TEST,)) + private_key
    write_paced(port, request)
    try:
        response = read_exact(port, RESPONSE_SIZE)
    except TimeoutError as e:
        print(f"[lmots-keygen(0x60)] NO RESPONSE (hang): {e}")
        return
    dump_frame("lmots-keygen(0x60)", response)
    try:
        actual = read_exact(port, len(public_key))
        print(f"[lmots-keygen] pub got ={actual.hex()}")
        print(f"[lmots-keygen] pub exp ={public_key.hex()}")
        print(f"[lmots-keygen] pub_match={actual == public_key}")
    except TimeoutError as e:
        print(f"[lmots-keygen] pub read timeout: {e}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", default="COM5")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--only", default="", help="once|lmots-verify|lmots-sign|lms-verify|lmots-keygen")
    args = parser.parse_args()

    vector = load_vector()
    print(f"vector: msg_len={len(bytes.fromhex(vector['MESSAGE']))} "
          f"h={vector['PRIVATE_KEY'][:8]} ots={vector['PRIVATE_KEY'][8:16]}")
    print(f"LMOTS_SIGNATURE len={len(bytes.fromhex(vector['LMOTS_SIGNATURE']))} "
          f"SIGNATURE len={len(bytes.fromhex(vector['SIGNATURE']))}")

    with serial.Serial(args.port, args.baud, timeout=args.timeout,
                       write_timeout=args.timeout) as port:
        port.reset_input_buffer()
        port.reset_output_buffer()
        time.sleep(0.05)
        port.timeout = 0.2
        while port.read(4096):
            pass
        port.timeout = args.timeout
        port.reset_input_buffer()

        only = args.only
        if only == "" or only == "once":
            test_hash_once(port)
        if only == "" or only == "lmots-verify":
            test_lmots_verify(port, vector)
        if only == "" or only == "lmots-sign":
            test_lmots_sign(port, vector)
        if only == "" or only == "lms-verify":
            test_lms_verify(port, vector)
        if only == "" or only == "lmots-keygen":
            test_lmots_keygen(port, vector)
    return 0


if __name__ == "__main__":
    sys.exit(main())
