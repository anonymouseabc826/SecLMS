#!/usr/bin/env python3
"""SecLMS soft-core classic-algorithm benchmark runner (CW305):
cycles for RSA-2048 / ECDSA P-256 on Ibex RV32IMC (same metric as LMS board tests:
firmware SOC_CYCLE_COUNT counts periods, so cycle values are clock-frequency
independent; ms is reported at the paper's 50 MHz scope, ms = cycles/50e6).
Firmware: fw/lms_bench.c (embedded in bench bit), protocol per that file's header comment.
Signatures are independently verified with Python cryptography (OpenSSL backend) to prove firmware correctness.
Usage:
  python scripts/bench_classic.py --transport cw305
"""
import argparse
import os
import struct
import sys
import time

MBEDTLS_DIR = os.environ.get("MBEDTLS_DIR", "mbedtls-2.28.9")
MBEDTLS_DATA = os.path.join(MBEDTLS_DIR, "tests", "data_files")
CLK_MHZ = 50.0  # paper scope: single 50 MHz SoC clock domain (ms = cycles/50e6)

# Fixed 64B message matching the firmware (bytes 0x00..0x3f)
MSG = bytes(range(64))

RESPONSE = 0x52
CMD_SHA, CMD_RSA_SIGN, CMD_RSA_VERIFY, CMD_EC_SIGN, CMD_EC_VERIFY = 0x53, 0x52, 0x56, 0x45, 0x44


def load_keys():
    from cryptography.hazmat.primitives import serialization
    rsa_priv = serialization.load_pem_private_key(
        open(f"{MBEDTLS_DATA}/rsa_pkcs1_2048_clear.pem", "rb").read(), None)
    ec_priv = serialization.load_pem_private_key(
        open(f"{MBEDTLS_DATA}/ec_256_prv.pem", "rb").read(), None)
    # Public keys derived deterministically from the private keys (mbedTLS test data has no paired pub files)
    return rsa_priv.public_key(), ec_priv.public_key()


def read_exact(port, size, timeout=30.0):
    data = bytearray()
    deadline = time.monotonic() + timeout
    while len(data) < size:
        if time.monotonic() > deadline:
            raise RuntimeError(f"read timeout: got {len(data)}/{size}")
        chunk = port.read(size - len(data))
        if chunk:
            data.extend(chunk)
        else:
            time.sleep(0.01)
    return bytes(data)


def write_paced(port, data, chunk_size=1, sleep_time=0.001):
    for i in range(0, len(data), chunk_size):
        port.write(data[i:i + chunk_size])
        if sleep_time:
            time.sleep(sleep_time)


def run_cmd(port, cmd, payload=b"", read_payload=0, timeout=120.0):
    """Send command+payload, read response frame (marker+status+cycles), then read payload. Returns (status, cycles, payload)."""
    write_paced(port, bytes((cmd,)) + payload)
    head = read_exact(port, 6, timeout=timeout)
    if head[0] != RESPONSE:
        raise RuntimeError(f"marker=0x{head[0]:02x} (expect 0x{RESPONSE:02x})")
    status, cycles = head[1], struct.unpack_from("<I", head, 2)[0]
    body = read_exact(port, read_payload, timeout=timeout) if read_payload else b""
    return status, cycles, body


def bench_all(port):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    rsa_pub, ec_pub = load_keys()
    digest = __import__("hashlib").sha256(MSG).digest()
    rows = []

    # ---- SHA-256 smoke ----
    status, cycles, body = run_cmd(port, CMD_SHA, read_payload=32, timeout=120.0)
    if status != 0 or body != digest:
        raise RuntimeError(f"SHA-256 smoke: status={status} digest_match={body == digest}")
    print(f"PASS: SHA-256(64B) cycles={cycles}")

    # ---- RSA-2048 sign ----
    status, cycles_rsa_s, sig_rsa = run_cmd(port, CMD_RSA_SIGN, read_payload=256, timeout=600.0)
    if status != 0 or len(sig_rsa) != 256:
        raise RuntimeError(f"RSA sign: status={status} len={len(sig_rsa)}")
    rsa_pub.verify(sig_rsa, MSG, padding.PKCS1v15(), hashes.SHA256())
    print(f"PASS: RSA-2048 sign cycles={cycles_rsa_s} (host verify OK)")

    # ---- RSA-2048 verify ----
    status, cycles_rsa_v, _ = run_cmd(port, CMD_RSA_VERIFY, payload=sig_rsa, timeout=600.0)
    if status != 0:
        raise RuntimeError(f"RSA verify: status={status}")
    print(f"PASS: RSA-2048 verify cycles={cycles_rsa_v} (firmware verify OK)")

    # ---- ECDSA P-256 sign ----
    status, cycles_ec_s, body = run_cmd(port, CMD_EC_SIGN, read_payload=1, timeout=600.0)
    if status != 0:
        raise RuntimeError(f"EC sign: status={status}")
    sig_len = body[0]
    sig_ec = read_exact(port, sig_len, timeout=600.0)
    r, s = decode_dss_signature(sig_ec)
    ec_pub.verify(sig_ec, MSG, ec.ECDSA(hashes.SHA256()))
    print(f"PASS: ECDSA P-256 sign cycles={cycles_ec_s} (host verify OK, r/s={r:x}/{s:x})")

    # ---- ECDSA P-256 verify ----
    status, cycles_ec_v, _ = run_cmd(port, CMD_EC_VERIFY, payload=bytes((sig_len,)) + sig_ec, timeout=600.0)
    if status != 0:
        raise RuntimeError(f"EC verify: status={status}")
    print(f"PASS: ECDSA P-256 verify cycles={cycles_ec_v} (firmware verify OK)")

    rows = [
        ("SHA-256 (64B)", cycles),
        ("RSA-2048 sign (PKCS#1 v1.5/SHA-256)", cycles_rsa_s),
        ("RSA-2048 verify", cycles_rsa_v),
        ("ECDSA P-256 sign (det)", cycles_ec_s),
        ("ECDSA P-256 verify", cycles_ec_v),
    ]
    print("\n==== SecLMS soft-core (Ibex RV32IMC) classic-algorithm benchmark ====")
    print(f"{'operation':<38}{'cycles':>14}{'ms @50MHz':>16}")
    for name, cyc in rows:
        print(f"{name:<38}{cyc:>14,}{cyc / (CLK_MHZ * 1e3):>15.2f}")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transport", default="cw305")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--port", default=None, help="DaVinci Pro COM port (legacy platform)")
    args = ap.parse_args()

    if args.transport == "cw305":
        sys.path.insert(0, "scripts")
        from cw305_serial import Cw305Serial  # type: ignore
        port_ctx = Cw305Serial(timeout=args.timeout, write_timeout=args.timeout)
    else:
        import serial
        port_ctx = serial.Serial(args.port, 115200, timeout=args.timeout, write_timeout=args.timeout)

    with port_ctx as port:
        port.reset_input_buffer()
        port.reset_output_buffer()
        time.sleep(0.05)
        port.timeout = 0.2
        while port.read(4096):
            pass
        port.timeout = args.timeout
        bench_all(port)
    print("BENCH CLASSIC PASSED")


if __name__ == "__main__":
    main()
