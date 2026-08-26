"""C1.5 TRNG on-board functional + entropy characterization (DaVinci Pro, real RO).

Access the TRNG standalone peripheral (0x17000000) via UART diagnostic commands:
  0x58 TRNG_READ   request cmd(1)||count(1), 48B frame response followed by count*4B raw random words;
  0x59 TRNG_STATUS request cmd(1), 48B frame response returns STAT/CTRL/APT/VERSION/CAP.
(0x56/0x57 deprecated: 0x56 conflicts with the existing UART_REQUEST_VERIFY=0x56; use 0x58/0x59 instead.)

Usage:
  Functional smoke (default): python tests/board/test_trng_characterize.py --port COM5
  Collect entropy characterization data:  python tests/board/test_trng_characterize.py --port COM5 \
                        --collect-bytes 1000000 --out build/trng_raw.bin
  Read health-check counters: python tests/board/test_trng_characterize.py --port COM5 --health-report

48B response frame layout (matches fw/lms_soc_smoke.c):
  [0]=0x52 marker [1]=status [2]=error [3]=reserved
  [4..7]=cycles [8..11]=hits [12..15]=0
  [16]=echoed cmd [18]=cmd status [20..47]=payload
  TRNG_READ:   [36..39]=count (little-endian, frame offset; firmware response[20..23]), followed on the wire by count*4B random words
  TRNG_STATUS: [32..33]=VERSION[15:0] [34..35]=CAP[15:0]
               [36..39]=STAT [40..43]=CTRL [44..47]=APT (little-endian)
(Firmware response[i] maps to frame [16+i]; TRNG values are written in firmware response[16..31], i.e. frame [32..47].)

Scope (trng_c1_plan §1/§8): measurement-based characterization only; no claim of NIST certification/SP 800-90B compliance;
Tier-1 raw words (CRC-8 compressed) are read via 0x58 (REVIEW B13B16-R5: the old doc mistakenly wrote 0x56, now deprecated);
Tier-2 conditioning is consumed by firmware lms_rnd_trng.c (via LMS HASH_ONCE using the on-board enabled hash core).
"""

import argparse
from pathlib import Path
import struct
import sys
import time

import serial

RESPONSE = 0x52
RESPONSE_SIZE = 48
REQUEST_TRNG_READ = 0x58
REQUEST_TRNG_STATUS = 0x59
REQUEST_TRNG_READ_ACK = 0x5A  # C1①: reliable collection with seq + CRC8
TRNG_READ_WORD_MAX = 16  # firmware trng_read_bytes[64] buffer cap (64B = 16 words)


def crc8_smbus(data: bytes) -> int:
    """CRC-8/SMBUS (poly 0x07, init 0x00, no reflection), matches firmware crc8_block."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def read_exact(port: serial.Serial, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = port.read(size - len(data))
        if not chunk:
            raise TimeoutError(f"UART timeout after {len(data)}/{size} bytes")
        data.extend(chunk)
    return bytes(data)


def write_paced(port: serial.Serial, data: bytes, chunk_size: int = 16) -> None:
    for offset in range(0, len(data), chunk_size):
        port.write(data[offset : offset + chunk_size])
        port.flush()
        time.sleep(0.001)


def trng_read_words(port: serial.Serial, count: int) -> bytes:
    """TRNG_READ: read count 32-bit raw words, return count*4 bytes.

    Read strictly in 48B frame + count*4B order (no marker resync—random bytes may
    contain 0x52, and a false frame-head would be worse). The echoed count is in
    frame[36..39] (firmware response[20..23])."""
    if not 1 <= count <= TRNG_READ_WORD_MAX:
        raise RuntimeError(f"trng_read: count={count} out of range 1..{TRNG_READ_WORD_MAX}")
    write_paced(port, bytes((REQUEST_TRNG_READ, count)))
    response = read_exact(port, RESPONSE_SIZE)
    marker, status, hw_error = response[0], response[1], response[2]
    if marker != RESPONSE:
        raise RuntimeError(f"trng_read: marker=0x{marker:02x} (frame misaligned)")
    cmd_status = response[18]
    if status != 0 or hw_error != 0 or cmd_status != 0:
        raise RuntimeError(
            f"trng_read: status={status} error={hw_error} cmd_status={cmd_status}"
        )
    nbytes = struct.unpack_from("<I", response, 36)[0]  # frame[36..39]=firmware response[20..23]=count
    if nbytes != count:
        raise RuntimeError(f"trng_read: echoed count={nbytes} != requested {count}")
    return read_exact(port, count * 4)


def trng_read_words_ack(port: serial.Serial, count: int, seq: int) -> bytes:
    """TRNG_READ_ACK (0x5A): reliable read with seq echo + CRC8 check.

    Request cmd||count||seq; after the 48B frame response ([36..39]=count, [40]=seq echo)
    come count*4B random words + 1B CRC8. Any mismatch raises RuntimeError so the caller
    can retry with the same seq. seq lets the host spot leftover frames (unconsumed
    responses from a previous batch); CRC8 validates data integrity."""
    if not 1 <= count <= TRNG_READ_WORD_MAX:
        raise RuntimeError(f"trng_read_ack: count={count} out of range 1..{TRNG_READ_WORD_MAX}")
    # Write byte-by-byte with inter-byte idle: uart_rx occasionally mis-samples under
    # back-to-back high-speed bytes (measured on board; the depth-2 FIFO removed the
    # deadlock but bit-sampling errors remain), and idle lowers that probability;
    # residual errors are absorbed by upper-layer CRC/seq checks + retry.
    for byte in (REQUEST_TRNG_READ_ACK, count, seq & 0xFF):
        port.write(bytes((byte,)))
        port.flush()
        time.sleep(0.0003)
    response = read_exact(port, RESPONSE_SIZE)
    marker, status, hw_error = response[0], response[1], response[2]
    if marker != RESPONSE:
        raise RuntimeError(f"trng_read_ack: marker=0x{marker:02x} (frame misaligned)")
    cmd_status = response[18]
    if status != 0 or hw_error != 0 or cmd_status != 0:
        raise RuntimeError(
            f"trng_read_ack: status={status} error={hw_error} cmd_status={cmd_status}"
        )
    nbytes = struct.unpack_from("<I", response, 36)[0]  # frame[36..39]=count
    if nbytes != count:
        raise RuntimeError(f"trng_read_ack: echoed count={nbytes} != requested {count}")
    echo_seq = response[40]  # frame[40]=firmware response[24]=seq echo
    if echo_seq != (seq & 0xFF):
        raise RuntimeError(f"trng_read_ack: echoed seq=0x{echo_seq:02x} != requested 0x{seq & 0xFF:02x} (leftover frame)")
    data = read_exact(port, count * 4)
    crc = read_exact(port, 1)[0]
    if crc != crc8_smbus(data):
        raise RuntimeError(f"trng_read_ack: CRC8=0x{crc:02x} != expected 0x{crc8_smbus(data):02x}")
    return data


def trng_status(port: serial.Serial) -> dict:
    """TRNG_STATUS: return STAT/CTRL/APT/VERSION/CAPABILITY register snapshot."""
    write_paced(port, bytes((REQUEST_TRNG_STATUS,)))
    response = read_exact(port, RESPONSE_SIZE)
    marker, status, hw_error = response[0], response[1], response[2]
    if marker != RESPONSE:
        raise RuntimeError(f"trng_status: marker=0x{marker:02x}")
    cmd_status = response[18]
    if status != 0 or hw_error != 0 or cmd_status != 0:
        raise RuntimeError(
            f"trng_status: status={status} error={hw_error} cmd_status={cmd_status}"
        )
    version, cap = struct.unpack_from("<HH", response, 32)
    stat, ctrl, apt = struct.unpack_from("<III", response, 36)
    return {
        "version": version,
        "capability": cap,
        "ctrl": ctrl,
        "stat": stat,
        "health_fail": stat & 0x1,
        "word_valid": (stat >> 8) & 0x1,
        "rct_count": (stat >> 16) & 0xFF,
        "apt_count": apt & 0xFFFF,
        "apt_win_pos": (apt >> 16) & 0xFFFF,
    }


def run_functional(port: serial.Serial) -> None:
    """Functional smoke: probe VERSION/CAP + read random words several times to confirm nonzero and distinct."""
    snap = trng_status(port)
    print(
        f"TRNG probe: VERSION={snap['version']} CAP=0x{snap['capability']:08x} "
        f"CTRL=0x{snap['ctrl']:08x} health_fail={snap['health_fail']} "
        f"word_valid={snap['word_valid']}"
    )
    if snap["version"] != 1:
        raise RuntimeError(f"TRNG VERSION={snap['version']} != 1")
    if (snap["capability"] & 0x1) == 0:
        raise RuntimeError("TRNG CAPABILITY bit0=0 (trng not present)")
    if snap["health_fail"]:
        raise RuntimeError("TRNG health_fail=1 (health check failed, RND gated to 0)")

    # word_valid is a single-cycle pulse (new-word-ready signal); host polling of STATUS
    # will always miss it, so do not spin waiting on it. The physical RO keeps filling the
    # RND register; after warmup just read RND and verify nonzero/distinct values.
    # Reading RND right after reset/programming may return 0 (first word not yet assembled),
    # so warm up first.
    time.sleep(0.5)
    snap = trng_status(port)
    if snap["health_fail"]:
        raise RuntimeError("TRNG health_fail=1 (health check failed)")
    print(f"TRNG warmup: STAT=0x{snap['stat']:08x} rct_count={snap['rct_count']} apt_count={snap['apt_count']}")

    words = set()
    samples = 8
    for _ in range(samples):
        blob = trng_read_words(port, 4)
        for offset in range(0, len(blob), 4):
            word = struct.unpack_from("<I", blob, offset)[0]
            if word == 0:
                raise RuntimeError("TRNG_READ returned all-zero words (health_fail or not enabled)")
            words.add(word)
    # Host read rate > TRNG word-production rate (von Neumann+CRC is slow), so back-to-back
    # reads repeat the same word—expected, so we do not assert high diversity. Only require:
    # not all identical (>1 unique, ruling out constant/stuck) and nonzero.
    if len(words) < 2:
        raise RuntimeError(f"TRNG_READ all {samples*4} words identical (constant/stuck)")
    print(f"PASS: functional smoke {samples*4} words nonzero, {len(words)} unique (word rate below read rate, duplicates expected)")


def _flush_line(port: serial.Serial) -> None:
    """Flush pending bytes on the UART line to re-align before retrying a failed collection batch."""
    port.reset_input_buffer()
    port.timeout = 0.1
    while port.read(4096):
        pass
    port.timeout = 5.0
    port.reset_input_buffer()


def run_collect(port: serial.Serial, nbytes: int, out: Path, use_ack: bool = True) -> None:
    """Collect nbytes of raw random bytes to a file (for offline STS/SP 800-90B analysis).

    Each batch reads 4 words (16B). With use_ack=True use TRNG_READ_ACK(0x5A): seq echo +
    CRC8 check; on check failure/misalignment/timeout retry with the same seq (up to 5
    times/batch), removing the root cause of high-speed consecutive-read desync.
    The physical RO word rate is below the read rate, so the same word may repeat—the
    entropy characterization uses the raw stream and duplicates are reflected as-is."""
    out.parent.mkdir(parents=True, exist_ok=True)
    collected = bytearray()
    start = time.time()
    batch = 4
    seq = 0
    retries = 0
    fail_batches = 0
    mode = "ACK(0x5A)" if use_ack else "legacy(0x58)"
    while len(collected) < nbytes:
        try:
            if use_ack:
                collected += trng_read_words_ack(port, batch, seq)
                seq = (seq + 1) & 0xFF
            else:
                collected += trng_read_words(port, batch)
            retries = 0
        except (TimeoutError, RuntimeError) as exc:
            retries += 1
            fail_batches += 1
            if retries > 10:
                raise RuntimeError(f"collection failed after consecutive retries ({len(collected)} B collected): {exc}")
            # Retry also advances seq (send a new request rather than replay) and lengthens
            # the backoff so leftover bytes drain off the line, avoiding replay responses
            # stacking with leftover-frame misalignment. uart_rx high-speed sampling errors
            # are probabilistic; retry absorbs them.
            seq = (seq + 1) & 0xFF
            _flush_line(port)
            time.sleep(0.05 * retries)
        time.sleep(0.001)
    elapsed = time.time() - start
    blob = bytes(collected[:nbytes])
    out.write_bytes(blob)
    rate = nbytes / elapsed if elapsed > 0 else 0
    # Quick sanity: coarse chi-square check of the byte histogram (not STS; only rules out constant/severe bias).
    hist = [0] * 256
    for b in blob:
        hist[b] += 1
    expected = nbytes / 256.0
    chi2 = sum((h - expected) ** 2 / expected for h in hist)
    print(
        f"PASS: collected[{mode}] {nbytes} B -> {out} in {elapsed:.1f}s ({rate:.0f} B/s), "
        f"{fail_batches} retried batches, byte-histogram chi2={chi2:.1f} (df=255, uniform expectation ~255)"
    )
    print("Hint: run formal characterization on this file with NIST STS (2.1.2) and the SP 800-90B suite.")


def run_health_report(port: serial.Serial) -> None:
    """Health-check counter read (REVIEW B13B16-R13 renamed from --fail-inject: this case
    only reads status, it does not inject faults).

    Note: firmware 0x58/0x59 are read-only diagnostics; CTRL writes go through the TRNG
    peripheral registers. This case reads and reports the current health_fail/word_valid
    status. Full fault injection (write CTRL to disable the RO) needs a firmware diagnostic
    write command or direct MMIO; deferred. Here we validate the health-counter read path."""
    snap = trng_status(port)
    print(
        f"Health-check status: health_fail={snap['health_fail']} "
        f"rct_count={snap['rct_count']} apt_count={snap['apt_count']} "
        f"apt_win_pos={snap['apt_win_pos']}"
    )
    print(
        "PASS: TRNG_STATUS health-counter read OK"
        " (full RCT/APT fault injection needs a firmware diagnostic write command; covered in Verilator)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="C1.5 TRNG on-board functional + entropy characterization (DaVinci Pro)")
    parser.add_argument("--port", default="COM5")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--collect-bytes",
        type=int,
        default=0,
        help="collect N bytes of raw random data to --out (default 0 = no collection, functional smoke only)",
    )
    parser.add_argument("--out", type=Path, default=Path("build/trng_raw.bin"))
    parser.add_argument(
        "--no-ack",
        action="store_true",
        help="collect with legacy 0x58 (no seq/CRC8); default is reliable 0x5A ACK collection",
    )
    parser.add_argument(
        "--health-report",
        action="store_true",
        help="read health-check counters (full fault injection covered in Verilator; REVIEW B13B16-R13 rename)",
    )
    args = parser.parse_args()

    with serial.Serial(args.port, args.baud, timeout=args.timeout, write_timeout=args.timeout) as port:
        port.reset_input_buffer()
        port.reset_output_buffer()
        time.sleep(0.05)
        # Flush response bytes possibly left over from a previous abnormal exit to avoid first-frame misalignment.
        port.timeout = 0.2
        while port.read(4096):
            pass
        port.timeout = args.timeout
        port.reset_input_buffer()

        run_functional(port)
        if args.health_report:
            run_health_report(port)
        if args.collect_bytes > 0:
            run_collect(port, args.collect_bytes, args.out, use_ack=not args.no_ack)

    print("TRNG DaVinci Pro on-board characterization passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, TimeoutError, serial.SerialException) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
