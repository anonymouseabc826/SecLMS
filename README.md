# SecLMS

SecLMS is a secure hardware–software co-design of the Leighton–Micali Signature (LMS) scheme (RFC 8554) for resource-constrained platforms, implemented on a Xilinx Artix-7 FPGA with an Ibex RV32IMC soft-core processor.

The design addresses two challenges of deploying LMS on constrained devices:

- **Secure signing-state management.** LMS is stateful: the one-time signing key indexed by `q` must never be reused. SecLMS enforces signing-state uniqueness in hardware through an HMAC-authenticated dual-slot state, two monotonic counters, and an atomic reserve–sign–commit signing path. The private seed is protected under PUF-derived wrapping keys and persisted only as an authenticated wrapped blob.
- **Computational efficiency.** The dominant hash workloads (LM-OTS Winternitz chains and Merkle-tree computations) are offloaded to a dedicated hash accelerator with batch task scheduling, dual-core execution, and hardware-assisted input formatting.

## Features

- Full LMS single-tree signing, verification, and key generation; encoding conforms to RFC 8554.
- Two hash backends behind a hash-agnostic accelerator: SHAKE256 and SHA-256.
- Hardware security domain: bus-unreadable key slots, HMAC-authenticated dual-slot state records, monotonic counters, atomic `SEC_SIGN` transaction, fail-closed recovery.
- Bare-metal RV32 firmware orchestrating key generation, tree management, signing, and recovery.
- Reproducible build flow: Verilator simulation, Vivado synthesis/implementation, and board-level tests.

## Directory Layout

- `include/` — public API headers (LMS, HSS, unified hash interface).
- `src/` — LMS/HSS implementation (LM-OTS, parameters, tree, sign, verify, hash API) and the MMIO client.
- `hashs/` — hash implementations (SHA-256, SHAKE256 via FIPS202/XKCP, Haraka).
- `fw/` — RV32 firmware: UART command server, security-state module, random-source abstraction, SoC runtime.
- `rtl/` — RTL: hash cores/engines, LMS MMIO wrappers, security domain, Ibex SoC, board-level shells.
- `flow/` — Verilator and Vivado build/implementation scripts and constraints.
- `tests/` — PC functional/vector tests, Verilator RTL simulations, and board-level UART tests.
- `bench/` — classical-algorithm benchmarks (RSA-2048 / ECDSA P-256 via Mbed TLS) used as the same-platform comparison baseline.
- `scripts/` — board bring-up, performance sweep, and side-channel (TVLA/CPA) measurement/analysis scripts.
- `deploy/` — deployment-scope design notes.

## Build & Test

Toolchain: RISC-V GNU toolchain (rv32imc), Verilator, Vivado 2020.2, Python 3 (for firmware hex generation).

```sh
# PC software regression (LMS/MMIO/hash/HSS/rnd)
make test

# PC demo (LMS/HSS sign/verify command-line demo)
make demo

# Build the SoC firmware (RV32 binary, used by RTL simulation and FPGA bitstreams)
make build/lms_soc_smoke/firmware.hex HASH_IMPL=shake256

# Verilator RTL simulation (individual cores/wrappers and full SoC)
make test-rtl-sha256
make test-rtl-shake256-mmio
make test-rtl-lms-soc HASH_IMPL=shake256 RTL_PYTHON3="<python3 path>"

# FPGA implementation
make impl-cw305 VIVADO="<vivado.bat path>" HASH_IMPL=shake256
make impl-davinci-pro VIVADO="<vivado.bat path>"

# Classical-algorithm benchmarks (requires a local mbedtls-2.28.9 checkout)
make bench-native MBEDTLS_DIR="<path to mbedtls-2.28.9>"
make bench-fw MBEDTLS_DIR="<path to mbedtls-2.28.9>"
```

## Experiments

See [`EXPERIMENTS.md`](EXPERIMENTS.md) for the complete reproduction guide and [`RESULTS.md`](RESULTS.md) for the measurement data
mapping every paper result (performance, resource utilization, TVLA/CPA
side-channel, fault injection, board tests, and the RSA/ECDSA comparison) to
its concrete commands and scripts.

## License

Project code is licensed under the MIT License (see `LICENSE`). Third-party components and their licenses are listed in `NOTICE`; the full text of the Apache-2.0 license (used by the Ibex core) is in `LICENSE.Apache-2.0`.
