# LMS RTL Sources

## SHA-256

`lms_sha256_round.v` is adapted from `rtl/sha256_round.v` in the SLotH project:

- Project: SLotH, Accelerating SLH-DSA
- Author: Markku-Juhani O. Saarinen
- Upstream location: https://github.com/slh-dsa/sloth (`rtl/sha256_round.v`)
- Upstream license: BSD 3-Clause, reproduced in `LICENSE.sloth`

The adapted module removes SLotH compile-time configuration dependencies and renames signals and helper functions. Its round function and message schedule semantics are unchanged.

`lms_sha256_core.v` is project-local control logic. It executes one SHA-256 compression block in 64 busy cycles and supports initialization from the SHA-256 IV or continuation from the preceding chaining value. Padding and arbitrary-message scheduling are intentionally outside this core.

`lms_sha256_mmio.v` is the project-local single-core LMS accelerator. It implements the v0.2 register window, padding for bounded `HASH_ONCE`, autonomous RFC 8554 LM-OTS `CHAIN`, fused `DERIVE_CHAIN`, deterministic randomizer derivation, sticky status/error state, capability reporting, and cycle counting.

The v0.2 seed slot is write-only from the test provisioning interface and is not exposed to RV32 RAM or normal read MMIO. Secure KeyGen/Sign requests use a key handle and do not carry SEED; private elements are derived internally and fed directly into CHAIN. The slot is a functional model of the target scheme's secure register, not a claim that ordinary FPGA FFs provide ASIC-grade physical isolation or non-volatility.

The RTL is validated at three boundaries: the SHA-256 compression core, direct register transactions against the MMIO wrapper, and the real C MMIO client driving the Verilated wrapper with software fallback disabled.

`pug_rv32.v`, `pug_rvc.v`, and `pug_muldiv.v` were the original RV32IMC controller
(BSD-3-Clause SLotH) and have been **removed** in the Ibex migration (t6).

The SoC now uses **Ibex** (`rtl/ibex/`), a clean RV32IMC core from lowRISC:
- `ibex_top` is instantiated by `lms_soc.v` with RV32M single-cycle multiply,
  FF register file, no ICache, and no PMP.
- Only the modules actually synthesized are kept under `rtl/ibex/`; unused
  Ibex blocks (icache, lockstep, PMP, tracer, FPGA/latch register files) are
  excluded. `rtl/ibex/prim_*.sv` and `dv_fcov_macros.svh` are minimal stubs
  (no SVA dependency) that are shared by both Verilator and Vivado builds.
- `lms_soc_config.vh` no longer defines the pug-era `CORE_*` switches; Ibex
  features are configured through `ibex_top` parameters.

`uart_tx.v` and `uart_rx.v` are copied from SLotH under the same license. `lms_fpga_ram.v` adapts the upstream dual-port RAM with optional firmware initialization, while `lms_soc.v` is the project-local interconnect for 128 KiB RAM, polling UART/GPIO MMIO, the LMS accelerator at `0x16000000` (bridged through `lms_sha256_mmio_bridge.v`), and the TRNG peripheral at `0x17000000`.

No SLH-DSA ADRS or original SLotH MMIO mapping is included. The LMS-specific Winternitz controller and RFC Appendix A private derivation are project-local logic with software, Verilator, SoC and board-level differential tests.