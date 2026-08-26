CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -O2
CPPFLAGS ?= -Iinclude -Ihashs
# Header dependency (REVIEW B01B02-R13): targets previously listed only source files, so editing a .h did not trigger rebuilds.
HDRS = $(wildcard include/*.h src/*.h hashs/*.h hashs/xkcp/*.h fw/*.h)
VERILATOR ?= verilator
VERILATOR_ROOT ?=
RTL_PYTHON3 ?= python3
BOARD_PYTHON ?= python3
BOARD_PORT ?= COM5
BOARD_HASH ?= shake256
VIVADO ?= vivado
RISCV_PREFIX ?= riscv64-unknown-elf-

# Under Windows(MSYS), -GFIRMWARE_HEX must be given a Windows-readable path: MSYS make's $(abspath)
# returns /e/... style paths, and once env.ps1's MSYS2_ARG_CONV_EXCL='*' is in effect (so the official verilator
# wrapper command name is not converted to a verilator_bin.exe backslash path), MSYS no longer converts paths
# automatically, so cygpath -m is used to explicitly convert to E:/... for verilator_bin to read the firmware. Other platforms use MSYS paths (the wrapper converts them itself).
ifeq ($(OS),Windows_NT)
FIRMWARE_HEX_ARG := -GFIRMWARE_HEX=\"$(shell cygpath -m $(abspath build/lms_soc_smoke/firmware.hex))\"
FIRMWARE_HEX_ARG_BENCH := -GFIRMWARE_HEX=\"$(shell cygpath -m $(abspath build/lms_soc_bench/firmware_bench.hex))\"
else
FIRMWARE_HEX_ARG := -GFIRMWARE_HEX=\"$(abspath build/lms_soc_smoke/firmware.hex)\"
FIRMWARE_HEX_ARG_BENCH := -GFIRMWARE_HEX=\"$(abspath build/lms_soc_bench/firmware_bench.hex)\"
endif

# DEPLOY switch (P1-6, 0.1.274): DEPLOY=1 switches to the deploy scope in one shot —
#   INSECURE_TEST_MODE=0 (RTL: plaintext SEED_LOAD(arg_key=0) rejected; K_WRAP/K_STATE
#   staging retained for prototype sim-PUF loading; SEED staging bus writes inside SEC
#   left open — command-layer rejection preserved, see the note in rtl/lms_sha256_sec.v 0.1.281)
#   + SEC_TEST=0 (firmware: INJECT_TAG/FACTORY_INIT rejected, BOOT recovers SEED
#   via wrapped→UNWRAP)
#   + RND_IMPL defaults to trng (0.1.281 model B: in deployment, I/C/SEED are all generated on-site by the in-device TRNG;
#   an explicit user RND_IMPL= overrides, as the ?= before LMS_RND_SRC evaluation below respects the command-line value).
# Default 0 = research-prototype test configuration (zero regressions at present).
# Note: this block must come before SEC_TEST's FW_SEC_TEST_FLAGS is evaluated (make takes values in parse order),
# and also before RND_IMPL's LMS_RND_SRC is evaluated (otherwise the deploy default trng does not take effect).
DEPLOY ?= 0
INSECURE_TEST_MODE ?= 1
ifeq ($(DEPLOY),1)
SEC_TEST = 0
INSECURE_TEST_MODE = 0
RND_IMPL ?= trng
endif

# Random-source implementation switch (C1.3): det (default, deterministic derivation, KAT/regression) / stub / trng (real TRNG, SoC firmware only).
# With DEPLOY=1 the default above is trng; other builds default to det.
RND_IMPL ?= det
ifeq ($(RND_IMPL),trng)
LMS_RND_SRC = fw/lms_rnd_trng.c
LMS_RND_CFLAGS = -DLMS_RND_IMPL_TRNG
else ifeq ($(RND_IMPL),stub)
LMS_RND_SRC = fw/lms_rnd_stub.c
LMS_RND_CFLAGS =
else
LMS_RND_SRC = fw/lms_rnd_det.c
LMS_RND_CFLAGS =
endif

# SoC firmware segmentation profile (LMS_MMIO_SOC_PROFILE macro): enabled with FW_PROFILE=1, off by default (not in official builds).
FW_PROFILE ?= 0
ifeq ($(FW_PROFILE),1)
FW_PROFILE_FLAGS = -DLMS_MMIO_SOC_PROFILE
else
FW_PROFILE_FLAGS =
endif

# Pure-software baseline (LMS_FW_NO_HW_ACCEL macro): with NO_HW_ACCEL=1 the firmware registers no hardware backend
# and depends on neither MMIO nor accelerators (algorithms fully in software), serving as the paper's same-platform speedup baseline (zero RTL changes).
# Note: same class of cache trap as HASH_IMPL — toggling NO_HW_ACCEL does not trigger a rebuild;
# you must manually clean build/lms_soc_smoke and rebuild.
NO_HW_ACCEL ?= 0
ifeq ($(NO_HW_ACCEL),1)
FW_NO_HW_ACCEL_FLAGS = -DLMS_FW_NO_HW_ACCEL
else
FW_NO_HW_ACCEL_FLAGS =
endif

# Pure-software baseline with authentication-path tree caching disabled (LMS_FW_NO_TREE_CACHE): with NO_TREE_CACHE=1 the pure-software
# firmware does not enable the lms_subtree cache (Sign recomputes the authentication path recursively per signature, KeyGen builds the tree fully in software),
# matching the literature (Cortex-M4 without cache) under the same methodology. Default 0 (cache enabled, the paper's primary scope).
NO_TREE_CACHE ?= 0
ifeq ($(NO_TREE_CACHE),1)
FW_NO_TREE_CACHE_FLAGS = -DLMS_FW_NO_TREE_CACHE
else
FW_NO_TREE_CACHE_FLAGS =
endif

# TVLA lightweight mitigation (scheme B, 2026-08-19): with RANDOM_DELAY=1 the firmware inserts a
# TRNG random wait (LMS_TVLA_RANDOM_DELAY) before the 0x6D DERIVE, breaking the phase alignment of a single PRF relative to the trigger edge →
# single-point t is diluted. Only for TVLA mitigation evaluation; zero impact on normal builds.
RANDOM_DELAY ?= 0
ifeq ($(RANDOM_DELAY),1)
FW_RANDOM_DELAY_FLAGS = -DLMS_TVLA_RANDOM_DELAY
else
FW_RANDOM_DELAY_FLAGS =
endif
# DERIVE_SHUFFLE ?= 0 — added 2026-08-25: previously there was no default definition, which shifted the impl-cw305 tclargs
# positional string (DERIVE_SHUFFLE mistakenly got ALLOW_XQ_DERIVE's value 1, ALLOW_XQ_DERIVE mistakenly got
# -notrace). Test targets (-GDERIVE_SHUFFLE=1) pass arguments explicitly and are unaffected.
DERIVE_SHUFFLE ?= 0

# Secure-domain test backdoor (LMS_FW_SEC_TEST_MODE, 0.1.269 H4): SEC_TEST=1 (default) keeps
# test-only subcommands such as SEC_SUB_INJECT_TAG (relied on by Verilator/board fault injection); SEC_TEST=0
# is the deploy scope, where the firmware is compiled without / rejects these subcommands (narrowing the UART attack surface).
SEC_TEST ?= 1
ifeq ($(SEC_TEST),1)
FW_SEC_TEST_FLAGS = -DLMS_FW_SEC_TEST_MODE
else
FW_SEC_TEST_FLAGS =
endif

# Hash core build options (flexible build version, 2026-08-06):
#   HASH_IMPL = comma-separated list of hash primitives, e.g. sha256,shake256.
#   Adding a new hash later only requires appending to the list; no changes to existing logic.
#   HAS_SECURITY = 1 (default; includes WRAP/UNWRAP/HMAC/MC) or 0 (pure LMS algorithm hardware).
# Mapped to the independent ENABLE_* parameters of the SoC-top lms_hash_mmio thin shell.
HASH_IMPL ?= sha256
ENABLE_SHA256   = $(if $(findstring sha256,$(HASH_IMPL)),1,0)
ENABLE_SHAKE256 = $(if $(findstring shake256,$(HASH_IMPL)),1,0)
HASH_ARGS = -GENABLE_SHA256=$(ENABLE_SHA256) -GENABLE_SHAKE256=$(ENABLE_SHAKE256)

HAS_SECURITY ?= 1
HAS_SEC_ARGS = -GHAS_SECURITY=$(HAS_SECURITY)

# SCA trigger (TVLA side-channel evaluation only, 2026-08-17): with SCA_TEST=1 the CW305 top level outputs
# sca_trigger (T14, 20-pin tio_trigger). Default 0 — deploy/normal builds have no trigger interface
# (memory.md §12 red line: test interfaces can be compiled out).
SCA_TEST ?= 0

# ALLOW_XQ_DERIVE (2026-08-25): TVLA isolation of a single x_q[i] (allows DERIVE_CHAIN steps=0,
# side-channel SEED-leakage characterization fix).
# Default 0 = deploy keeps the M3 gate; only TVLA builds (with SCA_TEST=1/INSECURE_TEST_MODE=1) set it to 1.
ALLOW_XQ_DERIVE ?= 0

# Hash expectations of the SoC tests and the fixed-vector generator (only a pure-SHAKE256 build switches to SHAKE256;
# under both/the default sha256, SoC tests and vectors stay on the SHA-256 scope).
SOC_TEST_HASH_DEF =
VEC_SHAKE_DEF =
VEC_TYPE_ARGS =
ifeq ($(ENABLE_SHA256),0)
ifeq ($(ENABLE_SHAKE256),1)
SOC_TEST_HASH_DEF = -DFW_HASH_SHAKE256
VEC_SHAKE_DEF = -DLMS_VECTOR_SHAKE256
VEC_TYPE_ARGS = --lms=21 --lmots=19   # SHAKE256 W4/H5 (generator defaults to the same; passed explicitly to prevent drift)
endif
else
VEC_TYPE_ARGS = --lms=5 --lmots=3     # SHA-256 W4/H5 (generator default is SHAKE; must be overridden explicitly)
endif
LMS_SRCS = src/lms.c src/lms_params.c src/lm_ots.c src/lms_tree.c src/lms_sign.c src/lms_verify.c src/hash_api.c src/lms_coprocess.c hashs/sha256.c hashs/fips202.c hashs/haraka.c
HSS_SRCS = src/hss.c $(LMS_SRCS)

.PHONY: all test bench-authpath test-rtl-sha256 test-rtl-sha256-blockgen test-rtl-sha256-engine test-rtl-keccak-core test-rtl-shake256-mmio test-rtl-shake256-batch test-rtl-shake256-batch-shuffle test-rtl-hash-mmio test-rtl-hash-mmio-shake test-rtl-hash-mmio-both test-rtl-sha256-mmio test-rtl-sha256-batch test-rtl-sha256-sec test-rtl-lms-mmio-client test-rtl-lms-mmio-bridge test-rtl-uart-bridge test-rtl-cw305-bridge test-rtl-cw305-soc-bridge test-rtl-trng-mmio test-rtl-lms-soc test-rtl-lms-soc-deploy test-board-uart synth-rtl-sha256 synth-rtl-sha256-mmio synth-rtl-lms-mmio-bridge impl-davinci-pro program-davinci-pro impl-cw305 demo clean

all: build/test_lms build/test_lms_mmio build/test_lms_coprocess build/test_lms_subtree build/test_hashes build/test_hss build/test_lms_rnd build/lms_demo

build:
	mkdir -p build

build/lms_demo: $(LMS_SRCS) $(HDRS) fw/lms_main.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ fw/lms_main.c $(LMS_SRCS)

build/test_lms: $(LMS_SRCS) $(HDRS) tests/test_lms.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tests/test_lms.c $(LMS_SRCS)

build/test_lms_mmio: $(LMS_SRCS) $(HDRS) src/lms_mmio.c src/lms_mmio.h tests/test_lms_mmio.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o $@ tests/test_lms_mmio.c src/lms_mmio.c $(LMS_SRCS)

build/test_lms_coprocess: $(LMS_SRCS) $(HDRS) src/lms_mmio.c src/lms_mmio.h tests/test_lms_coprocess.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o $@ tests/test_lms_coprocess.c src/lms_mmio.c $(LMS_SRCS)

build/test_lms_subtree: $(LMS_SRCS) $(HDRS) src/lms_subtree.c src/lms_subtree.h tests/test_lms_subtree.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o $@ tests/test_lms_subtree.c src/lms_subtree.c $(LMS_SRCS)

# Design doc step 6a: Sign authentication-path performance benchmark (baseline recursion vs lms_subtree cache). Not in make test.

build/test_hashes: src/hash_api.c $(HDRS) hashs/sha256.c hashs/fips202.c hashs/haraka.c tests/test_hashes.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tests/test_hashes.c src/hash_api.c hashs/sha256.c hashs/fips202.c hashs/haraka.c

# XKCP 32-bit adapter cross-validation (REVIEW B04-R3): same KAT as test_hashes, SHAKE via
# hashs/xkcp (-DLMS_HASH_XKCP_32BI) - covers the gap where FW_HASH_XKCP is not in the closed loop by default.
build/test_hashes_xkcp: src/hash_api.c $(HDRS) hashs/sha256.c hashs/haraka.c hashs/xkcp/KeccakP-1600-inplace32BI.c hashs/xkcp/xkcp_shake.c tests/test_hashes.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -DLMS_HASH_XKCP_32BI -Ihashs/xkcp -o $@ tests/test_hashes.c src/hash_api.c hashs/sha256.c hashs/haraka.c hashs/xkcp/KeccakP-1600-inplace32BI.c hashs/xkcp/xkcp_shake.c

# t8 multi-parameter-set PC smoke test (REVIEW B13B16-R14 wired into the Makefile; previously an orphan manually compiled target).
# Full-matrix pure-software correctness (including the W8 soft chain); takes a while, not part of the default make test set.
build/multiparam_smoke: $(LMS_SRCS) src/lms_subtree.c $(HDRS) tests/multiparam_smoke.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o $@ tests/multiparam_smoke.c src/lms_subtree.c $(LMS_SRCS)

build/test_hss: $(HSS_SRCS) $(HDRS) tests/test_hss.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tests/test_hss.c $(HSS_SRCS)

build/test_lms_rnd: tests/test_lms_rnd.c $(HDRS) fw/lms_rnd_det.c hashs/sha256.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -Ifw -o $@ tests/test_lms_rnd.c fw/lms_rnd_det.c hashs/sha256.c

build/generate_lms_verify_vector.exe: $(LMS_SRCS) $(HDRS) tests/generate_lms_verify_vector.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) $(VEC_SHAKE_DEF) -o $@ tests/generate_lms_verify_vector.c $(LMS_SRCS)

# Vectors must pick their type explicitly per HASH_IMPL (the generator defaults to the SHAKE256 scope; SHA-256 unit tests/SoC
# reading the wrong scope get a wrong oracle -> LMOTS_SIGN/VERIFY false FAILs). FORCE ensures the vectors rebuild after switching HASH_IMPL
# (make does not notice parameter changes when the exe is unchanged); content comparison avoids needless downstream relinking.
build/lms_verify_vector.txt: build/generate_lms_verify_vector.exe FORCE
	./build/generate_lms_verify_vector.exe $(VEC_TYPE_ARGS) > $@.tmp && (cmp -s $@.tmp $@ || mv -f $@.tmp $@); rm -f $@.tmp
build/rtl_sha256/test_sha256_rtl.exe: rtl/lms_sha256_round.v rtl/lms_sha256_core.v tests/rtl/test_sha256_core.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_sha256_core \
		-Mdir build/rtl_sha256 -CFLAGS "-std=c++17" -o test_sha256_rtl.exe \
		tests/rtl/test_sha256_core.cpp rtl/lms_sha256_round.v rtl/lms_sha256_core.v
	$(MAKE) -C build/rtl_sha256 -f Vlms_sha256_core.mk \
		PYTHON3="$(RTL_PYTHON3)" test_sha256_rtl.exe

build/rtl_sha256_blockgen/test_sha256_blockgen_rtl.exe: rtl/lms_sha256_blockgen.v tests/rtl/test_sha256_blockgen.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_sha256_blockgen \
		-Mdir build/rtl_sha256_blockgen -CFLAGS "-std=c++17" -o test_sha256_blockgen_rtl.exe \
		tests/rtl/test_sha256_blockgen.cpp rtl/lms_sha256_blockgen.v
	$(MAKE) -C build/rtl_sha256_blockgen -f Vlms_sha256_blockgen.mk \
		PYTHON3="$(RTL_PYTHON3)" test_sha256_blockgen_rtl.exe

build/rtl_sha256_engine/test_sha256_engine_rtl.exe: rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v tests/rtl/test_sha256_engine.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_hash_engine -GHASH_TYPE=0 \
		-Mdir build/rtl_sha256_engine -CFLAGS "-std=c++17" -o test_sha256_engine_rtl.exe \
		tests/rtl/test_sha256_engine.cpp rtl/lms_sha256_round.v rtl/lms_sha256_core.v \
		rtl/lms_keccak_round.v rtl/lms_keccak_core.v rtl/lms_sha256_blockgen.v \
		rtl/lms_shake256_blockgen.v rtl/lms_hash_engine.v
	$(MAKE) -C build/rtl_sha256_engine -f Vlms_hash_engine.mk \
		PYTHON3="$(RTL_PYTHON3)" test_sha256_engine_rtl.exe

build/rtl_keccak/test_keccak_core_rtl.exe: rtl/lms_keccak_core.v rtl/lms_keccak_round.v tests/rtl/test_keccak_core.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_keccak_core \
		-Mdir build/rtl_keccak -CFLAGS "-std=c++17" -o test_keccak_core_rtl.exe \
		tests/rtl/test_keccak_core.cpp rtl/lms_keccak_core.v rtl/lms_keccak_round.v
	$(MAKE) -C build/rtl_keccak -f Vlms_keccak_core.mk \
		PYTHON3="$(RTL_PYTHON3)" test_keccak_core_rtl.exe

build/rtl_shake256_mmio/test_shake256_mmio_rtl.exe: rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_shake256_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_shake256_blockgen.v rtl/lms_sha256_sec.v tests/rtl/test_shake256_mmio.cpp $(HASSEC_STAMP) | build
	$(VERILATOR) -Wall --cc --trace --exe --top-module lms_shake256_mmio -GINSECURE_TEST_MODE=1 $(HAS_SEC_ARGS) \
		-Mdir build/rtl_shake256_mmio -CFLAGS "-std=c++17" -o test_shake256_mmio_rtl.exe \
		tests/rtl/test_shake256_mmio.cpp rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_shake256_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_shake256_blockgen.v rtl/lms_sha256_sec.v
	$(MAKE) -C build/rtl_shake256_mmio -f Vlms_shake256_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_shake256_mmio_rtl.exe

build/rtl_shake256_batch/test_shake256_batch_rtl.exe: rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_shake256_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_shake256_blockgen.v rtl/lms_sha256_sec.v tests/rtl/test_shake256_batch.cpp $(HASSEC_STAMP) | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_shake256_mmio -GINSECURE_TEST_MODE=1 $(HAS_SEC_ARGS) \
		-Mdir build/rtl_shake256_batch -CFLAGS "-std=c++17" -o test_shake256_batch_rtl.exe \
		tests/rtl/test_shake256_batch.cpp rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_shake256_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_shake256_blockgen.v rtl/lms_sha256_sec.v
	$(MAKE) -C build/rtl_shake256_batch -f Vlms_shake256_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_shake256_batch_rtl.exe

# DERIVE_SHUFFLE=1 (DERIVE phase shuffling, TVLA lightweight protection) functional verification:
# values oracle all pass; SIGN cycle assertion relaxed to WARN (shuffling moves the 0-step chain position -> bounded jitter in the folding cadence).
build/rtl_shake256_batch_shuffle/test_shake256_batch_rtl.exe: rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_shake256_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_shake256_blockgen.v rtl/lms_sha256_sec.v tests/rtl/test_shake256_batch.cpp $(HASSEC_STAMP) | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_shake256_mmio -GINSECURE_TEST_MODE=1 $(HAS_SEC_ARGS) -GDERIVE_SHUFFLE=1 \
		-Mdir build/rtl_shake256_batch_shuffle -CFLAGS "-std=c++17 -DDERIVE_SHUFFLE_TEST=1" -o test_shake256_batch_rtl.exe \
		tests/rtl/test_shake256_batch.cpp rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_shake256_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_shake256_blockgen.v rtl/lms_sha256_sec.v
	$(MAKE) -C build/rtl_shake256_batch_shuffle -f Vlms_shake256_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_shake256_batch_rtl.exe

test-rtl-shake256-batch-shuffle: build/rtl_shake256_batch_shuffle/test_shake256_batch_rtl.exe
	./build/rtl_shake256_batch_shuffle/test_shake256_batch_rtl.exe

# Top-level thin shell lms_hash_mmio test: three modes - sha256 only / shake256 only / both
HASH_MMIO_RTL = rtl/lms_hash_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v

build/rtl_hash_mmio/test_hash_mmio_rtl.exe: $(HASH_MMIO_RTL) tests/rtl/test_hash_mmio.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_hash_mmio -GENABLE_SHA256=1 -GENABLE_SHAKE256=0 -GHAS_SECURITY=1 -GINSECURE_TEST_MODE=1 \
		-Mdir build/rtl_hash_mmio -CFLAGS "-std=c++17 -DHASH_SEL_TEST=0" -o test_hash_mmio_rtl.exe \
		tests/rtl/test_hash_mmio.cpp $(HASH_MMIO_RTL)
	$(MAKE) -C build/rtl_hash_mmio -f Vlms_hash_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_hash_mmio_rtl.exe

build/rtl_hash_mmio_shake/test_hash_mmio_rtl.exe: $(HASH_MMIO_RTL) tests/rtl/test_hash_mmio.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_hash_mmio -GENABLE_SHA256=0 -GENABLE_SHAKE256=1 -GHAS_SECURITY=0 -GINSECURE_TEST_MODE=1 \
		-Mdir build/rtl_hash_mmio_shake -CFLAGS "-std=c++17 -DHASH_SEL_TEST=1" -o test_hash_mmio_rtl.exe \
		tests/rtl/test_hash_mmio.cpp $(HASH_MMIO_RTL)
	$(MAKE) -C build/rtl_hash_mmio_shake -f Vlms_hash_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_hash_mmio_rtl.exe

build/rtl_hash_mmio_both/test_hash_mmio_rtl.exe: $(HASH_MMIO_RTL) tests/rtl/test_hash_mmio.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_hash_mmio -GENABLE_SHA256=1 -GENABLE_SHAKE256=1 -GHAS_SECURITY=1 -GINSECURE_TEST_MODE=1 \
		-Mdir build/rtl_hash_mmio_both -CFLAGS "-std=c++17 -DHASH_SEL_TEST=2" -o test_hash_mmio_rtl.exe \
		tests/rtl/test_hash_mmio.cpp $(HASH_MMIO_RTL)
	$(MAKE) -C build/rtl_hash_mmio_both -f Vlms_hash_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_hash_mmio_rtl.exe

build/rtl_sha256_mmio/test_sha256_mmio_rtl.exe: rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v tests/rtl/test_sha256_mmio.cpp $(HASSEC_STAMP) build/lms_verify_vector.txt | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_sha256_mmio -GINSECURE_TEST_MODE=1 $(HAS_SEC_ARGS) \
		-Mdir build/rtl_sha256_mmio -CFLAGS "-std=c++17" -o test_sha256_mmio_rtl.exe \
		tests/rtl/test_sha256_mmio.cpp rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v
	$(MAKE) -C build/rtl_sha256_mmio -f Vlms_sha256_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_sha256_mmio_rtl.exe

build/rtl_sha256_sec/test_lms_sha256_sec_rtl.exe: rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_sec.v tests/rtl/lms_sha256_sec_testtop.v tests/rtl/test_lms_sha256_sec.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_sha256_sec_testtop -GINSECURE_TEST_MODE=1 \
		-Mdir build/rtl_sha256_sec -CFLAGS "-std=c++17" -o test_lms_sha256_sec_rtl.exe \
		tests/rtl/test_lms_sha256_sec.cpp rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_sec.v tests/rtl/lms_sha256_sec_testtop.v
	$(MAKE) -C build/rtl_sha256_sec -f Vlms_sha256_sec_testtop.mk \
		PYTHON3="$(RTL_PYTHON3)" test_lms_sha256_sec_rtl.exe

build/rtl_sha256_batch/test_sha256_batch_rtl.exe: rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v tests/rtl/test_sha256_batch.cpp $(HASSEC_STAMP) | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_sha256_mmio -GINSECURE_TEST_MODE=1 $(HAS_SEC_ARGS) \
		-Mdir build/rtl_sha256_batch -CFLAGS "-std=c++17" -o test_sha256_batch_rtl.exe \
		tests/rtl/test_sha256_batch.cpp rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v
	$(MAKE) -C build/rtl_sha256_batch -f Vlms_sha256_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_sha256_batch_rtl.exe

build/rtl_sha256_mmio_client/lms_mmio.o: src/lms_mmio.c src/lms_mmio.h src/lms_internal.h | build
	mkdir -p build/rtl_sha256_mmio_client
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -c -o $@ src/lms_mmio.c

build/rtl_sha256_mmio_client/lms_params.o: src/lms_params.c src/lms_internal.h | build
	mkdir -p build/rtl_sha256_mmio_client
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -c -o $@ src/lms_params.c

build/rtl_sha256_mmio_client/sha256.o: hashs/sha256.c hashs/sha256.h | build
	mkdir -p build/rtl_sha256_mmio_client
	$(CC) $(CFLAGS) $(CPPFLAGS) -Ihashs -c -o $@ hashs/sha256.c

build/rtl_sha256_mmio_client/test_lms_mmio_client_rtl.exe: rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v tests/rtl/test_lms_mmio_client.cpp $(HASSEC_STAMP) build/rtl_sha256_mmio_client/lms_mmio.o build/rtl_sha256_mmio_client/lms_params.o build/rtl_sha256_mmio_client/sha256.o | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_sha256_mmio -GINSECURE_TEST_MODE=1 $(HAS_SEC_ARGS) \
		-Mdir build/rtl_sha256_mmio_client \
		-CFLAGS "-std=c++17 -I$(shell cygpath -m $(abspath include)) -I$(shell cygpath -m $(abspath src))" \
		-LDFLAGS "lms_mmio.o lms_params.o sha256.o" -o test_lms_mmio_client_rtl.exe \
		tests/rtl/test_lms_mmio_client.cpp rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v
	$(MAKE) -C build/rtl_sha256_mmio_client -f Vlms_sha256_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_lms_mmio_client_rtl.exe

build/rtl_lms_mmio_bridge/test_lms_mmio_bridge_rtl.exe: rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_sha256_mmio_bridge.v rtl/lms_hash_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v tests/rtl/test_lms_sha256_mmio_bridge.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_sha256_mmio_bridge \
		-Mdir build/rtl_lms_mmio_bridge -CFLAGS "-std=c++17" \
		-o test_lms_mmio_bridge_rtl.exe tests/rtl/test_lms_sha256_mmio_bridge.cpp \
		rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_mmio.v rtl/lms_sha256_sec.v rtl/lms_sha256_mmio_bridge.v rtl/lms_hash_mmio.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v
	$(MAKE) -C build/rtl_lms_mmio_bridge -f Vlms_sha256_mmio_bridge.mk \
		PYTHON3="$(RTL_PYTHON3)" test_lms_mmio_bridge_rtl.exe

build/rtl_trng_mmio/test_trng_mmio_rtl.exe: rtl/lms_trng.v rtl/lms_trng_mmio.v tests/rtl/test_trng_mmio.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_trng_mmio -GSIM_MODE=1 \
		-Mdir build/rtl_trng_mmio -CFLAGS "-std=c++17" -o test_trng_mmio_rtl.exe \
		tests/rtl/test_trng_mmio.cpp rtl/lms_trng.v rtl/lms_trng_mmio.v
	$(MAKE) -C build/rtl_trng_mmio -f Vlms_trng_mmio.mk \
		PYTHON3="$(RTL_PYTHON3)" test_trng_mmio_rtl.exe

# REVIEW G-M4 fix: the TRNG boundary regression previously had only a build target and no run target (dead target).
test-rtl-trng-mmio: build/rtl_trng_mmio/test_trng_mmio_rtl.exe
	./build/rtl_trng_mmio/test_trng_mmio_rtl.exe


test: build/test_lms build/test_lms_mmio build/test_lms_coprocess build/test_lms_subtree build/test_hashes build/test_hashes_xkcp build/test_hss build/test_lms_rnd
	./build/test_lms
	./build/test_lms_mmio
	./build/test_lms_coprocess
	./build/test_lms_subtree
	./build/test_hashes
	./build/test_hashes_xkcp
	./build/test_hss
	./build/test_lms_rnd

build/bench_lms_authpath: $(LMS_SRCS) src/lms_subtree.c src/lms_subtree.h tests/bench_lms_authpath.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o $@ tests/bench_lms_authpath.c src/lms_subtree.c $(LMS_SRCS)

bench-authpath: build/bench_lms_authpath
	./build/bench_lms_authpath

test-rtl-sha256: build/rtl_sha256/test_sha256_rtl.exe
	./build/rtl_sha256/test_sha256_rtl.exe

test-rtl-sha256-blockgen: build/rtl_sha256_blockgen/test_sha256_blockgen_rtl.exe
	./build/rtl_sha256_blockgen/test_sha256_blockgen_rtl.exe

test-rtl-sha256-engine: build/rtl_sha256_engine/test_sha256_engine_rtl.exe
	./build/rtl_sha256_engine/test_sha256_engine_rtl.exe

test-rtl-keccak-core: build/rtl_keccak/test_keccak_core_rtl.exe
	./build/rtl_keccak/test_keccak_core_rtl.exe

test-rtl-shake256-mmio: build/rtl_shake256_mmio/test_shake256_mmio_rtl.exe
	./build/rtl_shake256_mmio/test_shake256_mmio_rtl.exe

test-rtl-shake256-batch: build/rtl_shake256_batch/test_shake256_batch_rtl.exe
	./build/rtl_shake256_batch/test_shake256_batch_rtl.exe

build/rtl_uart_bridge/test_uart_bridge_rtl.exe: rtl/lms_uart_bridge.v tests/rtl/test_uart_bridge.cpp | build
	$(VERILATOR) -Wall --cc --exe --top-module lms_uart_bridge \
		-Mdir build/rtl_uart_bridge -CFLAGS "-std=c++17" -o test_uart_bridge_rtl.exe \
		tests/rtl/test_uart_bridge.cpp rtl/lms_uart_bridge.v
	$(MAKE) -C build/rtl_uart_bridge -f Vlms_uart_bridge.mk \
		PYTHON3="$(RTL_PYTHON3)" test_uart_bridge_rtl.exe

test-rtl-uart-bridge: build/rtl_uart_bridge/test_uart_bridge_rtl.exe
	./build/rtl_uart_bridge/test_uart_bridge_rtl.exe

build/rtl_cw305_bridge/test_cw305_bridge_rtl.exe: rtl/lms_cw305_afifo.v rtl/lms_cw305_usb_uart.v rtl/uart_tx.v rtl/uart_rx.v tests/rtl/test_cw305_bridge.cpp | build
	$(VERILATOR) -Wall --Wno-fatal --cc --exe --trace --top-module lms_cw305_usb_uart \
		-Mdir build/rtl_cw305_bridge -CFLAGS "-std=c++17 -DCW305_TRACE -DTEST_BITCLKS=64" -Irtl \
		-GUART_BITCLKS=64 -o test_cw305_bridge_rtl.exe \
		tests/rtl/test_cw305_bridge.cpp rtl/lms_cw305_afifo.v rtl/lms_cw305_usb_uart.v rtl/uart_tx.v rtl/uart_rx.v
	$(MAKE) -C build/rtl_cw305_bridge -f Vlms_cw305_usb_uart.mk \
		PYTHON3="$(RTL_PYTHON3)" test_cw305_bridge_rtl.exe

test-rtl-cw305-bridge: build/rtl_cw305_bridge/test_cw305_bridge_rtl.exe
	./build/rtl_cw305_bridge/test_cw305_bridge_rtl.exe

build/rtl_cw305_soc_bridge/test_cw305_soc_bridge_rtl.exe: tests/rtl/sim_cw305_soc_bridge.v tests/rtl/test_cw305_soc_bridge.cpp rtl/lms_cw305_usb_uart.v rtl/lms_cw305_afifo.v rtl/lms_cw305_regs.vh $(IBEX_SRCS) $(IBEX_STUBS) rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v build/lms_soc_smoke/firmware.hex | build
	$(VERILATOR) -Wall --Wno-fatal -Irtl -Irtl/ibex --cc --exe --public --top-module sim_cw305_soc_bridge \
		$(FIRMWARE_HEX_ARG) \
		-GINSECURE_TEST_MODE=1 -GTRNG_SIM_MODE=1 -GUART_BITCLKS=434 \
		-GENABLE_SHA256=0 -GENABLE_SHAKE256=1 -GHAS_SECURITY=1 -GSCA_TEST=1 \
		-Mdir build/rtl_cw305_soc_bridge -CFLAGS "-std=c++17" -o test_cw305_soc_bridge_rtl.exe \
		tests/rtl/test_cw305_soc_bridge.cpp tests/rtl/sim_cw305_soc_bridge.v \
		$(IBEX_SRCS) $(IBEX_STUBS) \
		rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v \
		rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v \
		rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v \
		rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v \
		rtl/lms_cw305_usb_uart.v rtl/lms_cw305_afifo.v
	$(MAKE) -C build/rtl_cw305_soc_bridge -f Vsim_cw305_soc_bridge.mk \
		PYTHON3="$(RTL_PYTHON3)" test_cw305_soc_bridge_rtl.exe

test-rtl-cw305-soc-bridge: build/rtl_cw305_soc_bridge/test_cw305_soc_bridge_rtl.exe
	./build/rtl_cw305_soc_bridge/test_cw305_soc_bridge_rtl.exe

test-rtl-hash-mmio: build/rtl_hash_mmio/test_hash_mmio_rtl.exe
	./build/rtl_hash_mmio/test_hash_mmio_rtl.exe

test-rtl-hash-mmio-shake: build/rtl_hash_mmio_shake/test_hash_mmio_rtl.exe
	./build/rtl_hash_mmio_shake/test_hash_mmio_rtl.exe

test-rtl-hash-mmio-both: build/rtl_hash_mmio_both/test_hash_mmio_rtl.exe
	./build/rtl_hash_mmio_both/test_hash_mmio_rtl.exe

test-rtl-sha256-mmio: build/rtl_sha256_mmio/test_sha256_mmio_rtl.exe build/lms_verify_vector.txt
	./build/rtl_sha256_mmio/test_sha256_mmio_rtl.exe

test-rtl-sha256-batch: build/rtl_sha256_batch/test_sha256_batch_rtl.exe
	./build/rtl_sha256_batch/test_sha256_batch_rtl.exe

test-rtl-sha256-sec: build/rtl_sha256_sec/test_lms_sha256_sec_rtl.exe
	./build/rtl_sha256_sec/test_lms_sha256_sec_rtl.exe

test-rtl-lms-mmio-client: build/rtl_sha256_mmio_client/test_lms_mmio_client_rtl.exe build/lms_verify_vector.txt
	./build/rtl_sha256_mmio_client/test_lms_mmio_client_rtl.exe

test-rtl-lms-mmio-bridge: build/rtl_lms_mmio_bridge/test_lms_mmio_bridge_rtl.exe
	./build/rtl_lms_mmio_bridge/test_lms_mmio_bridge_rtl.exe

test-rtl-lms-soc: build/rtl_lms_soc/test_lms_soc_rtl.exe
	./build/rtl_lms_soc/test_lms_soc_rtl.exe

# P1-6 (0.1.274) deploy-scope SoC regression: INSECURE_TEST_MODE=0 + SEC_TEST=0 firmware,
# separate objdir + separate hex copy (to avoid confusion with the test configuration's Verilate cache/shared hex).
# Prerequisite: first run test-rtl-lms-soc (test configuration) to produce build/deploy_blob.bin (wrapped-blob
# capture, the deploy regression input; if missing, deploy cases exit with an error).
# firmware_deploy.hex is an explicit target (depends on firmware sources+stamp): right after the deploy sub-build, the
# test-configuration hex is restored, so the shared hex is not polluted into the test exe.
build/rtl_lms_soc_deploy/firmware_deploy.hex: fw/lms_soc_start.S fw/lms_soc_smoke.c fw/lms_sec_state.c fw/lms_main.c $(LMS_SOC_VERIFY_SRCS) fw/lms_soc.ld $(FW_FLAGS_STAMP) | build
	mkdir -p build/rtl_lms_soc_deploy
	$(MAKE) build/lms_soc_smoke/firmware.hex DEPLOY=1
	cp build/lms_soc_smoke/firmware.hex $@
	$(MAKE) build/lms_soc_smoke/firmware.hex

build/rtl_lms_soc_deploy/test_lms_soc_rtl_deploy.exe: rtl/lms_soc_config.vh $(IBEX_SRCS) $(IBEX_STUBS) rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v tests/rtl/test_lms_soc.cpp $(HASSEC_STAMP) build/rtl_lms_soc_deploy/firmware_deploy.hex build/lms_verify_vector.txt | build
	$(VERILATOR) -Wall --Wno-fatal -Irtl -Irtl/ibex --cc --exe --public --trace --top-module lms_soc \
		$(HASH_ARGS) $(HAS_SEC_ARGS) $(SOC_TEST_HASH_DEF) \
		-GFIRMWARE_HEX=\"$(shell cygpath -m $(abspath build/rtl_lms_soc_deploy/firmware_deploy.hex))\" \
		-GINSECURE_TEST_MODE=0 -GTRNG_SIM_MODE=1 \
		-Mdir build/rtl_lms_soc_deploy -CFLAGS "-std=c++17 $(SOC_TEST_HASH_DEF)" -o test_lms_soc_rtl_deploy.exe \
		tests/rtl/test_lms_soc.cpp $(IBEX_SRCS) $(IBEX_STUBS) \
		rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v \
		rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v \
		rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v \
		rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v
	$(MAKE) -C build/rtl_lms_soc_deploy -f Vlms_soc.mk \
		PYTHON3="$(RTL_PYTHON3)" test_lms_soc_rtl_deploy.exe

test-rtl-lms-soc-deploy: build/rtl_lms_soc_deploy/test_lms_soc_rtl_deploy.exe
	./build/rtl_lms_soc_deploy/test_lms_soc_rtl_deploy.exe --deploy

test-board-uart: build/lms_verify_vector.txt
	$(BOARD_PYTHON) tests/board/test_lms_uart.py --port $(BOARD_PORT) --hash $(BOARD_HASH)

# Firmware hash build options (aligned with RTL-side HASH_IMPL / HAS_SECURITY)
FW_HASH_FLAGS =
FW_HASH_SRCS = hashs/sha256.c
ifeq ($(ENABLE_SHA256),1)
FW_HASH_FLAGS += -DFW_HASH_SHA256
endif
ifeq ($(ENABLE_SHAKE256),1)
FW_HASH_FLAGS += -DFW_HASH_SHAKE256
# REVIEW B04-R4: the firmware does not use Haraka at runtime (SoC typecodes are SHA256/SHAKE256 only),
# so haraka.c is no longer linked (saves ~2KB .bss/.rodata); hash_api drops the branch via LMS_NO_HARAKA.
FW_HASH_FLAGS += -DLMS_NO_HARAKA
FW_HASH_SRCS += hashs/fips202.c
endif
# SHAKE256 requires non-SHA256_ONLY mode (allows FIPS202/Haraka parameter sets)
ifneq ($(ENABLE_SHAKE256),1)
FW_HASH_FLAGS += -DLMS_SHA256_ONLY
endif

# Software SHAKE256 uses XKCP inplace32BI (32-bit-lane Keccak, an accelerated alternative for RV32 without 64-bit instructions):
# with FW_HASH_XKCP=1, hash_shake256 in hash_api.c goes through xkcp_shake256 (XKCP CC0 license).
FW_HASH_XKCP ?= 0
ifeq ($(FW_HASH_XKCP),1)
FW_HASH_FLAGS += -DLMS_HASH_XKCP_32BI
FW_HASH_SRCS += hashs/xkcp/KeccakP-1600-inplace32BI.c hashs/xkcp/xkcp_shake.c
endif

LMS_SOC_VERIFY_SRCS = \
	fw/lms_soc_runtime.c \
	$(LMS_RND_SRC) \
	fw/lms_sec_state.c \
	src/lms.c src/lms_params.c src/lm_ots.c src/lms_tree.c src/lms_sign.c src/lms_verify.c \
	src/hash_api.c src/lms_mmio.c src/lms_subtree.c $(FW_HASH_SRCS)

FORCE:

# Firmware build-macro stamp (fixed after 0.1.269, re-fixed 2026-08-15): switching HASH_IMPL/NO_HW_ACCEL/SEC_TEST etc.
# does not touch source files, so a firmware.elf depending only on sources creates the same class of "SHA-256 engine + SHAKE firmware"
# cache trap (the firmware-side twin of the 0.1.268 DEAD root cause). All macros are written into the stamp file and listed as a dependency: macro change →
# stamp update → forced rebuild.
# Note: the stamp target must be FORCE (an ordinary target with no prerequisites never re-runs its recipe once the file exists;
# the 0.1.269 version only took effect on first creation — switching HASH_IMPL no longer triggered a rebuild, and the 2026-08-15 synthesis again produced
# a "SHAKE engine + SHA-256 firmware" DEAD bitstream). cmp ensures mtime is untouched when macros are unchanged, avoiding spurious rebuilds.
FW_FLAGS_STAMP = build/lms_soc_smoke/.fwflags
$(FW_FLAGS_STAMP): FORCE | build
	mkdir -p build/lms_soc_smoke
	@echo '$(CPPFLAGS) $(FW_HASH_FLAGS) $(LMS_RND_CFLAGS) $(LMS_RND_SRC) $(FW_PROFILE_FLAGS) $(FW_NO_HW_ACCEL_FLAGS) $(FW_NO_TREE_CACHE_FLAGS) $(FW_SEC_TEST_FLAGS) $(FW_RANDOM_DELAY_FLAGS)' > $@.tmp && (cmp -s $@.tmp $@ || mv -f $@.tmp $@); rm -f $@.tmp

# HAS_SECURITY macro stamp (REVIEW B01B02-R14): RTL test targets carrying $(HAS_SEC_ARGS) previously did not
# re-Verilate on macro switch (HAS_SECURITY 1<->0) -> stale-configuration test binaries misled results. Same
# FORCE+cmp mechanism as .fwflags; mtime is touched only when the content changes.
HASSEC_STAMP = build/.hassec_flags
$(HASSEC_STAMP): FORCE | build
	@echo '$(HAS_SEC_ARGS)' > $@.tmp && (cmp -s $@.tmp $@ || mv -f $@.tmp $@); rm -f $@.tmp

build/lms_soc_smoke/firmware.elf: fw/lms_soc_start.S fw/lms_soc_smoke.c $(LMS_SOC_VERIFY_SRCS) $(HDRS) fw/lms_soc.ld $(FW_FLAGS_STAMP) | build
	mkdir -p build/lms_soc_smoke
	$(RISCV_PREFIX)gcc -march=rv32imc -mabi=ilp32 -O2 -Wall -Wextra \
		$(CPPFLAGS) -Isrc -Ifw $(FW_HASH_FLAGS) $(LMS_RND_CFLAGS) $(FW_PROFILE_FLAGS) $(FW_NO_HW_ACCEL_FLAGS) $(FW_NO_TREE_CACHE_FLAGS) $(FW_SEC_TEST_FLAGS) $(FW_RANDOM_DELAY_FLAGS) -ffreestanding -fno-builtin \
		-ffunction-sections -fdata-sections -nostdlib -nostartfiles -msmall-data-limit=0 \
		-Wl,-T,fw/lms_soc.ld,--gc-sections,--no-relax \
		-o $@ fw/lms_soc_start.S fw/lms_soc_smoke.c $(LMS_SOC_VERIFY_SRCS) -lgcc

build/lms_soc_smoke/firmware.bin: build/lms_soc_smoke/firmware.elf
	$(RISCV_PREFIX)objcopy -O binary $< $@

build/lms_soc_smoke/firmware.hex: build/lms_soc_smoke/firmware.bin
	$(RTL_PYTHON3) -c "import struct; data=bytearray(open('$<','rb').read()); data.extend(b'\0' * (-len(data) % 4)); words=[struct.unpack_from('<I',data,i)[0] for i in range(0,len(data),4)]; pad=['00000013']*32; open('$@','w',newline='\n').write('\n'.join(pad+[f'{word:08x}' for word in words])+'\n')"

IBEX_SRCS = \
	rtl/ibex/ibex_pkg.sv \
	rtl/ibex/ibex_alu.sv \
	rtl/ibex/ibex_compressed_decoder.sv \
	rtl/ibex/ibex_controller.sv \
	rtl/ibex/ibex_counter.sv \
	rtl/ibex/ibex_cs_registers.sv \
	rtl/ibex/ibex_csr.sv \
	rtl/ibex/ibex_decoder.sv \
	rtl/ibex/ibex_dummy_instr.sv \
	rtl/ibex/ibex_ex_block.sv \
	rtl/ibex/ibex_fetch_fifo.sv \
	rtl/ibex/ibex_id_stage.sv \
	rtl/ibex/ibex_if_stage.sv \
	rtl/ibex/ibex_load_store_unit.sv \
	rtl/ibex/ibex_multdiv_slow.sv \
	rtl/ibex/ibex_multdiv_fast.sv \
	rtl/ibex/ibex_prefetch_buffer.sv \
	rtl/ibex/ibex_register_file_ff.sv \
	rtl/ibex/ibex_branch_predict.sv \
	rtl/ibex/ibex_wb_stage.sv \
	rtl/ibex/ibex_core.sv \
	rtl/ibex/ibex_top.sv

IBEX_STUBS = \
	rtl/ibex/prim_assert.sv \
	rtl/ibex/prim_ram_1p_pkg.sv \
	rtl/ibex/prim_secded_pkg.sv \
	rtl/ibex/prim_clock_gating.sv \
	rtl/ibex/prim_buf.sv \
	rtl/ibex/prim_flop.sv

synth-rtl-sha256:
	$(VIVADO) -mode batch -source flow/synth_sha256_core.tcl -notrace

synth-rtl-sha256-mmio:
	$(VIVADO) -mode batch -source flow/synth_sha256_mmio.tcl -notrace

synth-rtl-lms-mmio-bridge:
	$(VIVADO) -mode batch -source flow/synth_lms_mmio_bridge.tcl -notrace

impl-davinci-pro: build/lms_soc_smoke/firmware.hex
	$(VIVADO) -mode batch -source flow/impl_lms_davinci_pro.tcl -tclargs $(HAS_SECURITY) $(ENABLE_SHA256) $(ENABLE_SHAKE256) $(INSECURE_TEST_MODE) -notrace

program-davinci-pro:
	$(VIVADO) -mode batch -source flow/program_lms_davinci_pro.tcl -notrace

# ===== CW305 port targets (2026-08-18, independent of DaVinci, do not overwrite each other) =====
# Usage: make impl-cw305 VIVADO="<vivado.bat>" HASH_IMPL=shake256 HAS_SECURITY=1 ...
# SCA_TEST=1: enables the SCA trigger output (T14, TVLA side-channel evaluation only; default 0 = deploy/normal builds have no trigger interface).
impl-cw305: build/lms_soc_smoke/firmware.hex
	$(VIVADO) -mode batch -source flow/impl_lms_cw305.tcl -tclargs $(HAS_SECURITY) $(ENABLE_SHA256) $(ENABLE_SHAKE256) $(INSECURE_TEST_MODE) $(SCA_TEST) $(RANDOM_DELAY) $(DERIVE_SHUFFLE) $(ALLOW_XQ_DERIVE) -notrace

# ===== Classical algorithm benchmarks (RSA-2048 / ECDSA P-256, mbedTLS 2.28.9, same-platform comparison for the paper) =====
# Purpose: cycles benchmark of RSA/ECDSA on the Ibex RV32IMC soft core (same-scope comparison with LMS hardware/pure software).
# mbedTLS is an external dependency (Apache-2.0 OR GPL-2.0-or-later; this project adopts it under Apache-2.0, see NOTICE).
# Point MBEDTLS_DIR at a local mbedtls-2.28.9 checkout, e.g. make bench-native MBEDTLS_DIR=/path/to/mbedtls-2.28.9
# Note -I. must be kept: the config include name starts with bench/ (bench/mbedtls_lms_config.h),
# only -I. can resolve it (-Ibench would become bench/bench/...); bench_crypto.h goes via -Ibench.
MBEDTLS_DIR ?= mbedtls-2.28.9
MBEDTLS_INC = -I$(MBEDTLS_DIR)/include
# Use the -include shim to set MBEDTLS_CONFIG_FILE (not -D with quotes: under MSYS2_ARG_CONV_EXCL='*'
# the \" escaping fails -> the macro value carries a backslash -> #include cannot find the config)
MBEDTLS_CFG = -include bench/mbedtls_cfg_file.h
MBEDTLS_LIB_SRCS = \
	$(MBEDTLS_DIR)/library/bignum.c \
	$(MBEDTLS_DIR)/library/rsa.c \
	$(MBEDTLS_DIR)/library/rsa_internal.c \
	$(MBEDTLS_DIR)/library/ecp.c \
	$(MBEDTLS_DIR)/library/ecp_curves.c \
	$(MBEDTLS_DIR)/library/ecdsa.c \
	$(MBEDTLS_DIR)/library/hmac_drbg.c \
	$(MBEDTLS_DIR)/library/md.c \
	$(MBEDTLS_DIR)/library/sha256.c \
	$(MBEDTLS_DIR)/library/pk.c \
	$(MBEDTLS_DIR)/library/pk_wrap.c \
	$(MBEDTLS_DIR)/library/pkparse.c \
	$(MBEDTLS_DIR)/library/asn1parse.c \
	$(MBEDTLS_DIR)/library/asn1write.c \
	$(MBEDTLS_DIR)/library/oid.c \
	$(MBEDTLS_DIR)/library/pem.c \
	$(MBEDTLS_DIR)/library/base64.c \
	$(MBEDTLS_DIR)/library/constant_time.c \
	$(MBEDTLS_DIR)/library/platform.c \
	$(MBEDTLS_DIR)/library/platform_util.c
BENCH_SRCS = bench/bench_crypto.c
BENCH_HDRS = bench/bench_crypto.h bench/mbedtls_lms_config.h bench/mbedtls_cfg_file.h

# PC self-check (native gcc, BENCH_NATIVE uses libc; validates the mbedTLS trimmed config + RSA/ECDSA correctness)
build/bench_native_check.exe: bench/bench_native_check.c $(BENCH_SRCS) $(BENCH_HDRS) $(MBEDTLS_LIB_SRCS) | build
	$(CC) -std=c99 -Wall -Wextra -O2 -Ibench -I. $(MBEDTLS_INC) $(MBEDTLS_CFG) -DBENCH_NATIVE -o $@ bench/bench_native_check.c $(BENCH_SRCS) $(MBEDTLS_LIB_SRCS)

bench-native: build/bench_native_check.exe
	./build/bench_native_check.exe

# SoC benchmark firmware hex (independent of the LMS firmware; riscv rv32imc -O2 same toolchain; BENCH_NATIVE not defined ->
# uses bench_crypto.c's built-in bare-metal allocator; memcpy/memset/memcmp/strings are provided by fw/lms_soc_runtime.c
# (LMS_RUNTIME_NO_ALLOC skips its malloc/free to avoid duplicate symbols with the allocator))
build/lms_soc_bench/firmware_bench.hex: fw/lms_soc_start.S fw/lms_bench.c fw/lms_soc_runtime.c $(BENCH_SRCS) $(BENCH_HDRS) $(MBEDTLS_LIB_SRCS) fw/lms_soc.ld | build
	mkdir -p build/lms_soc_bench
	$(RISCV_PREFIX)gcc -march=rv32imc -mabi=ilp32 -O2 -Wall -Wextra \
		-Ibench -I. $(MBEDTLS_INC) $(MBEDTLS_CFG) -ffreestanding -fno-builtin \
		-ffunction-sections -fdata-sections -nostdlib -nostartfiles -msmall-data-limit=0 \
		-Wl,-T,fw/lms_soc.ld,--gc-sections,--no-relax \
		-o build/lms_soc_bench/firmware_bench.elf fw/lms_soc_start.S fw/lms_bench.c fw/lms_soc_runtime.c \
		-DLMS_RUNTIME_NO_ALLOC $(BENCH_SRCS) $(MBEDTLS_LIB_SRCS) -lgcc
	$(RISCV_PREFIX)objcopy -O binary build/lms_soc_bench/firmware_bench.elf build/lms_soc_bench/firmware_bench.bin
	$(RTL_PYTHON3) -c "import struct; data=bytearray(open('build/lms_soc_bench/firmware_bench.bin','rb').read()); data.extend(b'\0' * (-len(data) % 4)); words=[struct.unpack_from('<I',data,i)[0] for i in range(0,len(data),4)]; pad=['00000013']*32; open('build/lms_soc_bench/firmware_bench.hex','w',newline='\n').write('\n'.join(pad+[f'{word:08x}' for word in words])+'\n')"

bench-fw: build/lms_soc_bench/firmware_bench.hex
	@echo "firmware_bench.hex ready: build/lms_soc_bench/firmware_bench.hex"

# Classic-algorithm benchmark firmware SoC smoke test (Verilator; bench hex; 'S'/'E'/'D' protocol round-trip.
# Correctness is backed by the bench-native PC self-check; this target validates RV32 execution + bare-metal allocator + UART protocol)
build/rtl_bench_soc/test_bench_soc_rtl.exe: rtl/lms_soc_config.vh $(IBEX_SRCS) $(IBEX_STUBS) rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v tests/rtl/test_bench_soc.cpp $(HASSEC_STAMP) build/lms_soc_bench/firmware_bench.hex | build
	$(VERILATOR) -Wall --Wno-fatal -Irtl -Irtl/ibex --cc --exe --public --trace --top-module lms_soc \
		$(HASH_ARGS) $(HAS_SEC_ARGS) $(SOC_TEST_HASH_DEF) \
		-GFIRMWARE_HEX=\"$(shell cygpath -m $(abspath build/lms_soc_bench/firmware_bench.hex))\" \
		-GINSECURE_TEST_MODE=1 -GTRNG_SIM_MODE=1 \
		-Mdir build/rtl_bench_soc -CFLAGS "-std=c++17" -o test_bench_soc_rtl.exe \
		tests/rtl/test_bench_soc.cpp $(IBEX_SRCS) $(IBEX_STUBS) \
		rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v \
		rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v \
		rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v \
		rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v
	$(MAKE) -C build/rtl_bench_soc -f Vlms_soc.mk \
		PYTHON3="$(RTL_PYTHON3)" test_bench_soc_rtl.exe

bench-soc-smoke: build/rtl_bench_soc/test_bench_soc_rtl.exe
	./build/rtl_bench_soc/test_bench_soc_rtl.exe

# Full-chain (including USB<->UART bridge) bench smoke test: reproduces/validates the on-board "command processed twice" artifact
build/rtl_bench_cw305_bridge/test_bench_cw305_bridge_rtl.exe: tests/rtl/sim_cw305_soc_bridge.v tests/rtl/test_bench_cw305_bridge.cpp rtl/lms_cw305_usb_uart.v rtl/lms_cw305_afifo.v rtl/lms_cw305_regs.vh $(IBEX_SRCS) $(IBEX_STUBS) rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v build/lms_soc_bench/firmware_bench.hex | build
	$(VERILATOR) -Wall --Wno-fatal -Irtl -Irtl/ibex --cc --exe --public --top-module sim_cw305_soc_bridge \
		$(FIRMWARE_HEX_ARG_BENCH) \
		-GINSECURE_TEST_MODE=1 -GTRNG_SIM_MODE=1 -GUART_BITCLKS=434 \
		-GENABLE_SHA256=0 -GENABLE_SHAKE256=1 -GHAS_SECURITY=1 -GSCA_TEST=1 \
		-Mdir build/rtl_bench_cw305_bridge -CFLAGS "-std=c++17" -o test_bench_cw305_bridge_rtl.exe \
		tests/rtl/test_bench_cw305_bridge.cpp tests/rtl/sim_cw305_soc_bridge.v \
		$(IBEX_SRCS) $(IBEX_STUBS) \
		rtl/uart_tx.v rtl/uart_rx.v rtl/lms_fpga_ram.v rtl/lms_sha256_round.v \
		rtl/lms_sha256_core.v rtl/lms_sha256_sec.v rtl/lms_trng.v rtl/lms_trng_mmio.v rtl/lms_sha256_mmio.v rtl/lms_sha256_mmio_bridge.v \
		rtl/lms_hash_mmio.v rtl/lms_shake256_mmio.v rtl/lms_keccak_core.v rtl/lms_keccak_round.v rtl/lms_hash_cmd_check.v \
		rtl/lms_hash_engine.v rtl/lms_sha256_blockgen.v rtl/lms_shake256_blockgen.v rtl/lms_uart_bridge.v rtl/lms_soc.v \
		rtl/lms_cw305_usb_uart.v rtl/lms_cw305_afifo.v
	$(MAKE) -C build/rtl_bench_cw305_bridge -f Vsim_cw305_soc_bridge.mk \
		PYTHON3="$(RTL_PYTHON3)" test_bench_cw305_bridge_rtl.exe

bench-bridge-smoke: build/rtl_bench_cw305_bridge/test_bench_cw305_bridge_rtl.exe
	./build/rtl_bench_cw305_bridge/test_bench_cw305_bridge_rtl.exe

demo: build/lms_demo
	./build/lms_demo

clean:
	rm -rf build
	# REVIEW B01B02-R16: also clean up Vivado session leftovers (- prefix: may be held by a running Vivado)
	-rm -rf .Xil vivado*.jou webtalk*.jou vivado*.log webtalk*.log vivado*.backup.jou vivado*.backup.log webtalk*.backup.jou webtalk*.backup.log usage_statistics_webtalk.html usage_statistics_webtalk.xml tight_setup_hold_pins.txt
