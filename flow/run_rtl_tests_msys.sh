#!/usr/bin/env bash
# flow/run_rtl_tests_msys.sh - Run the Verilator RTL test suite under MSYS2.
#
# Under MSYS2 installed at "C:\Program Files\msys64", Verilator writes
# VERILATOR_ROOT into its generated makefiles as a Windows path containing spaces
# (C:/Program Files/...), which breaks make's path handling and confuses the MSYS
# python invoked as verilator_includer. This script:
#   1. exports a space-free (8.3 short-path) VERILATOR_ROOT for the verilator run;
#   2. rewrites the generated Vlms_*.mk / Vsim_*.mk VERILATOR_ROOT to the MSYS-style
#      path /c/PROGRA~1/msys64/... so the g++/python steps resolve correctly;
#   3. points PYTHON3 at the MSYS python (which understands MSYS paths).
#
# Usage (repo root, inside an MSYS2 shell):
#   bash flow/run_rtl_tests_msys.sh [target ...]
#   bash flow/run_rtl_tests_msys.sh test-rtl-sha256 test-rtl-keccak-core
# No args: run every test-rtl-* target.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="/mingw64/bin:/usr/bin:/bin:$PATH"
# Ensure a writable temp dir (MSYS2 /tmp may map into an unwritable Program Files path).
if [ -n "${USERPROFILE:-}" ] && [ -d "$USERPROFILE/AppData/Local/Temp" ]; then
  export TMP="$(cygpath -u "$USERPROFILE/AppData/Local/Temp")"
  export TEMP="$TMP"
elif [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
  export TMP="$HOME"
  export TEMP="$HOME"
fi
LOG="$HOME/lms_rtl_make.log"

if ! command -v verilator >/dev/null 2>&1; then
  echo "ERROR: verilator not found. Install: pacman -S mingw-w64-x86_64-verilator" >&2
  exit 1
fi
VERILATOR_BIN="$(command -v verilator)"
VERILATOR_DIR="$(dirname "$VERILATOR_BIN")"
# Space-free short root for the verilator run itself.
SHORT_ROOT="$(cygpath -s "$VERILATOR_DIR/.." 2>/dev/null || echo "$VERILATOR_DIR/..")"
export VERILATOR_ROOT="${SHORT_ROOT}/share/verilator"
# MSYS-style root for rewriting the generated makefiles.
MSYS_ROOT="$(cygpath -u "$VERILATOR_DIR/.." 2>/dev/null)/share/verilator"
MSYS_PYTHON="$(command -v python3 || command -v python)"

echo "Verilator: $("$VERILATOR_BIN" --version | head -1)"
echo "VERILATOR_ROOT (short): $VERILATOR_ROOT"
echo "MSYS root (rewrite):    $MSYS_ROOT"
echo "PYTHON3: $MSYS_PYTHON"

rewrite_mks() {
  find build -name 'Vlms_*.mk' -o -name 'Vsim_*.mk' 2>/dev/null | while read -r mkf; do
    if grep -q 'VERILATOR_ROOT = ' "$mkf"; then
      sed -i "s|^VERILATOR_ROOT = .*|VERILATOR_ROOT = $MSYS_ROOT|" "$mkf"
    fi
  done
}

run_target() {
  local tgt="$1"
  echo ""
  echo "===== $tgt ====="
  # 1. Run verilator (generates the model + Vlms_*.mk) via make -n semantics:
  #    run the raw verilator step by invoking make with the target but stop before
  #    the C++ build, rewrite the mk, then build the exe manually.
  # Simpler: run make once (verilator + C++), then fix the mk and rebuild the exe.
  # The first make's C++ step may fail on the un-fixed root; ignore and fix.
  set +e
  TMP="$TMP" TEMP="$TEMP" make "$tgt" RTL_PYTHON3="$MSYS_PYTHON" >"$LOG" 2>&1
  local rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    # Verilator step may have succeeded while the C++ build failed on the path.
    # Rewrite the mk and retry the generated-make build if the model exists.
    if find build -name 'Vlms_*.mk' -o -name 'Vsim_*.mk' 2>/dev/null | grep -q .; then
      rewrite_mks
      local mkf bdir exe
      mkf="$(find build -name 'Vlms_*.mk' -o -name 'Vsim_*.mk' 2>/dev/null | head -1)"
      bdir="$(dirname "$mkf")"
      exe="$(grep -m1 '^default: ' "$mkf" | sed 's/default: //')"
      echo "retrying generated build: make -C $bdir -f $(basename "$mkf") $exe"
      (cd "$bdir" && TMP="$TMP" TEMP="$TEMP" make -f "$(basename "$mkf")" PYTHON3="$MSYS_PYTHON" "$exe" && "./$exe")
      return $?
    fi
    echo "ERROR: $tgt failed (see "$LOG")" >&2
    cat "$LOG" >&2
    return $rc
  fi
  # Success on first pass; run the test binary if the target is a run target.
  return 0
}

if [ $# -eq 0 ]; then
  TARGETS="$(make -qp 2>/dev/null | grep -oE '^test-rtl-[a-z0-9-]+:' | sed 's/:$//' | sort -u || true)"
  echo "Running all RTL targets:"
  echo "$TARGETS"
  FAILED=0
  for t in $TARGETS; do
    run_target "$t" || FAILED=$((FAILED+1))
  done
  [ "$FAILED" -eq 0 ] || { echo "$FAILED target(s) failed" >&2; exit 1; }
else
  for t in "$@"; do
    run_target "$t" || exit 1
  done
fi

echo ""
echo "All requested RTL tests completed."
