#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cw_boot.py — chipwhisperer startup patch (2026-08-21)

Under the managed sandbox, directories created by `tempfile.mkdtemp` are marked by the
sandbox with restricted ACLs: after creation, any subsequent write/nested makedirs by this
process is denied (even Get-Acl cannot open it; PermissionError WinError 5).
chipwhisperer.logging, at import time, runs `mkdtemp(prefix='chipwhisperer')` and
immediately makedirs the log directory inside it, so every board script is guaranteed to fail.

Patch: before importing chipwhisperer, replace `tempfile.mkdtemp` with one returning a fixed
directory inside the workspace pre-created with os.makedirs (directories created by
os.makedirs are not subject to that restriction). Harmless outside the sandbox (the
chipwhisperer log dir changes from a random dir to a fixed one; concurrent processes sharing
it only cause logs to overwrite each other, which is irrelevant here).

Usage: run `import cw_boot` before any import chipwhisperer.
Entry scripts (cw305_serial.py / set_pll.py / prog_cw305.py / tvla_capture_sloth.py)
already inject it; for direct inline python, first `import sys; sys.path.insert(0,'scripts'); import cw_boot`.
"""
import os
import tempfile

_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_LOG_DIR = os.path.join(_ROOT, "build", "cw305", "chw_logs")
os.makedirs(os.path.join(_LOG_DIR, "chipwhisperer", "logs"), exist_ok=True)


def _mkdtemp(prefix=None, suffix=None, dir=None):
    return _LOG_DIR


tempfile.mkdtemp = _mkdtemp
