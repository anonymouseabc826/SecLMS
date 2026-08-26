#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""husky_diag.py rev2 - Husky stored-error diagnostics (SAM layer + XADC/ADC)

Connect to the Husky and probe error sources item by item:
  1) scope.XADC.status / errors   (voltage/temperature)
  2) scope.adc.errors             (sampling)
  3) scope.sam_errors             (SAM3U layer: serial rx/tx overflow)
  4) scope.sam_led_setting        (LED mode)
  5) attempt to clear: scope.sam_errors.clear() / naeusb.clear_sam_errors()
"""
import os
import sys

_LOG = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "cw305"))
os.makedirs(_LOG, exist_ok=True)
os.environ["TMP"] = _LOG
os.environ["TEMP"] = _LOG


def probe(name, fn):
    try:
        v = fn()
        print("  [%s] %s = %r" % ("OK" if v in (False, None, "good") else "HIT", name, v))
        return v
    except Exception as e:
        print("  [..] %s: %r" % (name, e))
        return None


def main():
    import chipwhisperer as cw
    scope = cw.scope()
    print("scope connected (Husky)")

    print("\n-- XADC / ADC --")
    probe("scope.XADC.status", lambda: getattr(scope.XADC, "status", "?"))
    probe("scope.XADC.errors()", lambda: scope.XADC.errors())
    probe("scope.adc.errors", lambda: scope.adc.errors)

    print("\n-- SAM layer --")
    probe("scope.sam_led_setting", lambda: scope.sam_led_setting)
    probe("scope.sam_errors", lambda: scope.sam_errors)
    probe("scope.naeusb.check_sam_errors()", lambda: scope.naeusb.check_sam_errors())

    print("\n-- clear attempts --")
    cleared = False
    try:
        scope.sam_errors.clear()
        print("  [OK] scope.sam_errors.clear()")
        cleared = True
    except Exception as e:
        print("  [..] sam_errors.clear: %r" % (e,))
    if not cleared:
        try:
            scope.naeusb.clear_sam_errors()
            print("  [OK] scope.naeusb.clear_sam_errors()")
            cleared = True
        except Exception as e:
            print("  [..] naeusb.clear_sam_errors: %r" % (e,))

    print("\n-- after clear --")
    probe("scope.sam_errors(after)", lambda: scope.sam_errors)
    probe("scope.XADC.errors(after)", lambda: scope.XADC.errors())

    print("\nDone: if SAM errors are cleared and the LED stops blinking => stale residue; still blinking => live problem (power/USB)")


if __name__ == "__main__":
    main()
