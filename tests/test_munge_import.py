# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the diagmunge.munge subpackage (#N)."""
import importlib
import sys


def test_munge_modules_import_and_expose_main():
    for mod_name in (
        "diagmunge.munge.hdlc_to_dlf",
        "diagmunge.munge.capture_dlf_from_diag",
    ):
        mod = importlib.import_module(mod_name)
        assert callable(mod.main), f"{mod_name}.main must be callable"


def test_core_import_stays_diaggrok_free():
    # Importing the top-level package must NOT pull in the munge subpackage
    # (which would drag diaggrok into the stdlib-only core transport).
    for cached in [m for m in sys.modules if m.startswith("diagmunge.munge")]:
        del sys.modules[cached]
    import diagmunge  # noqa: F401

    assert "diagmunge.munge.hdlc_to_dlf" not in sys.modules
