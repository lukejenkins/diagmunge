# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the diagmunge package boundary (#N).

These prove the relocated transport core stands alone as a package: the flat
top-level API is present, and `import diagmunge` needs neither pyserial nor
diaggrok (both are lazy, optional extras). Behavioural coverage of DiagClient
lives in the consumers' suites (tests/test_diag_*.py, apps/diaggpsd/tests/).
"""
from __future__ import annotations

import builtins

import pytest


def test_flat_public_api_is_exported():
    import diagmunge

    # Transport + DGE1 surface
    assert diagmunge.DiagClient.__name__ == "DiagClient"
    assert callable(diagmunge.parse_dge1_header)
    assert diagmunge.Dge1SeqTracker.__name__ == "Dge1SeqTracker"
    # DIAG_* opcode constants
    assert diagmunge.DIAG_BAD_CMD_F == 0x13
    assert diagmunge.DIAG_LOG_F == 16
    # Everything advertised in __all__ actually resolves
    for name in diagmunge.__all__:
        assert hasattr(diagmunge, name), f"__all__ lists {name} but it is missing"


def test_import_does_not_require_pyserial_or_diaggrok(monkeypatch):
    """The core transport must import with both optional extras absent."""
    real_import = builtins.__import__

    def _blocked(name, *args, **kwargs):
        top = name.split(".")[0]
        if top in {"serial", "diaggrok"}:
            raise ImportError(f"{top} is blocked for this test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked)

    import importlib

    import diagmunge

    # Reloading under the block proves no top-level dependency on the extras.
    importlib.reload(diagmunge)
    assert diagmunge.DiagClient is not None


def test_private_transports_live_on_the_internal_module():
    """Underscore transports are internal — reachable via diagmunge.transport,
    not re-exported at the package top level."""
    from diagmunge import transport

    assert hasattr(transport, "_UdpBroadcastTransport")
    assert hasattr(transport, "_UdpListenTransport")
    with pytest.raises(AttributeError):
        import diagmunge

        _ = diagmunge._UdpListenTransport  # noqa: B018 — asserting it's NOT here
