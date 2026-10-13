# SPDX-License-Identifier: Apache-2.0
"""The ``DIAG_BAD_CMD_F`` warning must not blame ``AT!OPENLOCK`` for every
rejection.

The old line ended "(common cause: AT!OPENLOCK / SPC unlock required)" on
every BAD_CMD — wrong for the stale-prefix case (the modem parsed a
different frame) and for by-design rejections on non-Sierra parts (QSH
``0x4b``/``0x9001`` on pre-SDX). The hint is now chosen from the echo.
"""
from __future__ import annotations

import logging

from diagmunge.transport import DIAG_BAD_CMD_F, DiagClient, bad_cmd_hint


class TestBadCmdHint:
    def test_stale_prefix_echo_is_named_as_such(self):
        # "ati\r" glued ahead of a 0x4b request
        hint = bad_cmd_hint(0x4B, bytes.fromhex("6174690d4b1201"))
        assert "0x61" in hint and "0x4b" in hint
        # Assert the meaning, not the tracker id: the public carve scrubs
        # "#NNNN" refs out of string literals too.
        assert "stale bytes" in hint
        assert "OPENLOCK" not in hint

    def test_matching_echo_is_unsupported_or_gated_with_openlock_scoped_to_sierra(self):
        hint = bad_cmd_hint(0x4B, bytes.fromhex("4b0190"))
        assert "unsupported" in hint
        assert "Sierra" in hint
        assert "common cause" not in hint

    def test_empty_echo(self):
        assert "empty echo" in bad_cmd_hint(0x4B, b"")


class _OneShot:
    def __init__(self, framer: DiagClient, frame: bytes):
        self._chunk = framer._hdlc_encapsulate(frame)
        self._done = False

    def fileno(self) -> int:
        return 0

    def write(self, data: bytes) -> None:
        pass

    def read(self, n: int) -> bytes:
        if self._done:
            return b""
        self._done = True
        return self._chunk


def _run(opcode: int, echo: bytes, caplog) -> tuple:
    framer = DiagClient(None, no_crc=False)
    client = DiagClient(_OneShot(framer, bytes([DIAG_BAD_CMD_F]) + echo), no_crc=False)
    with caplog.at_level(logging.WARNING, logger="diagmunge.transport"):
        return client._send_recv(opcode, b"\x12\x22", timeout=2.0)


def test_send_recv_warning_uses_the_stale_prefix_hint(caplog):
    result = _run(0x4B, bytes.fromhex("6174690d4b1222"), caplog)
    assert result == (DIAG_BAD_CMD_F, bytes.fromhex("6174690d4b1222"))
    text = caplog.text
    assert "DIAG_BAD_CMD_F" in text
    assert "stale bytes" in text
    assert "OPENLOCK" not in text


def test_send_recv_warning_no_longer_claims_openlock_is_the_common_cause(caplog):
    _run(0x4B, bytes.fromhex("4b1222"), caplog)
    assert "common cause: AT!OPENLOCK" not in caplog.text
    assert "unsupported" in caplog.text
