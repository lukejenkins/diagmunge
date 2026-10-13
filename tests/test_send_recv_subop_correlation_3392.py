# SPDX-License-Identifier: Apache-2.0
"""``DiagClient._send_recv`` must correlate a 0x73 reply on its SUB-OPERATION,
not on the opcode alone.

## The bug

DIAG ``LOG_CONFIG`` (opcode ``0x73``) carries the actual operation
(``RETRIEVE_RANGES`` = 1, ``SET_MASK`` = 3) in a u32 at offset 3 of the body —
the opcode is the same for every sub-operation. ``_send_recv`` returned the
first frame whose *opcode* matched, so when a modem streams fast enough for a
reply to still be in flight, a late ``RETRIEVE_RANGES`` reply satisfies the
*next* ``SET_MASK`` request. The caller then asserts ``operation == SET_MASK``
and dies with ``AssertionError: Unexpected op 1`` (reproduced live on the TCL
IK41US MDM9607 in both diagmunge ``subscribe_logs`` and diaggulp
``_build_narrow_mask``). Worse, disarming a sticky mask *requires* this
handshake, so the firehose blocks its own remedy.

## The fix under test

``_send_recv`` takes an optional keyword-only ``match(op, body)`` predicate. A
frame whose opcode matches but whose ``match`` returns ``False`` is *drained*
(kept reading within the timeout) instead of bound to the request. The 0x73
call sites pass ``log_config_reply_matches(op, body, <expected sub-op>)``.
"""
from __future__ import annotations

import time
from struct import pack, unpack_from

import pytest

from diagmunge.transport import (
    DIAG_LOG_CONFIG_F,
    DiagClient,
    _LOG_CFG_RETRIEVE_RANGES,
    _LOG_CFG_SET_MASK,
    _LOG_CFG_SUCCESS,
    log_config_reply_matches,
)

_NOT_HUNG_SECONDS = 5.0


def _retrieve_ranges_reply(bitsizes: "tuple[int, ...]" = (0,) * 16) -> bytes:
    """A well-formed RETRIEVE_RANGES reply body (sub-op 1)."""
    return pack("<3xII", _LOG_CFG_RETRIEVE_RANGES, _LOG_CFG_SUCCESS) + pack("<16I", *bitsizes)


def _set_mask_reply() -> bytes:
    """A well-formed SET_MASK reply body (sub-op 3)."""
    return pack("<3xII", _LOG_CFG_SET_MASK, _LOG_CFG_SUCCESS)


def _subop_of(body: bytes) -> int:
    return unpack_from("<3xI", body)[0]


class _ScriptedTransport:
    """Yields a fixed sequence of pre-framed replies, one chunk per read().

    Each chunk is the concatenation of one transaction's frames (an aliased
    reply followed by the real one), so a single _send_recv sees both in its
    buffer and must drain the aliased one to reach the real one.
    """

    def __init__(self, framer: DiagClient, chunks: "list[list[tuple[int, bytes]]]"):
        self._chunks = [
            b"".join(framer._hdlc_encapsulate(bytes([op]) + body) for op, body in frames)
            for frames in chunks
        ]
        self._i = 0
        self.writes: list[bytes] = []

    def fileno(self) -> int:
        return 0

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    def read(self, n: int) -> bytes:
        if self._i >= len(self._chunks):
            return b""
        chunk = self._chunks[self._i]
        self._i += 1
        return chunk


class _AliasFloodTransport:
    """Only ever streams RETRIEVE_RANGES replies (sub-op 1) — the SET_MASK reply
    the caller waits for never arrives, so a correct correlator times out
    instead of binding the wrong sub-operation."""

    def __init__(self, framer: DiagClient):
        self._chunk = b"".join(
            framer._hdlc_encapsulate(bytes([DIAG_LOG_CONFIG_F]) + _retrieve_ranges_reply())
            for _ in range(16)
        )
        self.writes: list[bytes] = []

    def fileno(self) -> int:
        return 0

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    def read(self, n: int) -> bytes:
        return self._chunk


def _client(kind, *args) -> DiagClient:
    framer = DiagClient(None, no_crc=False)
    return DiagClient(kind(framer, *args), no_crc=False)


# ── the predicate ───────────────────────────────────────────────────────────
class TestLogConfigReplyMatches:
    def test_matches_the_expected_sub_operation(self):
        assert log_config_reply_matches(
            DIAG_LOG_CONFIG_F, _set_mask_reply(), _LOG_CFG_SET_MASK) is True

    def test_rejects_a_different_sub_operation(self):
        # the aliasing case: a RETRIEVE reply offered for a SET_MASK request
        assert log_config_reply_matches(
            DIAG_LOG_CONFIG_F, _retrieve_ranges_reply(), _LOG_CFG_SET_MASK) is False

    def test_rejects_a_different_opcode(self):
        assert log_config_reply_matches(
            0x10, _set_mask_reply(), _LOG_CFG_SET_MASK) is False

    def test_rejects_a_body_too_short_to_carry_the_sub_op(self):
        assert log_config_reply_matches(
            DIAG_LOG_CONFIG_F, b"\x00\x00\x00", _LOG_CFG_SET_MASK) is False


# ── the drain behaviour in _send_recv ────────────────────────────────────────
class TestSendRecvDrainsAliasedSubOp:
    def test_aliased_reply_is_drained_and_the_real_one_returned(self):
        # buffer holds [aliased RETRIEVE reply, real SET_MASK reply]
        client = _client(_ScriptedTransport, [[
            (DIAG_LOG_CONFIG_F, _retrieve_ranges_reply()),
            (DIAG_LOG_CONFIG_F, _set_mask_reply()),
        ]])
        result = client._send_recv(
            DIAG_LOG_CONFIG_F, pack("<3xI", _LOG_CFG_SET_MASK), timeout=2.0,
            match=lambda op, b: log_config_reply_matches(op, b, _LOG_CFG_SET_MASK),
        )
        assert result is not None
        op, body = result
        assert op == DIAG_LOG_CONFIG_F
        assert _subop_of(body) == _LOG_CFG_SET_MASK, (
            "returned the aliased RETRIEVE reply instead of draining it"
        )

    def test_without_a_matcher_the_first_opcode_still_wins(self):
        """Backward compatibility: the default path is unchanged."""
        client = _client(_ScriptedTransport, [[
            (DIAG_LOG_CONFIG_F, _retrieve_ranges_reply()),
            (DIAG_LOG_CONFIG_F, _set_mask_reply()),
        ]])
        op, body = client._send_recv(DIAG_LOG_CONFIG_F, b"", timeout=2.0)
        assert op == DIAG_LOG_CONFIG_F
        assert _subop_of(body) == _LOG_CFG_RETRIEVE_RANGES

    def test_only_aliased_replies_times_out_rather_than_binding_the_wrong_one(self):
        client = _client(_AliasFloodTransport)
        start = time.monotonic()
        result = client._send_recv(
            DIAG_LOG_CONFIG_F, pack("<3xI", _LOG_CFG_SET_MASK), timeout=0.2,
            match=lambda op, b: log_config_reply_matches(op, b, _LOG_CFG_SET_MASK),
        )
        elapsed = time.monotonic() - start
        assert result is None, "a wrong-sub-op reply must never satisfy the request"
        assert elapsed < _NOT_HUNG_SECONDS


# ── subscribe_logs end to end over an aliasing link ──────────────────────────
class TestSubscribeLogsSurvivesAliasing:
    def test_handshake_completes_when_each_reply_is_preceded_by_an_alias(self):
        bitsizes = tuple([0, 8] + [0] * 14)  # exactly one non-zero group → 1 SET_MASK
        client = _client(_ScriptedTransport, [
            # transaction 1 (RETRIEVE): a stale SET_MASK reply arrives first
            [(DIAG_LOG_CONFIG_F, _set_mask_reply()),
             (DIAG_LOG_CONFIG_F, _retrieve_ranges_reply(bitsizes))],
            # transaction 2 (SET_MASK for group 1): a stale RETRIEVE reply first
            [(DIAG_LOG_CONFIG_F, _retrieve_ranges_reply(bitsizes)),
             (DIAG_LOG_CONFIG_F, _set_mask_reply())],
        ])
        # Must NOT raise AssertionError("Unexpected op ...").
        client.subscribe_logs([0x1001])  # code in group 1 (0x1 << 12 | 1)
        # sanity: both transactions actually wrote a request
        assert len(client._transport.writes) == 2
