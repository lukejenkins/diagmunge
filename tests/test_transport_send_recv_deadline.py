# SPDX-License-Identifier: Apache-2.0
"""``DiagClient._send_recv`` terminates under a saturated link.

## Why this file exists — a REFUTED hypothesis, pinned so it stays refuted

diaggulp was once seen outliving its ``timeout(1)`` SIGTERM by nine minutes
.
Its stated hypothesis was *"a SIGTERM handler doing graceful shutdown and
blocking forever on a serial read with no timeout"*, and the obvious suspect
is ``emit_version_anchor()`` — a **blocking DIAG request/response**, issued
from diaggulp's ``finally:`` block *after* the signal,
on a stream that is still flowing at full rate.

Reading ``_send_recv`` makes that look confirmed. It computes a deadline and
then runs two nested loops::

    self.send(opcode, payload)
    deadline = time.monotonic() + timeout
    while True:                              # outer: dispatch one frame
        while b'\\x7e' not in self._pend:     # inner: fill the buffer
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None                  # <-- the ONLY deadline check
            ...

The deadline is checked **only in the inner loop**, which runs only when the
buffer holds no complete frame. On a saturated link every iteration finds
another ``0x7E`` already buffered — so, the argument goes, the inner loop is
skipped forever and the deadline is never evaluated.

⛔ **That argument is wrong, and this file is the proof.** ``self._pend``
drains exactly one frame per outer iteration and is refilled *only* when it
reaches empty. So the inner loop — and its deadline check — is guaranteed to
run at least once per read buffer. Worst-case overshoot is the time to
dispatch one 64 KB buffer of frames, i.e. milliseconds. ``_send_recv``
terminates under flood, and the ``timeout=`` argument is honoured.

The tests below were written to fail against unpatched ``transport.py`` and
**passed**, which is what settled it. They are kept as characterization
tests: the drain-to-empty invariant is load-bearing and invisible, and a
future refactor that refills ``_pend`` opportunistically (say, draining the
socket whenever bytes are ready rather than only when the buffer empties)
would silently make the original hypothesis TRUE. These tests would catch
that.

**That hang's actual root cause remains unknown** — it is a once-observed,
unreproduced event on live hardware. What this file removes is a plausible
dead end, so the next person doesn't spend the session I spent on it.
"""
from __future__ import annotations

import time

import pytest

from diagmunge.transport import DIAG_VERNO_F, DiagClient

# Any bound comfortably above "one 64 KB buffer of frames" and comfortably
# below "a hang". The distinction under test is milliseconds vs. forever, so
# the exact value does not matter.
_NOT_HUNG_SECONDS = 5.0


class _FloodTransport:
    """A modem that never stops pushing unsolicited LOG frames.

    Models the saturated-link condition: every ``read()`` returns a fresh
    batch of complete, CRC-correct frames whose opcode never matches the
    request, so a matching response never arrives.
    """

    def __init__(self, framer: DiagClient, opcode: int = 0x10):
        self._chunk = b"".join(
            framer._hdlc_encapsulate(bytes([opcode]) + b"\xab" * 32)
            for _ in range(16)
        )
        self.reads = 0
        self.writes: list[bytes] = []

    def fileno(self) -> int:
        # Only consulted from the inner buffer-fill loop's select(). fd 0 is
        # readable-or-EOF under pytest, so select returns promptly either way
        # and the loop's own deadline arithmetic — not select's blocking —
        # is what the test is measuring.
        return 0

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    def read(self, n: int) -> bytes:
        self.reads += 1
        return self._chunk


class _IdleThenAnswerTransport:
    """An idle link that answers once — the ordinary handshake."""

    def __init__(self, framer: DiagClient, opcode: int):
        self._response = framer._hdlc_encapsulate(bytes([opcode]) + b"\x01\x02")
        self._sent = False
        self.writes: list[bytes] = []

    def fileno(self) -> int:
        return 0

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    def read(self, n: int) -> bytes:
        if self._sent:
            return b""
        self._sent = True
        return self._response


def _client(kind, *args) -> DiagClient:
    """Build a DiagClient over ``kind``. A second bare DiagClient is used
    purely as a framer so the fake can pre-encode valid HDLC."""
    framer = DiagClient(None, no_crc=False)
    return DiagClient(kind(framer, *args), no_crc=False)


class TestSendRecvUnderFlood:
    def test_saturated_link_still_returns_within_the_timeout(self):
        client = _client(_FloodTransport, 0x10)

        start = time.monotonic()
        result = client._send_recv(DIAG_VERNO_F, b"", timeout=0.2)
        elapsed = time.monotonic() - start

        assert result is None, "no matching response was ever sent"
        assert elapsed < _NOT_HUNG_SECONDS, (
            f"_send_recv ran {elapsed:.1f}s against a 0.2s timeout — the "
            f"drain-to-empty invariant that bounds the outer loop is gone "
            f"; the inner loop's deadline check is now unreachable"
        )

    def test_the_flood_fake_really_does_saturate(self):
        """Guards the test above: if the fake ever went idle, it would pass
        vacuously — the inner loop would run for ordinary reasons and prove
        nothing about the outer one."""
        framer = DiagClient(None, no_crc=False)
        t = _FloodTransport(framer)
        assert t.read(0x10000).count(b"\x7e") >= 16
        assert t.read(0x10000) == t.read(0x10000), "flood must not exhaust"

    def test_zero_timeout_returns_immediately(self):
        client = _client(_FloodTransport, 0x10)
        start = time.monotonic()
        assert client._send_recv(DIAG_VERNO_F, b"", timeout=0.0) is None
        assert time.monotonic() - start < _NOT_HUNG_SECONDS

    def test_request_was_actually_sent(self):
        """Sanity: the timeout path is reached *after* a send, not instead of
        one. A fake that silently failed to write would make every timing
        assertion here meaningless."""
        client = _client(_FloodTransport, 0x10)
        client._send_recv(DIAG_VERNO_F, b"", timeout=0.2)
        assert client._transport.writes, "request frame was never written"


class TestSendRecvHappyPath:
    def test_idle_link_matching_response_returns_the_body(self):
        client = _client(_IdleThenAnswerTransport, DIAG_VERNO_F)
        result = client._send_recv(DIAG_VERNO_F, b"", timeout=2.0)
        assert result is not None
        opcode, body = result
        assert opcode == DIAG_VERNO_F
        assert body == b"\x01\x02"


class TestEmitVersionAnchorUnderFlood:
    """The suspect itself: diaggulp's teardown anchor, issued after
    SIGTERM while the modem is still streaming at full rate."""

    def test_anchor_gives_up_instead_of_hanging(self):
        client = _client(_FloodTransport, 0x10)

        start = time.monotonic()
        anchor = client.emit_version_anchor(timeout=0.2)
        elapsed = time.monotonic() - start

        assert anchor is None, "best-effort anchor returns None on timeout"
        assert elapsed < _NOT_HUNG_SECONDS, (
            f"emit_version_anchor ran {elapsed:.1f}s against a 0.2s timeout "
            f"— this is the call suspected of hanging diaggulp's "
            f"finally: block, and it must stay bounded"
        )
