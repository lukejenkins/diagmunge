"""Streaming DIAG peek filter — decode only the frames a consumer wants.

Part 0 of the DIAG consumer-filtering design (peek filter).

A raw HDLC DIAG stream is mostly frames a given consumer does not care about
(a GNSS consumer wants a handful of log codes out of a max-mask firehose). The
full path — split, unescape the whole frame, CRC it, then classify — pays that
cost for every frame. This module classifies from the **first ≤32 escaped
bytes** and does the full unescape + CRC only for frames that match:

- :class:`FrameSplitter` — split a chunked byte stream on ``0x7E``, carrying a
  partial frame across chunk boundaries (DGE1 slices are not frame-aligned).
- :func:`peek` — outer opcode, the ``0x98`` multi-radio wrapper's inner
  opcode, and the (inner) ``0x10`` LOG code, from the escaped head.
- :class:`FrameFilter` — frozen match sets built once; ``feed()`` yields a
  :class:`Match` (original escaped bytes + unescaped, CRC-stripped frame) per
  wanted frame.

Stdlib-only. The ``0x98`` inner-frame offset table is a local copy of
``diaggrok.hdlc.MULTI_RADIO_WRAPPER_OFFSET``, pinned equal to it by a test —
importing ``diaggrok.hdlc`` would run diaggrok's package init, which loads
every parser module (~1.1 s on x86-64, several seconds on a Pi): longer than
filtering a whole 63 MB capture. The CRC is diagmunge's own CRC-16/X.25
(``transport._crc16``).

⚠️ Unescape is the two-``replace`` form: ``7D 5E → 7E`` FIRST, then
``7D 5D → 7D``. The reverse order would turn an escaped ``7D`` followed by a
literal ``5E`` into a spurious ``7E``. DIAG framing only escapes ``7D``/``7E``;
any other ``7D xx`` is not valid framing and such a frame fails its CRC.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Iterator

from .transport import _crc16

__all__ = [
    "F3_OPCODES",
    "EVENT_OPCODE",
    "LOG_OPCODE",
    "FilterStats",
    "FrameFilter",
    "FrameSplitter",
    "Match",
    "Peek",
    "peek",
    "unescape",
]

LOG_OPCODE = 0x10            # DIAG_LOG_F
EVENT_OPCODE = 0x60          # DIAG_EVENT_REPORT_F
F3_OPCODES = frozenset({0x79, 0x99, 0x92})  # EXT_MSG_F / QSR4 terse / QSR legacy

#: ``0x98`` DIAG_MULTI_RADIO wrapper -> offset of the wrapped frame. A copy of
#: ``diaggrok.hdlc.MULTI_RADIO_WRAPPER_OFFSET``; a test pins the two equal.
MULTI_RADIO_WRAPPER_OFFSET: dict[int, int] = {0x98: 8}

_PEEK_WINDOW = 32            # escaped bytes examined by peek()
_LOG_CODE_OFF = 6            # 0x10 frame: [0]=op [1]=more [2:4]=len [4:6]=len2 [6:8]=code
_ESC = 0x7D
_FLAG = 0x7E


def unescape(esc: bytes) -> bytes:
    """HDLC-unescape a DIAG frame (``7D 5E → 7E`` first, then ``7D 5D → 7D``)."""
    if b"\x7d" not in esc:
        return esc
    return esc.replace(b"\x7d\x5e", b"\x7e").replace(b"\x7d\x5d", b"\x7d")


class FrameSplitter:
    """Split a chunked HDLC stream into complete escaped frames (no ``0x7E``)."""

    __slots__ = ("_carry",)

    def __init__(self) -> None:
        self._carry = b""

    def feed(self, chunk: bytes) -> list[bytes]:
        """Return every frame completed by ``chunk``; empty elements dropped."""
        parts = (self._carry + chunk).split(b"\x7e")
        self._carry = parts.pop()
        return [p for p in parts if p]

    def flush(self) -> bytes:
        """Return and clear the trailing partial frame (``b""`` if none)."""
        carry, self._carry = self._carry, b""
        return carry


@dataclass(frozen=True, slots=True)
class Peek:
    opcode: int                  # outer opcode (byte 0)
    inner_opcode: int | None     # for 0x98 wrappers: opcode of the wrapped frame
    log_code: int | None         # for (inner) 0x10 LOG frames


def _head(esc: bytes) -> bytes:
    """Unescaped head of ``esc`` — always enough for every field peek reads.

    peek reads at most unescaped index 15 (a wrapped LOG code, ``[14:16]``).
    32 escaped bytes unescape to ≥16 bytes, and if the window cuts an escape
    pair the lone trailing ``7D`` sits at index ≥16 — so neither widening nor a
    cut-pair guard is ever needed (both were tried; mutation testing showed
    them unreachable).
    """
    win = esc[:_PEEK_WINDOW]
    return unescape(win) if _ESC in win else win


def peek(esc: bytes) -> Peek | None:
    """Classify an escaped frame from its head; ``None`` = too short to classify.

    A frame whose (inner) opcode is ``0x10`` but which is too short to carry a
    log code is ``None`` too — it cannot be a valid LOG frame.
    """
    if not esc:
        return None
    head = _head(esc)
    op = head[0]
    inner = None
    base = 0
    wrap_off = MULTI_RADIO_WRAPPER_OFFSET.get(op)
    if wrap_off is not None:
        if len(head) <= wrap_off:
            return None
        inner = head[wrap_off]
        base = wrap_off
    eff = op if inner is None else inner
    code = None
    if eff == LOG_OPCODE:
        o = base + _LOG_CODE_OFF
        if len(head) < o + 2:
            return None
        code = head[o] | (head[o + 1] << 8)
    return Peek(op, inner, code)


@dataclass(frozen=True, slots=True)
class Match:
    escaped: bytes   # original escaped bytes, WITHOUT the 0x7E delimiters
    frame: bytes     # unescaped frame, CRC stripped
    peek: Peek


@dataclass(slots=True)
class FilterStats:
    frames_seen: int = 0
    frames_matched: int = 0
    crc_bad: int = 0
    bytes_seen: int = 0
    short: int = 0


def _escaped_first_bytes(opcodes: Iterable[int]) -> frozenset[int]:
    """Escaped first byte of a frame whose unescaped opcode is in ``opcodes``."""
    out = set()
    for op in opcodes:
        out.add(_ESC if op in (_ESC, _FLAG) else op)
    return frozenset(out)


class FrameFilter:
    """Yield only the wanted frames of a raw HDLC DIAG stream.

    Match rules (all sets frozen in ``__init__``):

    - ``log_codes`` — bare ``0x10`` and ``0x98``-wrapped ``0x10`` with that code;
    - ``all_logs`` (or ``0x10`` in ``opcodes``) — every LOG frame;
    - ``f3`` — opcodes ``{0x79, 0x99, 0x92}``, bare or ``0x98``-wrapped;
    - ``events`` — opcode ``0x60``, bare or ``0x98``-wrapped;
    - ``opcodes`` — any other opcode, matched as the outer opcode or, for a
      ``0x98`` wrapper, the inner one (so ``opcodes={0x98}`` takes every
      wrapper whole).

    A CRC failure is counted in ``stats.crc_bad`` and the frame dropped, never
    raised. ``verify_crc=False`` skips the check for pre-validated sources.
    """

    def __init__(self, *, log_codes: Iterable[int] = (), opcodes: Iterable[int] = (),
                 f3: bool = False, events: bool = False, all_logs: bool = False,
                 verify_crc: bool = True) -> None:
        self._log_codes = frozenset(log_codes)
        opcodes = frozenset(opcodes)
        self._all_logs = bool(all_logs) or LOG_OPCODE in opcodes
        eff = set(opcodes) - {LOG_OPCODE}
        if f3:
            eff |= F3_OPCODES
        if events:
            eff.add(EVENT_OPCODE)
        self._outer_opcodes = frozenset(opcodes)
        self._eff_opcodes = frozenset(eff)
        self._want_logs = self._all_logs or bool(self._log_codes)
        # Outer opcodes worth peeking at: wanted ones, LOG (if any log wanted),
        # and every wrapper (its inner opcode decides).
        cand = set(self._outer_opcodes) | set(self._eff_opcodes) | set(MULTI_RADIO_WRAPPER_OFFSET)
        if self._want_logs:
            cand.add(LOG_OPCODE)
        self._first_bytes = _escaped_first_bytes(cand)
        self.verify_crc = verify_crc
        self.stats = FilterStats()
        self._splitter = FrameSplitter()

    def matches(self, p: Peek) -> bool:
        if p.opcode in self._outer_opcodes:
            return True
        eff = p.opcode if p.inner_opcode is None else p.inner_opcode
        if eff == LOG_OPCODE:
            return self._all_logs or p.log_code in self._log_codes
        return eff in self._eff_opcodes

    def wants(self, esc: bytes) -> Peek | None:
        """Classify one escaped frame: its :class:`Peek` if it matches, else
        ``None``. Cheap-rejects on the first byte; no unescape, no CRC. This is
        what a byte-exact pass-through (``--invert``) needs; ``short`` is
        counted for a candidate frame too short to classify."""
        if esc[0] not in self._first_bytes:
            return None
        p = peek(esc)
        if p is None:
            self.stats.short += 1
            return None
        return p if self.matches(p) else None

    def _process(self, esc: bytes) -> Match | None:
        p = self.wants(esc)
        if p is None:
            return None
        raw = unescape(esc)
        if len(raw) < 3:
            self.stats.short += 1
            return None
        body = raw[:-2]
        if self.verify_crc and _crc16(body) != struct.unpack_from("<H", raw, len(raw) - 2)[0]:
            self.stats.crc_bad += 1
            return None
        self.stats.frames_matched += 1
        return Match(esc, body, p)

    def feed(self, chunk: bytes) -> Iterator[Match]:
        """Feed a chunk; yield a :class:`Match` per wanted frame it completes."""
        st = self.stats
        st.bytes_seen += len(chunk)
        first = self._first_bytes
        frames = self._splitter.feed(chunk)
        st.frames_seen += len(frames)
        for esc in frames:
            if esc[0] not in first:   # cheap reject inlined: the hot path
                continue
            m = self._process(esc)
            if m is not None:
                yield m

    def finish(self) -> Iterator[Match]:
        """End of stream: treat the trailing partial frame as complete.

        Matches whole-buffer semantics (``bytes.split`` keeps the last
        element). For a live stream that is merely paused, do not call this.
        """
        tail = self._splitter.flush()
        if tail:
            self.stats.frames_seen += 1
            m = self._process(tail)
            if m is not None:
                yield m

    def reset(self) -> None:
        """Discard the carried partial frame (DGE1 ``RESTART`` / sequence gap).

        Counted as ``short`` when anything was discarded (spec §6).
        """
        if self._splitter.flush():
            self.stats.short += 1
