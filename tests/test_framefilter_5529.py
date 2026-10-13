"""Tests for ``diagmunge.framefilter`` — the streaming DIAG peek filter."""
from __future__ import annotations

import json
import os
import random
import struct
import time
from pathlib import Path

import pytest

from diagmunge.framefilter import (
    FrameFilter,
    FrameSplitter,
    Peek,
    peek,
    unescape,
)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "diag_peek_vectors.json").read_text())
_IDS = [v["name"] for v in VECTORS["vectors"]]


def _vector_filter() -> FrameFilter:
    return FrameFilter(**VECTORS["filter"])


# --------------------------------------------------------------------------
# Shared vectors (also consumed by the C twin)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("v", VECTORS["vectors"], ids=_IDS)
def test_vector_peek(v):
    got = peek(bytes.fromhex(v["escaped"]))
    want = v["peek"]
    if want is None:
        assert got is None
    else:
        assert got == Peek(want["opcode"], want["inner_opcode"], want["log_code"])


@pytest.mark.parametrize("v", VECTORS["vectors"], ids=_IDS)
def test_vector_match_and_yield(v):
    f = _vector_filter()
    esc = bytes.fromhex(v["escaped"])
    p = peek(esc)
    assert (p is not None and f.matches(p)) == v["matches"]
    out = list(f.feed(b"\x7e" + esc + b"\x7e"))
    assert bool(out) == v["yields"]
    if out:
        (m,) = out
        assert m.escaped == esc                       # original bytes, byte-exact
        assert m.frame == _reference_unescape(esc)[:-2]  # CRC stripped


def test_vectors_cover_the_spec_cases():
    names = set(_IDS)
    for need in ("bare_log_wanted", "wrapped_log_wanted", "ext_msg_0x79",
                 "qsr4_terse_0x99", "event_0x60", "log_code_escaped_low_byte",
                 "truncated_log", "bad_crc_wanted"):
        assert need in names


def test_wrapper_table_matches_diaggrok():
    """framefilter keeps a local copy (import cost); diaggrok is the truth."""
    hdlc = pytest.importorskip("diaggrok.hdlc")
    from diagmunge.framefilter import MULTI_RADIO_WRAPPER_OFFSET
    assert MULTI_RADIO_WRAPPER_OFFSET == hdlc.MULTI_RADIO_WRAPPER_OFFSET


def test_framefilter_import_is_diaggrok_free():
    import subprocess
    import sys
    code = ("import sys, diagmunge.framefilter; "
            "sys.exit(1 if any(m == 'diaggrok' or m.startswith('diaggrok.') for m in sys.modules) else 0)")
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


def test_bad_crc_is_counted_not_raised():
    f = _vector_filter()
    v = next(x for x in VECTORS["vectors"] if x["name"] == "bad_crc_wanted")
    assert list(f.feed(b"\x7e" + bytes.fromhex(v["escaped"]) + b"\x7e")) == []
    assert f.stats.crc_bad == 1 and f.stats.frames_matched == 0


def test_verify_crc_false_yields_bad_crc_frame():
    f = FrameFilter(**VECTORS["filter"], verify_crc=False)
    v = next(x for x in VECTORS["vectors"] if x["name"] == "bad_crc_wanted")
    assert len(list(f.feed(b"\x7e" + bytes.fromhex(v["escaped"]) + b"\x7e"))) == 1


# --------------------------------------------------------------------------
# Unescape + splitter
# --------------------------------------------------------------------------

def _reference_unescape(esc: bytes) -> bytes:
    """Byte-loop unescape (the general 7D xx -> xx^0x20 rule)."""
    out, i = bytearray(), 0
    while i < len(esc):
        if esc[i] == 0x7D and i + 1 < len(esc):
            out.append(esc[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(esc[i])
            i += 1
    return bytes(out)


def test_unescape_order_trap():
    # escaped 0x7D followed by a LITERAL 0x5E must stay 7D 5E, not become 7E.
    assert unescape(b"\x7d\x5d\x5e") == b"\x7d\x5e"
    assert unescape(b"\x7d\x5d\x7d\x5e") == b"\x7d\x7e"
    assert unescape(b"\x01\x02") == b"\x01\x02"


def test_splitter_carries_partial_frames():
    s = FrameSplitter()
    assert s.feed(b"\x7eab") == []
    assert s.feed(b"c\x7e\x7ede") == [b"abc"]
    assert s.feed(b"\x7e") == [b"de"]
    assert s.flush() == b""
    assert s.feed(b"xy") == [] and s.flush() == b"xy"


def test_reset_discards_carry_as_short():
    f = FrameFilter(all_logs=True)
    list(f.feed(b"\x7e\x10\x00\x00"))
    f.reset()
    assert f.stats.short == 1
    assert list(f.finish()) == []


# --------------------------------------------------------------------------
# Equivalence vs the full-unescape path + chunk-boundary fuzz
# --------------------------------------------------------------------------

def _crc(data: bytes) -> int:
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0x8408 if c & 1 else c >> 1
    return c ^ 0xFFFF


def _full_path(stream: bytes, *, log_codes, f3, events):
    """Reference: unescape EVERY frame, CRC it, then classify the whole frame."""
    want_ops = ({0x79, 0x99, 0x92} if f3 else set()) | ({0x60} if events else set())
    out = []
    for esc in stream.split(b"\x7e"):
        if not esc:
            continue
        raw = _reference_unescape(esc)
        if len(raw) < 3 or _crc(raw[:-2]) != struct.unpack_from("<H", raw, len(raw) - 2)[0]:
            continue
        body = raw[:-2]
        inner = body[8:] if body[0] == 0x98 and len(body) > 8 else None
        eff = inner if inner is not None else body
        if eff[0] == 0x10:
            if len(eff) >= 8 and (eff[6] | eff[7] << 8) in log_codes:
                out.append(esc)
        elif eff[0] in want_ops:
            out.append(esc)
    return out


def _random_stream(seed: int, n: int = 600) -> bytes:
    rng = random.Random(seed)
    frames = []
    for _ in range(n):
        kind = rng.random()
        if kind < 0.5:
            code = rng.choice([0x1476, 0x1477, 0xB0C0, 0x147E, 0x7D7E, 0xB193])
            plen = rng.randrange(0, 80)
            body = bytes([0x10, 0]) + struct.pack("<HHH", plen + 12, plen + 12, code) \
                + bytes(rng.randrange(256) for _ in range(8 + plen))
        elif kind < 0.65:
            body = bytes([rng.choice([0x79, 0x99, 0x92, 0x60, 0x9D, 0x7E])]) \
                + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 60)))
        else:
            code = rng.choice([0x1476, 0xB0C0, 0x147E])
            inner = bytes([0x10, 0]) + struct.pack("<HHH", 20, 20, code) + bytes(rng.randrange(256) for _ in range(14))
            if rng.random() < 0.3:
                inner = bytes([rng.choice([0x99, 0x60, 0x79])]) + bytes(rng.randrange(256) for _ in range(20))
            body = bytes([0x98, 1, 0, 0]) + struct.pack("<I", 1) + inner
        crc = _crc(body) ^ (0xFFFF if rng.random() < 0.05 else 0)
        raw = body + struct.pack("<H", crc)
        esc = bytearray()
        for b in raw:
            esc += bytes((0x7D, b ^ 0x20)) if b in (0x7D, 0x7E) else bytes((b,))
        frames.append(bytes(esc))
        if rng.random() < 0.02:
            frames.append(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 6))).replace(b"\x7e", b""))
    return b"\x7e" + b"\x7e".join(frames) + b"\x7e"


def _run(stream: bytes, chunk_sizes, **kw) -> list[bytes]:
    f = FrameFilter(**kw)
    out, i, k = [], 0, 0
    while i < len(stream):
        n = chunk_sizes[k % len(chunk_sizes)]
        out += [m.escaped for m in f.feed(stream[i:i + n])]
        i += n
        k += 1
    out += [m.escaped for m in f.finish()]
    return out


KW = dict(log_codes={0x1476, 0x147E, 0x7D7E}, f3=True, events=True)


@pytest.mark.parametrize("seed", range(5))
def test_equivalent_to_full_unescape_path(seed):
    stream = _random_stream(seed)
    want = _full_path(stream, **KW)
    assert want, "positive control: the reference path must match something"
    assert _run(stream, [len(stream)], **KW) == want


@pytest.mark.parametrize("seed", range(3))
def test_chunk_boundary_fuzz(seed):
    stream = _random_stream(100 + seed)
    whole = _run(stream, [len(stream)], **KW)
    rng = random.Random(seed)
    for sizes in ([1], [2, 3], [7], [rng.randrange(1, 65537) for _ in range(50)], [65536]):
        assert _run(stream, sizes, **KW) == whole


# --------------------------------------------------------------------------
# Reference capture — a real max-mask raw HDLC capture named by the
# DIAG_PEEK_REF_CAPTURE env var; slow, skipped when unset or absent.
# --------------------------------------------------------------------------

def _reference_capture() -> bytes:
    ref = os.environ.get("DIAG_PEEK_REF_CAPTURE")
    if not ref or not Path(ref).is_file():
        pytest.skip(f"reference capture unset or absent: DIAG_PEEK_REF_CAPTURE={ref!r}")
    return Path(ref).read_bytes()


@pytest.mark.slow
def test_reference_capture_bit_identical_to_full_path():
    """Same matched set as diaggrok's own full path (``hdlc_unescape`` +
    ``crc16_ccitt`` on EVERY frame, then classify): 0 missed, 0 extra."""
    from diaggrok.hdlc import crc16_ccitt, hdlc_unescape

    data = _reference_capture()
    valid = []  # (escaped, effective frame) for every CRC-valid frame, once
    for esc in data.split(b"\x7e"):
        if not esc:
            continue
        raw = hdlc_unescape(esc)
        if len(raw) < 3 or crc16_ccitt(raw[:-2]) != struct.unpack_from("<H", raw, len(raw) - 2)[0]:
            continue
        body = raw[:-2]
        valid.append((esc, body[8:] if body[0] == 0x98 and len(body) > 8 else body))
    cases = (
        (dict(log_codes={0x1476}), lambda e: e[0] == 0x10 and len(e) >= 8 and (e[6] | e[7] << 8) == 0x1476),
        (dict(events=True), lambda e: e[0] == 0x60),
    )
    for kw, want_fn in cases:
        want = [esc for esc, eff in valid if want_fn(eff)]
        assert want, f"positive control: {kw} must match something"
        assert _run(data, [65536], **kw) == want


@pytest.mark.slow
def test_reference_capture_throughput_floor():
    data = _reference_capture()
    best = 0.0
    for _ in range(3):
        f = FrameFilter(log_codes={0x1476})
        t = time.perf_counter()
        for i in range(0, len(data), 65536):
            for _m in f.feed(data[i:i + 65536]):
                pass
        best = max(best, len(data) / (time.perf_counter() - t) / 1e6)
    assert best >= 200, f"{best:.0f} MB/s < 200 MB/s floor"
