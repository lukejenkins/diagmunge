# SPDX-License-Identifier: Apache-2.0
"""Tests for the GNSS-free diagmunge replay core (#N)."""
import io
import json
import struct

import pytest

from diagmunge.munge import replay


def _dlf(records):
    out = b""
    for code, ts64, payload in records:
        out += struct.pack("<HHQ", 12 + len(payload), code, ts64) + payload
    return out


def test_iter_dlf_records_roundtrips():
    recs = [(0xB0C0, 1, b"\x01\x02"), (0x1476, 2, b"")]
    assert list(replay.iter_dlf_records(_dlf(recs))) == recs


def test_replay_to_jsonl_injects_dispatch_and_filter():
    # A fake, non-GNSS dispatch proves the core has no GNSS knowledge.
    class _Pkt:
        def __init__(self, code): self._c = code
        def to_dict(self): return {"code": self._c}

    recs = [(0x1111, 5, b"a"), (0x2222, 6, b"b")]
    out = io.StringIO()
    stats = replay.replay_to_jsonl(
        replay.iter_dlf_records(_dlf(recs)),
        dispatch=lambda code, ts, pl: _Pkt(code),
        code_filter={0x1111},          # only the first record passes the filter
        out=out,
    )
    lines = [json.loads(l) for l in out.getvalue().splitlines()]
    assert lines == [{"code": 0x1111}]
    assert stats["records_total"] == 2 and stats["records_matched"] == 1 and stats["parsed"] == 1


def test_replay_to_jsonl_counts_parse_errors_and_none():
    recs = [(1, 0, b"x"), (2, 0, b"y"), (3, 0, b"z")]
    out = io.StringIO()

    def _disp(code, ts, pl):
        if code == 1:
            raise ValueError("boom")
        if code == 2:
            return None
        class _P:
            def to_dict(self): return {"ok": code}
        return _P()

    stats = replay.replay_to_jsonl(
        replay.iter_dlf_records(_dlf(recs)),
        dispatch=_disp, code_filter={1, 2, 3}, out=out,
    )
    assert stats["parse_errors"] == 1 and stats["parsed"] == 1
    assert json.loads(out.getvalue().strip()) == {"ok": 3}


def test_read_chunks_file_and_missing(tmp_path):
    f = tmp_path / "c.bin"
    f.write_bytes(b"abcdefg")
    assert b"".join(replay.read_chunks(str(f), chunk_size=3)) == b"abcdefg"
    with pytest.raises(FileNotFoundError):
        list(replay.read_chunks(str(tmp_path / "nope.bin")))
    with pytest.raises(IsADirectoryError):
        list(replay.read_chunks(str(tmp_path)))
