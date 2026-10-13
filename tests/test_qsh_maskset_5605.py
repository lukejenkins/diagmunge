# SPDX-License-Identifier: Apache-2.0
"""Vendor-free QSH-trace maskset sources — synthetic data only."""
import struct

import pytest

from diagmunge.diag_cmd import build_qsh_trace_maskset_set
from diagmunge.qsh_maskset import (
    QSH_TRACE_MAX_PAIRS, derive_pairs, harvest_cfg, sweep_pairs, sweep_windows, wire_key,
)


def _hdlc(inner: bytes) -> bytes:
    esc = inner.replace(b"\x7d", b"\x7d\x5d").replace(b"\x7e", b"\x7d\x5e")
    return esc + b"\x00\x00" + b"\x7e"  # CRC value is not checked by harvest_cfg


def test_sweep_windows_cover_1_to_255_without_ssid_0_and_within_cap():
    ws = sweep_windows()
    assert [(w.start, w.stop) for w in ws] == [(1, 111), (111, 221), (221, 256)]
    assert all(len(w) <= QSH_TRACE_MAX_PAIRS for w in ws)


def test_sweep_pairs_is_ascending_all_bits_and_refuses_over_cap():
    p = sweep_pairs(range(110, 0, -1))
    assert p[0] == (1, 0xFFFF) and p[-1] == (110, 0xFFFF) and list(p) == sorted(p)
    with pytest.raises(ValueError, match="cap"):
        sweep_pairs(range(1, 112))
    with pytest.raises(ValueError, match="ssid"):
        sweep_pairs([0])


def test_wire_key_unpacks_subsys_and_sub_stream():
    w2 = (0x6B << 6) | (3 << 1)
    frame = bytes((0x9D, 0)) + struct.pack("<H", w2) + bytes(12)
    assert wire_key(frame) == (0x6B, 3)
    assert wire_key(b"\x79" + frame[1:]) is None
    assert wire_key(frame[:3]) is None


def test_derive_pairs_ors_bits_drops_unarmable_and_sorts():
    got = derive_pairs({0x61: [0], 0x06: [4, 8], 0x10: [16], 0: [1]})
    assert got == ((0x06, 0x0110), (0x61, 0x0001))


def test_harvest_cfg_round_trips_the_encoder_through_hdlc_escaping():
    # levels chosen so the encoded frame contains raw 0x7E and 0x7D bytes
    pairs = ((0x07, 0x7E7D), (0x7D, 0x0001), (0x7E, 0x00FF))
    inner = build_qsh_trace_maskset_set(pairs)
    assert b"\x7e" in inner and b"\x7d" in inner
    noise = _hdlc(bytes((0x73, 0, 0, 0)))  # an unrelated mask frame
    assert harvest_cfg(noise + _hdlc(inner) + noise) == [pairs]


def test_harvest_cfg_skips_a_length_inconsistent_frame():
    inner = bytearray(build_qsh_trace_maskset_set(((0x10, 1), (0x20, 1))))
    inner[4] += 1  # arg_count no longer 3 + count
    assert harvest_cfg(_hdlc(bytes(inner))) == []


def test_bundled_maskset_encodes_as_one_set():
    from diagmunge.qsh_maskset import bundled_maskset
    union = bundled_maskset()
    assert len(build_qsh_trace_maskset_set(union)) == 4 + 16 + 4 * len(union)
    with pytest.raises(KeyError, match="have"):
        bundled_maskset("nope")


def test_load_pairs_file_reads_the_discover_tool_format(tmp_path):
    import json
    from diagmunge.qsh_maskset import load_pairs_file
    f = tmp_path / "mine.json"
    f.write_text(json.dumps({"pairs": [[6, 272], [61, 1], [119, 2]]}) + "\n")
    got = load_pairs_file(f)
    assert got == ((6, 272), (61, 1), (119, 2))
    assert len(build_qsh_trace_maskset_set(got)) == 4 + 16 + 4 * 3


@pytest.mark.parametrize("doc, match", [
    ('{"pairs": [[61, 1], [6, 272]]}', "strictly ascending"),
    ('{"pairs": [[6, 1], [6, 2]]}', "strictly ascending"),
    ('{"pairs": [[0, 1]]}', "ssid"),
    ('{"pairs": [[6, 65536]]}', "level"),
    ('{"pairs": [[6]]}', "not \\[ssid, level\\]"),
    ('{"pairs": [[6, true]]}', "not \\[ssid, level\\]"),
    ('{"pairs": [["6", 1]]}', "not \\[ssid, level\\]"),
    ('{"pairs": []}', "disarm"),
    ('[[6, 1]]', "expected"),
    ('not json', "not JSON"),
])
def test_load_pairs_file_refuses_what_the_modem_would_reject(tmp_path, doc, match):
    from diagmunge.qsh_maskset import load_pairs_file
    f = tmp_path / "bad.json"
    f.write_text(doc)
    with pytest.raises(ValueError, match=match):
        load_pairs_file(f)


def test_load_pairs_file_refuses_over_the_per_set_cap(tmp_path):
    import json
    from diagmunge.qsh_maskset import load_pairs_file
    f = tmp_path / "wide.json"
    f.write_text(json.dumps({"pairs": [[s, 1] for s in range(1, 112)]}))
    with pytest.raises(ValueError, match="cap"):
        load_pairs_file(f)
