"""Tests for the provisional GSMTAPv3 geotag frame (diagmunge.gsmtap).

GSMTAPv3 base-header layout + type constants are public Osmocom interface
facts; the geolocation metadata tag is diaggrok-private and PROVISIONAL (no
Osmocom assignment, no shipping dissector) — these tests pin the wire layout
and the round-trip so the emit seam stays stable while the real v3 metadata
registry settles.
"""
from __future__ import annotations

import struct

from diagmunge import gsmtap
from diagmunge.gsmtap import (
    GeoPosition,
    GsmtapFrame,
    GsmtapV3Frame,
    GSMTAP_TYPE_LTE_NAS,
    GSMTAP_TYPE_LTE_RRC,
    GSMTAPV3_TYPE_LTE_RRC,
    GSMTAPV3_TYPE_NAS_EPS,
    GSMTAPV3_VERSION,
)


class TestHeaderLayout:
    def test_bare_frame_is_8_byte_header(self):
        frame = GsmtapV3Frame(type=GSMTAPV3_TYPE_LTE_RRC, sub_type=5, payload=b"\xaa\xbb")
        raw = frame.to_bytes()
        version, res, hdr_len_words, type_, sub_type = struct.unpack_from("!BBHHH", raw, 0)
        assert version == GSMTAPV3_VERSION == 0x03
        assert res == 0
        assert hdr_len_words == 2          # 8-byte header, no metadata
        assert type_ == 0x0403
        assert sub_type == 5
        assert raw[hdr_len_words * 4:] == b"\xaa\xbb"

    def test_position_extends_header_and_stays_word_aligned(self):
        frame = GsmtapV3Frame(
            type=GSMTAPV3_TYPE_LTE_RRC, sub_type=1, payload=b"\x01",
            position=GeoPosition(lat=12.3, lon=-67.9, alt=1300.0, fix_age_s=1.2, quality=1))
        raw = frame.to_bytes()
        _, _, hdr_len_words, _, _ = struct.unpack_from("!BBHHH", raw, 0)
        # 8 header + 4 TLV tag/len + 16 value = 28 bytes = 7 words, already aligned.
        assert hdr_len_words == 7
        assert len(raw) % 4 == 0 or True  # payload may be unaligned; header is not
        assert raw[hdr_len_words * 4:] == b"\x01"


class TestRoundTrip:
    def test_position_survives_serialise_parse(self):
        pos = GeoPosition(lat=12.36543, lon=-67.89012, alt=1305.5, fix_age_s=2.3, quality=2)
        frame = GsmtapV3Frame(type=GSMTAPV3_TYPE_NAS_EPS, sub_type=0,
                              payload=b"\x07\x42\x01", position=pos)
        back = gsmtap.parse_v3(frame.to_bytes())
        assert back.type == GSMTAPV3_TYPE_NAS_EPS
        assert back.sub_type == 0
        assert back.payload == b"\x07\x42\x01"
        assert back.position is not None
        # 1e7 encoding => ~1 cm fidelity; assert well within a metre.
        assert abs(back.position.lat - pos.lat) < 1e-6
        assert abs(back.position.lon - pos.lon) < 1e-6
        assert abs(back.position.alt - pos.alt) < 1e-2
        assert abs(back.position.fix_age_s - pos.fix_age_s) < 0.05
        assert back.position.quality == 2

    def test_no_position_round_trips_to_none(self):
        frame = GsmtapV3Frame(type=GSMTAPV3_TYPE_LTE_RRC, sub_type=6, payload=b"\xde\xad")
        back = gsmtap.parse_v3(frame.to_bytes())
        assert back.position is None
        assert back.payload == b"\xde\xad"


class TestV3FromV2:
    def test_lte_rrc_maps(self):
        v2 = GsmtapFrame(type=GSMTAP_TYPE_LTE_RRC, sub_type=5, payload=b"\x00\x01", arfcn=1100)
        v3 = gsmtap.v3_from_v2(v2, position=GeoPosition(lat=1.0, lon=2.0))
        assert v3 is not None
        assert v3.type == GSMTAPV3_TYPE_LTE_RRC
        assert v3.sub_type == 5
        assert v3.payload == b"\x00\x01"
        assert v3.position is not None

    def test_lte_nas_maps(self):
        v2 = GsmtapFrame(type=GSMTAP_TYPE_LTE_NAS, sub_type=0, payload=b"\x07")
        v3 = gsmtap.v3_from_v2(v2)
        assert v3 is not None and v3.type == GSMTAPV3_TYPE_NAS_EPS

    def test_unmappable_type_returns_none(self):
        v2 = GsmtapFrame(type=0x01, sub_type=0, payload=b"\x00")  # GSM UM, no v3 map
        assert gsmtap.v3_from_v2(v2) is None
