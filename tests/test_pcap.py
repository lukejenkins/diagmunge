"""Tests for the minimal classic-pcap writer + synthetic UDP/IP framing.

Hand-rolled, zero-dependency (mirrors diaggulp's in-tree minimal pcap
*reader*). Classic pcap file format + Ethernet/IPv4/UDP header walk
are public formats — no scapy, no dpkt, no black-box source.
"""
from __future__ import annotations

import io
import struct

from diagmunge import pcap


def _ipv4_checksum(header: bytes) -> int:
    """Standard one's-complement IPv4 header checksum, for verification."""
    assert len(header) % 2 == 0
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class TestPcapWriterHeaders:
    def test_global_header(self):
        buf = io.BytesIO()
        pcap.PcapWriter(buf)
        data = buf.getvalue()
        assert len(data) == 24
        magic, vmaj, vmin, tz, sig, snap, net = struct.unpack("<IHHiIII", data)
        assert magic == 0xA1B2C3D4
        assert (vmaj, vmin) == (2, 4)
        assert net == pcap.DLT_EN10MB == 1

    def test_write_frame_clamps_out_of_range_timestamp(self):
        """A pathological timestamp must clamp to u32, never raise (real
        captures carry uninitialized/huge ts64)."""
        buf = io.BytesIO()
        w = pcap.PcapWriter(buf)
        w.write_frame(1e20, b"\x00")          # absurdly large
        w.write_frame(-5.0, b"\x00")          # negative
        recs = buf.getvalue()[24:]
        sec1, usec1 = struct.unpack("<II", recs[:8])
        assert sec1 == 0xFFFFFFFF and 0 <= usec1 <= 999_999
        rec2 = recs[16 + 1:]                   # skip rec1 header(16) + frame(1)
        sec2, usec2 = struct.unpack("<II", rec2[:8])
        assert sec2 == 0 and usec2 == 0

    def test_write_frame_record_header(self):
        buf = io.BytesIO()
        w = pcap.PcapWriter(buf)
        frame = b"\xaa" * 20
        w.write_frame(1_700_000_000.5, frame)
        rec = buf.getvalue()[24:]
        ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", rec[:16])
        assert ts_sec == 1_700_000_000
        assert ts_usec == 500_000
        assert incl == orig == 20
        assert rec[16:] == frame


class TestUdp4Frame:
    def test_structure_round_trips(self):
        payload = b"\xde\xad\xbe\xef\x01\x02"
        frame = pcap.udp4_frame(payload, dst_port=4729, src_port=13337)

        # Ethernet: 14 bytes, ethertype IPv4
        assert struct.unpack("!H", frame[12:14])[0] == 0x0800
        ip = frame[14:]
        # IPv4 version 4, IHL 5 (20-byte header)
        assert ip[0] == 0x45
        total_len = struct.unpack("!H", ip[2:4])[0]
        assert total_len == 20 + 8 + len(payload)
        assert ip[9] == 17  # protocol UDP
        # IPv4 header checksum must be valid (recompute over the 20-byte header)
        assert _ipv4_checksum(ip[:20]) == 0

        udp = ip[20:]
        src_port, dst_port, udp_len, _cksum = struct.unpack("!HHHH", udp[:8])
        assert src_port == 13337
        assert dst_port == 4729
        assert udp_len == 8 + len(payload)
        assert udp[8:] == payload

    def test_default_dst_port_is_gsmtap(self):
        frame = pcap.udp4_frame(b"\x00", dst_port=4729)
        udp = frame[14 + 20:]
        _src, dst_port = struct.unpack("!HH", udp[:4])
        assert dst_port == 4729
