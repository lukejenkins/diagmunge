"""Tests for the minimal pcapng writer with per-packet comments.

pcapng block layout is the public spec. The reader below is a self-contained
round-trip check (no tshark needed); the tshark dissection + frame.comment
visibility are verified interactively against a real tshark.
"""
from __future__ import annotations

import io
import struct

from diagmunge import pcap


def _read_pcapng(data: bytes):
    """Yield (ts_unix, packet_bytes, comment_or_None) for each EPB. Minimal."""
    off = 0
    ns_per_unit = 1_000_000  # will be overridden from if_tsresol
    while off + 12 <= len(data):
        btype, total = struct.unpack_from("<II", data, off)
        body = data[off + 8:off + total - 4]
        if btype == pcap._PCAPNG_IDB:
            # linktype(2) res(2) snaplen(4) then options
            opt = 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack_from("<HH", body, opt)
                val = body[opt + 4:opt + 4 + olen]
                if code == 0:
                    break
                if code == pcap._PCAPNG_OPT_IF_TSRESOL and olen >= 1:
                    ns_per_unit = 10 ** (6 - val[0]) * 1000 if val[0] <= 6 else 1
                opt += 4 + olen + ((-olen) % 4)
        elif btype == pcap._PCAPNG_EPB:
            if_id, ts_hi, ts_lo, cap, orig = struct.unpack_from("<IIIII", body, 0)
            ts_units = (ts_hi << 32) | ts_lo
            packet = body[20:20 + cap]
            # options begin after the 32-bit-padded packet data
            opt = 20 + cap + ((-cap) % 4)
            comment = None
            while opt + 4 <= len(body):
                code, olen = struct.unpack_from("<HH", body, opt)
                val = body[opt + 4:opt + 4 + olen]
                if code == 0:
                    break
                if code == pcap._PCAPNG_OPT_COMMENT:
                    comment = val.decode("utf-8")
                opt += 4 + olen + ((-olen) % 4)
            # if_tsresol=6 -> microseconds -> unix seconds
            yield ts_units / 1_000_000.0, packet, comment
        off += total


class TestPcapngWriter:
    def test_header_blocks_present(self):
        buf = io.BytesIO()
        pcap.PcapngWriter(buf)
        data = buf.getvalue()
        btype, _ = struct.unpack_from("<II", data, 0)
        assert btype == pcap._PCAPNG_SHB
        magic = struct.unpack_from("<I", data, 8)[0]
        assert magic == pcap._PCAPNG_BYTE_ORDER_MAGIC

    def test_frame_without_comment_round_trips(self):
        buf = io.BytesIO()
        w = pcap.PcapngWriter(buf)
        w.write_frame(1712000000.5, b"\x11\x22\x33")
        frames = list(_read_pcapng(buf.getvalue()))
        assert len(frames) == 1
        ts, packet, comment = frames[0]
        assert abs(ts - 1712000000.5) < 1e-3
        assert packet == b"\x11\x22\x33"
        assert comment is None

    def test_frame_with_comment_round_trips(self):
        buf = io.BytesIO()
        w = pcap.PcapngWriter(buf)
        w.write_frame(1712000000.0, b"\xab\xcd", comment="lat=12.3,lon=-67.9")
        w.write_frame(1712000001.0, b"\xef", comment=None)
        frames = list(_read_pcapng(buf.getvalue()))
        assert len(frames) == 2
        assert frames[0][2] == "lat=12.3,lon=-67.9"
        assert frames[1][2] is None
        assert frames[0][1] == b"\xab\xcd"

    def test_odd_length_frame_pads_correctly(self):
        # 5-byte packet forces a 3-byte pad; the reader must still find options.
        buf = io.BytesIO()
        w = pcap.PcapngWriter(buf)
        w.write_frame(1.0, b"\x01\x02\x03\x04\x05", comment="x")
        frames = list(_read_pcapng(buf.getvalue()))
        assert frames[0][1] == b"\x01\x02\x03\x04\x05"
        assert frames[0][2] == "x"

    def test_second_interface_carries_its_own_linktype(self):
        """One stream, two link types (GSMTAP-on-Ethernet + DLT 252)."""
        buf = io.BytesIO()
        w = pcap.PcapngWriter(buf)
        assert w.add_interface(252) == 1
        w.write_frame(1.0, b"\x01", interface_id=0)
        w.write_frame(2.0, b"\x02", interface_id=1)
        data, off, idbs, epb_ifaces = buf.getvalue(), 0, [], []
        while off < len(data):
            btype, total = struct.unpack_from("<II", data, off)
            if btype == pcap._PCAPNG_IDB:
                idbs.append(struct.unpack_from("<H", data, off + 8)[0])
            elif btype == pcap._PCAPNG_EPB:
                epb_ifaces.append(struct.unpack_from("<I", data, off + 8)[0])
            off += total
        assert idbs == [pcap.DLT_EN10MB, 252]
        assert epb_ifaces == [0, 1]

    def test_undeclared_interface_is_refused(self):
        w = pcap.PcapngWriter(io.BytesIO())
        try:
            w.write_frame(1.0, b"\x01", interface_id=1)
        except ValueError:
            return
        raise AssertionError("an EPB naming an undeclared IDB must not be written")
