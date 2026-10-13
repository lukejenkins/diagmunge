"""Minimal classic-pcap writer + synthetic Ethernet/IPv4/UDP framing.

Zero-dependency, hand-rolled — mirroring diaggulp's in-tree minimal pcap
*reader*. The classic libpcap file format and the Ethernet/IPv4/UDP
header layout are public formats; nothing here pulls in scapy (GPLv2) or
dpkt, keeping diagmunge's Apache-2.0 licence firewall intact.

The synthetic UDP framing exists so GSMTAP payloads land on UDP port 4729 —
the port Wireshark binds the GSMTAP dissector to — which means a produced
pcap dissects with no manual "decode as".

``PcapWriter`` is a class (not a one-shot helper) so the future live path can
hold it open and append frames to a growing file unchanged.
"""
from __future__ import annotations

from struct import pack
from typing import BinaryIO

# Link-layer header type: Ethernet (libpcap DLT_EN10MB).
DLT_EN10MB = 1

_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION = (2, 4)
_DEFAULT_SNAPLEN = 262_144

_ETHERTYPE_IPV4 = 0x0800
_IP_PROTO_UDP = 17
# Loopback addresses for the synthetic frames; the content is what matters,
# not the (fabricated) endpoints.
_SRC_IP = bytes((127, 0, 0, 1))
_DST_IP = bytes((127, 0, 0, 1))
_DEFAULT_SRC_PORT = 13337


class PcapWriter:
    """Write a classic (little-endian) pcap stream frame by frame."""

    def __init__(self, fobj: BinaryIO, linktype: int = DLT_EN10MB,
                 snaplen: int = _DEFAULT_SNAPLEN) -> None:
        self._f = fobj
        self._snaplen = snaplen
        self._f.write(pack(
            "<IHHiIII",
            _PCAP_MAGIC,
            _PCAP_VERSION[0],
            _PCAP_VERSION[1],
            0,            # thiszone (GMT)
            0,            # sigfigs
            snaplen,
            linktype,
        ))

    def write_frame(self, ts_unix: float, frame: bytes) -> None:
        """Append one captured frame with a Unix-epoch timestamp.

        ``ts_sec`` is clamped to the u32 range so a pathological timestamp
        (real captures carry uninitialized/huge ts64) can never
        raise mid-write.
        """
        ts_sec = int(ts_unix)
        ts_usec = int(round((ts_unix - ts_sec) * 1_000_000))
        if ts_usec >= 1_000_000:  # rounding spill
            ts_sec += 1
            ts_usec -= 1_000_000
        if ts_sec < 0:
            ts_sec, ts_usec = 0, 0
        elif ts_sec > 0xFFFFFFFF:
            ts_sec, ts_usec = 0xFFFFFFFF, 0
        if ts_usec < 0:
            ts_usec = 0
        incl = min(len(frame), self._snaplen)
        self._f.write(pack("<IIII", ts_sec, ts_usec, incl, len(frame)))
        self._f.write(frame[:incl])


# --- minimal pcapng writer (per-packet comments) --------------------------
# pcapng is used instead of classic pcap only where a per-packet annotation is
# needed: the geotagging pcap producer writes each
# signalling frame's co-temporal lat/lon into the Enhanced Packet Block's
# ``opt_comment`` so it is visible + filterable (``frame.comment``) in today's
# Wireshark — which does NOT yet dissect a GSMTAPv3 position element. The block
# layout is the public pcapng spec; this mirrors diaggulp's in-tree pcapng
# *reader* with no new dependency.
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_EPB = 0x00000006
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_PCAPNG_OPT_ENDOFOPT = 0
_PCAPNG_OPT_COMMENT = 1        # opt_comment (any block)
_PCAPNG_OPT_SHB_USERAPPL = 4   # shb_userappl
_PCAPNG_OPT_IF_TSRESOL = 9     # if_tsresol
_TSRESOL_MICROSECONDS = 6      # 10^-6 s per timestamp unit


def _pcapng_pad4(b: bytes) -> bytes:
    """Zero-pad ``b`` up to a 32-bit boundary (pcapng aligns everything to 4)."""
    return b + b"\x00" * ((-len(b)) % 4)


def _pcapng_option(code: int, value: bytes) -> bytes:
    """One pcapng option: code(u16) + length(u16, unpadded) + padded value."""
    return pack("<HH", code, len(value)) + _pcapng_pad4(value)


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    """Wrap a block body in its type + (leading & trailing) total-length fields."""
    body = _pcapng_pad4(body)
    total = 12 + len(body)
    return pack("<II", block_type, total) + body + pack("<I", total)


class PcapngWriter:
    """Write a little-endian pcapng stream with optional per-packet comments.

    One interface (``linktype``, id 0) is declared up front, timestamped in
    microseconds. Use ``write_frame(ts, frame, comment=...)`` to annotate a frame
    — the comment lands in the packet's ``opt_comment`` (Wireshark's "Packet
    Comment").

    :meth:`add_interface` declares a further link type in the same section, so
    one stream can carry frames of different link types (GSMTAP-in-UDP LTE on
    Ethernet beside NR on Exported-PDU, DLT 252) — which classic pcap,
    with its single file-wide link type, cannot. Pass the returned id as
    ``write_frame(..., interface_id=)``."""

    def __init__(self, fobj: BinaryIO, linktype: int = DLT_EN10MB,
                 snaplen: int = _DEFAULT_SNAPLEN,
                 application: str = "diaggrok") -> None:
        self._f = fobj
        self._snaplen = snaplen
        shb_opts = b""
        if application:
            shb_opts = (_pcapng_option(_PCAPNG_OPT_SHB_USERAPPL, application.encode())
                        + pack("<HH", _PCAPNG_OPT_ENDOFOPT, 0))
        shb_body = pack("<IHHq", _PCAPNG_BYTE_ORDER_MAGIC, 1, 0, -1) + shb_opts
        self._f.write(_pcapng_block(_PCAPNG_SHB, shb_body))
        self._n_ifaces = 0
        self.add_interface(linktype)

    def add_interface(self, linktype: int) -> int:
        """Declare another interface (an IDB) and return its id.

        Call it before the first frame that uses the new id: a pcapng reader
        resolves an EPB's interface id against the IDBs it has already read.
        """
        idb_opts = (_pcapng_option(_PCAPNG_OPT_IF_TSRESOL, bytes([_TSRESOL_MICROSECONDS]))
                    + pack("<HH", _PCAPNG_OPT_ENDOFOPT, 0))
        idb_body = pack("<HHI", linktype & 0xFFFF, 0, self._snaplen) + idb_opts
        self._f.write(_pcapng_block(_PCAPNG_IDB, idb_body))
        self._n_ifaces += 1
        return self._n_ifaces - 1

    def write_frame(self, ts_unix: float, frame: bytes,
                    comment: str | None = None, interface_id: int = 0) -> None:
        """Append one frame (an Enhanced Packet Block) with an optional comment.

        ``ts_unix`` is stored at microsecond resolution; a non-positive or
        out-of-range value clamps to 0 rather than raising mid-write (real
        captures carry uninitialized ts)."""
        ts = int(round(ts_unix * 1_000_000)) if ts_unix and ts_unix > 0 else 0
        if ts < 0:
            ts = 0
        ts &= 0xFFFFFFFFFFFFFFFF
        incl = min(len(frame), self._snaplen)
        opts = b""
        if comment:
            opts = (_pcapng_option(_PCAPNG_OPT_COMMENT, comment.encode("utf-8"))
                    + pack("<HH", _PCAPNG_OPT_ENDOFOPT, 0))
        if not 0 <= interface_id < self._n_ifaces:
            raise ValueError(f"interface_id {interface_id} not declared "
                             f"({self._n_ifaces} interface(s))")
        body = (pack("<IIIII", interface_id, (ts >> 32) & 0xFFFFFFFF,
                     ts & 0xFFFFFFFF, incl, len(frame))
                + _pcapng_pad4(frame[:incl]) + opts)
        self._f.write(_pcapng_block(_PCAPNG_EPB, body))


def _ipv4_checksum(header: bytes) -> int:
    """One's-complement checksum over a 20-byte IPv4 header."""
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp4_frame(payload: bytes, dst_port: int,
               src_port: int = _DEFAULT_SRC_PORT) -> bytes:
    """Wrap ``payload`` in Ethernet + IPv4 + UDP headers (DLT_EN10MB).

    The IPv4 header checksum is computed; the UDP checksum is left 0
    (legal/disabled for IPv4). Wireshark dissects the inner payload by the
    UDP destination port.
    """
    udp_len = 8 + len(payload)
    udp = pack("!HHHH", src_port, dst_port, udp_len, 0) + payload

    total_len = 20 + udp_len
    ip_no_cksum = (
        pack("!BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, _IP_PROTO_UDP, 0)
        + _SRC_IP + _DST_IP
    )
    cksum = _ipv4_checksum(ip_no_cksum)
    ip = ip_no_cksum[:10] + pack("!H", cksum) + ip_no_cksum[12:]

    eth = b"\x00" * 6 + b"\x00" * 6 + pack("!H", _ETHERTYPE_IPV4)
    return eth + ip + udp
