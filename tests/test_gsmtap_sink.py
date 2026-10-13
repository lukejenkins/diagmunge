"""Tests for the live GSMTAP UDP sink (diagmunge.gsmtap_sink).

The sink streams ``gsmtap.encode()`` frames to a UDP socket (default
127.0.0.1:4729) so a live Wireshark — which binds its GSMTAP dissector to
that port — decodes them in real time. This is the "future live/streaming
path" the gsmtap module docstring anticipates: the same pure ``encode()``
serves both the batch pcap CLI and this sink unchanged.

Clean-room note: nothing here derives from qcsuper/SCAT source. The only
wire format asserted is the public Osmocom GSMTAP header (via
``GsmtapFrame.to_bytes()``); the kernel supplies the IP/UDP framing for a
live socket, so — unlike the pcap path — there is NO synthetic
Ethernet/IPv4/UDP wrapper around the GSMTAP bytes.
"""
from __future__ import annotations

import socket

import pytest

from diagmunge import gsmtap
from diagmunge.gsmtap_sink import GsmtapUdpSink


def _make_frame(payload: bytes = b"\xab\xcd") -> gsmtap.GsmtapFrame:
    return gsmtap.GsmtapFrame(
        type=gsmtap.GSMTAP_TYPE_LTE_RRC,
        sub_type=gsmtap.GSMTAP_LTE_RRC_SUB_DL_CCCH,
        payload=payload,
    )


@pytest.fixture
def udp_receiver():
    """A bound loopback UDP receiver on an OS-assigned ephemeral port.

    Port 0 lets the OS pick a free port — avoids root (4729 is < 1024? no,
    but a real Wireshark may already hold 4729) and keeps the test hermetic.
    """
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(2.0)
    try:
        yield rx, rx.getsockname()
    finally:
        rx.close()


def test_send_delivers_raw_gsmtap_bytes(udp_receiver):
    """The bytes on the wire are EXACTLY frame.to_bytes() — no IP/UDP wrapper."""
    rx, (host, port) = udp_receiver
    frame = _make_frame(b"\x00\x01\x02\x03")
    with GsmtapUdpSink(host=host, port=port) as sink:
        sink.send(frame)
    got, _ = rx.recvfrom(4096)
    assert got == frame.to_bytes()
    # GSMTAP header sanity: version 0x02, hdr_len 4 words, type LTE_RRC.
    assert got[0] == gsmtap.GSMTAP_VERSION
    assert got[1] == gsmtap.GSMTAP_HDR_LEN_WORDS
    assert got[2] == gsmtap.GSMTAP_TYPE_LTE_RRC
    assert got[16:] == b"\x00\x01\x02\x03"


def test_default_target_is_gsmtap_port():
    """Default destination is the Wireshark-bound GSMTAP port, localhost."""
    sink = GsmtapUdpSink()
    try:
        assert sink.host == "127.0.0.1"
        assert sink.port == gsmtap.GSMTAP_UDP_PORT == 4729
    finally:
        sink.close()


def test_send_returns_frame_count(udp_receiver):
    """send() reports 1 (sent) so callers can tally; sent counter accrues."""
    rx, (host, port) = udp_receiver
    with GsmtapUdpSink(host=host, port=port) as sink:
        assert sink.send(_make_frame()) == 1
        assert sink.send(_make_frame()) == 1
        assert sink.sent == 2
    # both frames really arrived
    rx.recvfrom(4096)
    rx.recvfrom(4096)


def test_send_none_is_a_noop(udp_receiver):
    """Passing None (an encode() miss) sends nothing and counts nothing."""
    rx, (host, port) = udp_receiver
    with GsmtapUdpSink(host=host, port=port) as sink:
        assert sink.send(None) == 0
        assert sink.sent == 0
    rx.settimeout(0.2)
    with pytest.raises(socket.timeout):
        rx.recvfrom(4096)


def test_context_manager_closes_socket():
    """Exiting the context closes the underlying socket."""
    with GsmtapUdpSink() as sink:
        sock = sink._sock
    # A closed socket raises OSError on use.
    with pytest.raises(OSError):
        sock.send(b"x")


def test_injected_socket_is_used(udp_receiver):
    """A caller-supplied socket is used verbatim (DI seam for tests/tools)."""
    rx, (host, port) = udp_receiver
    my_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink = GsmtapUdpSink(host=host, port=port, sock=my_sock)
    assert sink._sock is my_sock
    sink.send(_make_frame(b"\xde\xad"))
    got, _ = rx.recvfrom(4096)
    assert got[16:] == b"\xde\xad"
    sink.close()
