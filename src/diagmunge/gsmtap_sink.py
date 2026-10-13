"""Live GSMTAP UDP sink — stream encoded frames to a running Wireshark.

This is the "future live/streaming path" the :mod:`diagmunge.gsmtap` module
docstring anticipates. The same pure ``gsmtap.encode()`` that feeds the batch
DIAG-to-pcap CLI feeds this sink unchanged; the only
difference is the transport:

* **pcap path** — wraps ``frame.to_bytes()`` in a *synthetic* Ethernet/IPv4/UDP
  header (``diagmunge.pcap.udp4_frame``) because a pcap file has no network
  stack, then writes it to disk.
* **live path (this module)** — hands ``frame.to_bytes()`` to a real UDP
  socket; the **kernel** supplies the IP/UDP framing. So the GSMTAP bytes go
  out *raw* as the UDP payload, destined for ``127.0.0.1:4729`` — the port
  Wireshark binds its GSMTAP dissector to (`-i lo -f "udp port 4729"`).

Only GSMTAP-eligible records (LTE RRC ``0xB0C0`` / LTE NAS ``0xB0Ex``) ride
this sink: GSMTAP is a UDP/4729 pseudo-link-layer. NR signalling uses the
Exported-PDU link type and is **not** GSMTAP-expressible, so it cannot
share this port — :mod:`diagmunge.exported_pdu` stays a file-only path.

Clean-room provenance is inherited from :mod:`diagmunge.gsmtap`: the wire bytes
are produced solely by that module's public-spec encoder; this file only opens
a socket and calls ``sendto``. No qcsuper/SCAT source is involved.
"""
from __future__ import annotations

import socket
from typing import Optional

from diagmunge.gsmtap import GSMTAP_UDP_PORT, GsmtapFrame

__all__ = ["GsmtapUdpSink"]


class GsmtapUdpSink:
    """Send :class:`~diagmunge.gsmtap.GsmtapFrame` frames over UDP.

    Defaults to ``127.0.0.1:4729`` (the Wireshark GSMTAP port). Usable as a
    context manager so the socket is always closed::

        with GsmtapUdpSink() as sink:
            for log_code, ts64, payload in iter_records(data):
                sink.send(gsmtap.encode(log_code, parse(...)))

    A caller-supplied ``sock`` is used verbatim — the dependency-injection seam
    that lets tests point the sink at an ephemeral loopback receiver (and lets
    a future tool reuse a pre-configured socket, e.g. with SO_REUSEADDR).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = GSMTAP_UDP_PORT,
                 sock: Optional[socket.socket] = None) -> None:
        self.host = host
        self.port = port
        self.sent = 0
        self._sock = sock if sock is not None else socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, frame: Optional[GsmtapFrame]) -> int:
        """Send one frame; return 1 if sent, 0 if ``frame`` is ``None``.

        ``None`` is accepted (and is a no-op) so callers can pipe
        ``gsmtap.encode()`` straight in without a None-guard at every site —
        an encode miss simply sends nothing, mirroring the pcap path's
        ``encode_skipped`` accounting.
        """
        if frame is None:
            return 0
        self._sock.sendto(frame.to_bytes(), (self.host, self.port))
        self.sent += 1
        return 1

    def close(self) -> None:
        """Close the underlying socket (idempotent)."""
        self._sock.close()

    def __enter__(self) -> "GsmtapUdpSink":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
