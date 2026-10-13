"""Named DIAG log-code presets shared by the filtering consumers.

One source of truth for "which log codes does a GNSS consumer need", read by
the standalone peek-filter CLI (``--preset``) and, per the
consumer-filtering design, by diagbarf's ``--mask gnss`` (via a generated C
header) and diaggpsd's mask ownership.

``GNSS_BASIC`` is fixed: tier-1 NMEA / TPV needs only the ``0x1476``
PositionReport. ``GNSS_EXTENDED`` is defined by the design as *derived* from
diaggpsd's ``required_codes()`` with every tier-2 output enabled, not
hand-listed: a test holds the literal below equal to that function.
"""
from __future__ import annotations

GNSS_BASIC: tuple[int, ...] = (0x1476,)

#: Every GNSS log code diaggpsd consumes with all of its outputs enabled:
#: position (0x1476), the measurement reports behind SKY / RINEX (0x1477,
#: 0x1480, 0x1886, 0x14DE), and the extra codes its JSON stream carries
#: (0x1478 clock, 0x147B SV health, 0x14D8 ME fix, 0x14E1 SV poly). A test pins
#: this equal to ``diaggpsd.required_codes()`` with every output on.
GNSS_EXTENDED: tuple[int, ...] = (
    0x1476, 0x1477, 0x1478, 0x147B, 0x1480, 0x14D8, 0x14DE, 0x14E1, 0x1886,
)

#: CLI name -> log codes. A name absent here is not yet defined.
PRESETS: dict[str, tuple[int, ...]] = {
    "gnss-basic": GNSS_BASIC,
    "gnss-extended": GNSS_EXTENDED,
}
