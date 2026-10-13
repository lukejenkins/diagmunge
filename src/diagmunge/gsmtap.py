"""GSMTAP encapsulation of decoded DIAG records.

Wraps a decoded diaggrok record (e.g. an LTE RRC OTA message) into a GSMTAP
frame so Wireshark's protocol dissectors can decode it. GSMTAP is the
Osmocom pseudo-link-layer that carries cellular signalling PDUs over UDP
port 4729; Wireshark binds the GSMTAP dissector to that port, which in turn
hands the inner PDU to the right dissector (lte-rrc, nas-eps, nr-rrc, ...).

Clean-room provenance
---------------------
The 16-byte GSMTAP header layout and the LTE-RRC sub-type constants below are
taken from the **public Osmocom GSMTAP specification** (``gsmtap.h``). Nothing
here is derived from the qcsuper or SCAT source — those black-box tools are
used only as an *output* oracle (diff our pcap against theirs), never as a
source. This keeps diagmunge's Apache-2.0 licence firewall intact (the same
firewall that keeps scapy (GPL) and pycrate (LGPL) out of the package).

This module is pure: ``encode()`` is a function of a decoded record with no
I/O, so the same code serves the batch DIAG-to-pcap CLI and the
future live/streaming path unchanged. The ``_ENCODERS`` registry is the
per-log-code extensibility seam toward LTE NAS / NR RRC / NR NAS.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import pack, unpack_from
from typing import Any, Callable, Optional

from diaggrok.codes import (
    LOG_LTE_NAS_EMM_PLAIN_OTA_IN_MSG,
    LOG_LTE_NAS_EMM_PLAIN_OTA_OUT_MSG,
    LOG_LTE_NAS_ESM_B0E1,
    LOG_LTE_NAS_ESM_PLAIN_OTA_IN_MSG,
    LOG_LTE_NAS_ESM_PLAIN_OTA_OUT_MSG,
    LOG_LTE_RRC_OTA_MSG,
)

# --- GSMTAP header constants (Osmocom gsmtap.h, public spec) ---------------
GSMTAP_UDP_PORT = 4729
GSMTAP_VERSION = 0x02
GSMTAP_HDR_LEN_WORDS = 4  # header length in 32-bit words = 16 bytes

# arfcn flag bits (Osmocom gsmtap.h): bit 14 marks an uplink PDU.
GSMTAP_ARFCN_F_UPLINK = 0x4000

GSMTAP_TYPE_LTE_RRC = 0x0D

GSMTAP_TYPE_LTE_NAS = 0x12
# GSMTAP_TYPE_LTE_NAS sub-types — Osmocom gsmtap.h. The sub-type is only a
# plain-vs-security-protected selector; Wireshark's nas-eps dissector reads the
# NAS security header out of the PDU bytes itself.
GSMTAP_LTE_NAS_PLAIN = 0
GSMTAP_LTE_NAS_SEC_HEADER = 1

# GSMTAP_TYPE_LTE_RRC sub-types (channel) — Osmocom gsmtap.h
GSMTAP_LTE_RRC_SUB_DL_CCCH = 0
GSMTAP_LTE_RRC_SUB_DL_DCCH = 1
GSMTAP_LTE_RRC_SUB_UL_CCCH = 2
GSMTAP_LTE_RRC_SUB_UL_DCCH = 3
GSMTAP_LTE_RRC_SUB_BCCH_BCH = 4
GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH = 5
GSMTAP_LTE_RRC_SUB_PCCH = 6
GSMTAP_LTE_RRC_SUB_MCCH = 7

_U16_MAX = 0xFFFF


@dataclass
class GsmtapFrame:
    """A single GSMTAP frame: 16-byte header + inner PDU payload."""
    type: int
    sub_type: int
    payload: bytes
    arfcn: int = 0
    frame_number: int = 0
    timeslot: int = 0
    signal_dbm: int = 0
    snr_db: int = 0

    def to_bytes(self) -> bytes:
        """Serialise to the 16-byte big-endian GSMTAP header + payload."""
        header = pack(
            "!BBBBHbbIBBBB",
            GSMTAP_VERSION,
            GSMTAP_HDR_LEN_WORDS,
            self.type & 0xFF,
            self.timeslot & 0xFF,
            self.arfcn & _U16_MAX,
            self.signal_dbm,
            self.snr_db,
            self.frame_number & 0xFFFFFFFF,
            self.sub_type & 0xFF,
            0,  # antenna_nr
            0,  # sub_slot
            0,  # res
        )
        return header + self.payload


# --- per-log-code encoder registry ----------------------------------------
_ENCODERS: dict[int, Callable[[Any], GsmtapFrame | None]] = {}


def register_encoder(log_code: int) -> Callable[
        [Callable[[Any], GsmtapFrame | None]], Callable[[Any], GsmtapFrame | None]]:
    """Register a per-log-code GSMTAP encoder (the family-extensibility seam)."""
    def _wrap(fn: Callable[[Any], GsmtapFrame | None]) -> Callable[[Any], GsmtapFrame | None]:
        _ENCODERS[log_code] = fn
        return fn
    return _wrap


def eligible_codes() -> frozenset[int]:
    """Log codes that have a registered GSMTAP encoder."""
    return frozenset(_ENCODERS)


# Codes on the GSMTAP roadmap: parsers + embedded signalling PDUs already
# exist, but there is no live GSMTAP encoder yet — blocked on the NR-framing
# decision, not on fundamental ineligibility. Curated here, next to
# eligible_codes(), so every consumer shares one source instead of re-hardcoding
# the list in each tool.
_ROADMAP_CODES: frozenset[int] = frozenset(
    {0xB821, 0xB823}              # NR RRC
    | set(range(0xB800, 0xB80C))  # NR NAS 0xB800..0xB80B
    | {0xB814}                    # NR NAS registration
)


def pcap_eligible_codes() -> frozenset[int]:
    """Every code with a live pcap encoder in *any* framing.

    The federation of both output registries: GSMTAP (:func:`eligible_codes`,
    LTE RRC/NAS on UDP/4729) **and** Exported-PDU
    (:func:`diagmunge.exported_pdu.eligible_codes`, NR RRC/NAS on link type 252).
    This is the single library-owned source of truth for "is this code
    pcap-expressible today" — consumers (e.g. the per-modem decode-status
    table's column 8 ✅ tier) render off this instead of re-hardcoding which
    framings exist, so an NR code does not read as unshipped just because it
    rides Exported-PDU rather than GSMTAP.

    The ``exported_pdu`` import is lazy (function-body) to keep the two encoder
    modules independent peers: neither imports the other at module load,
    matching the pure-encoder seam described in this module's docstring."""
    from diagmunge import exported_pdu  # lazy: keep gsmtap/exported_pdu independent
    return eligible_codes() | exported_pdu.eligible_codes()


def roadmap_codes() -> frozenset[int]:
    """Roadmap codes that do not yet carry a live encoder.

    "Roadmap" = the curated set minus every code that already has a live encoder
    in *either* output framing (:func:`pcap_eligible_codes`). NR signalling
    (NR RRC 0xB821, NR NAS 0xB80x) ships via Exported-PDU, so subtracting only
    the GSMTAP registry left those shipped codes wrongly labelled 🟢 roadmap in
    consumers (the per-modem decode-status table's column 8). Federating both
    registries makes the 🟢→✅ transition automatic across both framings — a code
    that graduates in either path leaves the roadmap with no edit here."""
    return _ROADMAP_CODES - pcap_eligible_codes()


def encode(log_code: int, record: Any) -> GsmtapFrame | None:
    """Encode a decoded record to a GsmtapFrame, or None if not encodable.

    Returns None when the log code has no encoder, the record is None, or the
    encoder declines the record (empty PDU, unknown channel, ...).
    """
    if record is None:
        return None
    fn = _ENCODERS.get(log_code)
    if fn is None:
        return None
    return fn(record)


# --- LTE RRC OTA (0xB0C0) --------------------------------------------------
# Key on the canonical channel NAME, not the raw channel_type integer.
# The 0xB0C0 wire format uses DIFFERENT integer enums per version (v20 byte[12]
# is {2:BCCH-DL-SCH, 5:PCCH, 8:UL-CCCH}; the legacy byte[2]-era enum is
# {0x30:BCCH-DL-SCH, 0x0C:PCCH, 0x08:DL-CCCH, ...}), so the same integer means
# different channels on different versions. The parser already resolves
# channel_name correctly per version — encoding off the name is version-robust
# and fixes the pcap channel mislabel that integer keying caused.
_LTE_RRC_CHANNEL_NAME_TO_GSMTAP_SUB: dict[str, int] = {
    "BCCH-BCH": GSMTAP_LTE_RRC_SUB_BCCH_BCH,
    "BCCH-DL-SCH": GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH,
    "PCCH": GSMTAP_LTE_RRC_SUB_PCCH,
    "DL-CCCH": GSMTAP_LTE_RRC_SUB_DL_CCCH,
    "DL-DCCH": GSMTAP_LTE_RRC_SUB_DL_DCCH,
    "UL-CCCH": GSMTAP_LTE_RRC_SUB_UL_CCCH,
    "UL-DCCH": GSMTAP_LTE_RRC_SUB_UL_DCCH,
}


@register_encoder(LOG_LTE_RRC_OTA_MSG)
def encode_0xb0c0(record: Any) -> GsmtapFrame | None:
    """Encode a parsed LTE RRC OTA record (Diag0xB0C0) as a GSMTAP frame.

    Skips (returns None) records with no PDU bytes or an unknown channel
    (which cannot be mapped to a GSMTAP LTE-RRC sub-type and would dissect as
    malformed). Keyed on the canonical channel NAME so it is correct across the
    per-version channel enums.
    """
    msg_data = getattr(record, "msg_data", b"") or b""
    if not msg_data:
        return None
    sub_type = _LTE_RRC_CHANNEL_NAME_TO_GSMTAP_SUB.get(
        getattr(record, "channel_name", None)
    )
    if sub_type is None:
        return None
    # GSMTAP arfcn is u16; LTE EARFCN can exceed 65535 (e.g. band 66). Clamp
    # an out-of-range EARFCN to 0 rather than emit a corrupted value — it is
    # informational only and not needed for dissection.
    earfcn = getattr(record, "earfcn", 0) or 0
    arfcn = earfcn if 0 <= earfcn <= _U16_MAX else 0
    return GsmtapFrame(
        type=GSMTAP_TYPE_LTE_RRC,
        sub_type=sub_type,
        payload=msg_data,
        arfcn=arfcn,
        frame_number=getattr(record, "sfn", 0) or 0,
    )


# --- LTE NAS OTA (0xB0EC/ED EMM plain, 0xB0E2/E3 ESM plain, 0xB0E1) ---------
# GSMTAP wrapping needs only the raw OTA PDU bytes + a plain-vs-protected
# flag — Wireshark's nas-eps does the field decode. So this is independent of
# the TS 24.007 L3 field decoder: we wrap the bytes, Wireshark reads
# them. sec_hdr_type selects the sub-type; a record that does not expose it
# (the bare ESM PDUs of 0xB0E2/0xB0E3) resolves to None -> PLAIN. We
# deliberately do NOT infer sec_hdr_type from nas_pdu[0]>>4 — on an ESM PDU that
# nibble is the EPS bearer id, not a security header. 0xB0E1 is the protected
# outer: it exposes sec_hdr_type=2 and nas_pdu = the whole protected PDU,
# so it frames as GSMTAP_LTE_NAS_SEC_HEADER and nas-eps dissects MAC and SQN.
_NAS_SEC_HDR_PROTECTED = frozenset((1, 2, 3, 4, 12))  # integrity/cipher; 12 = SR


def _encode_lte_nas(record: Any) -> GsmtapFrame | None:
    """Shared encoder for the 0xB0Ex LTE NAS OTA family → GSMTAP type 0x12.

    Returns None when the record carries no PDU bytes. The payload is the raw
    OTA ``nas_pdu`` verbatim (nas-eps decodes it); the sub-type flags whether
    the message is security-protected, and the uplink arfcn flag is set from
    ``is_uplink`` when present (EARFCN is not carried on NAS records, so the
    arfcn field is otherwise 0 — informational only, not needed for dissection).
    """
    nas_pdu = getattr(record, "nas_pdu", b"") or b""
    if not nas_pdu:
        return None
    sec_hdr_type = getattr(record, "sec_hdr_type", None)
    sub_type = (GSMTAP_LTE_NAS_SEC_HEADER
                if sec_hdr_type in _NAS_SEC_HDR_PROTECTED
                else GSMTAP_LTE_NAS_PLAIN)
    arfcn = GSMTAP_ARFCN_F_UPLINK if getattr(record, "is_uplink", False) else 0
    return GsmtapFrame(
        type=GSMTAP_TYPE_LTE_NAS,
        sub_type=sub_type,
        payload=nas_pdu,
        arfcn=arfcn,
    )


# Register the one shared encoder for every NAS OTA code that yields nas_pdu.
# 0xB0E0 (secure incoming twin) is intentionally absent — no corpus capture and
# parser pending; add it the round a capture lands.
for _nas_code in (
    LOG_LTE_NAS_EMM_PLAIN_OTA_IN_MSG,   # 0xB0EC
    LOG_LTE_NAS_EMM_PLAIN_OTA_OUT_MSG,  # 0xB0ED
    LOG_LTE_NAS_ESM_PLAIN_OTA_IN_MSG,   # 0xB0E2
    LOG_LTE_NAS_ESM_PLAIN_OTA_OUT_MSG,  # 0xB0E3
    LOG_LTE_NAS_ESM_B0E1,               # 0xB0E1
):
    register_encoder(_nas_code)(_encode_lte_nas)
del _nas_code


# --- GSMTAPv3 (forward-looking geotag path) ----------------------------
# GSMTAPv3 is the Osmocom draft that adds a length-prefixed header with a
# T16L16V (16-bit tag, 16-bit length, value) metadata area — the mechanism the
# issue wants for carrying a co-temporal position on each signalling frame. The
# base-header field order, the ``version``/``hdr_len``-in-32-bit-words layout,
# and the LTE type constants below are public interface facts (Osmocom
# ``gsmtap_v3.h``), reproduced the same clean-room way the v2 constants above
# were — no qcsuper/SCAT source read.
#
# ⚠️ PROVISIONAL, and deliberately not the primary output. Two facts, both
# verified this session, bound what v3 can be today:
#   1. No shipping Wireshark dissects v3 — tshark 4.4.15 has only
#      ``gsmtap.version`` + ``gsmtap.version.invalid`` and flags a v3 frame as an
#      unknown version, so neither the position NOR the inner RRC/NAS PDU
#      dissects. (Both SCAT and qcsuper still emit plain v2.)
#   2. Osmocom has NOT assigned a geolocation metadata tag as of 2026-08 — the
#      v3 metadata registry is still in flux — so there is no "correct" tag to
#      encode against.
# Consequently the position tag below is a diaggrok-private experimental value,
# and the authoritative, tool-readable geo output is the GeoJSON sidecar +
# per-packet pcapng comments written by the geotagging pcap producer. This
# path exists so the emit seam is in place for the day v3 lands in Wireshark.
GSMTAPV3_VERSION = 0x03
GSMTAPV3_TYPE_LTE_RRC = 0x0403
GSMTAPV3_TYPE_NAS_EPS = 0x0404
GSMTAPV3_TYPE_NR_RRC = 0x0503
GSMTAPV3_TYPE_NAS_5GS = 0x0504

# Shipped-v2 GSMTAP type -> v3 type constant, for reusing the v2 encoders.
_V2_TYPE_TO_V3: dict[int, int] = {
    GSMTAP_TYPE_LTE_RRC: GSMTAPV3_TYPE_LTE_RRC,
    GSMTAP_TYPE_LTE_NAS: GSMTAPV3_TYPE_NAS_EPS,
}

# Provisional diaggrok geolocation metadata tag (T16L16V). Osmocom has assigned
# none; 0xFExx is a private/experimental range unlikely to collide with a future
# real assignment. Value is 16 bytes, big-endian to match the v2 family:
#   int32  lat_e7    latitude  x 1e7 degrees   (WGS84)
#   int32  lon_e7    longitude x 1e7 degrees
#   int32  alt_mm    altitude in millimetres
#   uint16 fix_age_ds  age of the joined fix in deciseconds (0xFFFF = unknown)
#   uint16 quality   NMEA GGA fix quality (0 = none/unset)
GSMTAPV3_TAG_GEOLOC = 0xFE01
_GEO_STRUCT = "!iiiHH"
_GEO_VALUE_LEN = 16  # struct.calcsize(_GEO_STRUCT)
_GEO_AGE_UNKNOWN = 0xFFFF


@dataclass
class GeoPosition:
    """A WGS84 position joined to a signalling frame (see :class:`GsmtapV3Frame`)."""
    lat: float
    lon: float
    alt: float = 0.0
    fix_age_s: float = -1.0  # <0 => unknown
    quality: int = 0

    def to_tlv(self) -> bytes:
        """Serialise as the provisional geolocation T16L16V metadata element."""
        age_ds = (_GEO_AGE_UNKNOWN if self.fix_age_s < 0
                  else min(int(round(self.fix_age_s * 10)), _GEO_AGE_UNKNOWN - 1))
        value = pack(
            _GEO_STRUCT,
            int(round(self.lat * 1e7)),
            int(round(self.lon * 1e7)),
            int(round(self.alt * 1000)),
            age_ds,
            self.quality & 0xFFFF,
        )
        return pack("!HH", GSMTAPV3_TAG_GEOLOC, len(value)) + value


@dataclass
class GsmtapV3Frame:
    """A GSMTAPv3 frame: length-prefixed header + T16L16V metadata + inner PDU.

    ``position`` (when set) is emitted as the provisional geolocation metadata
    element; the inner ``payload`` is the same OTA PDU the v2 encoders carry.
    """
    type: int
    sub_type: int
    payload: bytes
    position: Optional[GeoPosition] = None

    def to_bytes(self) -> bytes:
        """Serialise to the GSMTAPv3 wire format (big-endian).

        ``hdr_len`` counts the whole header (global + metadata) in 32-bit words,
        so the metadata area is zero-padded up to a 4-byte boundary.
        """
        meta = self.position.to_tlv() if self.position is not None else b""
        meta += b"\x00" * ((-len(meta)) % 4)  # pad to a 32-bit-word boundary
        hdr_len_words = (8 + len(meta)) // 4
        header = pack("!BBHHH", GSMTAPV3_VERSION, 0, hdr_len_words,
                      self.type & 0xFFFF, self.sub_type & 0xFFFF)
        return header + meta + self.payload


def v3_from_v2(frame: GsmtapFrame,
               position: Optional[GeoPosition] = None) -> GsmtapV3Frame | None:
    """Lift a v2 :class:`GsmtapFrame` to a :class:`GsmtapV3Frame`, or None.

    Reuses the shipped, tested v2 encoders (which pick the type / sub_type /
    inner PDU from a decoded record) and only re-frames the result as v3,
    stamping ``position`` when supplied. Returns ``None`` for a v2 type with no
    v3 mapping (so an un-mappable frame is skipped, never mis-typed)."""
    v3_type = _V2_TYPE_TO_V3.get(frame.type)
    if v3_type is None:
        return None
    return GsmtapV3Frame(type=v3_type, sub_type=frame.sub_type,
                         payload=frame.payload, position=position)


def parse_v3(buf: bytes) -> GsmtapV3Frame:
    """Parse a GSMTAPv3 frame (the round-trip inverse of ``to_bytes``).

    Walks the T16L16V metadata to recover a geolocation element when present.
    Used by the tests (no shipping dissector reads v3 yet); tolerant of unknown
    tags, which it skips."""
    version, _res, hdr_len_words, type_, sub_type = unpack_from("!BBHHH", buf, 0)
    if version != GSMTAPV3_VERSION:
        raise ValueError(f"not a GSMTAPv3 frame (version 0x{version:02x})")
    hdr_len = hdr_len_words * 4
    meta = buf[8:hdr_len]
    payload = buf[hdr_len:]
    position = None
    off = 0
    while off + 4 <= len(meta):
        tag, ln = unpack_from("!HH", meta, off)
        value = meta[off + 4:off + 4 + ln]
        if tag == GSMTAPV3_TAG_GEOLOC and len(value) >= _GEO_VALUE_LEN:
            lat_e7, lon_e7, alt_mm, age_ds, quality = unpack_from(_GEO_STRUCT, value, 0)
            position = GeoPosition(
                lat=lat_e7 / 1e7, lon=lon_e7 / 1e7, alt=alt_mm / 1000.0,
                fix_age_s=(-1.0 if age_ds == _GEO_AGE_UNKNOWN else age_ds / 10.0),
                quality=quality)
        off += 4 + ln + ((-ln) % 4)  # values are padded to a 32-bit boundary
    return GsmtapV3Frame(type=type_, sub_type=sub_type, payload=payload,
                         position=position)
