"""Wireshark Exported-PDU encapsulation of decoded DIAG records (NR signaling).

The NR-signaling sibling of :mod:`diagmunge.gsmtap`. 5G NR RRC and NR NAS OTA
bytes cannot ride plain GSMTAP — the public ``gsmtap.h`` type range ends at
``GSMTAP_TYPE_GSM_RLP = 0x14`` with no NR type, and stock tshark binds no
``gsmtap.type`` to ``nr-rrc`` / ``nas-5gs``. So NR gets a
second, parallel output framing: a **Wireshark Exported-PDU** record
(``DLT_WIRESHARK_UPPER_PDU`` = 252) tagged with the stock NR dissector name.
The framing was chosen after confirming that stock tshark 4.6.6 dissects these
records.

```
DIAG → diaggrok.parse (0xB821 NR RRC / 0xB80x NR NAS) → Exported-PDU record
   (EXP_PDU_TAG_DISSECTOR_NAME tag) → classic .pcap → tshark dissects as
   nr-rrc.<channel> / nas-5gs
```

Clean-room provenance
---------------------
The Exported-PDU tag layout is read from the **public** ``epan/exported_pdu.h``
constants (facts, not copied code); the NR dissector names are read from
``tshark -G dissectors``. As with :mod:`diagmunge.gsmtap`, qcsuper / SCAT /
Wireshark are an **output oracle, never a source** — the encoder does no field
decode, it wraps the parser's verbatim OTA PDU and the stock dissector decodes
it. This keeps diagmunge's Apache-2.0-licence firewall intact (the same firewall
that keeps scapy (GPL) and pycrate (LGPL) out of the package); the alternative
``qcdiag.log.nr_rrc`` framing was rejected partly to avoid reverse-engineering
qcsuper/SCAT framing.

This module is pure: ``encode()`` is a function of a decoded record with no I/O,
so the same code serves the batch DIAG-to-pcap CLI and the future
live path unchanged. ``_ENCODERS`` is the per-log-code extensibility seam.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import pack
from typing import Any, Callable

from diaggrok.codes import LOG_NR5G_RRC_OTA_MSG

# --- Exported-PDU constants (public epan/exported_pdu.h) --------------------
# libpcap link-layer header type for a Wireshark Upper-PDU export.
DLT_WIRESHARK_UPPER_PDU = 252

# Option tags. A record is a sequence of (u16 type, u16 length, value) options
# terminated by an END_OF_OPT tag (type 0, length 0); the verbatim PDU follows.
EXP_PDU_TAG_END_OF_OPT = 0
# Carry the target dissector by its registered short name (string value).
EXP_PDU_TAG_DISSECTOR_NAME = 12


def exported_pdu_block(dissector_name: str, pdu: bytes) -> bytes:
    """Build one Exported-PDU record: a dissector-name tag + the verbatim PDU.

    Layout (all multi-byte fields big-endian / network order, per the public
    ``epan/exported_pdu.h`` and the stock packet-exported_pdu dissector, which
    advances by exactly each tag's declared length — so values are NOT padded):

        [u16 EXP_PDU_TAG_DISSECTOR_NAME][u16 len][name bytes]
        [u16 EXP_PDU_TAG_END_OF_OPT    ][u16 0  ]
        [verbatim PDU ...]

    The frame *is* this block — a ``DLT_WIRESHARK_UPPER_PDU`` pcap carries it
    directly (no Ethernet/IP/UDP wrapper, unlike the GSMTAP path).
    """
    name = dissector_name.encode("ascii")
    return (
        pack("!HH", EXP_PDU_TAG_DISSECTOR_NAME, len(name)) + name
        + pack("!HH", EXP_PDU_TAG_END_OF_OPT, 0)
        + pdu
    )


@dataclass
class ExportedPduFrame:
    """A single Exported-PDU frame: a dissector-name tag + verbatim PDU."""
    dissector_name: str
    payload: bytes

    def to_bytes(self) -> bytes:
        return exported_pdu_block(self.dissector_name, self.payload)


# --- per-log-code encoder registry ----------------------------------------
_ENCODERS: dict[int, Callable[[Any], ExportedPduFrame | None]] = {}


def register_encoder(log_code: int) -> Callable[
        [Callable[[Any], ExportedPduFrame | None]],
        Callable[[Any], ExportedPduFrame | None]]:
    """Register a per-log-code Exported-PDU encoder (family-extensibility seam)."""
    def _wrap(fn: Callable[[Any], ExportedPduFrame | None]) -> Callable[[Any], ExportedPduFrame | None]:
        _ENCODERS[log_code] = fn
        return fn
    return _wrap


def eligible_codes() -> frozenset[int]:
    """Log codes that have a registered Exported-PDU encoder."""
    return frozenset(_ENCODERS)


def encode(log_code: int, record: Any) -> ExportedPduFrame | None:
    """Encode a decoded record to an ExportedPduFrame, or None if not encodable.

    Returns None when the log code has no encoder, the record is None, or the
    encoder declines the record (empty PDU, unknown channel, ...).
    """
    if record is None:
        return None
    fn = _ENCODERS.get(log_code)
    if fn is None:
        return None
    return fn(record)


# --- NR RRC OTA (0xB821) → nr-rrc.<channel> ------------------------
# The 0xB821 parser resolves the canonical 3GPP TS 38.331 logical-channel name
# per its version-keyed pdu_id map. NR RRC routes by channel because the
# ASN.1 entry point differs per channel — each channel has its own stock
# dissector (verified `tshark -G dissectors | grep '^nr-rrc\.'`, 4.6.6). Keyed
# on the channel NAME (version-robust), mirroring the LTE-RRC encoder.
_NR_RRC_CHANNEL_NAME_TO_DISSECTOR: dict[str, str] = {
    "BCCH-BCH": "nr-rrc.bcch.bch",
    "BCCH-DL-SCH": "nr-rrc.bcch.dl.sch",
    "DL-CCCH": "nr-rrc.dl.ccch",
    "DL-DCCH": "nr-rrc.dl.dcch",
    "UL-CCCH": "nr-rrc.ul.ccch",
    "UL-DCCH": "nr-rrc.ul.dcch",
    "PCCH": "nr-rrc.pcch",
    "MCCH": "nr-rrc.mcch",
    # SCAT's pdu_id map names two records by MESSAGE TYPE rather than logical
    # channel — pdu_id 9/10 → RRC-RECONF / RRC-RECONF-COMPLETE (the v9/v12/v14/
    # v17 maps in parsers/diag_0xb821.py). The payload is a *bare*
    # RRCReconfiguration / RRCReconfigurationComplete (not a DL-DCCH-Message),
    # so it routes to the stock message-level dissectors, verified against
    # tshark -G dissectors (nr-rrc.rrc_reconf / nr-rrc.rrc_reconf_compl) and
    # confirmed dissecting the rm520n v17 diag_capture2 records.
    "RRC-RECONF": "nr-rrc.rrc_reconf",
    "RRC-RECONF-COMPLETE": "nr-rrc.rrc_reconf_compl",
    # UL-CCCH1 (rrcResumeRequest1): the parser maps it, so it needs an entry
    # here or its records are silently encode_skipped.
    "UL-CCCH1": "nr-rrc.ul.ccch1",
    # Standalone SIB records: a bare SIB SEQUENCE on a
    # per-version pdu_id (parsers/diag_0xb821._STANDALONE_SIB_PDU_IDS), routed
    # to the stock per-SIB dissectors (tshark -G dissectors: nr-rrc.sib2/4/5).
    "SIB2": "nr-rrc.sib2",
    "SIB4": "nr-rrc.sib4",
    "SIB5": "nr-rrc.sib5",
    # v12 pdu_id 25: a bare RadioBearerConfig (EN-DC SCG bearer add),
    # byte-equal to the LTE nr-RadioBearerConfig2-r15 that carried it.
    "RADIO-BEARER-CONFIG": "nr-rrc.radiobearerconfig",
}


@register_encoder(LOG_NR5G_RRC_OTA_MSG)  # 0xB821
def encode_nr_rrc(record: Any) -> ExportedPduFrame | None:
    """Encode a parsed NR RRC OTA record (Diag0xB821) as an Exported-PDU frame.

    Skips (returns None) records with no PDU bytes or an unmapped channel (which
    has no ``nr-rrc.<channel>`` dissector and would dissect as malformed). The
    payload is the raw ASN.1 PER ``msg_data`` verbatim — the stock per-channel
    nr-rrc dissector does the ASN.1 decode. Keyed on the canonical channel name
    so it is correct across the per-version pdu_id enums.
    """
    msg_data = getattr(record, "msg_data", b"") or b""
    if not msg_data:
        return None
    dissector = _NR_RRC_CHANNEL_NAME_TO_DISSECTOR.get(
        getattr(record, "channel_name", None)
    )
    if dissector is None:
        return None
    return ExportedPduFrame(dissector_name=dissector, payload=msg_data)


# --- NR NAS OTA (0xB800–B80B) → nas-5gs ----------------------------
# 5GS NAS is a single dissector tag (no per-channel routing, unlike NR RRC):
# the nas-5gs dissector reads the 5GMM/5GSM EPD and — for the security-protected
# codes 0xB808/B809 — the outer 5GS security header out of the PDU bytes itself.
# So, exactly like the LTE NAS GSMTAP encoder, the encoder just wraps
# the verbatim OTA ``nas_pdu`` (which starts at the EPD and includes any security
# header); Wireshark does the field decode. A ciphered inner (sec_hdr_type 2/4)
# stays opaque but the security header still dissects — correct behavior.
_NAS_5GS_DISSECTOR = "nas-5gs"

# The 5GS NAS OTA codes (TS 24.501): 5GSM plain in/out, 5GSM security-protected
# in/out, 5GMM plain in/out. All decode to Nr5gNasOtaMsg, exposing nas_pdu.
_NR_NAS_OTA_CODES = (
    0xB800,  # LOG_NR5G_NAS_SM5G_PLAIN_OTA_INCOMING_MSG
    0xB801,  # LOG_NR5G_NAS_SM5G_PLAIN_OTA_OUTGOING_MSG
    0xB808,  # LOG_NR5G_NAS_MM5G_SECURITY_PROTECTED_OTA_INCOMING_MSG
    0xB809,  # LOG_NR5G_NAS_MM5G_SECURITY_PROTECTED_OTA_OUTGOING_MSG
    0xB80A,  # LOG_NR5G_NAS_MM5G_PLAIN_OTA_INCOMING_MSG
    0xB80B,  # LOG_NR5G_NAS_MM5G_PLAIN_OTA_OUTGOING_MSG
    0xB814,  # NR5G NAS 5GMM Plain OTA Container — parser already decodes
             # to Nr5gNasOtaMsg (registration/service/config-update bodies) and
             # exposes nas_pdu, so it rides the identical nas-5gs path.
)


def encode_nr_nas(record: Any) -> ExportedPduFrame | None:
    """Encode a parsed NR NAS OTA record (Nr5gNasOtaMsg) as an Exported-PDU frame.

    Returns None when the record carries no PDU bytes. The payload is the raw OTA
    ``nas_pdu`` verbatim (starting at the EPD, including any 5GS security header);
    the single ``nas-5gs`` dissector decodes it — no per-direction or per-message
    tag is needed (5GS NAS is one dissector, unlike the per-channel NR RRC path).
    """
    nas_pdu = getattr(record, "nas_pdu", b"") or b""
    if not nas_pdu:
        return None
    return ExportedPduFrame(dissector_name=_NAS_5GS_DISSECTOR, payload=nas_pdu)


for _nas_code in _NR_NAS_OTA_CODES:
    register_encoder(_nas_code)(encode_nr_nas)
del _nas_code
