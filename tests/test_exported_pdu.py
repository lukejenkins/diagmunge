"""Tests for Wireshark Exported-PDU encapsulation (diagmunge.exported_pdu).

The Exported-PDU tag layout comes from the public ``epan/exported_pdu.h``; the
NR dissector names from ``tshark -G dissectors``. These tests pin the wire
format and the NR-RRC channel→dissector mapping so the implementation cannot
drift from its design. Clean-room: nothing here is derived from
qcsuper/SCAT source.

An optional end-to-end test dissects a produced Exported-PDU pcap with stock
tshark when it is on PATH (skipped otherwise — CI hosts may lack it).
"""
from __future__ import annotations

import shutil
import struct
from types import SimpleNamespace

import pytest

from tshark_oracle import assert_tshark_dissects
from diagmunge import exported_pdu
from diaggrok.codes import LOG_NR5G_RRC_OTA_MSG
from diagmunge.pcap import PcapWriter


def _rrc(msg_data=b"\x43\x0d\x04\xa4", channel_name="BCCH-BCH", **extra):
    """A minimal NR RRC OTA record stand-in (the encoder reads via getattr)."""
    return SimpleNamespace(msg_data=msg_data, channel_name=channel_name, **extra)


class TestExportedPduBlock:
    def test_block_layout_unpadded(self):
        # EXP_PDU_TAG_DISSECTOR_NAME(12) len, name, END_OF_OPT(0) len 0, then PDU.
        block = exported_pdu.exported_pdu_block("nr-rrc.bcch.bch", b"\xaa\xbb")
        name = b"nr-rrc.bcch.bch"
        expected = (
            struct.pack("!HH", 12, len(name)) + name
            + struct.pack("!HH", 0, 0)
            + b"\xaa\xbb"
        )
        assert block == expected
        # The dissector-name tag length is the exact strlen (no NUL padding) —
        # the stock dissector advances by exactly the declared length.
        assert block[2:4] == struct.pack("!H", len(name))

    def test_frame_to_bytes_matches_block(self):
        frame = exported_pdu.ExportedPduFrame("nas-5gs", b"\x7e\x00")
        assert frame.to_bytes() == exported_pdu.exported_pdu_block("nas-5gs", b"\x7e\x00")

    def test_dlt_constant(self):
        assert exported_pdu.DLT_WIRESHARK_UPPER_PDU == 252


class TestNrRrcEncoder:
    def test_registered_for_0xb821(self):
        assert LOG_NR5G_RRC_OTA_MSG == 0xB821
        assert 0xB821 in exported_pdu.eligible_codes()

    @pytest.mark.parametrize("channel,dissector", [
        ("BCCH-BCH", "nr-rrc.bcch.bch"),
        ("BCCH-DL-SCH", "nr-rrc.bcch.dl.sch"),
        ("DL-CCCH", "nr-rrc.dl.ccch"),
        ("DL-DCCH", "nr-rrc.dl.dcch"),
        ("UL-CCCH", "nr-rrc.ul.ccch"),
        ("UL-DCCH", "nr-rrc.ul.dcch"),
        ("PCCH", "nr-rrc.pcch"),
        ("MCCH", "nr-rrc.mcch"),
        # SCAT's pdu_id map names some records by MESSAGE TYPE, not logical
        # channel: pdu_id 9/10 resolve to RRC-RECONF / RRC-RECONF-COMPLETE
        # (v9/v12/v14/v17 maps). These are bare RRCReconfiguration /
        # RRCReconfigurationComplete PDUs and dissect via the stock
        # message-level nr-rrc dissectors, not the per-channel ones.
        ("RRC-RECONF", "nr-rrc.rrc_reconf"),
        ("RRC-RECONF-COMPLETE", "nr-rrc.rrc_reconf_compl"),
        # UL-CCCH1 (rrcResumeRequest1) is mapped by the parser, so it must be
        # here too or its records are silently encode_skipped.
        ("UL-CCCH1", "nr-rrc.ul.ccch1"),
        # Standalone SIB records: a bare SIB SEQUENCE,
        # routed to the stock per-SIB dissectors.
        ("SIB2", "nr-rrc.sib2"),
        ("SIB4", "nr-rrc.sib4"),
        ("SIB5", "nr-rrc.sib5"),
    ])
    def test_channel_maps_to_dissector(self, channel, dissector):
        frame = exported_pdu.encode(0xB821, _rrc(channel_name=channel))
        assert frame is not None
        assert frame.dissector_name == dissector
        assert frame.payload == b"\x43\x0d\x04\xa4"

    def test_empty_msg_data_skipped(self):
        assert exported_pdu.encode(0xB821, _rrc(msg_data=b"")) is None

    def test_unknown_channel_skipped(self):
        # An unmapped channel name has no nr-rrc.<channel> dissector → skip
        # rather than emit a frame that dissects as malformed.
        assert exported_pdu.encode(0xB821, _rrc(channel_name="SBCCH-SL-BCH")) is None
        assert exported_pdu.encode(0xB821, _rrc(channel_name="")) is None

    def test_none_record_and_unregistered_code(self):
        assert exported_pdu.encode(0xB821, None) is None
        assert exported_pdu.encode(0x1234, _rrc()) is None


def _nas(nas_pdu=b"\x7e\x00\x42\x01"):
    """A minimal NR NAS OTA record stand-in (the encoder reads via getattr)."""
    return SimpleNamespace(nas_pdu=nas_pdu)


class TestNrNasEncoder:
    # 0xB814 (NR5G NAS 5GMM Plain OTA Container) shares the Nr5gNasOtaMsg
    # record + nas_pdu field with the OTA in/out band, so it rides the same
    # encode_nr_nas → nas-5gs path. Its parser was already complete; only the
    # encoder was missing.
    @pytest.mark.parametrize(
        "code", [0xB800, 0xB801, 0xB808, 0xB809, 0xB80A, 0xB80B, 0xB814])
    def test_registered_for_nas_codes(self, code):
        assert code in exported_pdu.eligible_codes()

    @pytest.mark.parametrize(
        "code", [0xB800, 0xB801, 0xB808, 0xB809, 0xB80A, 0xB80B, 0xB814])
    def test_nas_maps_to_single_dissector(self, code):
        frame = exported_pdu.encode(code, _nas())
        assert frame is not None
        assert frame.dissector_name == "nas-5gs"
        assert frame.payload == b"\x7e\x00\x42\x01"

    def test_verbatim_pdu_includes_security_header(self):
        # The security-protected codes carry the full OTA message starting at the
        # EPD incl. the 5GS security header — wrapped verbatim, nas-5gs decodes it.
        sec_pdu = bytes.fromhex("7e0312345678") + b"\x7e\x00helloplain"
        frame = exported_pdu.encode(0xB808, _nas(nas_pdu=sec_pdu))
        assert frame.payload == sec_pdu

    def test_empty_nas_pdu_skipped(self):
        assert exported_pdu.encode(0xB800, _nas(nas_pdu=b"")) is None


# stock NR RRC PDU bytes proven to dissect on stock tshark: a MIB body for
# BCCH-BCH ('43 0d 04 a4' — the nr5g_rrc_mib docstring's example msg_data).
_MIB_PDU = bytes.fromhex("430d04a4")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not on PATH")
def test_tshark_dissects_nr_rrc_mib(tmp_path):
    """End-to-end: a produced Exported-PDU pcap dissects as nr-rrc on stock
    tshark with no plugin/profile, as an automated check."""
    pcap = tmp_path / "nr.pcap"
    with open(pcap, "wb") as f:
        w = PcapWriter(f, linktype=exported_pdu.DLT_WIRESHARK_UPPER_PDU)
        frame = exported_pdu.encode(0xB821, _rrc(msg_data=_MIB_PDU, channel_name="BCCH-BCH"))
        w.write_frame(0.0, frame.to_bytes())
    assert_tshark_dissects(pcap, "nr-rrc")


# A complete plain 5GMM Registration complete (msg_type 0x43): EPD 0x7e,
# sec_hdr 0, type 0x43 — no mandatory IEs, so a self-contained synthetic vector
# with no guessed field bytes and no PII.
_NAS_5GMM_REG_COMPLETE = bytes.fromhex("7e0043")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not on PATH")
def test_tshark_dissects_nas_5gs(tmp_path):
    """End-to-end: a produced NR NAS Exported-PDU pcap dissects as nas-5gs on
    stock tshark with no plugin/profile, as an automated check."""
    pcap = tmp_path / "nas.pcap"
    with open(pcap, "wb") as f:
        w = PcapWriter(f, linktype=exported_pdu.DLT_WIRESHARK_UPPER_PDU)
        frame = exported_pdu.encode(0xB80B, _nas(nas_pdu=_NAS_5GMM_REG_COMPLETE))
        w.write_frame(0.0, frame.to_bytes())
    assert_tshark_dissects(pcap, "nas-5gs")
