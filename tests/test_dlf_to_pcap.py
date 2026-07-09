"""Tests for diagmunge.munge.dlf_to_pcap — DIAG capture → GSMTAP/Exported-PDU pcap.

Mirrors tests/test_diag_pcap.py (the private tool this publicly ports). Builds a
synthetic flat-DLF capture, drives the code, re-reads the pcap in pure Python.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from diaggrok import gsmtap
from diaggrok.dlf import pack_records
from diaggrok.pcap import PcapWriter
from diaggrok.parsers.diag_0xb0c0 import (
    LTE_RRC_V20_CHANNEL_BCCH_DL_SCH,
    LTE_RRC_V20_CHANNEL_OFFSET,
    LTE_RRC_V20_CHANNEL_PCCH,
    LTE_RRC_V20_CHANNEL_UL_CCCH,
)

from diagmunge.munge import dlf_to_pcap

LOG_LTE_RRC_OTA_MSG = 0xB0C0
_V20_HEADER_SIZE = 19


def _make_v20_b0c0(channel_type, body, *, pci=100, earfcn=2300, sfn=512, subfn=3):
    buf = bytearray(_V20_HEADER_SIZE)
    buf[0] = 20
    buf[1] = 15
    buf[2] = 0x30
    struct.pack_into("<H", buf, 4, pci)
    struct.pack_into("<H", buf, 6, earfcn)
    struct.pack_into("<H", buf, 8, (sfn << 4) | (subfn & 0xF))
    buf[10] = 1
    buf[LTE_RRC_V20_CHANNEL_OFFSET] = channel_type
    struct.pack_into("<H", buf, 17, len(body))
    return bytes(buf) + body


def _detection_primer(n=8):
    return [(LOG_LTE_RRC_OTA_MSG, 10 + i,
             _make_v20_b0c0(LTE_RRC_V20_CHANNEL_PCCH, b"")) for i in range(n)]


def test_diag_to_pcap_writes_gsmtap_frames(tmp_path):
    data = pack_records(_detection_primer() + [
        (LOG_LTE_RRC_OTA_MSG, 1000, _make_v20_b0c0(
            LTE_RRC_V20_CHANNEL_UL_CCCH, b"\xde\xad\xbe\xef")),
    ])
    out = tmp_path / "out.pcap"
    with open(out, "wb") as f:
        stats = dlf_to_pcap.diag_to_pcap(
            data, PcapWriter(f), frozenset({LOG_LTE_RRC_OTA_MSG}),
            base_epoch=1000.0)
    assert stats["written"] == 1
    assert stats["eligible"] == 9  # 8 primers (empty→encode_skipped) + 1 real
    assert stats["encode_skipped"] == 8


def test_distinct_channels_map_to_distinct_subtypes(tmp_path):
    data = pack_records(_detection_primer() + [
        (LOG_LTE_RRC_OTA_MSG, 1000, _make_v20_b0c0(
            LTE_RRC_V20_CHANNEL_UL_CCCH, b"\xde\xad")),
        (LOG_LTE_RRC_OTA_MSG, 2000, _make_v20_b0c0(
            LTE_RRC_V20_CHANNEL_BCCH_DL_SCH, b"\x11\x22")),
    ])
    out = tmp_path / "o.pcap"
    with open(out, "wb") as f:
        stats = dlf_to_pcap.diag_to_pcap(
            data, PcapWriter(f), frozenset({LOG_LTE_RRC_OTA_MSG}))
    assert stats["written"] == 2
    assert stats["by_sub"] == {
        gsmtap.GSMTAP_LTE_RRC_SUB_UL_CCCH: 1,
        gsmtap.GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH: 1,
    }


def test_pcapsink_declines_empty_pdu():
    from types import SimpleNamespace
    sink = dlf_to_pcap.PcapSink(writer=None)
    # channel_name maps to a sub-type but msg_data empty -> gsmtap.encode None
    rec = SimpleNamespace(msg_data=b"", channel_name="PCCH", earfcn=0, sfn=0)
    assert sink.write_record(0xB0C0, 0.0, rec) is False
    assert sink.encode_skipped == 1


def _iter_pcap_gsmtap(pcap_bytes):
    assert struct.unpack_from("<I", pcap_bytes, 0)[0] == 0xA1B2C3D4
    off, n = 24, len(pcap_bytes)
    while off + 16 <= n:
        _s, _u, incl, _o = struct.unpack_from("<IIII", pcap_bytes, off)
        off += 16
        frame = pcap_bytes[off:off + incl]
        off += incl
        gh = frame[14 + 20 + 8: 14 + 20 + 8 + 16]
        yield struct.unpack_from("!B", gh, 2)[0], gh[12], frame[14 + 20 + 8 + 16:]


def _write_capture(tmp_path, records):
    cap = tmp_path / "capture.dlf"
    cap.write_bytes(pack_records(_detection_primer() + list(records)))
    return cap


def test_cli_default_output_name_and_frames(tmp_path):
    cap = _write_capture(tmp_path, [
        (LOG_LTE_RRC_OTA_MSG, 1000, _make_v20_b0c0(
            LTE_RRC_V20_CHANNEL_UL_CCCH, b"\xaa\xbb")),
    ])
    assert dlf_to_pcap.main([str(cap)]) == 0
    out = tmp_path / "capture.diaggrok.pcap"
    assert out.exists()
    frames = list(_iter_pcap_gsmtap(out.read_bytes()))
    assert len(frames) == 1
    assert frames[0] == (gsmtap.GSMTAP_TYPE_LTE_RRC,
                         gsmtap.GSMTAP_LTE_RRC_SUB_UL_CCCH, b"\xaa\xbb")


def test_ineligible_code_gives_header_only_pcap(tmp_path):
    cap = _write_capture(tmp_path, [(0x1234, 1000, b"\x00\x01\x02\x03")])
    out = tmp_path / "o.pcap"
    assert dlf_to_pcap.main([str(cap), "-o", str(out)]) == 0
    assert out.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"      # valid magic
    assert list(_iter_pcap_gsmtap(out.read_bytes())) == []
    # No NR frames -> the sibling .nr.pcap must not be left behind.
    assert not (tmp_path / "o.nr.pcap").exists()


def test_import_diagmunge_stays_diaggrok_free():
    # The core-import contract: `import diagmunge` must not pull diaggrok.
    # dlf_to_pcap imports diaggrok at top level, so munge/__init__ must not
    # eagerly import it. Assert the submodule is not auto-loaded.
    import importlib
    import sys as _sys
    for m in [k for k in _sys.modules if k.startswith("diagmunge")]:
        del _sys.modules[m]
    importlib.import_module("diagmunge")
    assert "diagmunge.munge.dlf_to_pcap" not in _sys.modules


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not on PATH")
def test_tshark_dissects_lte_rrc(tmp_path):
    cap = _write_capture(tmp_path, [
        (LOG_LTE_RRC_OTA_MSG, 1000, _make_v20_b0c0(
            LTE_RRC_V20_CHANNEL_BCCH_DL_SCH, bytes.fromhex("6003a0"))),
    ])
    out = tmp_path / "o.pcap"
    assert dlf_to_pcap.main([str(cap), "-o", str(out)]) == 0
    res = subprocess.run(
        ["tshark", "-r", str(out), "-T", "fields", "-e", "_ws.col.Protocol"],
        capture_output=True, text=True)
    assert "LTE RRC" in res.stdout or "lte" in res.stdout.lower(), res.stdout + res.stderr
