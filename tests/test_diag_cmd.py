# SPDX-License-Identifier: Apache-2.0
from diagmunge.diag_cmd import (
    DIAG_SUBSYS_CMD_F,
    DIAG_SUBSYS_LTE,
    build_subsys_command,
)


def test_constants():
    assert DIAG_SUBSYS_CMD_F == 0x4B
    assert DIAG_SUBSYS_LTE == 0x44


def test_envelope_empty_payload():
    assert build_subsys_command(0x44, 0x9002) == bytes.fromhex("4b440290")


def test_envelope_with_payload():
    got = build_subsys_command(0x44, 0x9004, b"\x00\x00\x00\x00")
    assert got == bytes.fromhex("4b44049000000000")


def test_subcmd_is_little_endian():
    # subsys_cmd 0x0001 must serialize as 01 00, not 00 01
    assert build_subsys_command(0x0B, 0x0001, b"\xAB") == bytes.fromhex("4b0b0100ab")


def test_range_validation():
    import pytest
    with pytest.raises(ValueError):
        build_subsys_command(0x100, 0x9002)      # subsys_id too big
    with pytest.raises(ValueError):
        build_subsys_command(0x44, 0x1_0000)     # subsys_cmd too big


# --- DIAG event reporting (0x60) enable/disable --------------------

from diagmunge.diag_cmd import DIAG_EVENT_REPORT_F, build_event_report_enable


def test_event_report_constant():
    assert DIAG_EVENT_REPORT_F == 0x60


def test_event_report_enable_vector():
    # Top-level command (NOT the 0x4B subsys envelope): [0x60, 0x01].
    assert build_event_report_enable(True) == bytes.fromhex("6001")


def test_event_report_disable_vector():
    assert build_event_report_enable(False) == bytes.fromhex("6000")


def test_event_report_default_is_enable():
    assert build_event_report_enable() == build_event_report_enable(True)
