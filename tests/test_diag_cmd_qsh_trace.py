# SPDX-License-Identifier: Apache-2.0
"""Encoder-lock tests for the QSH-trace SET (0x9001) + ext-msg SET_RT_MASK (0x7D).

Every vector here is synthetic: hand-computed from the layout in
``diagmunge.diag_cmd``, not lifted from any device's configuration. These lock
the *encoder* and the ascending-ssid merge rule.
"""

import pytest

from diagmunge.diag_cmd import (
    QSH_TRACE_MASKSET_SET_SUBCMD,
    QSH_TRACE_SET_MIN_ARGS,
    EXT_MSG_CONFIG_SET_RT_MASK,
    DIAG_EXT_MSG_CONFIG_F,
    build_qsh_trace_maskset_set,
    build_ext_msg_set_rt_mask,
    merge_qsh_trace_pairs,
)

# A small synthetic, strictly ascending maskset (ssid, level).
BASE = ((0x08, 0x05), (0x21, 0x11), (0x44, 0x0C), (0x66, 0x30))

# --- 0x9001 QSH-trace maskset SET -----------------------------------------


def test_subcmd_constant():
    assert QSH_TRACE_MASKSET_SET_SUBCMD == 0x9001


def test_full_frame_vector():
    # 4b/subsys 0x44/cmd 0x9001 + 4-word header + one u16 pair per ssid.
    assert build_qsh_trace_maskset_set(BASE) == bytes.fromhex(
        "4b440190"                                    # 0x4B, subsys 0x44, cmd 0x9001 (LE)
        "07000000" "01000000" "01000000" "04000000"   # arg_count=7, word_a=1, word_b=1, count=4
        "08000500" "21001100" "44000c00" "66003000"
    )


def test_arg_count_is_three_plus_count():
    # arg_count word (bytes 4..8 of inner, after the 4-byte subsys envelope)
    # counts word_a + word_b + count-word + one u32 per pair = 3 + n.
    got = build_qsh_trace_maskset_set(((0x22, 0x01), (0x31, 0x07)))
    arg_count = int.from_bytes(got[4:8], "little")
    assert arg_count == QSH_TRACE_SET_MIN_ARGS + 2 == 5


def test_empty_pairs_is_header_only():
    got = build_qsh_trace_maskset_set(())
    assert got == bytes.fromhex("4b440190" "03000000" "01000000" "01000000" "00000000")


def test_bitmask_level_survives_roundtrip():
    # A level word can be a per-subsystem bitmask, not a threshold.
    got = build_qsh_trace_maskset_set(((0x3A, 0x0A81),))
    assert got[-4:] == bytes.fromhex("3a00810a")  # ssid=0x3a LE, level=0x0a81 LE


def test_header_words_are_overridable():
    got = build_qsh_trace_maskset_set((), word_a=2, word_b=3)
    assert got[8:12] == (2).to_bytes(4, "little")
    assert got[12:16] == (3).to_bytes(4, "little")


@pytest.mark.parametrize("pair", [(0x10000, 1), (-1, 1), (1, 0x10000), (1, -1)])
def test_out_of_range_pair_rejected(pair):
    with pytest.raises(ValueError):
        build_qsh_trace_maskset_set((pair,))


# --- 0x7D DIAG_EXT_MSG_CONFIG_F SET_RT_MASK -------------------------------


def test_ext_msg_subtype_constant():
    assert DIAG_EXT_MSG_CONFIG_F == 0x7D
    assert EXT_MSG_CONFIG_SET_RT_MASK == 0x04


def test_single_ssid_vector():
    assert build_ext_msg_set_rt_mask(0x07, (0x0F,)) == bytes.fromhex(
        "7d04" "0700" "0700" "0000" "0f000000"
    )


def test_multi_ssid_range_vector():
    # ssid_last is derived: 0x20 + 3 - 1 = 0x22.
    assert build_ext_msg_set_rt_mask(0x20, (0x1F, 0x03, 0x1F)) == bytes.fromhex(
        "7d04" "2000" "2200" "0000" "1f000000" "03000000" "1f000000"
    )


def test_ssid_last_is_derived_from_level_count():
    got = build_ext_msg_set_rt_mask(0x0E, (0x01, 0x02, 0x03, 0x04, 0x05))
    ssid_first = int.from_bytes(got[2:4], "little")
    ssid_last = int.from_bytes(got[4:6], "little")
    assert (ssid_first, ssid_last) == (0x0E, 0x12)  # first + 5 - 1


def test_high_ssid_vector():
    # A u16 ssid above 0xff is little-endian on both range ends.
    assert build_ext_msg_set_rt_mask(0x1234, (0x3E,)) == bytes.fromhex(
        "7d04" "3412" "3412" "0000" "3e000000"
    )


def test_reserved_field_position():
    # The u16 reserved sits between ssid_last and the mask array; default 0.
    got = build_ext_msg_set_rt_mask(0x00, (0x1E,))
    assert got[6:8] == b"\x00\x00"


def test_empty_levels_rejected():
    with pytest.raises(ValueError):
        build_ext_msg_set_rt_mask(0x00, ())


# --- merge_qsh_trace_pairs: the ascending-ssid ordering rule --------
#
# Hardware-established on a Telit FT980m (SDX55): the 0x9001 maskset array must
# be in strictly ascending ssid order or the modem returns status 1. See
# merge_qsh_trace_pairs' docstring for the seven-vector bisection. These lock
# the helper that keeps callers on the legal side of it.

LOC = ((0x5A, 0xFF), (0x5B, 0xFF), (0x5C, 0xFF), (0x5D, 0xFF), (0x5F, 0xFF))


def test_base_is_strictly_ascending():
    ssids = [ssid for ssid, _ in BASE]
    assert ssids == sorted(set(ssids)), "the fixture must satisfy the rule it models"


def test_merge_sorts_appended_pairs_that_would_otherwise_break_order():
    # Naive concatenation puts 0x5a after BASE's last ssid (0x66) -> status 1.
    assert [s for s, _ in BASE + LOC] != sorted(s for s, _ in BASE + LOC)
    merged = merge_qsh_trace_pairs(BASE, LOC)
    ssids = [s for s, _ in merged]
    assert ssids == sorted(ssids)
    assert len(merged) == len(BASE) + len(LOC)
    assert dict(merged)[0x5B] == 0xFF


def test_merge_dedupes_with_last_group_winning():
    # 0x44 is already in BASE at level 0x0c; a later group must override it,
    # and must NOT produce a duplicate (adjacent equal ssids are rejected too).
    merged = merge_qsh_trace_pairs(BASE, ((0x44, 0x0F),))
    ssids = [s for s, _ in merged]
    assert len(ssids) == len(set(ssids)) == len(BASE)
    assert dict(merged)[0x44] == 0x0F


def test_merged_maskset_encodes_with_correct_count_and_arg_count():
    merged = merge_qsh_trace_pairs(BASE, ((0x5A, 0xFF), (0x5F, 0xFF)))
    got = build_qsh_trace_maskset_set(merged)
    # inner = 4b 4401 90 ... ; payload starts after the 4-byte subsys envelope.
    payload = got[4:]
    arg_count = int.from_bytes(payload[0:4], "little")
    count = int.from_bytes(payload[12:16], "little")
    assert count == len(BASE) + 2
    assert arg_count == QSH_TRACE_SET_MIN_ARGS + count
