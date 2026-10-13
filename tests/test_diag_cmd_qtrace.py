# SPDX-License-Identifier: Apache-2.0
from diagmunge.diag_cmd import (
    QTRACE_MASKSET_FILTER_SUBCMD,
    build_qtrace_maskset_filter,
    build_qtrace_disable,
)


def test_subcmd_constant():
    assert QTRACE_MASKSET_FILTER_SUBCMD == 0x9004


def test_disable_vector():
    assert build_qtrace_disable() == bytes.fromhex("4b44049000000000")


def test_disable_matches_empty_filter():
    assert build_qtrace_disable() == build_qtrace_maskset_filter(())


def test_filter_with_items():
    expected = bytes.fromhex("4b440490" "02000000" "11000000" "22000000")
    assert build_qtrace_maskset_filter((0x11, 0x22)) == expected


def test_item_count_matches_list_len():
    got = build_qtrace_maskset_filter((1, 2, 3, 4))
    item_count = int.from_bytes(got[4:8], "little")
    assert item_count == 4
