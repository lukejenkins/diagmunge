# SPDX-License-Identifier: Apache-2.0
from diagmunge.diag_cmd import (
    QSH_METRICS_CONFIG_SUBCMD,
    QSH_ACTION_FLUSH_CLEAR,
    QSH_ENABLE_OFF,
    QSH_ENABLE_ON,
    build_qsh_metrics_config,
    build_qsh_metrics_disable,
    build_qsh_metrics_enable,
)


def test_subcmd_constant():
    assert QSH_METRICS_CONFIG_SUBCMD == 0x9002


def test_disable_vector():
    expected = bytes.fromhex(
        "4b440290" "04000000" "02000000" "00000000" "00000000" "00000000"
    )
    assert build_qsh_metrics_disable() == expected


def test_disable_matches_explicit_config():
    assert build_qsh_metrics_disable() == build_qsh_metrics_config(
        action=QSH_ACTION_FLUSH_CLEAR, enable=QSH_ENABLE_OFF
    )


def test_enable_vector():
    # Global enable: flush+clear, enable=1, no items. Differs from disable only
    # in the enable word (01 vs 00). An SDX24 modem answers it with status 0.
    expected = bytes.fromhex(
        "4b440290" "04000000" "02000000" "01000000" "00000000" "00000000"
    )
    assert build_qsh_metrics_enable() == expected


def test_enable_matches_explicit_config():
    assert build_qsh_metrics_enable() == build_qsh_metrics_config(
        action=QSH_ACTION_FLUSH_CLEAR, enable=QSH_ENABLE_ON
    )


def test_enable_differs_from_disable_only_in_enable_word():
    en, dis = build_qsh_metrics_enable(), build_qsh_metrics_disable()
    diff = [i for i in range(len(en)) if en[i] != dis[i]]
    assert diff == [12]  # the enable u32 (byte 12 of the inner) — 01 vs 00


def test_enable_with_one_item():
    expected = bytes.fromhex(
        "4b440290" "05000000" "02000000" "01000000" "00000000" "01000000" "07000000"
    )
    got = build_qsh_metrics_config(
        action=QSH_ACTION_FLUSH_CLEAR, enable=QSH_ENABLE_ON, client_id=0, item_ids=(7,)
    )
    assert got == expected


def test_arg_count_tracks_item_count():
    # arg_count word (bytes 4..8 of inner, after the 4-byte envelope) must be 4 + n_items
    got = build_qsh_metrics_config(
        action=QSH_ACTION_FLUSH_CLEAR, enable=QSH_ENABLE_ON, item_ids=(1, 2, 3)
    )
    arg_count = int.from_bytes(got[4:8], "little")
    assert arg_count == 4 + 3
