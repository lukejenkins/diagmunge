# SPDX-License-Identifier: Apache-2.0
"""Bundled masksets measured across modems, and their computed union."""
import json
from importlib.resources import files

import pytest

from diagmunge.qsh_maskset import (
    BUNDLED_DEFAULT_PROFILE, BUNDLED_MASKSET_FILE, QSH_TRACE_MAX_PAIRS, UNION_PROFILE,
    bundled_maskset, bundled_measured_on, bundled_profile_table, bundled_profiles,
    union_maskset, validate_pairs,
)

UNITS = {"rm500q-ae", "t99w175", "rm520n-gl", "t99w640-retail", "t99w640-engineering-sample"}

#: The union that was armed live on four modems. The provenance doc's
#: frame counts are measurements of exactly this set, so it must not drift.
VALIDATED_UNION = (
    (6, 336), (9, 39), (11, 2), (13, 1), (18, 2), (42, 1), (52, 6), (54, 7),
    (61, 3), (73, 111), (76, 89), (78, 2), (80, 1), (83, 43), (84, 14), (87, 3),
    (89, 3), (97, 1), (98, 8), (99, 3), (101, 2), (107, 3), (108, 1), (109, 2),
    (113, 3), (115, 2), (119, 2), (122, 3),
)

#: The first T99W640 retail sweep, the old public default.
FIRST_T99W640_RETAIL = ((6, 272), (61, 1), (76, 1), (78, 2), (87, 1), (89, 1), (107, 3), (119, 2))


def _stored_profiles():
    for name in bundled_profiles()[1]:
        if name != UNION_PROFILE:
            yield name, bundled_maskset(name)


def test_one_bundled_file_defaults_to_the_union_and_lists_every_unit():
    default, names = bundled_profiles()
    assert BUNDLED_MASKSET_FILE == "qsh_maskset_measured.json"
    assert default == UNION_PROFILE
    assert set(names) == UNITS | {UNION_PROFILE}


def test_the_no_argument_maskset_is_the_union():
    assert bundled_maskset() == union_maskset() == bundled_maskset(UNION_PROFILE)


def test_the_union_is_exactly_the_set_validated_live():
    assert union_maskset() == VALIDATED_UNION


def test_the_retail_profile_contains_the_first_retail_sweep():
    retail = dict(bundled_maskset("t99w640-retail"))
    for ssid, level in FIRST_T99W640_RETAIL:
        assert retail.get(ssid, 0) & level == level, ssid


def test_union_covers_every_bit_of_every_stored_profile():
    union = dict(union_maskset())
    for name, pairs in _stored_profiles():
        for ssid, level in pairs:
            assert union.get(ssid, 0) & level == level, (name, ssid)


def test_union_arms_nothing_no_profile_measured():
    seen: dict[int, int] = {}
    for _name, pairs in _stored_profiles():
        for ssid, level in pairs:
            seen[ssid] = seen.get(ssid, 0) | level
    assert union_maskset() == tuple(sorted(seen.items()))


def test_union_is_a_legal_single_set_and_reaches_ssids_the_sweep_cannot():
    union = union_maskset()
    assert validate_pairs(union) == union and len(union) <= QSH_TRACE_MAX_PAIRS
    ssids = {s for s, _ in union}
    # 113 (SDX62), 115 and 119 (SDX72) are above the 1..110 sweep.
    assert {113, 115, 119} <= ssids


def test_profile_table_names_every_profile_measured_and_defaults_to_the_union():
    table = bundled_profile_table()
    assert set(table) == {"measured-" + n for n in UNITS | {UNION_PROFILE}}
    assert table[BUNDLED_DEFAULT_PROFILE] == union_maskset()
    assert BUNDLED_DEFAULT_PROFILE == "measured-union"
    assert table["measured-rm520n-gl"] == bundled_maskset("rm520n-gl")
    assert not any(k.startswith("t99w640-") for k in table)


def test_measured_on_names_the_units_behind_a_profile():
    who = bundled_measured_on("measured-union")
    assert who == "RM500Q-AE, T99W175, RM520N-GL and T99W640"
    assert bundled_measured_on("measured-rm520n-gl") == "RM520N-GL"
    assert bundled_measured_on("measured-t99w640-retail") == "T99W640"


def test_unknown_profile_is_refused():
    with pytest.raises(KeyError, match="have"):
        bundled_maskset("nope")
    with pytest.raises(KeyError):
        bundled_measured_on("measured-nope")
    with pytest.raises(KeyError):
        bundled_measured_on("t99w640-retail")
    # A foreign prefix as long as "measured-" leaves a valid tail once sliced
    # off, so only the prefix check refuses it.
    with pytest.raises(KeyError, match="not a bundled"):
        bundled_measured_on("notbundl-union")
    with pytest.raises(KeyError, match="not a bundled"):
        bundled_measured_on("t99w6400-union")


def test_only_the_measured_data_ships():
    data = files("diagmunge").joinpath("data")
    shipped = {p.name for p in data.iterdir() if p.name.endswith((".json", ".md"))}
    assert shipped == {"qsh_maskset_measured.json", "QSH_MASKSET_MEASURED.md"}


def test_measured_data_ships_apache_and_no_warranty_and_no_firmware_ids():
    data = files("diagmunge").joinpath("data")
    meta = json.loads(data.joinpath(BUNDLED_MASKSET_FILE).read_text())
    assert meta["license"] == "Apache-2.0" and meta["warranty"].startswith("NONE")
    assert UNION_PROFILE not in meta["profiles"]      # computed, never stored
    for p in meta["profiles"].values():
        assert set(p) == {"model", "unit", "chipset", "pairs"}
    doc = data.joinpath("QSH_MASKSET_MEASURED.md").read_text()
    assert "NO WARRANTY" in doc and "Apache License, Version 2.0" in doc and '"AS IS"' in doc


def test_the_document_explains_how_the_masksets_were_made():
    doc = files("diagmunge").joinpath("data", "QSH_MASKSET_MEASURED.md").read_text()
    assert "## How the masksets were made" in doc
    for profile in UNITS | {UNION_PROFILE}:
        assert f"`{profile}`" in doc, profile
    assert "QSH_MASKSET_T99W640" not in doc and "qsh_maskset_t99w640" not in doc
