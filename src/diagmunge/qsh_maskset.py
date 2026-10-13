# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""Vendor-free sources of QSH-trace (``0x9001``) masksets.

``build_qsh_trace_maskset_set`` (spec 05) encodes a maskset; this module answers
*where the ``(ssid, level)`` pairs come from* without shipping any vendor file.
Three sources, all of which carry **no vendor-derived values**:

1. :func:`sweep_pairs` — pure arithmetic: every SSID in a window, every
   sub-stream bit set. The modem accepts unknown SSIDs and any level and
   silently ignores what it does not implement, so an over-broad maskset is
   safe. It is limited only by the per-SET pair cap.
2. :func:`derive_pairs` — measured on the user's own modem: arm a sweep, read
   which ``(subsys_id, sub_stream)`` pairs actually arrive on the ``0x9D`` wire,
   and emit exactly those. The arming SSID *is* the wire ``subsys_id``
   (``u16@2`` bits [13:6]) and ``sub_stream`` (bits [5:1]) is the bit index into
   that SSID's ``level``, so the modem's own output names its maskset.
3. :func:`harvest_cfg` — read the ``0x9001`` frame(s) out of a mask file the
   user already holds: a DIAG mask file is a raw stream of HDLC-framed DIAG
   requests, so the maskset is one ``4B 44 01 90`` frame inside it.

Hardware facts this module relies on (all measured, none vendor-sourced):

- **Per-SET cap: 110 pairs** (111 → status 1); ``ssid = 0`` → status 1.
- **Strictly ascending ssid order**, or status 1.
- **A SET REPLACES the armed maskset; it does not accumulate.** Measured on an
  SDX72: arming SSIDs 1..110 gave 373 ``0x9D``/s over 7
  subsystems; a second SET of SSIDs 111..220 *without* a disarm dropped the
  stream to 0. The same holds on SDX55 (RM500Q-AE, T99W175) and SDX62
  (RM520N-GL): after 1..110, a SET of SSID 250 alone left no 1..110 traffic.
  So a sweep wider than 110 SSIDs must be run as separate windows, measured one
  at a time — never sent back-to-back expecting a union.
- **The RM520N-GL (SDX62) emits SSID 76 under ANY non-empty maskset**, even
  one that does not name it (a SET of SSID 250 alone gave ~12 frames/s, all
  SSID 76). Only the empty disarm stops it. So a discovery window that cannot
  contain 76 can still report it.

Also bundled: ``data/qsh_maskset_measured.json`` holds masksets measured this
way on an RM500Q-AE, a T99W175 (SDX55), an RM520N-GL (SDX62) and two T99W640
units (SDX72), one profile each. :func:`union_maskset` ORs every one of them
into a single SET, and :func:`bundled_maskset` returns that union by default.
The data **comes with NO WARRANTY**; ``data/QSH_MASKSET_MEASURED.md`` says how
it was measured. Read it before arming.
"""
from __future__ import annotations

import json
import struct
from collections.abc import Iterable, Mapping
from importlib.resources import files
from os import PathLike
from pathlib import Path

from .diag_cmd import DIAG_SUBSYS_LTE, QSH_TRACE_MASKSET_SET_SUBCMD

#: Max ``(ssid, level)`` pairs one ``0x9001`` SET accepts (111 → status 1).
QSH_TRACE_MAX_PAIRS: int = 110

#: ``level`` with every sub-stream bit the u16 word can carry.
QSH_TRACE_ALL_BITS: int = 0xFFFF

#: Opcode of a ``0x9D DIAG_QSH_TRACE_PAYLOAD_F`` frame.
QSH_TRACE_PAYLOAD_CMD: int = 0x9D

_SET_HEAD = bytes((0x4B, DIAG_SUBSYS_LTE)) + struct.pack("<H", QSH_TRACE_MASKSET_SET_SUBCMD)


def sweep_windows(first: int = 1, last: int = 255,
                  size: int = QSH_TRACE_MAX_PAIRS) -> list[range]:
    """Split ``[first..last]`` into SET-sized SSID windows (``ssid 0`` excluded)."""
    if size < 1 or size > QSH_TRACE_MAX_PAIRS:
        raise ValueError(f"window size must be 1..{QSH_TRACE_MAX_PAIRS}: {size!r}")
    first = max(first, 1)
    return [range(lo, min(lo + size, last + 1)) for lo in range(first, last + 1, size)]


def sweep_pairs(ssids: Iterable[int],
                level: int = QSH_TRACE_ALL_BITS) -> tuple[tuple[int, int], ...]:
    """Every SSID in ``ssids`` at ``level``, ordering-legal and cap-checked."""
    pairs = tuple(sorted({(s, level) for s in ssids}))
    _check(pairs)
    return pairs


def wire_key(frame: bytes) -> tuple[int, int] | None:
    """``(subsys_id, sub_stream)`` of a de-HDLC'd ``0x9D`` frame, else ``None``.

    ``frame`` starts at the ``0x9D`` opcode (unwrap any ``0x98`` envelope first).
    """
    if len(frame) < 4 or frame[0] != QSH_TRACE_PAYLOAD_CMD:
        return None
    w2 = struct.unpack_from("<H", frame, 2)[0]
    return (w2 >> 6) & 0xFF, (w2 >> 1) & 0x1F


def derive_pairs(observed: Mapping[int, Iterable[int]]) -> tuple[tuple[int, int], ...]:
    """Maskset that re-arms exactly what was observed: ``{subsys_id: sub_streams}``.

    Sub-streams above bit 15 cannot be expressed in the u16 ``level`` and are
    dropped. A ``subsys_id`` of 0 is never armable and is dropped too.
    """
    pairs = []
    for ssid, bits in observed.items():
        level = 0
        for b in bits:
            if 0 <= b < 16:
                level |= 1 << b
        if ssid and level:
            pairs.append((ssid, level))
    pairs.sort()
    _check(tuple(pairs))
    return tuple(pairs)


def harvest_cfg(data: bytes) -> list[tuple[tuple[int, int], ...]]:
    """Every ``0x9001`` maskset in a raw HDLC DIAG mask file, in file order.

    Frames are ``0x7E``-delimited, HDLC-escaped, with a 2-byte CRC trailer. A
    frame whose arg-count or pair count disagrees with its length is skipped
    rather than mis-read.
    """
    out = []
    for esc in data.split(b"\x7e"):
        f = esc.replace(b"\x7d\x5e", b"\x7e").replace(b"\x7d\x5d", b"\x7d")
        if not f.startswith(_SET_HEAD) or len(f) < 4 + 16 + 2:
            continue
        body = f[4:-2]
        argc, _a, _b, n = struct.unpack_from("<4I", body, 0)
        if argc != 3 + n or len(body) != 16 + 4 * n:
            continue
        out.append(tuple(struct.unpack_from("<HH", body, 16 + 4 * i) for i in range(n)))
    return out


#: The bundled measured masksets (NO WARRANTY — see ``QSH_MASKSET_MEASURED.md``
#: beside it): one profile per unit measured, across SDX55, SDX62 and SDX72.
BUNDLED_MASKSET_FILE = "qsh_maskset_measured.json"

#: Prefix of every bundled profile's public name (``measured-<profile>``), so a
#: bundled profile cannot collide with a caller's own profile names.
BUNDLED_PROFILE_PREFIX = "measured-"

#: The profile computed, never stored: the per-SSID OR of every stored profile.
#: Arming a sub-stream bit or SSID a part does not implement is harmless (the
#: 1..110 all-bits sweep is accepted on every part measured), so the union only
#: adds coverage.
UNION_PROFILE = "union"

#: The bundled profile diaggulp arms by default when it has no other profile.
BUNDLED_DEFAULT_PROFILE = BUNDLED_PROFILE_PREFIX + UNION_PROFILE


def _bundled_doc() -> dict:
    return json.loads(files(__package__).joinpath(
        "data", BUNDLED_MASKSET_FILE).read_text())


def bundled_profiles() -> tuple[str, tuple[str, ...]]:
    """``(default, all_names)`` of the bundled profiles, ``union`` included."""
    doc = _bundled_doc()
    return doc["default"], tuple(sorted({*doc["profiles"], UNION_PROFILE}))


def union_maskset() -> tuple[tuple[int, int], ...]:
    """The per-SSID OR of every stored bundled profile."""
    seen: dict[int, int] = {}
    for prof in _bundled_doc()["profiles"].values():
        for ssid, level in validate_pairs(prof["pairs"]):
            seen[ssid] = seen.get(ssid, 0) | level
    pairs = tuple(sorted(seen.items()))
    _check(pairs)
    return pairs


def bundled_maskset(profile: str | None = None) -> tuple[tuple[int, int], ...]:
    """A bundled maskset by profile name (default: the computed ``union``).

    Provided AS IS, with NO WARRANTY; see ``data/QSH_MASKSET_MEASURED.md``.
    """
    doc = _bundled_doc()
    name = profile or doc["default"]
    if name == UNION_PROFILE:
        return union_maskset()
    if name not in doc["profiles"]:
        raise KeyError(f"no bundled profile {name!r}; have {sorted(doc['profiles'])}")
    try:
        return validate_pairs(doc["profiles"][name]["pairs"])
    except ValueError as exc:
        raise ValueError(f"bundled profile {name!r}: {exc}") from None


def bundled_profile_table() -> dict[str, tuple[tuple[int, int], ...]]:
    """Every bundled profile as ``{"measured-<profile>": pairs}``."""
    return {BUNDLED_PROFILE_PREFIX + name: bundled_maskset(name)
            for name in bundled_profiles()[1]}


def bundled_measured_on(qualified: str) -> str:
    """Which models a ``measured-<profile>`` name was measured on, for a log line."""
    if not qualified.startswith(BUNDLED_PROFILE_PREFIX):
        raise KeyError(f"not a bundled profile name: {qualified!r}")
    name = qualified[len(BUNDLED_PROFILE_PREFIX):]
    doc = _bundled_doc()
    if name == UNION_PROFILE:
        profs = list(doc["profiles"].values())
    elif name in doc["profiles"]:
        profs = [doc["profiles"][name]]
    else:
        raise KeyError(f"no bundled profile {name!r}; have {sorted(doc['profiles'])}")
    models = list(dict.fromkeys(p["model"] for p in profs))
    return models[0] if len(models) == 1 else ", ".join(models[:-1]) + " and " + models[-1]


def validate_pairs(pairs: Iterable) -> tuple[tuple[int, int], ...]:
    """Check a maskset the modem will accept and return it as int tuples.

    Every rule is one the hardware enforces with status 1: at
    most :data:`QSH_TRACE_MAX_PAIRS` pairs, ``ssid >= 1``, and **strictly
    ascending** ``ssid`` order. Nothing is re-sorted: an out-of-order input is
    reported, not silently fixed, so a hand-edited file says what is wrong.
    """
    out = []
    for i, p in enumerate(pairs):
        if (not isinstance(p, (list, tuple)) or len(p) != 2
                or not all(isinstance(v, int) and not isinstance(v, bool) for v in p)):
            raise ValueError(f"pair {i} is not [ssid, level] integers: {p!r}")
        out.append((p[0], p[1]))
    pairs = tuple(out)
    _check(pairs)
    for i in range(1, len(pairs)):
        if pairs[i][0] <= pairs[i - 1][0]:
            raise ValueError(f"pairs must be strictly ascending by ssid: pair {i} "
                             f"(ssid {pairs[i][0]}) follows ssid {pairs[i - 1][0]}")
    return pairs


def load_pairs_file(path: str | PathLike) -> tuple[tuple[int, int], ...]:
    """Read and validate a ``{"pairs": [[ssid, level], ...]}`` JSON file.

    This is the format ``qsh_maskset_discover -o`` writes. Raises
    ``ValueError`` (never arms a partial maskset) on any shape or rule fault.
    """
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not JSON ({exc})") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("pairs"), list):
        raise ValueError(f'{path}: expected {{"pairs": [[ssid, level], ...]}}')
    if not doc["pairs"]:
        raise ValueError(f"{path}: no pairs (an empty maskset is the disarm, not an arm)")
    try:
        return validate_pairs(doc["pairs"])
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from None


def _check(pairs: tuple[tuple[int, int], ...]) -> None:
    if len(pairs) > QSH_TRACE_MAX_PAIRS:
        raise ValueError(f"{len(pairs)} pairs exceeds the per-SET cap of "
                         f"{QSH_TRACE_MAX_PAIRS}; split into windows")
    for ssid, level in pairs:
        if not 1 <= ssid <= 0xFFFF:
            raise ValueError(f"ssid out of range 1..65535: {ssid!r}")
        if not 0 <= level <= 0xFFFF:
            raise ValueError(f"level out of range 0..65535: {level!r}")
