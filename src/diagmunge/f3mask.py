"""F3 runtime-mask (``0x7D DIAG_EXT_MSG_CONFIG_F``) wire, readback and verified restore.

This is the F3-mask code of the diaggulp capture tool, kept here so that
consumers which cannot import diaggulp can save, zero and restore the F3 mask
the way diaggulp ``--restore-f3-mask-on-exit`` does. diaggpsd
``--mask own`` is the first of these. diaggulp re-imports every name, so its
behaviour and its mask-restore tests are unchanged.

The hardware findings behind each function are documented in the function
docstrings.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, NamedTuple

from diagmunge.transport import DIAG_BAD_CMD_F

if TYPE_CHECKING:
    from diagmunge.transport import DiagClient

DIAG_EXT_MSG_CONFIG_F = 0x7D
EXT_MSG_QUERY_SSID_RANGES = 1
EXT_MSG_GET_BUILD_MASK = 2
EXT_MSG_GET_RT_MASK = 3
EXT_MSG_SET_RT_MASK = 4
EXT_MSG_SET_ALL_RT_MASKS = 5
EXT_MSG_ALL_LEVELS = 0xFFFFFFFF

#: Bytes before the u32 mask array in a 0x7D mask-table request *or* reply.
#: ``sub_cmd u8 @0, ss_id_first u16 @1, ss_id_last u16 @3, status u16 @5``.
#: Hardware-verified on a live EG25-G. The reply to
#: sub_cmd 3 is 495 bytes == ``7 + 4 × 122`` and to sub_cmd 2 is 491 == ``7 +
#: 4 × 121``, both exact, and a bounded SET_RT_MASK on ss_id N moves exactly
#: the entry at ``7 + 4·N``.
EXT_MSG_MASK_TABLE_HDR_LEN = 7

#: Highest ss_id in the firmware's first (always-present) SSID range, 0..120.
#: Used as the default readback window: it is the range every build has, and a
#: sub_cmd 3 reply is a fixed 495 bytes regardless of the range requested.
EXT_MSG_SS_RANGE0_LAST = 120


def build_ext_msg_config_set_all_rt_masks_request(
    level: int = EXT_MSG_ALL_LEVELS,
) -> bytes:
    """0x7D SET_ALL_RT_MASKS request payload: sub-command, 2 pad, u32 level.

    Sets EVERY SSID's F3 runtime level at once. The default 0xFFFFFFFF is the
    "emit your whole F3 surface" request — note the two reserved bytes
    sit exactly where a response carries its status word, which is why the
    ``.ksy`` needs to be told the direction.
    """
    from struct import pack

    return pack("<BxxI", EXT_MSG_SET_ALL_RT_MASKS, level)


def parse_set_all_rt_masks_reply(body: bytes):
    """Parse a ``0x7D`` SET_ALL_RT_MASKS reply body → ``(sub_cmd, status, echoed_mask)``.

    Wire, measured on a live EG25-G / MDM9607::

        [0]    u8   sub-command echo  (== EXT_MSG_SET_ALL_RT_MASKS, 5)
        [1]    u8   status            (0x01 on every accepted arm observed)
        [2]    u8   pad               (0x00)
        [3:7]  u32 LE  the runtime level mask the firmware ACTUALLY stored

    e.g. ``SET_ALL 0x0000001F`` replied ``05 01 00 1f000000`` — the echoed u32 is
    the arm the firmware committed, which is not necessarily the one requested
    (a clamp or reject echoes a *different* value with the same status). Returns
    ``None`` when the body is too short or is not a SET_ALL_RT_MASKS echo, so a
    **truncated** or wrong-shaped reply cannot be silently read as a confirmed
    mask — the caller must treat ``None`` as "arming unconfirmed", never as OK.
    """
    if len(body) < 7 or body[0] != EXT_MSG_SET_ALL_RT_MASKS:
        return None
    return body[0], body[1], int.from_bytes(body[3:7], "little")


def build_ext_msg_config_get_mask_request(
    sub_cmd: int = EXT_MSG_GET_RT_MASK,
    ss_id_first: int = 0,
    ss_id_last: int = EXT_MSG_SS_RANGE0_LAST,
) -> bytes:
    """0x7D mask-table READ request payload: sub-command, ss_id_first, ss_id_last.

    ``sub_cmd`` selects which table is read (both share this request shape):

    * :data:`EXT_MSG_GET_RT_MASK` (3) — the **runtime** mask, i.e. what the F3
      plane is actually armed to right now. This readback exists because
      arming F3 is a modem-side state change that outlives the DIAG session,
      so the value an arm destroys must be read first.
    * :data:`EXT_MSG_GET_BUILD_MASK` (2) — the **build-time per-SSID capability**
      table, i.e. the levels this firmware image *can* emit. Hardware-verified
      invariant to the runtime mask: byte-identical when read at runtime
      ``0x00000000``, ``0xFFFFFFFF`` and ``0x0000001F``.

    Wire, hardware-verified on a live EG25-G (MDM9607)::

        [0]    u8   sub_cmd
        [1:3]  u16  ss_id_first
        [3:5]  u16  ss_id_last

    ⚠️ **A one-byte request is not a short reply — it is a short REQUEST.** A
    bare ``b"\\x03"`` returns a 7-byte header with **no array at all**, which is
    exactly the "n=1 misparse" an under-sized reply produces, arriving from
    the opposite direction. Always send the full 5-byte form.

    The two sub-commands size their replies differently, and only sub_cmd 2
    honours the requested window: sub_cmd 3 returns a fixed 495-byte body (122
    entries) whatever range is asked for, while sub_cmd 2 returns
    ``7 + 4·(min(ss_id_last, 121) + 1)`` bytes.
    """
    from struct import pack

    if sub_cmd not in (EXT_MSG_GET_BUILD_MASK, EXT_MSG_GET_RT_MASK):
        raise ValueError(
            f"sub_cmd {sub_cmd} is not a 0x7D mask-table read "
            f"({EXT_MSG_GET_BUILD_MASK} = build, {EXT_MSG_GET_RT_MASK} = runtime)"
        )
    if not (0 <= ss_id_first <= 0xFFFF and 0 <= ss_id_last <= 0xFFFF):
        raise ValueError(f"ss_id out of u16 range: {ss_id_first}..{ss_id_last}")
    if ss_id_last < ss_id_first:
        raise ValueError(f"ss_id_last {ss_id_last} < ss_id_first {ss_id_first}")
    return pack("<BHH", sub_cmd, ss_id_first, ss_id_last)


def parse_ext_msg_mask_table_reply(body: bytes):
    """Parse a 0x7D sub_cmd 2/3 mask-table reply → ``(sub_cmd, first, last, status, masks)``.

    Wire, hardware-verified on a live EG25-G (MDM9607,
    ``EG25GGBR07A08M2G``)::

        [0]    u8    sub_cmd echo   (2 = build capability, 3 = runtime)
        [1:3]  u16   ss_id_first
        [3:5]  u16   ss_id_last     (sub_cmd 3: echoes the request;
                                     sub_cmd 2: constant 121, the size of
                                     SSID range 0, NOT the array length)
        [5:7]  u16   status         (0x0001 on every accepted read observed)
        [7:]   u32[] LE             one runtime/capability mask PER ss_id

    ⛔ **The array starts at offset 7, not 9.** An earlier reading placed it at
    ``9 + 4·N``. That lands two bytes into the target entry, and because a
    *uniform* table of byte-splat values is invariant under a 16-bit rotation,
    the error is **completely invisible** on every mask the splat rule covers —
    it surfaces only on the non-uniform masks, which is precisely why they read
    as an unexplained residual. ``0x12345678`` stores ``0x7E7E7E78`` and was
    reported as ``0x7E787E7E``: the same bytes, rotated by 16. Offset 7 is
    self-checking — ``7 + 4×122 == 495`` and ``7 + 4×121 == 491`` exactly, and a
    bounded SET_RT_MASK on ss_id N moves exactly the entry at ``7 + 4·N``
    (verified on N = 3, 7, 10, 20 and the range 30..35).

    Returns ``None`` when the body is too short, is not a mask-table reply, or
    does not hold a whole number of u32 entries — so a truncated reply can never
    be read as "the mask is 0".
    """
    from struct import unpack_from

    if len(body) < EXT_MSG_MASK_TABLE_HDR_LEN:
        return None
    if body[0] not in (EXT_MSG_GET_BUILD_MASK, EXT_MSG_GET_RT_MASK):
        return None
    payload_len = len(body) - EXT_MSG_MASK_TABLE_HDR_LEN
    if payload_len == 0 or payload_len % 4:
        return None
    first, last, status = unpack_from("<HHH", body, 1)
    masks = [
        unpack_from("<I", body, EXT_MSG_MASK_TABLE_HDR_LEN + 4 * i)[0]
        for i in range(payload_len // 4)
    ]
    return body[0], first, last, status, masks


def ext_msg_set_all_stored_mask(requested: int) -> int:
    """Predict what SET_ALL_RT_MASKS actually STORES for ``requested``.

    ``SET_ALL_RT_MASKS`` does **not** store the u32 it is handed, and it does
    not store a low-byte splat either. Hardware-measured rule, EG25-G / MDM9607,
    16/16 rows including 7 stated as blind predictions *before* the arm
    ::

        stored_byte[i] = OR(requested_byte[0] .. requested_byte[i])

    i.e. a **cumulative prefix-OR over the little-endian bytes**. Worked::

        0x12345678  bytes 78 56 34 12  ->  78, 7E, 7E, 7E  ->  0x7E7E7E78
        0xAABBCCDD  bytes DD CC BB AA  ->  DD, DD, FF, FF  ->  0xFFFFDDDD
        0x01020408  bytes 08 04 02 01  ->  08, 0C, 0E, 0F  ->  0x0F0E0C08

    The long-standing "low byte replicated across all four bytes" reading is the
    special case where only byte 0 is set — every prefix-OR is then that byte —
    which covers ``0x1F``, ``0x78``, ``0xAB`` and both exact endpoints
    ``0x00000000`` / ``0xFFFFFFFF``. It is not the general rule. Byte order is
    pinned, not assumed: ``0x08040201`` stores ``0x0F070301`` (LE-cumulative),
    where a big-endian fold would give ``0x080C0E0F``.

    ⚠️ Scope: measured on **one** MDM9607 build. It is a prediction to compare a
    readback against, never a substitute for one — :func:`read_ext_msg_rt_mask`
    is the only trustworthy reading on an unmeasured part.

    ⚠️ This transform applies to SET_ALL_RT_MASKS (sub_cmd 5) **only**. The
    bounded per-SSID SET_RT_MASK (sub_cmd 4) stores its mask **verbatim** once
    the request is correctly framed — see :func:`_build_ext_msg_set_rt_mask`.
    """
    acc = 0
    out = bytearray()
    for byte in (requested & 0xFFFFFFFF).to_bytes(4, "little"):
        acc |= byte
        out.append(acc)
    return int.from_bytes(out, "little")


def _build_ext_msg_query_ss_ranges() -> bytes:
    """DIAG_EXT_MSG_CONFIG_F / QUERY_SSID_RANGES (sub_cmd 1) request payload.

    The RETRIEVE-equivalent that enumerates the firmware's valid SSID ranges —
    the only reliable way to discover which ss_ids ``--ext-msg-f3-ss`` may
    target on a given build (the SSID set is firmware-dependent). ``b"\\x01"``
    is the whole request.
    """
    return b"\x01"


#: Bytes before the range array in a QUERY_SSID_RANGES reply.
_EXT_MSG_SS_RANGES_HDR_LEN = 7


def _parse_ext_msg_ss_ranges(body: bytes) -> list[tuple[int, int]]:
    """Parse a QUERY_SSID_RANGES response body into (first, last) SSID pairs.

    ``body`` is the ``_send_recv`` response payload (everything after 0x7D),
    i.e. starts with the echoed sub_cmd byte. Layout, **hardware-verified**
    on a live Quectel EG25-G (MDM9607, ``EG25GGBR07A08M2G``) with the
    F3 plane silenced so the reply could not be truncated::

        [0]     u8    sub_cmd     == 1
        [1:3]   u16   status      == 1
        [3:5]   u16   num_ranges
        [5:7]   u16   reserved    == 0
        [7:]    num_ranges × { ss_id_first u16, ss_id_last u16 }

    ⚠️ **This corrects a layout that was wrong on real hardware.** The previous
    reading took ``num_ranges`` from ``u16 @1`` and started the array at offset
    3. On the EG25-G's 107-byte reply that yields **one** pair, ``(25, 0)`` — a
    range whose *last* is below its *first* — and silently discards the other
    **24** real ranges. The corrected offsets are self-checking: ``7 + 4 × 25``
    is exactly 107, every pair ascends, and the values are plainly SSID-shaped
    (``0..120``, ``500..506``, ``1000..1007`` … ``49152..49251``, 647 SSIDs).
    The old docstring flagged the shape as *"hardware-unverified in-repo"*; it
    now is, and it did not hold.

    Defensive: returns as many well-formed pairs as the buffer holds; never
    raises on a short/garbled tail, so a truncated reply degrades to a prefix
    rather than crashing a live capture.
    """
    from struct import unpack_from

    if len(body) < _EXT_MSG_SS_RANGES_HDR_LEN:
        return []
    num = unpack_from("<H", body, 3)[0]
    ranges: list[tuple[int, int]] = []
    off = _EXT_MSG_SS_RANGES_HDR_LEN
    for _ in range(num):
        if off + 4 > len(body):
            break
        first, last = unpack_from("<HH", body, off)
        ranges.append((first, last))
        off += 4
    return ranges


def _query_ext_msg_ss_ranges(client: DiagClient) -> list[tuple[int, int]]:
    """Send QUERY_SSID_RANGES and return the parsed (first, last) SSID pairs.

    Returns ``[]`` on timeout or an empty/garbled response.
    """
    result = client._send_recv(
        0x7D, _build_ext_msg_query_ss_ranges(), timeout=5.0
    )
    if result is None:
        return []
    op, body = result
    if op != 0x7D:
        return []
    return _parse_ext_msg_ss_ranges(body)


def build_ext_msg_set_rt_mask_array(ss_id_first: int, masks: "list[int]") -> bytes:
    """SET_RT_MASK request carrying an EXPLICIT per-ss_id mask array.

    The general form of :func:`_build_ext_msg_set_rt_mask` (which replicates one
    value). Restoring a *non-uniform* table needs this: SET_ALL_RT_MASKS can
    only write one value everywhere, so it cannot express a table that differs
    per SSID.
    """
    from struct import pack

    if not masks:
        raise ValueError("masks must be non-empty")
    ss_id_last = ss_id_first + len(masks) - 1
    if not (0 <= ss_id_first <= 0xFFFF and ss_id_last <= 0xFFFF):
        raise ValueError(f"ss_id out of u16 range: {ss_id_first}..{ss_id_last}")
    return pack(
        "<BHHH", EXT_MSG_SET_RT_MASK, ss_id_first, ss_id_last, 0
    ) + b"".join(pack("<I", m & 0xFFFFFFFF) for m in masks)


def read_ext_msg_rt_mask(
    client: DiagClient,
    ss_id_first: int = 0,
    ss_id_last: int = EXT_MSG_SS_RANGE0_LAST,
    sub_cmd: int = EXT_MSG_GET_RT_MASK,
    timeout: float = 10.0,
) -> "list[int] | None":
    """Read the modem's CURRENT F3 per-ss_id mask table. ``None`` if unreadable.

    Arming F3 is a **modem-side state change that outlives the DIAG session**
    — the runtime mask is sticky until the part re-enumerates — so a tool that
    arms it without reading it first destroys the prior value. That makes a later *"this build emits no F3
    for subsystem X"* indistinguishable from *"the previous session narrowed the
    mask and left"*, permanently and after the fact.

    Returns the list of per-ss_id u32 masks, or ``None`` on timeout, an explicit
    DIAG_BAD_CMD_F rejection, or a reply that does not parse — never a
    zero-filled list, because "unreadable" and "armed to zero" are the two
    readings this function exists to keep apart.

    ⚠️ Safe to call on a **noisy** port. ``_send_recv`` skips non-matching
    opcodes, so a saturating F3 plane (0x79/0x99) does not have to be silenced
    first — which matters, because silencing it is exactly the destructive act
    being logged. Verified against a live, fully-armed EG25-G.
    """
    result = client._send_recv(
        DIAG_EXT_MSG_CONFIG_F,
        build_ext_msg_config_get_mask_request(sub_cmd, ss_id_first, ss_id_last),
        timeout=timeout,
    )
    if result is None:
        return None
    op, body = result
    if op != DIAG_EXT_MSG_CONFIG_F:
        return None
    parsed = parse_ext_msg_mask_table_reply(body)
    if parsed is None:
        return None
    return parsed[4]


def describe_ext_msg_rt_mask(masks: "list[int] | None") -> str:
    """One-line human summary of a mask table, for the capture log."""
    if masks is None:
        return "UNREADABLE"
    if not masks:
        return "empty"
    distinct = set(masks)
    if len(distinct) == 1:
        return f"uniform 0x{masks[0]:08X} across {len(masks)} ss_id(s)"
    from collections import Counter

    top = Counter(masks).most_common(4)
    shown = ", ".join(f"0x{v:08X}×{n}" for v, n in top)
    more = "" if len(distinct) <= 4 else f", +{len(distinct) - 4} more"
    return f"{len(masks)} ss_id(s), {len(distinct)} distinct: {shown}{more}"


class F3MaskSnapshot(NamedTuple):
    """The F3 runtime mask of EVERY advertised SSID range, as read before an arm.

    ``ranges`` holds one ``(ss_id_first, ss_id_last, masks)`` per range that
    QUERY_SSID_RANGES (sub_cmd 1) advertised. ``masks`` is ``None`` for a range
    whose sub_cmd 3 read failed. ``complete`` is True only when the range query
    answered AND every range read back. A snapshot that is not complete cannot
    support a "VERIFIED" restore, because some SSIDs were never in view.

    ⛔ **Why per range, not one table.** Reading **range 0 only**
    (ss_id 0..121) is not enough: SET_ALL_RT_MASKS arms **every** range, so on
    an EP06-A (MDM9240, 25 ranges, 669 SSIDs) a range-0 restore puts 122 SSIDs
    back, reads the same 122 back, and reports VERIFIED, while F3 keeps flowing
    on the other 547 (`0x79` 1,019 + `0x92` 7,440 frames in an 8 s
    passive tap). Such a verify is accurate about what it read; it just never
    reads most of the device.
    """

    ranges: "tuple[tuple[int, int, list[int] | None], ...]"
    complete: bool

    def all_masks(self) -> "list[int]":
        return [m for _f, _l, masks in self.ranges if masks for m in masks]

    def unreadable(self) -> int:
        return sum(1 for _f, _l, masks in self.ranges if masks is None)


def describe_ext_msg_rt_snapshot(snap: "F3MaskSnapshot | None") -> str:
    """One-line summary of a whole-device snapshot, naming its coverage."""
    if snap is None or not snap.ranges:
        return "UNREADABLE"
    readable = len(snap.ranges) - snap.unreadable()
    if readable == 0:
        return f"UNREADABLE in all {len(snap.ranges)} range(s)"
    text = (f"{describe_ext_msg_rt_mask(snap.all_masks())} "
            f"in {readable} range(s)")
    if snap.unreadable():
        text += f" — ⚠️ {snap.unreadable()} range(s) UNREADABLE"
    if not snap.complete:
        text += " — ⚠️ PARTIAL (not every SSID range was read)"
    return text


def read_ext_msg_rt_mask_snapshot(
    client: DiagClient, ranges: "list[tuple[int, int]] | None" = None,
) -> "F3MaskSnapshot | None":
    """Read the runtime mask of every SSID range the firmware advertises.

    ``ranges`` defaults to a live QUERY_SSID_RANGES (sub_cmd 1). If that query
    fails, this falls back to range 0 alone and marks the snapshot
    ``complete=False``. A range-0-only reading is still worth logging. It just
    cannot certify a restore.

    Each range is read with one sub_cmd 3 request for ``first..last``. Wire,
    measured on a live EP06-A (MDM9240 silicon, ``EP06ALAR02A08M4G``):

    * the reply covers the **whole range containing** ``ss_id_first`` and
      ignores ``ss_id_last`` (``4500..4500`` returned all 85 entries);
    * the last range, ``49152..49251``, is advertised as 100 SSIDs but replies
      with **200** entries. The trailing 100 are not addressable SSIDs.

    So each table is **truncated to the advertised range length**. Comparing or
    writing the extra entries would address SSIDs the firmware never listed.

    Returns ``None`` only when not even range 0 could be read.
    """
    queried = ranges is None
    if queried:
        ranges = _query_ext_msg_ss_ranges(client)
    complete = bool(ranges)
    if not ranges:
        ranges = [(0, EXT_MSG_SS_RANGE0_LAST)]
    out = []
    for first, last in ranges:
        masks = read_ext_msg_rt_mask(client, first, last)
        if masks is not None:
            masks = masks[: last - first + 1]
        else:
            complete = False
        out.append((first, last, masks))
    snap = F3MaskSnapshot(tuple(out), complete)
    if snap.unreadable() == len(out):
        return None
    return snap


def log_pre_arm_ext_msg_rt_mask(client: DiagClient, *, who: str = "diaggulp") -> "F3MaskSnapshot | None":
    """Read and LOG the F3 runtime mask about to be overwritten.

    Always called before an arm. The logging half is unconditional, because it is
    the only record that the state ever existed. It reads **every** SSID range,
    since SET_ALL_RT_MASKS overwrites every range. Returns the snapshot so a
    caller that opted into restoring can hand it to
    :func:`restore_ext_msg_rt_mask`.
    """
    snap = read_ext_msg_rt_mask_snapshot(client)
    if snap is None:
        print(
            f"{who}: ⚠️ could not read the pre-arm F3 runtime mask "
            "(DIAG_EXT_MSG_CONFIG_F sub_cmd 3) — the state this arm overwrites "
            "is UNRECORDED, so a later 'no F3 for subsystem X' from this modem "
            "cannot be told apart from a mask a previous session narrowed",
            file=sys.stderr,
        )
        return None
    print(
        f"{who}: pre-arm F3 runtime mask — {describe_ext_msg_rt_snapshot(snap)} "
        "(read back via DIAG_EXT_MSG_CONFIG_F sub_cmd 3; this arm overwrites it "
        "and it is sticky until the modem re-enumerates)",
        file=sys.stderr,
    )
    return snap


def _snapshot_set_all_value(snap: F3MaskSnapshot) -> "int | None":
    """The one value SET_ALL can restore ``snap`` with, or ``None``.

    That is possible only when the snapshot is complete, every SSID holds the same
    value V, and SET_ALL stores V verbatim (:func:`ext_msg_set_all_stored_mask`).
    In practice V is ``0x00000000`` (the boot default) or ``0xFFFFFFFF``. SET_ALL
    also reaches SSIDs the range query does not advertise, so it is the more
    complete restore whenever it can express the table.
    """
    if not snap.complete:
        return None
    values = set(snap.all_masks())
    if len(values) != 1:
        return None
    (v,) = values
    return v if ext_msg_set_all_stored_mask(v) == v else None


def restore_ext_msg_rt_mask(
    client: DiagClient, saved: "F3MaskSnapshot | None", *, who: str = "diaggulp",
) -> bool:
    """Put the F3 runtime mask back to ``saved``, and VERIFY by reading it back.

    Opt-in only (``--restore-f3-mask-on-exit``). ⛔ It must not be the default: a
    capture run *meant* to leave the modem armed for a following passive tap
    would be broken by an automatic restore, and silently. Logging the pre-arm
    value (:func:`log_pre_arm_ext_msg_rt_mask`) is the half that always happens.

    It writes back **every** range in the snapshot. A uniform table goes back with
    one SET_ALL; anything else goes back with one SET_RT_MASK array per range.
    Then it re-reads every range.

    Returns ``True`` only when the snapshot is complete AND a readback of every
    range matches it entry-for-entry. The claim is never made from the request
    succeeding: SET_ALL_RT_MASKS stores a *transform* of what it is handed
    (:func:`ext_msg_set_all_stored_mask`) and its reply echoes the **request**,
    so an echo check would confirm the wrong thing. It is never made
    from a partial snapshot either. A gauge that read only part of the device
    cannot vouch for the rest.
    """
    if not saved or not saved.ranges:
        return False
    want = describe_ext_msg_rt_snapshot(saved)
    set_all = _snapshot_set_all_value(saved)
    if set_all is not None:
        writes = [build_ext_msg_config_set_all_rt_masks_request(set_all)]
    else:
        writes = [build_ext_msg_set_rt_mask_array(first, masks)
                  for first, _last, masks in saved.ranges if masks]
    for payload in writes:
        result = client._send_recv(DIAG_EXT_MSG_CONFIG_F, payload, timeout=10.0)
        if result is None or result[0] == DIAG_BAD_CMD_F:
            why = "timed out" if result is None else "was rejected (DIAG_BAD_CMD_F)"
            print(
                f"{who}: ⚠️ F3 runtime-mask restore {why}; the modem is LEFT AT "
                f"THE ARMED MASK, not the pre-arm one ({want})",
                file=sys.stderr,
            )
            return False
    post = read_ext_msg_rt_mask_snapshot(
        client, [(first, last) for first, last, _m in saved.ranges])
    mismatched = [
        (first, last) for (first, last, masks), got in zip(
            saved.ranges, post.ranges if post else [(0, 0, None)] * len(saved.ranges))
        if masks is not None and got[2] != masks
    ]
    if not mismatched and saved.complete:
        how = (f"one SET_ALL 0x{set_all:08X}" if set_all is not None
               else f"{len(writes)} per-range SET_RT_MASK write(s)")
        print(
            f"{who}: restored the pre-arm F3 runtime mask — {want} — via {how}, "
            f"VERIFIED by readback of all {len(saved.ranges)} range(s)",
            file=sys.stderr,
        )
        return True
    if not mismatched:
        print(
            f"{who}: ⚠️ F3 runtime-mask restore NOT verified: the pre-arm "
            f"snapshot was PARTIAL ({want}), so SSIDs outside it were never "
            "recorded and may still be armed — treat this modem's F3 state as "
            "unknown for the next session",
            file=sys.stderr,
        )
        return False
    shown = ", ".join(f"{f}..{l}" for f, l in mismatched[:6])
    more = "" if len(mismatched) <= 6 else f" (+{len(mismatched) - 6} more)"
    print(
        f"{who}: ⚠️ F3 runtime-mask restore NOT verified: wanted {want}, "
        f"readback gives {describe_ext_msg_rt_snapshot(post)}; "
        f"{len(mismatched)} range(s) differ: {shown}{more} — treat this modem's "
        "F3 state as unknown for the next session",
        file=sys.stderr,
    )
    return False
