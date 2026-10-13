# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""DIAG control-plane command builders (subsystem-dispatch envelope + QSH/QTrace).

Clean-room reimplementation. Builders return the *inner* (pre-HDLC) byte
string of a DIAG command; HDLC framing + CRC are the job of
``diagmunge.transport.DiagClient``, which the caller passes these bytes to.

Everything is little-endian (the whole DIAG protocol is LE).

Command families:
  - subsystem-dispatch envelope (0x4B)
  - QSH-metrics config (0x9002)
  - QTrace maskset filter (0x9004)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# --- Subsystem-dispatch envelope -----------------------------------------

DIAG_SUBSYS_CMD_F: int = 0x4B
DIAG_SUBSYS_LTE: int = 0x44  # subsystem-dispatch namespace (=68), NOT SCAT's 0x0B


def build_subsys_command(subsys_id: int, subsys_cmd: int, payload: bytes = b"") -> bytes:
    """Return the inner (pre-HDLC) bytes of a DIAG subsystem-dispatch command.

    Layout: u8(0x4B) + u8(subsys_id) + u16le(subsys_cmd) + payload.
    Raises ValueError if subsys_id not in 0..255 or subsys_cmd not in 0..65535.
    """
    if not 0 <= subsys_id <= 0xFF:
        raise ValueError(f"subsys_id out of range 0..255: {subsys_id!r}")
    if not 0 <= subsys_cmd <= 0xFFFF:
        raise ValueError(f"subsys_cmd out of range 0..65535: {subsys_cmd!r}")
    return struct.pack("<BBH", DIAG_SUBSYS_CMD_F, subsys_id, subsys_cmd) + payload


# --- DIAG event reporting (0x60, top-level) -------------------------------
#
# Events are a THIRD log flavor, distinct from log-code 0x10 LOG_F records and
# from F3 ext-msg text: discrete firmware state-transition markers (call drop,
# RRC state change, RACH outcome, …) carried on the DIAG_EVENT_REPORT_F stream.
# The on-switch is the generation-stable top-level command 0x60 with a single
# enable byte — honored MDM9x00 → SDX75, and the primitive qcsuper/SCAT use.
# Unlike the QSH 0x9002 subsystem command it is NOT wrapped in the 0x4B
# subsystem-dispatch envelope. Per-event narrowing is the separate 0x81/0x82
# event-mask pair below. The default-on policy still sends only 0x60
#; the mask is touched only when a capture asks for specific ids.

DIAG_EVENT_REPORT_F: int = 0x60


def build_event_report_enable(enable: bool = True) -> bytes:
    """Return inner (pre-HDLC) bytes of a DIAG event-report on/off command.

    Layout: ``u8(0x60) + u8(1 if enable else 0)``. Enabling makes the modem
    stream ``0x60`` event-report packets for the capture window; the default
    (all-events) surface needs no accompanying ``0x82`` mask set. This is the
    same event on-switch qcsuper/SCAT arm, and it is stable across every
    DIAG generation. HDLC framing + CRC are added by ``DiagClient``.
    """
    return struct.pack("<BB", DIAG_EVENT_REPORT_F, 1 if enable else 0)


# --- Per-event mask: GET (0x81) / SET (0x82) ----------------------
#
# The 0x60 on-switch arms the event stream; the event MASK decides which event
# ids are on it. The firmware ships a default mask, so an event it masks off
# never reaches a 0x60-only capture, and "never armed" looks exactly like
# "doesn't exist".
#
# Layout, after the opcode byte, for both the 0x81 reply and the 0x82 request:
#
#     u8 status | u16 pad | u16le num_bits | mask[...]
#
# Bit ``i`` of the mask (byte ``i // 8``, LSB-first) is event id ``i``.
#
# ⚠️ The mask WIDTH is asymmetric. A GET reply carries ``ceil(num_bits/8)``
# bytes; a SET request must carry ``num_bits//8 + 1``. The two differ by one
# byte exactly when num_bits is a multiple of 8. On such a build a SET of the
# GET's width is silently REFUSED: the 0x82 reply looks normal but echoes the
# unchanged mask (EM160R-GL, num_bits 3240, live). The 0x82 reply
# uses the SET width. :class:`EventMask` stores the canonical ``ceil`` width,
# accepts either on parse, and :func:`build_event_mask_set` always emits
# ``num_bits//8 + 1``.
#
# Pinned by:
#   - live single-bit differentials: toggling event 2608 moved exactly
#     body byte 331 bit 0 (= 5 + 2608//8, bit 2608%8) on a Sierra EM9291
#     (SDX62, num_bits 3428), and arming only 2608 read back ``[2608]`` on a
#     Quectel EM160R-GL (num_bits 3240);
#   - a vendor-tool-authored 0x82 request (``82 00 0000 fd0c`` + 416 mask
#     bytes, num_bits 3325);
#   - 0x81 replies at four widths (2880 / 3163 / 3240 / 3428 bits), each exactly
#     ``5 + ceil(num_bits/8)`` bytes long.
#
# ⚠️ ``0x60`` REWRITES the whole mask: ``build_event_report_enable(True)`` sets
# every bit and ``(False)`` clears every bit (both parts above, live). So
# "add ids" after the on-switch is a no-op, and any later ``0x60`` on (e.g. a
# reconnect re-arm) silently undoes a narrowed mask. Apply a mask AFTER the
# last 0x60.
# An earlier best-effort decoder read num_bits at offset 1, which lands on the
# zero pad word, and so fell back to treating the whole body as the mask. That
# reading shifts every event id by +40 (the 5 header bytes).
#
# ⛔ Never SET a mask whose width was not read from THIS modem. ``num_bits`` is
# the firmware's event count; a guessed width can disarm everything. Use
# read-modify-write: GET, ``EventMask.with_ids(...)``, SET.

DIAG_EVENT_MASK_GET_F: int = 0x81
DIAG_EVENT_MASK_SET_F: int = 0x82
EVENT_MASK_HEADER_LEN: int = 5  # status u8 + pad u16 + num_bits u16 (after opcode)


@dataclass(frozen=True)
class EventMask:
    """One modem's event mask: ``num_bits`` event ids, LSB-first bitfield.

    Immutable; :meth:`with_ids` / :meth:`without_ids` return a new mask of the
    SAME width, which is what makes a read-modify-write safe. ``status`` is the
    reply's status byte and is never sent (a request always carries 0).
    """

    num_bits: int
    mask: bytes
    status: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.num_bits <= 0xFFFF:
            raise ValueError(f"num_bits out of range 1..65535: {self.num_bits!r}")
        want = (self.num_bits + 7) // 8
        if len(self.mask) != want:
            raise ValueError(
                f"mask is {len(self.mask)} bytes; num_bits={self.num_bits} needs {want}"
            )

    @classmethod
    def empty(cls, num_bits: int) -> "EventMask":
        """A mask of ``num_bits`` ids with none armed. Take ``num_bits`` from a GET."""
        return cls(num_bits=num_bits, mask=bytes((num_bits + 7) // 8))

    def is_set(self, event_id: int) -> bool:
        """True if ``event_id`` is armed. Ids outside ``0..num_bits-1`` are False."""
        if not 0 <= event_id < self.num_bits:
            return False
        return bool(self.mask[event_id // 8] & (1 << (event_id % 8)))

    def set_ids(self) -> tuple[int, ...]:
        """Every armed event id, ascending. Padding bits past ``num_bits`` are ignored."""
        return tuple(i for i in range(self.num_bits) if self.is_set(i))

    def _edit(self, ids, on: bool) -> "EventMask":
        buf = bytearray(self.mask)
        for event_id in ids:
            if not 0 <= event_id < self.num_bits:
                raise ValueError(
                    f"event id {event_id!r} is outside this firmware's mask "
                    f"(num_bits={self.num_bits}); refusing to resize it"
                )
            bit = 1 << (event_id % 8)
            if on:
                buf[event_id // 8] |= bit
            else:
                buf[event_id // 8] &= ~bit & 0xFF
        return EventMask(num_bits=self.num_bits, mask=bytes(buf), status=self.status)

    def with_ids(self, ids) -> "EventMask":
        """Return this mask with ``ids`` also armed (every existing bit kept)."""
        return self._edit(ids, True)

    def without_ids(self, ids) -> "EventMask":
        """Return this mask with ``ids`` cleared (every other bit kept)."""
        return self._edit(ids, False)


def build_event_mask_get() -> bytes:
    """Return inner (pre-HDLC) bytes of a DIAG_EVENT_MASK_GET_F (0x81) request.

    ``u8(0x81) + 3 zero bytes``. A Sierra EM9291 (SDX62) answers ONLY this
    exact 4-byte form and silently drops a 1-, 3- or 5-byte request: a timeout,
    not ``BAD_CMD``. A Quectel EM160R-GL answers both this and the bare opcode
    the older committed readbacks were taken with (live).
    """
    return bytes([DIAG_EVENT_MASK_GET_F, 0, 0, 0])


def parse_event_mask_reply(body: bytes) -> EventMask:
    """Parse a 0x81 reply body (or a 0x82 request/reply body) into an :class:`EventMask`.

    ``body`` is everything AFTER the opcode byte, which is what
    ``DiagClient._send_recv`` returns. The mask may be the GET width
    ``ceil(num_bits/8)`` or the SET width ``num_bits//8 + 1``; the result is
    normalised to the GET width (the dropped byte holds only padding bits).
    Raises ``ValueError`` for any other length or ``num_bits == 0``. A body that
    does not fit is never guessed into a mask.
    """
    if len(body) < EVENT_MASK_HEADER_LEN:
        raise ValueError(f"event-mask body too short: {len(body)} bytes")
    status, _pad, num_bits = struct.unpack_from("<BHH", body, 0)
    if num_bits == 0:
        raise ValueError("event-mask body declares num_bits == 0")
    mask = body[EVENT_MASK_HEADER_LEN:]
    want = (num_bits + 7) // 8
    if len(mask) not in (want, num_bits // 8 + 1):
        raise ValueError(
            f"event-mask body carries {len(mask)} mask bytes; num_bits={num_bits} "
            f"needs {want} (GET width) or {num_bits // 8 + 1} (SET width)"
        )
    return EventMask(num_bits=num_bits, mask=bytes(mask[:want]), status=status)


def build_event_mask_set(mask: EventMask) -> bytes:
    """Return inner (pre-HDLC) bytes of a DIAG_EVENT_MASK_SET_F (0x82) request.

    Layout: ``u8(0x82) + u8(0) + u16(0) + u16le(num_bits) + mask``, with the
    mask zero-padded to the SET width ``num_bits//8 + 1`` (see the ⚠️ width
    note above). Build ``mask`` from a GET of the same modem (see the ⛔ note),
    e.g. ``EventMask.empty(parse_event_mask_reply(get_body).num_bits).with_ids([0xA30])``.
    Verify by a second GET, never by the 0x82 reply: a refused SET still replies.
    """
    width = mask.num_bits // 8 + 1
    payload = mask.mask + bytes(width - len(mask.mask))
    return struct.pack("<BBHH", DIAG_EVENT_MASK_SET_F, 0, 0, mask.num_bits) + payload


# --- QSH-metrics config (0x9002) -----------------------------------------
#
# ⚠️ Payload schema below is a single-source observation, validated only where
# a live modem has ACKed it (see the builder docstrings). The unit tests lock
# the *encoder*; only a live-modem ACK validates the *schema*.

QSH_METRICS_CONFIG_SUBCMD: int = 0x9002
QSH_METRICS_MIN_ARGS: int = 4
QSH_ACTION_FLUSH_CLEAR: int = 2  # flush accumulated metrics, then clear buffers
QSH_ENABLE_OFF: int = 0
QSH_ENABLE_ON: int = 1


def build_qsh_metrics_config(
    *,
    action: int,
    enable: int,
    client_id: int = 0,
    item_ids: tuple[int, ...] = (),
    subsys_id: int = DIAG_SUBSYS_LTE,
) -> bytes:
    """Return inner (pre-HDLC) bytes of a QSH-metrics config (0x9002) command.

    Payload = u32le(arg_count) + u32le(action) + u32le(enable)
              + u32le(client_id) + u32le(len(item_ids)) + u32le(id) for id in item_ids
    where arg_count = QSH_METRICS_MIN_ARGS + len(item_ids).
    Then wrapped by build_subsys_command(subsys_id, 0x9002, payload).

    ⚠️ **The ``item_ids=`` (enable-with-items) form is GENERATION-SPECIFIC**.
    - **SDX24 REJECTS it** (Telit LM960A18 fw 32.01.150): any ``0x9002``
      payload with ``item_count > 0`` is **uniformly rejected (status 3)** across 8
      action×enable combos × 6 item-block layouts — a *structural* rejection, not an
      item-id value check (bogus ``0xFFFFFFFF`` and firmware-confirmed NAMED ids
      ``3``=BLER/``4``=MCS/``5``=RACH_PWR behave identically).
    - **SDX62 ACCEPTS it** (Quectel RM520N-GL fw ``RM520NGLAAR01A08M4G_11.200.11.200``,
      ``/dev/mhi_DIAG``): ``0x9002`` with ``item_ids=(3,4,5)``
      (``item_count=3``) returns **status 0**. So the item block is a valid encoding
      on SDX6x — the SDX24 refutation is a per-generation quirk of that older part,
      NOT a defect in this builder. ``item_ids=`` is therefore kept and is usable on
      SDX55/62/72-class parts; on SDX24 route selection through ``0x9004``
      (:func:`build_qtrace_maskset_filter`) instead.

    ⚠️ **Acceptance (status 0) ≠ on-wire record emission.** Even on the SDX62 with
    the item block accepted AND the modem registered (T-Mobile, ``CGATT: 1``) under
    active RACH/RRC/NAS re-attach signaling, the capture banked **zero ``0x9D``
    QSH-metric records and zero ``0x1FE8`` QTrace** (``.scan.json`` ``qsh`` block
    ``present=false``). QSH metrics behave as a control/pull (internal-accumulator)
    surface, not an auto-streaming ``0x9D`` log push: ``0x9002``/``0x9004`` enable
    is necessary but NOT sufficient for on-wire records — an explicit QSH dump/query
    path (not set by this builder) appears to be required. The zero-item global form
    (:func:`build_qsh_metrics_enable`) is likewise status-0 on SDX24/SDX62 and
    ``0x13 BAD_CMD`` on pre-SDX MDM9607. The encoder unit tests lock the *encoding
    shape*, not its on-wire acceptance or record emission.
    """
    item_ids = tuple(item_ids)
    arg_count = QSH_METRICS_MIN_ARGS + len(item_ids)
    words = (arg_count, action, enable, client_id, len(item_ids), *item_ids)
    payload = struct.pack(f"<{len(words)}I", *words)
    return build_subsys_command(subsys_id, QSH_METRICS_CONFIG_SUBCMD, payload)


def build_qsh_metrics_disable(subsys_id: int = DIAG_SUBSYS_LTE) -> bytes:
    """Convenience: flush+clear and stop QSH metrics on ``subsys_id``.

    Equivalent to build_qsh_metrics_config(action=QSH_ACTION_FLUSH_CLEAR,
    enable=QSH_ENABLE_OFF, client_id=0, item_ids=(), subsys_id=subsys_id).
    """
    return build_qsh_metrics_config(
        action=QSH_ACTION_FLUSH_CLEAR,
        enable=QSH_ENABLE_OFF,
        client_id=0,
        item_ids=(),
        subsys_id=subsys_id,
    )


def build_qsh_metrics_enable(subsys_id: int = DIAG_SUBSYS_LTE) -> bytes:
    """Convenience: flush+clear and (globally) start QSH metrics on ``subsys_id``.

    Symmetric with :func:`build_qsh_metrics_disable` — the *global* enable form
    (``item_count = 0``): flush any stale accumulation, then turn metrics on.
    Equivalent to build_qsh_metrics_config(action=QSH_ACTION_FLUSH_CLEAR,
    enable=QSH_ENABLE_ON, client_id=0, item_ids=(), subsys_id=subsys_id).

    Hardware-validated on SDX24 (Telit LM960A18): returns a clean
    ``0x4B`` ACK with status 0. This is the global on-switch used to bank QSH
    metrics into a capture; the *selective* enable-with-items path is a separate
    (and, on SDX24, refuted) encoding. Incapable parts (pre-SDX
    MDM9607) return ``0x13 BAD_CMD``; callers arming captures should tolerate
    that rather than treat it as fatal.
    """
    return build_qsh_metrics_config(
        action=QSH_ACTION_FLUSH_CLEAR,
        enable=QSH_ENABLE_ON,
        client_id=0,
        item_ids=(),
        subsys_id=subsys_id,
    )


# --- QTrace maskset-filter (0x9004) --------------------------------------
#
# ⚠️ The 0x9004 subcommand and payload shape are single-source observations,
# subject to the same live-ACK validation caveat as 0x9002.

QTRACE_MASKSET_FILTER_SUBCMD: int = 0x9004


def build_qtrace_maskset_filter(
    item_ids: tuple[int, ...] = (),
    *,
    subsys_id: int = DIAG_SUBSYS_LTE,
) -> bytes:
    """Return inner (pre-HDLC) bytes of a QTrace maskset-filter (0x9004) command.

    Payload = u32le(len(item_ids)) + u32le(id) for id in item_ids.
    Wrapped by build_subsys_command(subsys_id, 0x9004, payload).
    """
    item_ids = tuple(item_ids)
    words = (len(item_ids), *item_ids)
    payload = struct.pack(f"<{len(words)}I", *words)
    return build_subsys_command(subsys_id, QTRACE_MASKSET_FILTER_SUBCMD, payload)


def build_qtrace_disable(subsys_id: int = DIAG_SUBSYS_LTE) -> bytes:
    """Convenience: clear all QTrace filters (item_count=0) on ``subsys_id``."""
    return build_qtrace_maskset_filter((), subsys_id=subsys_id)


# --- QSH-trace maskset SET (0x9001) ---------------------------------------
#
# The 0x9001 subcommand is the *SET* half of the QSH-trace control plane, as
# distinct from the 0x9004 *filter* (:func:`build_qtrace_maskset_filter`). It is
# the command that turns on the ``0x9D DIAG_QSH_TRACE_PAYLOAD_F`` stream from
# the host, with no EFS ``diag_bootup_flag`` write and no reboot. 0x9002
# (metrics-enable) + 0x9004 (filter) alone bank 0x9D=0.
#
# Host-side validated: on a tethered SDX55 a single 0x9001 SET takes
# 0x9D from 0 to ~1400/s with status 0, and the empty maskset (count 0) is the
# matching disarm. The *semantics* of the two constant header words are still
# unconfirmed; they are exposed as overridable keyword args.

QSH_TRACE_MASKSET_SET_SUBCMD: int = 0x9001
QSH_TRACE_SET_MIN_ARGS: int = 3  # word_a + word_b + count (each a u32 after arg_count)


def build_qsh_trace_maskset_set(
    pairs: tuple[tuple[int, int], ...],
    *,
    word_a: int = 1,
    word_b: int = 1,
    subsys_id: int = DIAG_SUBSYS_LTE,
) -> bytes:
    """Return inner (pre-HDLC) bytes of a QSH-trace maskset SET (0x9001) command.

    Payload = u32le(arg_count) + u32le(word_a) + u32le(word_b) + u32le(count)
              + [u16le(ssid) + u16le(level)] for (ssid, level) in pairs
    where ``count = len(pairs)`` and ``arg_count = QSH_TRACE_SET_MIN_ARGS + count``
    (i.e. 3 + count — each (ssid, level) pair occupies exactly one u32 slot, so it
    counts as one arg word, mirroring the 0x9002 arg-count convention). Then
    wrapped by :func:`build_subsys_command` (subsys ``0x44``, cmd ``0x9001``).

    ``pairs`` are opaque ``(ssid, level)`` tuples. **Unlike an F3 ext-msg level,
    a QSH-trace ``level`` is not a small monotonic threshold** — some SSIDs carry
    a per-subsystem *bitmask* in the level word (e.g. ``(0x3a, 0x0a81)`` arms
    bits 0, 7, 9 and 11 of one subsystem), so no range check is applied.

    ``word_a`` / ``word_b`` are the two u32 header words that sit between
    ``arg_count`` and ``count``; both default to ``1`` and their
    semantics are unconfirmed (likely a version and/or client-id pair, by analogy
    with the 0x9002 action/enable/client_id header). They are exposed as
    overridable keyword args so a hardware bisection can sweep them.

    ⛔ **``pairs`` MUST be in strictly ascending ``ssid`` order** — the modem
    rejects anything else with **status 1**. Use :func:`merge_qsh_trace_pairs`
    to extend an existing maskset rather than concatenating, and see that function
    for the hardware evidence. This is *not* enforced here: sending a
    deliberately mis-ordered set is the negative control that established the
    rule, and callers probing acceptance semantics need it.

    ⚠️ **status 1 therefore does NOT mean "the modem rejected that subsystem".**
    Appending an SSID below the maskset's last ssid breaks the ordering and
    fails no matter which SSID it is, so reading such a status as a
    per-subsystem capability signal is wrong. Judge subsystem acceptance by
    whether ``0x9D`` frames actually arrive carrying that ``subsys_id``,
    never by the SET status alone.
    """
    pairs = tuple(pairs)
    count = len(pairs)
    arg_count = QSH_TRACE_SET_MIN_ARGS + count
    payload = struct.pack("<4I", arg_count, word_a, word_b, count)
    for ssid, level in pairs:
        if not 0 <= ssid <= 0xFFFF:
            raise ValueError(f"ssid out of range 0..65535: {ssid!r}")
        if not 0 <= level <= 0xFFFF:
            raise ValueError(f"level out of range 0..65535: {level!r}")
        payload += struct.pack("<HH", ssid, level)
    return build_subsys_command(subsys_id, QSH_TRACE_MASKSET_SET_SUBCMD, payload)


def merge_qsh_trace_pairs(
    *groups: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, int], ...]:
    """Merge ``(ssid, level)`` groups into one ordering-legal QSH-trace maskset.

    The ``0x9001`` maskset array must be in **strictly ascending ssid order**;
    the modem returns status 1 the moment it reads an ssid that does not exceed
    its predecessor. Concatenating extra pairs onto an existing maskset
    therefore fails for every appended ssid below that maskset's last entry —
    which, for a wide maskset, is most of the interesting namespace. This
    helper sorts and de-duplicates so the result is always accepted; on a
    duplicate ssid the **last** group's level wins, so later groups override.

    Hardware-established on a Telit FT980m (SDX55, ``M0H.030002``) by
    seven falsifiable predictions, all confirmed. ``base`` is a strictly
    ascending multi-subsystem maskset whose last ssid is ``L``:

    ==========================================  ======  ==============
    maskset                                     status  reading
    ==========================================  ======  ==============
    ``sorted(base + LOC_*)``                    0       ordering OK
    ``base + LOC_*`` concatenated               1       order break
    ``reversed(base)``                          1       order break
    ``sorted(base + (0x01, 0x01))``             0       low ssid is fine *in order*
    ``base`` with one adjacent duplicate        1       must be *strictly* ascending
    ``((0x10, 1), (0x20, 1))``                  0       minimal ascending pair
    ``((0x20, 1), (0x10, 1))``                  1       minimal descending pair
    ==========================================  ======  ==============

    The tell that isolated ordering from ssid identity: appending an ssid
    above ``L`` is **accepted**, while appending an ssid already *in* ``base``
    is rejected. Nothing about which subsystem was named ever mattered.

    Example — extend a maskset with the location subsystems::

        BASE = ((0x08, 0x05), (0x44, 0x0C), (0x66, 0x30))
        LOC = ((0x5A, 0xFF), (0x5B, 0xFF), (0x5C, 0xFF), (0x5D, 0xFF), (0x5F, 0xFF))
        build_qsh_trace_maskset_set(merge_qsh_trace_pairs(BASE, LOC))
    """
    by_ssid: dict[int, int] = {}
    for group in groups:
        for ssid, level in group:
            by_ssid[ssid] = level
    return tuple(sorted(by_ssid.items()))


# --- DIAG_EXT_MSG_CONFIG_F SET_RT_MASK (0x7D / subtype 0x04) ---------------
#
# The runtime ext-msg (F3/trace) mask setter — top-level command 0x7D, NOT
# subsystem-wrapped. It raises the F3 ``0x79`` / ``0x99`` planes; it is NOT a
# prerequisite for the 0x9001 QSH-trace stream: a single 0x9001 SET suffices
#. One u32 runtime mask is supplied per SSID in the inclusive
# [ssid_first .. ssid_last] range.

DIAG_EXT_MSG_CONFIG_F: int = 0x7D
EXT_MSG_CONFIG_SET_RT_MASK: int = 0x04  # subtype: set runtime mask for an SSID range


def build_ext_msg_set_rt_mask(
    ssid_first: int,
    levels: tuple[int, ...],
    *,
    reserved: int = 0,
) -> bytes:
    """Return inner (pre-HDLC) bytes of a DIAG_EXT_MSG_CONFIG_F SET_RT_MASK (0x7D/0x04).

    Layout: u8(0x7D) + u8(0x04) + u16le(ssid_first) + u16le(ssid_last)
            + u16le(reserved) + u32le(level) for level in levels
    where ``ssid_last = ssid_first + len(levels) - 1`` — one 32-bit runtime mask
    per SSID in the inclusive range. The ``reserved`` u16 (a struct-alignment
    field between ``ssid_last`` and the mask array) is 0 in every observed frame;
    omitting it shifts every mask by two bytes, so it is explicit here.

    This is a **top-level** command (no ``0x4B`` subsystem-dispatch envelope),
    unlike the QSH 0x900x builders. HDLC framing + CRC are added by ``DiagClient``.
    """
    if not levels:
        raise ValueError("levels must be non-empty (one u32 mask per SSID in range)")
    if not 0 <= ssid_first <= 0xFFFF:
        raise ValueError(f"ssid_first out of range 0..65535: {ssid_first!r}")
    ssid_last = ssid_first + len(levels) - 1
    if ssid_last > 0xFFFF:
        raise ValueError(f"ssid range overflows u16: first={ssid_first} n={len(levels)}")
    header = struct.pack(
        "<BBHHH",
        DIAG_EXT_MSG_CONFIG_F,
        EXT_MSG_CONFIG_SET_RT_MASK,
        ssid_first,
        ssid_last,
        reserved,
    )
    return header + struct.pack(f"<{len(levels)}I", *levels)
