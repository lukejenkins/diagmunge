"""Save, zero and verified-restore the F3 runtime mask and the event mask.

A consumer that owns a DIAG port but wants only LOG records (diaggpsd
``--mask own``) should not pay for F3 and event traffic that an earlier tool
left armed. Both masks are modem-side sticky: they outlive the DIAG session.
So the consumer reads both, zeroes both, and puts both back on exit, the same
way diaggulp ``--restore-f3-mask-on-exit`` does for F3.

⛔ **A mask that could not be read is never zeroed.** Zeroing it would destroy
state that cannot be put back. That mask is left alone and the reason is
reported.

A restore is reported as verified only when a readback matches the saved value.
The F3 half is :func:`diagmunge.f3mask.restore_ext_msg_rt_mask`. The event
half re-reads 0x81 and compares the mask bytes.

The QSH-trace maskset is not covered here: it has no GET, so it cannot be
restored, only disarmed with diaggulp ``--disarm-qsh-on-exit``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from diagmunge.diag_cmd import (
    DIAG_EVENT_MASK_GET_F,
    DIAG_EVENT_MASK_SET_F,
    EventMask,
    build_event_mask_get,
    build_event_mask_set,
    parse_event_mask_reply,
)
from diagmunge.f3mask import (
    DIAG_EXT_MSG_CONFIG_F,
    F3MaskSnapshot,
    build_ext_msg_config_set_all_rt_masks_request,
    describe_ext_msg_rt_snapshot,
    read_ext_msg_rt_mask_snapshot,
    restore_ext_msg_rt_mask,
)
from diagmunge.transport import DIAG_BAD_CMD_F

if TYPE_CHECKING:
    from diagmunge.transport import DiagClient


@dataclass(frozen=True)
class SavedMasks:
    """What :func:`save_and_zero` read. ``None`` = unreadable, so it was left alone."""

    f3: "F3MaskSnapshot | None"
    events: "EventMask | None"
    f3_zeroed: bool = False
    events_zeroed: bool = False


def _say(who: str, msg: str) -> None:
    print(f"{who}: {msg}", file=sys.stderr)


def read_event_mask(client: DiagClient) -> "EventMask | None":
    """Read the event mask (0x81), or ``None``.

    Tries the 4-byte request first (the only form an EM9291 / SDX62 answers),
    then the bare opcode. ``None`` on BAD_CMD, on a reply that does not
    parse, or when neither form is answered.
    """
    for req in (build_event_mask_get(), bytes([DIAG_EVENT_MASK_GET_F])):
        res = client._send_recv(req[0], req[1:], timeout=3.0)
        if res is None:
            continue
        op, body = res
        if op != DIAG_EVENT_MASK_GET_F:
            return None
        try:
            return parse_event_mask_reply(body)
        except ValueError:
            return None
    return None


def _write_event_mask(client: DiagClient, mask: EventMask) -> bool:
    req = build_event_mask_set(mask)
    res = client._send_recv(req[0], req[1:], timeout=3.0)
    return res is not None and res[0] == DIAG_EVENT_MASK_SET_F


def save_and_zero(client: DiagClient, *, who: str) -> SavedMasks:
    """Read the F3 and event masks, then zero each one that read back completely."""
    f3 = read_ext_msg_rt_mask_snapshot(client)
    f3_zeroed = False
    if f3 is None or not f3.complete:
        _say(who, "⚠️ F3 runtime mask not fully readable "
                  f"({describe_ext_msg_rt_snapshot(f3)}); leaving it as found, "
                  "because a mask that was not read cannot be restored")
    elif any(f3.all_masks()):
        res = client._send_recv(DIAG_EXT_MSG_CONFIG_F,
                                build_ext_msg_config_set_all_rt_masks_request(0),
                                timeout=10.0)
        f3_zeroed = res is not None and res[0] != DIAG_BAD_CMD_F
        _say(who, f"saved F3 runtime mask ({describe_ext_msg_rt_snapshot(f3)}); "
                  + ("zeroed it for the run" if f3_zeroed else
                     "⚠️ the zeroing SET_ALL failed, so F3 stays armed"))
    else:
        _say(who, "F3 runtime mask already zero; nothing to quiet")

    events = read_event_mask(client)
    events_zeroed = False
    if events is None:
        _say(who, "⚠️ event mask (0x81) not readable; leaving it as found")
    elif events.set_ids():
        events_zeroed = _write_event_mask(client, EventMask.empty(events.num_bits))
        _say(who, f"saved event mask ({len(events.set_ids())} of {events.num_bits} "
                  "ids armed); "
                  + ("zeroed it for the run" if events_zeroed else
                     "⚠️ the zeroing 0x82 failed, so events stay armed"))
    else:
        _say(who, f"event mask already empty ({events.num_bits} ids); nothing to quiet")
    return SavedMasks(f3, events, f3_zeroed, events_zeroed)


def restore(client: DiagClient, saved: SavedMasks, *, who: str) -> "tuple[bool, bool]":
    """Put back whatever :func:`save_and_zero` zeroed, verifying each by readback.

    Returns ``(f3_ok, events_ok)``. A mask that was never zeroed is ``True``:
    nothing was changed, so there is nothing to put back.
    """
    f3_ok = True
    if saved.f3_zeroed:
        f3_ok = restore_ext_msg_rt_mask(client, saved.f3, who=who)
    events_ok = True
    if saved.events_zeroed and saved.events is not None:
        events_ok = False
        if _write_event_mask(client, saved.events):
            back = read_event_mask(client)
            events_ok = back is not None and back.mask == saved.events.mask
        n = len(saved.events.set_ids())
        _say(who, f"restored the event mask ({n} ids), VERIFIED by 0x81 readback"
             if events_ok else
             f"⚠️ event-mask restore NOT verified ({n} ids wanted); treat this "
             "modem's event mask as unknown for the next session")
    return f3_ok, events_ok
