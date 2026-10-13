"""maskstate: save, zero and verified-restore of the F3 runtime mask + event mask."""

from struct import pack, unpack_from

import pytest

from diagmunge import maskstate
from diagmunge.diag_cmd import DIAG_EVENT_MASK_GET_F, DIAG_EVENT_MASK_SET_F
from diagmunge.f3mask import (
    DIAG_EXT_MSG_CONFIG_F,
    EXT_MSG_GET_RT_MASK,
    EXT_MSG_QUERY_SSID_RANGES,
    EXT_MSG_SET_ALL_RT_MASKS,
    EXT_MSG_SET_RT_MASK,
    ext_msg_set_all_stored_mask,
)

RANGES = [(0, 3), (500, 501)]
EV_BITS = 20


class FakeModem:
    """Two F3 ranges plus a 20-bit event mask, with knobs for the failure paths."""

    def __init__(self, f3=None, events=0, *, f3_unreadable=False, ev_unreadable=False,
                 ev_ignores_restore=False, ranges_unanswered=False):
        self.ranges_unanswered = ranges_unanswered
        self.f3 = {first: list(f3[first]) if f3 else [0] * (last - first + 1)
                   for first, last in RANGES}
        self.events = events
        self.f3_unreadable = f3_unreadable
        self.ev_unreadable = ev_unreadable
        self.ev_ignores_restore = ev_ignores_restore
        self.ev_sets = 0

    def _send_recv(self, op, payload, timeout=5.0):
        payload = bytes(payload)
        if op == DIAG_EXT_MSG_CONFIG_F:
            sub = payload[0]
            if sub == EXT_MSG_QUERY_SSID_RANGES:
                if self.ranges_unanswered:
                    return None
                return (op, pack("<BHHH", 1, 0, len(RANGES), 0)
                        + b"".join(pack("<HH", f, l) for f, l in RANGES))
            if sub == EXT_MSG_GET_RT_MASK:
                if self.f3_unreadable:
                    return None
                first, last = unpack_from("<HH", payload, 1)
                return (op, pack("<BHHH", 3, first, last, 1)
                        + b"".join(pack("<I", m) for m in self.f3[first]))
            if sub == EXT_MSG_SET_ALL_RT_MASKS:
                v = ext_msg_set_all_stored_mask(unpack_from("<I", payload, 3)[0])
                self.f3 = {k: [v] * len(m) for k, m in self.f3.items()}
                return (op, payload[:7])
            if sub == EXT_MSG_SET_RT_MASK:
                first, last = unpack_from("<HH", payload, 1)
                self.f3[first] = [unpack_from("<I", payload, 7 + 4 * i)[0]
                                  for i in range(last - first + 1)]
                return (op, payload[:7])
        if op == DIAG_EVENT_MASK_GET_F:
            if self.ev_unreadable:
                return (0x13, b"")
            nbytes = (EV_BITS + 7) // 8
            return (op, pack("<BHH", 0, 0, EV_BITS) + self.events.to_bytes(nbytes, "little"))
        if op == DIAG_EVENT_MASK_SET_F:
            self.ev_sets += 1
            new = int.from_bytes(payload[5:], "little") & ((1 << EV_BITS) - 1)
            if not (self.ev_ignores_restore and new):
                self.events = new
            return (op, payload)
        raise AssertionError(f"unexpected op 0x{op:02X}")


ARMED_F3 = {0: [0x1F, 0, 0x7, 0], 500: [0xFF, 0x3]}   # non-uniform: per-range restore


def test_round_trip_zeroes_then_restores_both_masks_verified(capsys):
    m = FakeModem(ARMED_F3, events=0b1010_0000_0000_0000_0101)
    saved = maskstate.save_and_zero(m, who="t")
    assert saved.f3_zeroed and saved.events_zeroed
    assert all(v == 0 for ms in m.f3.values() for v in ms) and m.events == 0
    assert maskstate.restore(m, saved, who="t") == (True, True)
    assert m.f3 == ARMED_F3 and m.events == 0b1010_0000_0000_0000_0101
    err = capsys.readouterr().err
    assert "t: restored the pre-arm F3 runtime mask" in err      # who= reaches f3mask
    assert "VERIFIED by 0x81 readback" in err


def test_masks_already_quiet_are_never_written():
    m = FakeModem(events=0)
    saved = maskstate.save_and_zero(m, who="t")
    assert not saved.f3_zeroed and not saved.events_zeroed and m.ev_sets == 0
    assert maskstate.restore(m, saved, who="t") == (True, True)
    assert m.ev_sets == 0


def test_an_unreadable_f3_mask_is_left_armed_not_zeroed(capsys):
    m = FakeModem(ARMED_F3, f3_unreadable=True)
    saved = maskstate.save_and_zero(m, who="t")
    assert not saved.f3_zeroed
    assert m.f3 == ARMED_F3
    assert "cannot be restored" in capsys.readouterr().err


def test_a_partial_snapshot_is_not_zeroed(capsys):
    """Range query unanswered: range 0 reads back but the rest was never seen.

    Zeroing would wipe the SSIDs outside range 0 with no record to restore them from.
    """
    m = FakeModem(ARMED_F3, ranges_unanswered=True)
    saved = maskstate.save_and_zero(m, who="t")
    assert saved.f3 is not None and saved.f3.complete is False   # range 0 did read
    assert not saved.f3_zeroed and m.f3 == ARMED_F3
    assert "not fully readable" in capsys.readouterr().err


def test_an_unreadable_event_mask_is_left_alone():
    m = FakeModem(events=0b11, ev_unreadable=True)
    saved = maskstate.save_and_zero(m, who="t")
    assert saved.events is None and not saved.events_zeroed and m.ev_sets == 0


def test_an_event_restore_that_does_not_take_is_reported_unverified(capsys):
    m = FakeModem(events=0b11, ev_ignores_restore=True)
    saved = maskstate.save_and_zero(m, who="t")
    assert maskstate.restore(m, saved, who="t") == (True, False)
    assert "NOT verified" in capsys.readouterr().err


@pytest.mark.parametrize("name", [
    "read_ext_msg_rt_mask_snapshot", "restore_ext_msg_rt_mask",
    "parse_ext_msg_mask_table_reply", "F3MaskSnapshot",
])
def test_diaggulp_names_are_the_diagmunge_objects(name):
    """diaggulp re-imports the moved code; a private copy would drift."""
    import importlib.util
    import pathlib
    import diagmunge.f3mask as f3mask
    path = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diaggulp.py"
    if not path.exists():
        pytest.skip("diaggulp is -only; not in the carved package")
    spec = importlib.util.spec_from_file_location("diaggulp_5530", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert getattr(mod, name) is getattr(f3mask, name)
