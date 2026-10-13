# SPDX-License-Identifier: Apache-2.0
"""Per-event DIAG masking: 0x81 EVENT_MASK_GET reply / 0x82 EVENT_MASK_SET.

The layout under test — ``u8 status, u16 pad, u16 num_bits, mask[ceil(num_bits/8)]``
after the opcode byte — is pinned by two independent sources pointing the same way:

- a vendor-tool-authored **0x82 request** (3325 bits, 416 mask bytes);
- five committed **0x81 replies** at three distinct widths (2880 / 3163 / 3240
  bits), each satisfying ``5 + ceil(num_bits/8) == len(body)`` exactly.
"""
import pytest

from diagmunge.diag_cmd import (
    DIAG_EVENT_MASK_GET_F,
    DIAG_EVENT_MASK_SET_F,
    EVENT_MASK_HEADER_LEN,
    EventMask,
    build_event_mask_get,
    build_event_mask_set,
    parse_event_mask_reply,
)

# A synthetic 3325-bit mask (not from any device): ids 0, 0xA30 and the last
# id (num_bits - 1) set, everything else clear.
NUM_BITS = 3325


def _base() -> EventMask:
    mask = bytearray((NUM_BITS + 7) // 8)
    for i in (0, 0xA30, NUM_BITS - 1):
        mask[i // 8] |= 1 << (i % 8)
    return EventMask(num_bits=NUM_BITS, mask=bytes(mask))


def test_constants():
    assert DIAG_EVENT_MASK_GET_F == 0x81
    assert DIAG_EVENT_MASK_SET_F == 0x82
    assert EVENT_MASK_HEADER_LEN == 5


def test_synthetic_set_request_round_trips_byte_exact():
    req = build_event_mask_set(_base())
    assert len(req) == 1 + 5 + NUM_BITS // 8 + 1
    m = parse_event_mask_reply(req[1:])
    assert m.num_bits == NUM_BITS and m.status == 0
    assert m.set_ids() == (0, 0xA30, NUM_BITS - 1)
    assert build_event_mask_set(m) == req


@pytest.mark.parametrize("num_bits", [2880, 3163, 3240, 3325, 1, 8, 9])
def test_reply_width_matches_ceil(num_bits):
    n = (num_bits + 7) // 8
    body = bytes([0, 0, 0]) + num_bits.to_bytes(2, "little") + bytes(n)
    m = parse_event_mask_reply(body)
    assert m.num_bits == num_bits
    assert len(m.mask) == n


def test_reply_header_is_five_bytes_not_three():
    # A "layout A" parser reads num_bits at body[1:3]. On every real reply that
    # word is the zero PADDING, so a parser using it would see num_bits == 0. Pin
    # that num_bits comes from body[3:5].
    body = bytes.fromhex("000000400b") + bytes(360)
    assert parse_event_mask_reply(body).num_bits == 0x0B40


@pytest.mark.parametrize("body", [
    b"",
    bytes(4),                                         # shorter than the header
    bytes.fromhex("000000400b") + bytes(359),         # one mask byte short
    bytes.fromhex("000000400b") + bytes(362),         # two bytes past the GET width
    bytes.fromhex("0000003f0b") + bytes(361),         # 2879 bits: 360 is BOTH widths, 361 is neither
    bytes.fromhex("0000000000"),                      # num_bits == 0
])
def test_reply_rejects_inconsistent_bodies(body):
    with pytest.raises(ValueError):
        parse_event_mask_reply(body)


def test_get_request_is_four_bytes():
    # EM9291 (SDX62) answers only exactly 81 00 00 00; bare/3/5-byte are dropped.
    assert build_event_mask_get() == bytes.fromhex("81000000")


def test_set_reply_width_is_accepted_and_normalised():
    # EM160R-GL (num_bits 3240 = 405*8): the 0x82 reply carries 406 mask bytes.
    body = bytes.fromhex("000000a80c") + bytes(405) + b"\x00"
    m = parse_event_mask_reply(body)
    assert m.num_bits == 3240
    assert len(m.mask) == 405
    assert m == parse_event_mask_reply(bytes.fromhex("000000a80c") + bytes(405))


def test_set_request_pads_to_set_width_when_num_bits_is_a_multiple_of_8():
    # The live EM160R bug: a 405-byte SET (the GET width) is silently refused;
    # 406 (num_bits//8 + 1) is applied.
    m = EventMask.empty(3240).with_ids([0xA30])
    req = build_event_mask_set(m)
    assert len(req) == 1 + EVENT_MASK_HEADER_LEN + 406
    assert req[-1] == 0
    assert req[1 + EVENT_MASK_HEADER_LEN + 0xA30 // 8] == 1 << (0xA30 % 8)
    # and it parses back to the same ids
    assert parse_event_mask_reply(req[1:]).set_ids() == (0xA30,)


def test_set_request_width_equals_get_width_otherwise():
    for nb in (3428, 3325, 3163, 12):
        req = build_event_mask_set(EventMask.empty(nb))
        assert len(req) == 1 + EVENT_MASK_HEADER_LEN + (nb + 7) // 8


def test_empty():
    m = EventMask.empty(3428)
    assert m.num_bits == 3428 and len(m.mask) == 429 and m.set_ids() == ()


def test_set_request_layout():
    m = EventMask(num_bits=12, mask=bytes([0x01, 0x08]))
    assert build_event_mask_set(m) == bytes.fromhex("82" "00" "0000" "0c00" "0108")


def test_set_request_always_sends_status_zero():
    # status is a REPLY field; a request carries 0 whatever the source mask held.
    m = EventMask(num_bits=8, mask=b"\xff", status=7)
    assert build_event_mask_set(m)[1] == 0


@pytest.mark.parametrize("num_bits,mask", [
    (12, bytes(1)),        # too short for 12 bits
    (12, bytes(3)),        # too long
    (0, b""),              # zero width
    (0x10000, bytes(8192)),  # u16 overflow
])
def test_event_mask_rejects_width_mismatch(num_bits, mask):
    with pytest.raises(ValueError):
        EventMask(num_bits=num_bits, mask=mask)


def test_with_ids_is_read_modify_write():
    base = _base()
    got = base.with_ids([1, 2, 3])
    assert got.num_bits == base.num_bits            # width never changes
    assert got.is_set(1) and got.is_set(2) and got.is_set(3)
    # every bit the base had is still set
    assert set(base.set_ids()) <= set(got.set_ids())
    assert set(got.set_ids()) - set(base.set_ids()) == {1, 2, 3}
    # the base object is untouched (frozen; RMW returns a new mask)
    assert not base.is_set(1)


def test_with_ids_idempotent_on_already_set():
    base = _base()
    assert base.with_ids([0xA30]) == base


def test_without_ids_clears_only_those():
    base = _base()
    got = base.without_ids([0xA30])
    assert not got.is_set(0xA30)
    assert set(base.set_ids()) - set(got.set_ids()) == {0xA30}


def test_without_ids_on_an_already_clear_id_leaves_it_clear():
    # Clearing is not toggling: id 1 is clear in the base mask and must stay so.
    base = _base()
    assert not base.is_set(1)
    assert base.without_ids([1]) == base


@pytest.mark.parametrize("bad", [3325, 4000, -1])
def test_with_ids_refuses_ids_outside_the_firmware_width(bad):
    # Never extend the mask: an id the firmware's width does not cover is an
    # error, not a silent resize (a wrong width could disarm everything).
    base = _base()
    with pytest.raises(ValueError):
        base.with_ids([bad])


def test_padding_bits_beyond_num_bits_are_not_ids():
    # num_bits=9 → 2 bytes; bits 9..15 of the last byte are padding.
    m = EventMask(num_bits=9, mask=bytes([0x00, 0xFF]))
    assert m.set_ids() == (8,)
    assert not m.is_set(9)


def test_is_set_out_of_range_is_false():
    m = EventMask(num_bits=9, mask=bytes([0xFF, 0x01]))
    assert not m.is_set(9)
    assert not m.is_set(-1)
