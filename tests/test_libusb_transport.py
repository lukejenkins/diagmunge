# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the libusb DIAG transport.

Mirrors the serial-transport coverage but for the raw-USB-only DIAG path used
by the Inseego M3100 (SDX65) and other modems that expose DIAG as a bulk vendor
interface with no ttyUSB / cdc-wdm node.

A fake bulk-endpoint device (`_FakeBulkDev`) stands in for a pyusb device so the
byte-pipe mechanics — reader thread, os.pipe() bridge, select()-able fileno,
and a full DiagClient._send_recv round-trip — are exercised without hardware.
`pyusb` must be importable (its USBError class is referenced), which it is in
the project venv; the test itself never opens a real USB device.
"""
from __future__ import annotations

import collections
import select
import time

import pytest

from diagmunge.transport import (
    DiagClient,
    _LibusbTransport,
    _M3100_DIAG_EP_IN,
    _M3100_DIAG_EP_OUT,
    _M3100_DIAG_IFACE,
    _diag_iface_candidates,
    _resolve_diag_endpoints,
    _select_diag_candidate,
)

usb_core = pytest.importorskip("usb.core")


class _FakeBulkDev:
    """Minimal pyusb-device stand-in: a bulk-IN queue + a bulk-OUT recorder.

    ``on_write(data) -> bytes|None`` models a fake modem: when the transport
    writes a request to the OUT endpoint, the returned bytes (if any) are
    enqueued as the IN response the reader thread will deliver. An empty IN
    queue raises ``USBError(errno=110)`` (ETIMEDOUT) — exactly what libusb
    surfaces for an idle bulk read — after a short sleep so the reader thread
    doesn't busy-spin the test.
    """

    def __init__(self, in_chunks=(), on_write=None):
        self._in = collections.deque(bytes(c) for c in in_chunks)
        self.writes = []
        self._on_write = on_write

    def read(self, ep, size, timeout=None):
        if self._in:
            return self._in.popleft()
        time.sleep(0.005)
        err = usb_core.USBError("timed out")
        err.errno = 110
        raise err

    def write(self, ep, data, timeout=None):
        payload = bytes(data)
        self.writes.append((ep, payload))
        if self._on_write is not None:
            resp = self._on_write(payload)
            if resp:
                self._in.append(bytes(resp))
        return len(payload)


def _drain(transport, deadline_s=2.0):
    """Read all currently-available bytes from the transport via select()."""
    out = bytearray()
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        ready, _, _ = select.select([transport.fileno()], [], [], 0.1)
        if not ready:
            if out:
                break  # got something and the pipe went quiet — done
            continue
        out += transport.read(65536)
    return bytes(out)


def test_bulk_in_passthrough_is_byte_identical():
    """Bytes read off the bulk-IN endpoint reach the consumer verbatim and in
    order — the raw-HDLC contract downstream tooling depends on."""
    chunks = [b"\x7e\x10\x01\x02", b"\x03\x04\x7e", b"\x7e\xffmore\x7e"]
    dev = _FakeBulkDev(in_chunks=chunks)
    t = _LibusbTransport(dev, iface=3, ep_in=0x84, ep_out=0x02,
                         read_timeout_ms=50)
    try:
        got = _drain(t)
        assert got == b"".join(chunks)
    finally:
        t.close()


def test_write_forwards_to_bulk_out_endpoint():
    dev = _FakeBulkDev()
    t = _LibusbTransport(dev, iface=3, ep_in=0x84, ep_out=0x07,
                         read_timeout_ms=50)
    try:
        t.write(b"hello-diag")
        assert dev.writes == [(0x07, b"hello-diag")]
    finally:
        t.close()


def test_fileno_is_selectable():
    """The bridged fd must be a real, select()-able descriptor (the whole point
    of the self-pipe design — DiagClient/diaggulp select() before reading)."""
    dev = _FakeBulkDev(in_chunks=[b"payload\x7e"])
    t = _LibusbTransport(dev, iface=3, ep_in=0x84, ep_out=0x02,
                         read_timeout_ms=50)
    try:
        assert isinstance(t.fileno(), int)
        ready, _, _ = select.select([t.fileno()], [], [], 2.0)
        assert ready, "reader thread never made the pipe readable"
    finally:
        t.close()


def test_send_recv_round_trip_over_libusb():
    """End-to-end: DiagClient framing (CRC + HDLC) works over the libusb byte
    pipe. A fake modem echoes a canned DIAG_VERNO_F (opcode 0) response when it
    sees the request on the OUT endpoint; _send_recv must correlate it back."""
    # Build a correctly-CRC'd HDLC response frame the way the modem would, by
    # reusing DiagClient's own encapsulation (no_crc=False → real CRC).
    framer = DiagClient(None, no_crc=False)
    resp_payload = b"\x00VERSION-STUB"          # opcode 0 + body
    resp_frame = framer._hdlc_encapsulate(resp_payload)

    def on_write(_request):
        return resp_frame

    dev = _FakeBulkDev(on_write=on_write)
    client = DiagClient(
        _LibusbTransport(dev, iface=3, ep_in=0x84, ep_out=0x02,
                         read_timeout_ms=50),
        no_crc=False,
    )
    try:
        result = client._send_recv(0x00, b"", timeout=3.0)
        assert result is not None, "no response correlated over libusb transport"
        op, body = result
        assert op == 0x00
        assert body == b"VERSION-STUB"
        # The request really went out the OUT endpoint (opcode 0, CRC'd).
        assert dev.writes and dev.writes[0][0] == 0x02
    finally:
        client.close()


# --- endpoint / interface resolution --------------------------------------

def test_resolve_endpoints_explicit_short_circuits():
    """All three explicit → returned as-is, no descriptor read (dev unused)."""
    assert _resolve_diag_endpoints(None, 3, 0x84, 0x02) == (3, 0x84, 0x02)


class _NoConfigDev:
    def get_active_configuration(self):
        raise usb_core.USBError("no config")


def test_resolve_endpoints_falls_back_to_m3100_defaults():
    got = _resolve_diag_endpoints(_NoConfigDev(), None, None, None)
    assert got == (_M3100_DIAG_IFACE, _M3100_DIAG_EP_IN, _M3100_DIAG_EP_OUT)


class _FakeEndpoint:
    def __init__(self, addr, bulk=True):
        self.bEndpointAddress = addr
        # bmAttributes low 2 bits: 0b10 = bulk, 0b11 = interrupt
        self.bmAttributes = 0x02 if bulk else 0x03


class _FakeInterface:
    def __init__(self, num, cls, sub, proto, eps):
        self.bInterfaceNumber = num
        self.bInterfaceClass = cls
        self.bInterfaceSubClass = sub
        self.bInterfaceProtocol = proto
        self._eps = eps

    def __iter__(self):
        return iter(self._eps)


class _FakeConfig:
    def __init__(self, interfaces):
        self._interfaces = interfaces

    def __iter__(self):
        return iter(self._interfaces)


class _FakeDescDev:
    def __init__(self, cfg):
        self._cfg = cfg

    def get_active_configuration(self):
        return self._cfg


def test_resolve_endpoints_autodetects_from_descriptor():
    """Descriptor scan picks the ff/ff/0x30 vendor DIAG interface and its bulk
    IN/OUT endpoints — no hard-coded M3100 values needed."""
    diag_if = _FakeInterface(
        4, 0xFF, 0xFF, 0x30,
        eps=[_FakeEndpoint(0x02, bulk=True), _FakeEndpoint(0x83, bulk=True)],
    )
    other_if = _FakeInterface(0, 0xFF, 0xFF, 0x00, eps=[])
    dev = _FakeDescDev(_FakeConfig([other_if, diag_if]))
    iface, ep_in, ep_out = _resolve_diag_endpoints(dev, None, None, None)
    assert iface == 4
    assert ep_in == 0x83   # the IN endpoint (bit 0x80 set)
    assert ep_out == 0x02  # the OUT endpoint


# --- ranked candidates + probe-based selection ---------------------
#
# The measured WNC 81UMV91M21 (MDM9150, 05c6:90f0) composition
# `rndis,rmnet_gsi,ipc,diag,serial,ffs`, where protocol 0x30 is `ipc` and DIAG
# is a plain ff/ff/0xff — the inverse of the M3100/Foxconn shape the original
# descriptor scan assumed.

def _wnc_le_gadget_dev():
    return _FakeDescDev(_FakeConfig([
        _FakeInterface(3, 0xFF, 0xFF, 0x30,   # ipc — descriptor says "DIAG"
                       eps=[_FakeEndpoint(0x84), _FakeEndpoint(0x02)]),
        _FakeInterface(4, 0xFF, 0xFF, 0xFF,   # the REAL diag
                       eps=[_FakeEndpoint(0x85), _FakeEndpoint(0x03)]),
        _FakeInterface(5, 0xFF, 0xFF, 0xFF,   # serial
                       eps=[_FakeEndpoint(0x86), _FakeEndpoint(0x04)]),
    ]))


def test_resolve_endpoints_picks_ipc_on_an_le_gadget():
    """Documents the defect the probe exists to override.

    The descriptor-only resolver picks iface 3 — the `ipc` function — because
    it matches ff/ff/0x30 first. This test asserts that WRONG answer on purpose:
    it is the reason the choice cannot be made from descriptor bits, and if it
    ever changes the probe's rationale needs revisiting.
    """
    assert _resolve_diag_endpoints(_wnc_le_gadget_dev(), None, None, None) \
        == (3, 0x84, 0x02)


def test_candidates_ranks_0x30_first_but_still_offers_the_ff_interfaces():
    """The real DIAG iface must be REACHABLE, not just outranked — a candidate
    that is never considered cannot be found by any probe."""
    cands = _diag_iface_candidates(_wnc_le_gadget_dev())
    assert cands == [(3, 0x84, 0x02), (4, 0x85, 0x03), (5, 0x86, 0x04)]


def test_candidates_skip_interfaces_without_both_bulk_directions():
    """A DIAG byte-pipe needs a bulk IN *and* a bulk OUT; requiring both drops
    control-only functions without needing to know their names."""
    dev = _FakeDescDev(_FakeConfig([
        _FakeInterface(0, 0xFF, 0xFF, 0xFF, eps=[]),                      # none
        _FakeInterface(1, 0xFF, 0xFF, 0xFF, eps=[_FakeEndpoint(0x81)]),   # IN only
        _FakeInterface(2, 0xFF, 0xFF, 0xFF, eps=[_FakeEndpoint(0x02)]),   # OUT only
        _FakeInterface(3, 0xFF, 0xFF, 0xFF,                               # interrupt
                       eps=[_FakeEndpoint(0x83, bulk=False),
                            _FakeEndpoint(0x04, bulk=False)]),
        _FakeInterface(4, 0xFF, 0xFF, 0xFF,
                       eps=[_FakeEndpoint(0x85), _FakeEndpoint(0x05)]),   # keeper
    ]))
    assert _diag_iface_candidates(dev) == [(4, 0x85, 0x05)]


def test_candidates_ignore_non_vendor_class_and_honour_a_pinned_iface():
    dev = _FakeDescDev(_FakeConfig([
        _FakeInterface(0, 0x02, 0x0E, 0x00,                               # CDC
                       eps=[_FakeEndpoint(0x81), _FakeEndpoint(0x01)]),
        _FakeInterface(4, 0xFF, 0xFF, 0xFF,
                       eps=[_FakeEndpoint(0x85), _FakeEndpoint(0x03)]),
        _FakeInterface(5, 0xFF, 0xFF, 0xFF,
                       eps=[_FakeEndpoint(0x86), _FakeEndpoint(0x04)]),
    ]))
    assert _diag_iface_candidates(dev) == [(4, 0x85, 0x03), (5, 0x86, 0x04)]
    assert _diag_iface_candidates(dev, iface=5) == [(5, 0x86, 0x04)]


class _FakeProbeTransport:
    def __init__(self, cand):
        self.cand = cand
        self.closed = False

    def close(self):
        self.closed = True


class _FakeProbeClient:
    """Stands in for a DiagClient: answers DIAG_VERNO_F only on `answers`."""

    def __init__(self, transport, answers):
        self._transport = transport
        self._answers = answers

    def _send_recv(self, opcode, payload, timeout=5.0):
        if self._transport.cand[0] in self._answers:
            return (opcode, b"\x00" * 8)
        return None            # mute — exactly what the ipc function does


def _run_select(candidates, answers, opener=None):
    opened = []

    def _open(cand):
        if opener is not None:
            opener(cand)
        t = _FakeProbeTransport(cand)
        opened.append(t)
        return t

    chosen, transport = _select_diag_candidate(
        candidates, _open, lambda t: _FakeProbeClient(t, answers), timeout=0.01)
    return chosen, transport, opened


def test_select_skips_the_mute_ipc_iface_and_picks_the_one_that_answers():
    cands = _diag_iface_candidates(_wnc_le_gadget_dev())
    chosen, transport, opened = _run_select(cands, answers={4})
    assert chosen == (4, 0x85, 0x03)          # NOT iface 3, despite its 0x30
    assert transport is opened[-1]
    assert not transport.closed               # the winner stays open for the caller
    assert opened[0].closed                   # the losing probe released its iface
    assert len(opened) == 2                   # iface 5 never probed — 4 answered


def test_select_returns_none_and_closes_everything_when_nothing_answers():
    cands = _diag_iface_candidates(_wnc_le_gadget_dev())
    chosen, transport, opened = _run_select(cands, answers=set())
    assert chosen is None and transport is None
    assert len(opened) == 3 and all(t.closed for t in opened)


def test_select_treats_an_unopenable_iface_as_a_miss_not_a_failure():
    """A busy/claimed interface must not abort the walk — the next candidate
    may well be the right one."""
    def _opener(cand):
        if cand[0] == 3:
            raise usb_core.USBError("busy")

    chosen, _, opened = _run_select(
        _diag_iface_candidates(_wnc_le_gadget_dev()), answers={4}, opener=_opener)
    assert chosen == (4, 0x85, 0x03)
    assert [t.cand[0] for t in opened] == [4]


def test_select_treats_a_raising_probe_as_a_miss_and_still_closes_it():
    """The wrong endpoint can raise (USBTimeoutError on a bulk OUT that was
    never drained) rather than merely stay silent — same verdict, and the
    transport must still be closed so the interface is released."""
    class _RaisingClient(_FakeProbeClient):
        def _send_recv(self, opcode, payload, timeout=5.0):
            if self._transport.cand[0] == 3:
                raise usb_core.USBError("timeout", errno=110)
            return super()._send_recv(opcode, payload, timeout)

    opened = []

    def _open(cand):
        t = _FakeProbeTransport(cand)
        opened.append(t)
        return t

    chosen, transport = _select_diag_candidate(
        _diag_iface_candidates(_wnc_le_gadget_dev()), _open,
        lambda t: _RaisingClient(t, {4}), timeout=0.01)
    assert chosen == (4, 0x85, 0x03)
    assert opened[0].cand[0] == 3 and opened[0].closed
    assert not transport.closed
