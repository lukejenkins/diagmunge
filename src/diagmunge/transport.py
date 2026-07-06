# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""DiagClient — Qualcomm DIAG protocol transport over serial or TCP.

HDLC framing:
  delimiter  0x7E
  escape     0x7D, next byte XOR 0x20
  CRC        CRC-16/MCRF4XX (reflected poly=0x8408, init=0xFFFF, xorOut=0xFFFF), little-endian, appended to payload

DiagClient factory methods:
  DiagClient.from_serial(port, baudrate)       — USB direct connection
  DiagClient.from_tcp_server(host, port)       — wait for diag_socket_log to connect
"""

from __future__ import annotations

import collections
import errno
import logging
import select
import socket
import threading
import time
from struct import pack, unpack_from, calcsize

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CRC-16 for Qualcomm DIAG/HDLC (CRC-16/MCRF4XX aka CRC-16/X.25)
# poly=0x8408 (reflected 0x1021), init=0xFFFF, xorOut=0xFFFF
# This is the standard HDLC/PPP CRC used by Qualcomm's DIAG protocol.
# ---------------------------------------------------------------------------

def _build_crc16_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else crc >> 1
        table.append(crc)
    return table


_CRC16_TABLE = _build_crc16_table()


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC16_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFF


# ---------------------------------------------------------------------------
# DIAG constants
# ---------------------------------------------------------------------------

DIAG_VERNO_F = 0          # opcode for version request (#N anchor frames)
DIAG_BAD_CMD_F = 0x13     # opcode the modem returns for unsupported / gated commands (#N)
DIAG_LOG_F = 16           # opcode for log packets pushed by modem
DIAG_LOG_CONFIG_F = 115   # opcode for log configuration command
DIAG_NV_WRITE_F = 39      # opcode for NV item write
DIAG_SUBSYS_CMD_F = 75    # opcode for subsystem command
DIAG_SPC_F = 0x46         # opcode for Service Programming Code unlock (#N)

_LOG_CFG_RETRIEVE_RANGES = 1
_LOG_CFG_SET_MASK = 3
_LOG_CFG_SUCCESS = 0
_LOG_CFG_HDR_FMT = '<3xII'  # 3 pad bytes, uint32 operation, uint32 status

_DIAG_SUBSYS_GPS = 13
_CGPS_DIAG_PDAPI_CMD = 0x64
_CGPS_OEM_CONTROL = 202
_GPSDIAG_OEMFEATURE_DRE = 1
_GPSDIAG_OEM_DRE_ON = 1
_NV_GNSS_OEM_FEATURE_MASK = 7165


# ---------------------------------------------------------------------------
# Transport abstractions (duck-typed: fileno, read, write)
# ---------------------------------------------------------------------------

class _SerialTransport:
    def __init__(self, ser):
        self._ser = ser

    def fileno(self) -> int:
        return self._ser.fd

    def read(self, n: int) -> bytes:
        return self._ser.read(n)

    def write(self, data: bytes) -> None:
        self._ser.write(data)

    def close(self) -> None:
        self._ser.close()


# ERESTARTSYS (512) is a kernel-internal "restart this syscall" errno. It is not
# in the `errno` module and Python does NOT auto-retry it (unlike EINTR, PEP 475).
# It leaks through the MHI DIAG endpoint when the channel resets (e.g. T99W640
# SDX72 radio-revert, #N): a transient reset that usually returns immediately.
_ERESTARTSYS = 512
_RAWFD_RESTART_RETRIES = 8   # immediate in-syscall restarts before propagating
# Transient read errnos that mean "no data yet / retry", not "channel dead"
# (#N). A `select()`-ready fd can still yield EAGAIN (spurious wakeup) on a
# freshly-rebooted / settling MHI DIAG channel; ERESTARTSYS/EINTR are the
# syscall-restart family. `_send_recv` rides these out within its deadline
# instead of letting the request/response handshake die — the post-reboot
# mask/F3 arm was killing capture with a bare EAGAIN before this.
_TRANSIENT_RECV_ERRNOS = frozenset(
    (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR, _ERESTARTSYS)
)
_RECV_TRANSIENT_BACKOFF = 0.02   # seconds; avoid a busy-spin on a level-ready fd


class _RawFdTransport:
    """Fallback transport using raw file descriptor when pyserial fails."""
    def __init__(self, fd: int):
        self._fd = fd

    def fileno(self) -> int:
        return self._fd

    def read(self, n: int) -> bytes:
        import os
        import errno as _errno
        # Retry the small set of "restart the syscall" errnos a bounded number of
        # times (#N). A transient MHI DIAG reset surfaces as EINTR/ERESTARTSYS;
        # the channel usually comes right back, so a few immediate restarts avoid
        # killing the capture. A reset that outlasts these retries propagates so
        # the caller's loop (slurp) can survive it across select() cycles.
        for _ in range(_RAWFD_RESTART_RETRIES):
            try:
                return os.read(self._fd, n)
            except OSError as exc:
                if exc.errno in (_errno.EINTR, _ERESTARTSYS):
                    continue
                raise
        return os.read(self._fd, n)  # last attempt; propagate if still failing

    def write(self, data: bytes) -> None:
        import os
        os.write(self._fd, data)

    def close(self) -> None:
        import os
        os.close(self._fd)


class _TcpTransport:
    """TCP transport with automatic reconnection.

    Keeps the server socket open so that when diag_socket_log reconnects
    (its normal behavior after a burst), we can re-accept the new connection.
    """

    def __init__(self, conn: socket.socket, srv: socket.socket | None = None):
        self._conn = conn
        self._srv = srv  # keep server socket for reconnection

    def fileno(self) -> int:
        return self._conn.fileno()

    def read(self, n: int) -> bytes:
        data = self._conn.recv(n)
        if not data and self._srv is not None:
            # Connection closed — wait for reconnection
            self._reconnect()
            data = self._conn.recv(n)
        return data

    def _reconnect(self) -> None:
        """Accept a new connection from diag_socket_log after it reconnects."""
        logger.info("TCP connection closed — waiting for reconnection ...")
        try:
            self._conn.close()
        except Exception:
            pass
        self._srv.settimeout(30.0)
        try:
            conn, addr = self._srv.accept()
            self._conn = conn
            logger.info(f"diag_socket_log reconnected from {addr}")
        except socket.timeout:
            raise EOFError("No reconnection within 30s")

    def write(self, data: bytes) -> None:
        mv = memoryview(data)
        sent = 0
        while sent < len(data):
            try:
                n = self._conn.send(mv[sent:])
            except (BrokenPipeError, ConnectionResetError):
                if self._srv is not None:
                    self._reconnect()
                    continue
                raise
            if n == 0:
                raise OSError("TCP connection closed")
            sent += n

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass


class _UdpBroadcastTransport:
    """Receive QMDL2 records via UDP broadcast, extract DIAG log packets.

    diag_udp_fwd sends whole QMDL2 records as UDP datagrams (or
    fragments for large records with 0xFD magic).  This transport
    reassembles fragments, scans each record for DIAG log packets
    (cmd=0x10 with valid log code at offset +6), and feeds them to
    DiagClient.recv().  Handles both standard and v2 packet formats.

    Sequence tracking: datagrams may be prepended with a 4-byte
    sequence header [0xFE, 0x01, seq_lo, seq_hi].  When present,
    gaps in the 16-bit sequence are logged as dropped packets.
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._out = b''
        self._frag_buf = b''
        # Sequence tracking
        self._seq_expected = None  # None until first sequenced packet
        self._seq_drops = 0
        self._seq_total = 0

    def fileno(self) -> int:
        return self._sock.fileno()

    @property
    def seq_stats(self) -> dict:
        """Return packet sequence statistics."""
        return {
            'total': self._seq_total,
            'drops': self._seq_drops,
            'loss_pct': (100.0 * self._seq_drops / self._seq_total
                         if self._seq_total > 0 else 0.0),
        }

    def read(self, n: int) -> bytes:
        while not self._out:
            data = self._sock.recv(65536)
            if not data:
                raise EOFError("UDP closed")

            # Strip sequence header if present: [0xFE, 0x01, seq_lo, seq_hi]
            if len(data) > 4 and data[0] == 0xFE and data[1] == 0x01:
                seq = data[2] | (data[3] << 8)
                self._track_seq(seq)
                data = data[4:]  # Strip header, process remainder

            if len(data) > 4 and data[0] == 0xFD:
                flags = data[1]
                if flags & 0x01:
                    self._frag_buf = data[4:]
                else:
                    self._frag_buf += data[4:]
                if flags & 0x02:
                    self._extract_from_record(self._frag_buf)
                    self._frag_buf = b''
            else:
                self._extract_from_record(data)
        chunk = self._out[:n]
        self._out = self._out[n:]
        return chunk

    def _track_seq(self, seq: int) -> None:
        """Track sequence numbers and log gaps."""
        self._seq_total += 1
        if self._seq_expected is None:
            self._seq_expected = (seq + 1) & 0xFFFF
            return
        if seq != self._seq_expected:
            # Calculate gap (handle 16-bit wrap)
            gap = (seq - self._seq_expected) & 0xFFFF
            if gap <= 1000:  # Plausible gap (not a reset)
                self._seq_drops += gap
                logger.warning(
                    "UDP seq gap: expected %d got %d (%d packets dropped, "
                    "%d total drops / %d received)",
                    self._seq_expected, seq, gap,
                    self._seq_drops, self._seq_total)
            else:
                # Large gap likely means sender restarted
                logger.info("UDP seq reset detected: %d → %d (sender restart?)",
                            self._seq_expected, seq)
        self._seq_expected = (seq + 1) & 0xFFFF

    def _extract_from_record(self, record: bytes) -> None:
        """Extract DIAG log packets from a QMDL2 record via HDLC deframing.

        QMDL2 records contain HDLC-framed DIAG data delimited by 0x7E.
        Split on 0x7E, un-escape 0x7D sequences, strip 2-byte CRC,
        and inject LOG_F (opcode 0x10) packets into the output stream.

        This replaces the old heuristic byte-scan approach, which missed
        packets and produced false positives. The HDLC approach correctly
        handles both standard and multi-peripheral DIAG formats.
        """
        frames = record.split(b'\x7e')
        for frame in frames:
            if len(frame) < 8:
                continue
            # Un-escape HDLC: 0x7D 0x5E → 0x7E, 0x7D 0x5D → 0x7D
            unescaped = bytearray()
            j = 0
            while j < len(frame):
                if frame[j] == 0x7D and j + 1 < len(frame):
                    unescaped.append(frame[j + 1] ^ 0x20)
                    j += 2
                else:
                    unescaped.append(frame[j])
                    j += 1
            # Need at least: opcode(1) + pending(1) + outer_len(2) + inner(4) = 8
            if len(unescaped) < 8:
                continue
            # Only process LOG_F (opcode 0x10) packets
            if unescaped[0] != 0x10:
                continue
            # Strip 2-byte CRC from end (if present)
            raw = bytes(unescaped[:-2]) if len(unescaped) > 10 else bytes(unescaped)
            # Re-escape for HDLC safety in our output stream
            escaped = raw.replace(b'\x7d', b'\x7d\x5d')
            escaped = escaped.replace(b'\x7e', b'\x7d\x5e')
            # Add 2 dummy trailer bytes + delimiter (no-CRC mode strips trailer)
            self._out += escaped + b'\x00\x00\x7e'

    def write(self, data: bytes) -> None:
        pass

    def close(self) -> None:
        self._sock.close()


# ---------------------------------------------------------------------------
# DGE1 deframer (shared by the live udp-listen transport and the offline pcap
# replay path in tools/diaggulp.py, #N)
# ---------------------------------------------------------------------------

DGE1_MAGIC = b'DGE1'
DGE1_HDR = 12  # magic(4) | version(1) | flags(1) | seq(u32 LE) | len(u16 LE)


def parse_dge1_header(datagram: bytes) -> "tuple[bytes, int, bool] | None":
    """Validate + strip a single DGE1 datagram header.

    Returns ``(payload, seq, restart)`` for a well-formed datagram, or
    ``None`` if the datagram is too short, lacks the ``DGE1`` magic, or its
    declared payload length overruns the datagram. ``restart`` is the
    daemon's RESTART flag (bit 0 of ``flags``), set on the first datagram
    after it re-spawns its captive diag_socket_log.

    The datagram layout is::

        magic "DGE1"(4) | version(1) | flags(1) | seq(u32 LE) | len(u16 LE) | payload
    """
    if len(datagram) < DGE1_HDR or datagram[:4] != DGE1_MAGIC:
        return None
    flags = datagram[5]
    seq = int.from_bytes(datagram[6:10], 'little')
    plen = int.from_bytes(datagram[10:12], 'little')
    payload = datagram[DGE1_HDR:DGE1_HDR + plen]
    if len(payload) != plen:
        return None
    return payload, seq, bool(flags & 0x01)


class Dge1SeqTracker:
    """Per-stream DGE1 sequence-gap accounting.

    Shared by the live ``_UdpListenTransport`` and the offline pcap replay
    so both report identical gap statistics. The reliability model (the
    #N decision): best-effort delivery with gap *detection* — a forward
    seq gap counts the skipped datagrams as lost; a seq behind the expected
    value is a late/duplicate and is dropped (``track`` returns False); the
    RESTART flag re-baselines the sequence without counting the
    discontinuity as loss.
    """

    # Bounded window of recently-seen seqs, used only to split a
    # behind-expected datagram into "reordered" (a seq we have NOT seen — a
    # late/out-of-order arrival) vs "true duplicate" (a seq we HAVE seen — an
    # actual on-wire/stack copy). See gap_report() for why (#N).
    _SEEN_WINDOW = 8192

    _MASK = 0xFFFFFFFF

    def __init__(self, reorder_window: int = 0) -> None:
        self._expected = None       # next seq we expect, or None before first
        self._received = 0
        self._missing = 0           # estimated dropped datagrams (forward gaps)
        self._dups = 0              # late/duplicate datagrams dropped
        self._reordered = 0         # behind-expected but never-seen (out of order)
        self._true_dups = 0         # behind-expected AND already seen (real copy)
        self._restarts = 0
        self._bad = 0               # non-DGE1 / malformed datagrams
        self._first_seq = None
        self._last_seq = None
        self._seen: "collections.deque[int]" = collections.deque(
            maxlen=self._SEEN_WINDOW
        )
        self._seen_set: set[int] = set()
        # #N bounded reorder buffer. When reorder_window > 0, feed() holds
        # early-arrived (forward-of-expected) payloads keyed by seq and emits
        # them in seq order once the hole fills, instead of letting track()
        # drop the resequenced datagrams. reorder_window bounds BOTH the seq
        # span we wait across and the number of buffered datagrams, so memory
        # and delivery latency stay bounded. 0 (default) = no buffering: feed()
        # is byte-identical to the legacy track() decision, so every existing
        # call site and the offline pcap path are unchanged.
        self._reorder_window = int(reorder_window)
        self._pending: dict[int, bytes] = {}

    def _mark_seen(self, seq: int) -> None:
        if seq in self._seen_set:
            return
        if len(self._seen) == self._seen.maxlen:
            self._seen_set.discard(self._seen[0])  # evicted by the append below
        self._seen.append(seq)
        self._seen_set.add(seq)

    def note_malformed(self) -> None:
        self._bad += 1

    def track(self, seq: int, restart: bool) -> bool:
        """Update gap stats. Returns True if this datagram should be
        delivered, False if it is a late/duplicate to drop."""
        self._last_seq = seq
        if self._first_seq is None:
            self._first_seq = seq
        if restart or self._expected is None:
            if restart and self._expected is not None:
                self._restarts += 1
                logger.info("DGE1 stream restart at seq %d", seq)
            self._expected = (seq + 1) & 0xFFFFFFFF
            self._received += 1
            self._mark_seen(seq)
            return True
        if seq == self._expected:
            self._expected = (seq + 1) & 0xFFFFFFFF
            self._received += 1
            self._mark_seen(seq)
            return True
        gap = (seq - self._expected) & 0xFFFFFFFF
        if gap < 0x80000000:        # forward gap → datagrams lost
            self._missing += gap
            logger.warning("DGE1 seq gap: expected %d got %d (%d lost; %d total)",
                           self._expected, seq, gap, self._missing)
            self._expected = (seq + 1) & 0xFFFFFFFF
            self._received += 1
            self._mark_seen(seq)
            return True
        # behind expected → late/duplicate (dropped either way). Split the
        # cause so the metric can tell reordering apart from true duplication
        # (#N): a seq we've already seen is a real on-wire/stack copy; a
        # never-seen behind-expected seq is an out-of-order (reordered) late
        # arrival that the forward-gap branch already mis-counted as missing.
        self._dups += 1
        if seq in self._seen_set:
            self._true_dups += 1
        else:
            self._reordered += 1
            self._mark_seen(seq)
        return False

    # --- #N bounded reorder buffer -------------------------------------

    def feed(self, payload: bytes, seq: int, restart: bool) -> "list[bytes]":
        """Resequencing variant of track(): returns the payloads now ready to
        deliver, in strict seq order (possibly empty, possibly several).

        With reorder_window == 0 this is exactly ``[payload]`` when track()
        would deliver and ``[]`` when it would drop — no behavior change. With
        a positive window, a forward-of-expected datagram is buffered rather
        than counted lost, and a later-arriving lower seq fills the hole so the
        in-order run drains. true_duplicates keep drop semantics unchanged.
        """
        if self._reorder_window <= 0:
            return [payload] if self.track(seq, restart) else []

        self._last_seq = seq
        if self._first_seq is None:
            self._first_seq = seq

        if restart or self._expected is None:
            if restart and self._expected is not None:
                self._restarts += 1
                logger.info("DGE1 stream restart at seq %d", seq)
                # Buffered payloads belong to the pre-restart baseline; the
                # daemon re-spawned its reader, so drop them without counting
                # the discontinuity as loss (matches track()'s restart rule).
                self._pending.clear()
            self._expected = (seq + 1) & self._MASK
            self._received += 1
            self._mark_seen(seq)
            return [payload] + self._drain_contiguous()

        delta = (seq - self._expected) & self._MASK
        if delta == 0:
            self._expected = (seq + 1) & self._MASK
            self._received += 1
            self._mark_seen(seq)
            return [payload] + self._drain_contiguous()
        if delta < 0x80000000:
            # Arrived early (ahead of the hole at expected) — buffer it.
            if seq in self._pending or seq in self._seen_set:
                self._dups += 1
                self._true_dups += 1     # real copy of a buffered/delivered seq
                return []
            self._pending[seq] = payload
            self._mark_seen(seq)
            return self._enforce_window()
        # Behind expected: the base already advanced past this seq (its hole
        # was either filled or window-forced). Same split as track().
        self._dups += 1
        if seq in self._seen_set:
            self._true_dups += 1
        else:
            self._reordered += 1
            self._mark_seen(seq)
        return []

    def _drain_contiguous(self) -> "list[bytes]":
        """Pop buffered payloads that now form a contiguous run at expected."""
        out: list[bytes] = []
        while self._expected in self._pending:
            out.append(self._pending.pop(self._expected))
            self._received += 1
            self._expected = (self._expected + 1) & self._MASK
        return out

    def _enforce_window(self) -> "list[bytes]":
        """Advance the base while the buffer spans too far ahead of expected or
        holds too many datagrams. Each skipped (never-buffered) seq is declared
        missing; each buffered seq passed is delivered. Bounds memory + latency.
        """
        out: list[bytes] = []
        if not self._pending:
            return out
        # Furthest-ahead buffered seq, measured once from the current base;
        # every base advance below lowers this distance by exactly one.
        hi_ahead = max((s - self._expected) & self._MASK for s in self._pending)
        while self._pending and (hi_ahead >= self._reorder_window
                                 or len(self._pending) > self._reorder_window):
            if self._expected in self._pending:
                out.append(self._pending.pop(self._expected))
                self._received += 1
            else:
                self._missing += 1
            self._expected = (self._expected + 1) & self._MASK
            hi_ahead -= 1
        return out

    def flush(self) -> "list[bytes]":
        """Drain the reorder buffer at EOF, in seq order. Any hole still unfilled
        when the stream ends is a genuine loss and counts as missing."""
        out: list[bytes] = []
        while self._pending:
            if self._expected in self._pending:
                out.append(self._pending.pop(self._expected))
                self._received += 1
            else:
                self._missing += 1
            self._expected = (self._expected + 1) & self._MASK
        return out

    def gap_report(self) -> dict:
        total = self._received + self._missing
        return {
            'received': self._received,
            'missing': self._missing,
            'duplicates_dropped': self._dups,
            # Split of duplicates_dropped (== reordered + true_duplicates),
            # to disambiguate the #N "~8x duplication / ~99.8% loss"
            # pattern: severe REORDERING on a VLAN/GRO path inflates BOTH
            # missing and duplicates_dropped (a single out-of-order datagram
            # is counted once as missing when the gap opens, then again as a
            # duplicate when it arrives behind expected — see the seq tracker
            # test). If true_duplicates ~ 0 while reordered is large, there is
            # NO real on-wire duplication and the apparent loss is also a
            # reordering artifact, not packet loss. A large true_duplicates is
            # genuine on-wire/stack duplication.
            'reordered': self._reordered,
            'true_duplicates': self._true_dups,
            'restarts': self._restarts,
            'malformed': self._bad,
            'first_seq': self._first_seq,
            'last_seq': self._last_seq,
            'loss_pct': (100.0 * self._missing / total) if total else 0.0,
        }


class _UdpListenTransport:
    """Receive the #N diagbarf DGE1-framed UDP datagram stream.

    Each datagram is::

        magic "DGE1"(4) | version(1) | flags(1) | seq(u32 LE) | len(u16 LE) | payload

    where ``payload`` is an MTU-sized slice of the raw HDLC byte stream (NOT
    necessarily frame-aligned). We validate + strip the header, track per-stream
    sequence gaps, and return the payload bytes to DiagClient/diaggulp's slurp
    loop, which writes them straight out — so the reassembled output is the
    same raw HDLC stream a TCP sink would carry.

    Reliability model (the #N decision): best-effort delivery with gap
    *detection*. On a single-segment LAN, datagram reordering is effectively
    nonexistent; the dominant loss mode is buffer-overrun drops during firehose
    bursts, which show up as forward seq gaps. A datagram whose seq is behind
    the expected value (late/duplicate) is dropped rather than appended, to
    avoid corrupting the byte stream. The ``flags`` RESTART bit (set by the
    daemon on the first datagram after it re-spawns its captive
    diag_socket_log) resets the seq baseline without counting the discontinuity
    as loss.

    ``reorder_window`` (#N) optionally enables a bounded resequencing buffer
    for reordering paths (e.g. the CFW-3212 ``eno1.45`` host socket-receive
    path, where the on-wire stream is in order but the live socket sees heavy
    reordering — #N). When > 0, early-arrived datagrams are held by seq and
    delivered in order instead of dropped, bounded by the window. 0 (default)
    keeps the original best-effort-with-detection behavior byte-for-byte.
    """

    def __init__(self, sock: socket.socket, reorder_window: int = 0):
        self._sock = sock
        self._tracker = Dge1SeqTracker(reorder_window=reorder_window)
        # Payloads released by the reorder buffer, FIFO in seq order. One recv
        # can yield zero (hole opened) or several (a hole filled and a run
        # drained) payloads, so we buffer them across read() calls.
        self._ready: "collections.deque[bytes]" = collections.deque()
        self._eof = False

    def fileno(self) -> int:
        return self._sock.fileno()

    def read(self, n: int) -> bytes:
        # Return one payload per call (returning b'' would be read by diaggulp
        # as EOF). n is advisory — each payload is <= the daemon's 1400-byte
        # slice ceiling. Drain the resequenced ready-queue first; only recv
        # when it is empty.
        while True:
            if self._ready:
                return self._ready.popleft()
            if self._eof:
                raise EOFError("UDP closed")
            data = self._sock.recv(65536)
            if not data:
                # Socket EOF: flush any datagrams still held in the reorder
                # buffer (in order; unfilled holes are now genuine loss), then
                # signal EOF once the queue is exhausted.
                self._eof = True
                self._ready.extend(self._tracker.flush())
                continue
            parsed = parse_dge1_header(data)
            if parsed is None:
                self._tracker.note_malformed()
                continue
            payload, seq, restart = parsed
            self._ready.extend(self._tracker.feed(payload, seq, restart))

    def gap_report(self) -> dict:
        return self._tracker.gap_report()

    def write(self, data: bytes) -> None:
        pass

    def close(self) -> None:
        self._sock.close()


# ---------------------------------------------------------------------------
# DiagClient
# ---------------------------------------------------------------------------

class DiagClient:
    """Qualcomm DIAG client supporting serial and TCP transports.

    In TCP mode (via diag_socket_log), the modem's kernel DIAG driver
    delivers raw packets to diag_socket_log without HDLC CRC.
    diag_socket_log then wraps them with 0x7E delimiters and byte-stuffing
    but does NOT append a CRC.  Set _no_crc=True for this mode.
    """

    def __init__(self, transport, no_crc: bool = False):
        self._transport = transport
        self._pend = b''
        self._no_crc = no_crc

    # --- Factory methods ---

    @classmethod
    def from_serial(cls, port: str = '/dev/ttyUSB0', baudrate: int = 115200) -> 'DiagClient':
        """Open a serial DIAG port (e.g. /dev/ttyUSB0 on USB-connected Quectel)."""
        import termios
        from serial import Serial, SerialException

        def _open_raw_fd() -> 'DiagClient':
            # Char device with no usable line discipline. The DIAG HDLC framing
            # is software-side, so a bare raw fd with no termios is correct
            # (mirrors the qfenix MHI fix).
            import os
            fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            try:
                attrs = termios.tcgetattr(fd)
                attrs[0] = 0  # iflag
                attrs[1] = 0  # oflag
                attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL  # cflag
                attrs[3] = 0  # lflag
                attrs[4] = termios.B115200
                attrs[5] = termios.B115200
                attrs[6][termios.VMIN] = 0
                attrs[6][termios.VTIME] = 0
                termios.tcsetattr(fd, termios.TCSANOW, attrs)
                termios.tcflush(fd, termios.TCIOFLUSH)
                logger.debug(f"Opened DIAG port {port} via raw termios (pyserial ioctl failed)")
            except (termios.error, OSError) as terr:
                # MHI char device: line settings are meaningless for this transport.
                logger.debug(f"DIAG port {port}: no termios support ({terr}); using bare raw fd (MHI char device)")
            return cls(_RawFdTransport(fd), no_crc=False)

        try:
            ser = Serial(port, baudrate=baudrate, timeout=0, exclusive=True)
        except (BrokenPipeError, SerialException):
            # Two failure modes land here:
            #  - USB CDC serial drivers (option, qcserial) may not support
            #    DTR/RTS ioctls — open without modem control lines.
            #  - PCIe/MHI char devices (mhi_wwan_ctrl, e.g. EM160R-GL
            #    /dev/wwan0qcdm0) are not ttys at all: pyserial's
            #    _reconfigure_port raises SerialException("Could not configure
            #    port: (25, 'Inappropriate ioctl for device')") — ENOTTY.
            return _open_raw_fd()
        try:
            ser.flush()
            ser.reset_input_buffer()
            ser.reset_output_buffer()
        except (termios.error, OSError) as ferr:
            # Some MHI char devices (OOT pcie_mhi.ko /dev/mhi_DIAG) tolerate
            # open()+tcsetattr but reject tcdrain() with EINVAL — pyserial's
            # flush() raises termios.error here, which is NOT a SerialException
            # so it escapes the open() guard above. Fall back to the raw fd.
            logger.debug(f"DIAG port {port}: serial flush failed ({ferr}); falling back to raw fd (MHI char device)")
            try:
                ser.close()
            except Exception:
                pass
            return _open_raw_fd()
        logger.debug(f"Opened serial DIAG port {port}")
        return cls(_SerialTransport(ser), no_crc=False)

    @classmethod
    def from_tcp_server(cls, host: str = '0.0.0.0', port: int = 2500) -> 'DiagClient':
        """Listen for an incoming diag_socket_log connection on host:port.

        diag_socket_log (running on or proxied from the modem) connects to us.
        Blocks until the first connection is accepted.

        TCP mode uses raw-packet framing (0x7E delimiters + byte-stuffing,
        no CRC) because the kernel /dev/ffs-diag interface provides packets
        without HDLC CRC overhead.
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        logger.info(f"Waiting for diag_socket_log on {host}:{port} ...")
        conn, addr = srv.accept()
        # Keep srv open for reconnection (diag_socket_log reconnects after bursts)
        logger.info(f"diag_socket_log connected from {addr}")
        return cls(_TcpTransport(conn, srv=srv), no_crc=True)

    @classmethod
    def from_udp_broadcast(cls, host: str = '0.0.0.0', port: int = 2500) -> 'DiagClient':
        """Receive DIAG data via UDP broadcast from diag_udp_fwd.

        diag_udp_fwd (running on the modem alongside diag_mdlog) sends
        chunks of the growing QMDL2 file as UDP broadcast datagrams.
        This transport reassembles the stream and extracts individual
        DIAG log packets.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        logger.info(f"Listening for UDP broadcast DIAG on {host}:{port}")
        return cls(_UdpBroadcastTransport(sock), no_crc=True)

    @classmethod
    def from_tcp_client(cls, host: str, port: int = 12399) -> 'DiagClient':
        """Dial INTO a device that LISTENS for DIAG (the #N diagbarf
        TCP-listen sink — the inverse of from_tcp_server's #N model).

        The on-device daemon has already armed the global log mask and is
        fanning out raw HDLC; we are a passive read-only consumer, so callers
        MUST run with --no-mask (the daemon ignores client-side writes — it is
        the sole mask arbiter). Same no-CRC framing as the diag_socket_log path.
        """
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((host, port))
        logger.info(f"Connected to device DIAG listener {host}:{port}")
        return cls(_TcpTransport(conn, srv=None), no_crc=True)

    @classmethod
    def from_udp_listen(cls, host: str = '0.0.0.0', port: int = 12399,
                        reorder_window: int = 0) -> 'DiagClient':
        """Passively receive the #N diagbarf DGE1-framed UDP stream.

        Distinct from from_udp_broadcast (the FN980 diag_udp_fwd QMDL2 model):
        here the on-device daemon is the single MD reader that already armed
        the mask and pushes MTU-sized raw-HDLC slices wrapped in a DGE1 seq
        header. This transport validates/strips the header, tracks per-stream
        sequence gaps (loss is detectable, not recovered), and exposes the
        reassembled raw HDLC byte stream. Callers MUST run with --no-mask.

        ``reorder_window`` > 0 enables the #N bounded resequencing buffer for
        reordering host paths (see _UdpListenTransport); 0 (default) keeps the
        flat-LAN best-effort-with-detection behavior unchanged.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        sock.bind((host, port))
        logger.info(f"Listening for DGE1 UDP DIAG on {host}:{port}")
        return cls(_UdpListenTransport(sock, reorder_window=reorder_window),
                   no_crc=True)

    # --- HDLC framing ---

    def _hdlc_encapsulate(self, payload: bytes) -> bytes:
        """Append CRC, byte-stuff, and add 0x7E delimiter.

        CRC is always included — the modem's kernel verifies it even when the
        transport is TCP via diag_socket_log.
        """
        payload = payload + pack('<H', _crc16(payload))
        # Escape 0x7D first, then 0x7E — order matters
        payload = payload.replace(b'\x7d', b'\x7d\x5d')
        payload = payload.replace(b'\x7e', b'\x7d\x5e')
        return payload + b'\x7e'

    def _hdlc_decapsulate(self, frame: bytes) -> bytes:
        """Remove 0x7E delimiter, un-stuff bytes, and strip trailing CRC.

        In CRC mode (serial): verify the 2-byte CRC before stripping.
        In no-CRC mode (TCP/diag_socket_log): the modem appends 2 bytes that
        are not a standard CRC, so strip them without verification.
        """
        assert len(frame) >= 2, f"Frame too short ({len(frame)} bytes)"
        assert frame[-1:] == b'\x7e', "Missing frame delimiter"
        payload = frame[:-1]
        if not payload:
            raise AssertionError("Empty frame")
        # Unescape 0x7E first, then 0x7D — reverse of encapsulation order
        payload = payload.replace(b'\x7d\x5e', b'\x7e')
        payload = payload.replace(b'\x7d\x5d', b'\x7d')
        assert len(payload) >= 2, "Frame too short after un-stuffing"
        if self._no_crc:
            return payload[:-2]  # strip without verifying
        assert payload[-2:] == pack('<H', _crc16(payload[:-2])), "CRC mismatch"
        return payload[:-2]

    # --- Send / Recv ---

    def send(self, opcode: int, payload: bytes) -> None:
        """Encapsulate and send a DIAG packet."""
        self._transport.write(self._hdlc_encapsulate(bytes([opcode]) + payload))

    def recv(
        self,
        timeout: float | None = None,
        stop_event: threading.Event | None = None,
    ) -> tuple[int, bytes]:
        """Read the next complete HDLC frame. Returns (opcode, payload).

        Skips malformed frames (e.g. empty inter-frame delimiters).

        Parameters
        ----------
        timeout:
            Hard deadline in seconds. Raises ``TimeoutError`` if no
            complete frame arrives within this window. When ``None``
            (legacy default) the method blocks indefinitely, but still
            polls ``stop_event`` at a bounded cadence so wardrive
            shutdown doesn't hang if the modem stops emitting (#N).
        stop_event:
            Optional ``threading.Event``. When set, the read loop
            returns by raising ``InterruptedError``. The select()
            call is bounded to 1.0 s so this is honored promptly on
            unresponsive DIAG sockets.
        """
        deadline = time.monotonic() + timeout if timeout is not None else None
        while True:
            # Buffer until we have at least one 0x7E delimiter
            while b'\x7e' not in self._pend:
                if stop_event is not None and stop_event.is_set():
                    raise InterruptedError("stop_event set during DIAG recv")
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("DIAG recv timed out")
                    select_timeout = min(remaining, 1.0)
                else:
                    # No hard deadline but we still bound select() so a
                    # stop_event set mid-read is honored within ~1 s.
                    select_timeout = 1.0
                ready, _, _ = select.select(
                    [self._transport.fileno()], [], [], select_timeout
                )
                if not ready:
                    continue
                data = self._transport.read(0x10000)
                if not data:
                    raise EOFError("DIAG transport closed")
                self._pend += data

            # Split on the first delimiter; self._pend holds the remainder
            frame, self._pend = self._pend.split(b'\x7e', 1)
            try:
                payload = self._hdlc_decapsulate(frame + b'\x7e')
                return payload[0], payload[1:]
            except AssertionError as exc:
                logger.debug(f"Skipping malformed frame ({len(frame)} bytes): {exc}")

    def _send_recv(self, opcode: int, payload: bytes,
                   timeout: float = 5.0) -> tuple[int, bytes] | None:
        """Send a command and return the response with matching opcode.

        Skips LOG frames (pushed by modem) and other unsolicited frames
        (e.g. DIAG_STATUS_F = 0x15) until the matching response arrives or
        the timeout expires.

        Returns:
            ``(opcode, body)`` on success — ``opcode`` matches the request.
            ``(DIAG_BAD_CMD_F, echoed_payload)`` when the modem explicitly
                rejects the command (#N). The echoed payload starts with
                the rejected opcode (e.g. for a rejected ``DIAG_NV_WRITE_F``
                the response body is ``<echoed_opcode> <nv_id_le> <value_le>``).
                Common on Sierra Generic-PRI EM92xx where the DIAG NV
                subsystem is gated behind ``AT!OPENLOCK`` even after
                ``AT!CUSTOM="DIAGENABLE",1``.
            ``None`` on timeout (no response within ``timeout``).

        Callers MUST distinguish ``(DIAG_BAD_CMD_F, ...)`` from a success
        tuple before destructuring the body — the body layout is the
        rejected request's echo, not the success response.
        """
        self.send(opcode, payload)
        deadline = time.monotonic() + timeout
        while True:
            # Fill buffer until we have at least one complete frame
            while b'\x7e' not in self._pend:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    logger.debug(f"Timeout waiting for opcode {opcode:#04x} response")
                    return None
                ready, _, _ = select.select([self._transport.fileno()], [], [], remaining)
                if not ready:
                    logger.debug(f"Timeout waiting for opcode {opcode:#04x} response")
                    return None
                try:
                    data = self._transport.read(0x10000)
                except OSError as exc:
                    # Transient reset / spurious-ready on a settling channel
                    # (#N): retry within the deadline instead of dying. The
                    # outer `remaining <= 0` check bounds the loop; a short
                    # backoff avoids a busy-spin on a level-triggered ready fd.
                    if exc.errno in _TRANSIENT_RECV_ERRNOS:
                        logger.debug(
                            f"Transient read errno {exc.errno} during "
                            f"opcode {opcode:#04x} handshake; retrying"
                        )
                        time.sleep(_RECV_TRANSIENT_BACKOFF)
                        continue
                    raise
                if not data:
                    raise EOFError("DIAG transport closed")
                self._pend += data
            # Process one frame from the buffer
            frame, self._pend = self._pend.split(b'\x7e', 1)
            try:
                p = self._hdlc_decapsulate(frame + b'\x7e')
            except AssertionError as exc:
                logger.debug(f"Skipping malformed frame ({len(frame)} bytes): {exc}")
                continue
            op, d = p[0], p[1:]
            if op == opcode:
                return op, d
            # Modem explicitly rejected the command (#N). Surface to the
            # caller instead of silently dropping — otherwise the caller
            # waits for the wall-clock timeout and reports "modem didn't
            # respond" when the actual answer was "modem said no."
            if op == DIAG_BAD_CMD_F:
                logger.warning(
                    f"Modem returned DIAG_BAD_CMD_F (0x13) for opcode "
                    f"{opcode:#04x}; echoed payload = {d.hex()} "
                    f"(common cause: AT!OPENLOCK / SPC unlock required)"
                )
                return DIAG_BAD_CMD_F, d
            logger.debug(f"Discarding opcode {op:#04x} during {opcode:#04x} handshake")

    # --- Anchor frames for DLF↔host timestamp alignment (#N) ---

    def emit_version_anchor(self, timeout: float = 2.0) -> dict | None:
        """Send a DIAG_VERNO_F request and return an anchor record.

        Used by the capture pipeline (`/modem-diag-at-correlate`) at t0
        and tN to pin the DLF time base to the host monotonic clock. The
        returned dict has the shape::

            {
              "opcode": 0,                # DIAG_VERNO_F
              "host_mono_ns": int,        # time.monotonic_ns() at send
              "host_mono_recv_ns": int,   # time.monotonic_ns() at response
              "response_bytes_hex": str,  # raw response payload as hex
              "rtt_ns": int,              # recv - send
            }

        ``host_mono_ns`` is captured immediately before the send; the
        response is correlated to within the round-trip half. Callers
        that want a tighter pin can subtract ``rtt_ns // 2``.

        Returns ``None`` on timeout — anchor frames are best-effort, the
        caller's two-point fallback (current ``--auto-align`` behaviour
        in ``diaggrok_at_correlate``) remains correct.

        Per #N audit (2026-05-02): this is a thin public wrapper around
        the existing ``_send_recv`` request/response primitive.
        """
        host_mono_ns = time.monotonic_ns()
        result = self._send_recv(DIAG_VERNO_F, b"", timeout=timeout)
        host_mono_recv_ns = time.monotonic_ns()
        if result is None:
            return None
        _, resp = result
        return {
            "opcode": DIAG_VERNO_F,
            "host_mono_ns": host_mono_ns,
            "host_mono_recv_ns": host_mono_recv_ns,
            "response_bytes_hex": resp.hex(),
            "rtt_ns": host_mono_recv_ns - host_mono_ns,
        }

    # --- DIAG configuration ---

    def subscribe_logs(self, log_codes: list[int]) -> None:
        """Subscribe to a set of DIAG log codes.

        Runs the full LOG_CONFIG handshake:
          1. Retrieve bitmask size for each of the 16 log type groups.
          2. For each group that has at least one requested code: build and
             send the enable bitmask.
        """
        log_code_set = set(log_codes)

        # Step 1: get bitmask sizes for all 16 log type groups
        result = self._send_recv(
            DIAG_LOG_CONFIG_F,
            pack('<3xI', _LOG_CFG_RETRIEVE_RANGES),
            timeout=10.0,
        )
        if result is None:
            raise RuntimeError("Timed out waiting for LOG_CONFIG RETRIEVE_RANGES response")
        _, resp = result
        operation, status = unpack_from(_LOG_CFG_HDR_FMT, resp)
        assert operation == _LOG_CFG_RETRIEVE_RANGES, f"Unexpected op {operation}"
        assert status == _LOG_CFG_SUCCESS, f"Retrieve ranges failed (status={status})"

        bitsizes = unpack_from('<16I', resp, calcsize(_LOG_CFG_HDR_FMT))

        # Step 2: build and send mask for each log group
        for log_type, bitsize in enumerate(bitsizes):
            if not bitsize:
                continue
            mask = bytearray((bitsize + 7) // 8)
            for bit in range(bitsize):
                code = (log_type << 12) | bit
                if code in log_code_set:
                    mask[bit // 8] |= 1 << (bit % 8)

            result = self._send_recv(
                DIAG_LOG_CONFIG_F,
                pack('<3xIII', _LOG_CFG_SET_MASK, log_type, bitsize) + bytes(mask),
                timeout=10.0,
            )
            if result is None:
                raise RuntimeError(f"Timed out waiting for SET_MASK response for log type 0x{log_type:x}")
            _, resp = result
            operation, status = unpack_from(_LOG_CFG_HDR_FMT, resp)
            assert operation == _LOG_CFG_SET_MASK, f"Unexpected op {operation}"
            assert status == _LOG_CFG_SUCCESS, f"Set mask failed for type 0x{log_type:x} (status={status})"

            if any(mask):
                logger.debug(f"Subscribed to log group 0x{log_type:x} (bitsize={bitsize})")

        logger.info(f"Log subscription complete for {len(log_codes)} code(s)")

    def unlock_spc(self, spc: str = "000000") -> bool:
        """Send a DIAG SPC (Service Programming Code) unlock — opcode 0x46.

        Some modems (notably the Quectel EG25/EC25 MDM9607 family) gate the
        ``DIAG_LOG_CONFIG_F`` handshake behind an SPC unlock: ``subscribe_logs``
        fails with ``DIAG_BAD_CMD_F`` (0x13) until the SPC is accepted. Call
        this BEFORE ``subscribe_logs`` to enable SIM-less / locked-modem log
        streaming (#N — discovered during a <redacted-ref> SIM-less cell-search
        capture on an EG25-G).

        The 6-byte SPC body convention varies by vendor (see
        ``tools/diag_spc_unlock.py``): Quectel/Qualcomm reference firmware is
        ``"000000"`` (six ASCII zeros); Telit LM960A18 is ``"0000"`` (four ASCII
        zeros, NUL-padded to 6). The string is encoded as ASCII and NUL-padded
        (or truncated) to exactly 6 bytes.

        Returns:
            ``True`` if the modem accepted the SPC (status byte == 1),
            ``False`` on rejection, ``DIAG_BAD_CMD_F``, or timeout. A ``False``
            return is not necessarily fatal — a modem that doesn't gate
            LOG_CONFIG will still stream after a rejected/absent SPC.
        """
        body = spc.encode("ascii", "ignore")[:6].ljust(6, b"\x00")
        result = self._send_recv(DIAG_SPC_F, body, timeout=4.0)
        if result is None:
            logger.warning(f"SPC unlock {spc!r}: no response")
            return False
        op, resp = result
        if op == DIAG_SPC_F and resp and resp[0] == 1:
            logger.info(f"SPC unlock accepted ({spc!r})")
            return True
        logger.warning(f"SPC unlock {spc!r} rejected (op=0x{op:02x}, resp={resp.hex()})")
        return False

    def enable_oemdre_nv(self) -> bool:
        """Write NV item 7165 = 1 to enable OEM DRE feature in non-volatile storage.

        Returns True if the modem ACKed the write, False on timeout OR on
        explicit modem rejection (DIAG_BAD_CMD_F per #N). The failure
        mode is logged distinctly:

          * Timeout (None) → ``"NV write timed out"`` — modem may be unreachable
            or the write path doesn't ACK on this firmware.
          * BAD_CMD (0x13) → ``"NV write REJECTED"`` — modem explicitly
            said no (common cause: Sierra Generic-PRI gates NV opcodes
            behind ``AT!OPENLOCK`` even after ``AT!CUSTOM="DIAGENABLE",1``).

        Note: The modem may require a reboot for this NV change to take effect.
        """
        result = self._send_recv(DIAG_NV_WRITE_F, pack('<HI', _NV_GNSS_OEM_FEATURE_MASK, 1))
        if result is None:
            logger.warning("OEM DRE NV write timed out (non-fatal)")
            return False
        op, body = result
        if op == DIAG_BAD_CMD_F:
            logger.error(
                f"OEM DRE NV write REJECTED by modem (DIAG_BAD_CMD_F). "
                f"Echoed payload: {body.hex()}. On Sierra Generic-PRI EM9291 "
                f"this means the NV subsystem is gated behind AT!OPENLOCK — "
                f"DIAGENABLE alone is insufficient. See #N."
            )
            return False
        logger.debug("OEM DRE NV item written")
        return True

    def enable_oemdre_session(self) -> bool:
        """Send the GPS subsystem command to start an OEM DRE session.

        Returns True if the modem ACKed the command, False on timeout OR
        on explicit modem rejection (DIAG_BAD_CMD_F per #N). See
        :meth:`enable_oemdre_nv` for the BAD_CMD vs timeout distinction —
        same Sierra Generic-PRI gating story applies here.
        """
        result = self._send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BHBBIIII',
                 _DIAG_SUBSYS_GPS,
                 _CGPS_DIAG_PDAPI_CMD,
                 _CGPS_OEM_CONTROL,
                 0,                       # version
                 _GPSDIAG_OEMFEATURE_DRE,
                 _GPSDIAG_OEM_DRE_ON,
                 0, 0),
        )
        if result is None:
            logger.warning("OEM DRE session timed out (non-fatal, modem may not support it)")
            return False
        op, body = result
        if op == DIAG_BAD_CMD_F:
            logger.error(
                f"OEM DRE session REJECTED by modem (DIAG_BAD_CMD_F). "
                f"Echoed payload: {body.hex()}. Likely cause: same "
                f"AT!OPENLOCK gate that blocks the NV write — see #N."
            )
            return False
        logger.debug("OEM DRE session enabled")
        return True

    def wait_for_log_codes(self, log_codes: list[int], timeout: float) -> dict:
        """Wait up to `timeout` seconds for DIAG_LOG_F frames whose inner
        log_type is in `log_codes`.

        Drains all frames until the deadline expires, so the caller gets a
        full picture (not just the first hit). Unknown/malformed frames are
        skipped silently. Other opcodes are ignored.

        Returns {"observed_codes": sorted list of codes actually seen,
                 "frames_seen": total DIAG_LOG_F frames consumed,
                 "duration_s": wall-clock time spent waiting}.
        """
        from diaggrok.frame import parse_outer_frame

        wanted = set(log_codes)
        observed: set[int] = set()
        frames_seen = 0
        start = time.monotonic()
        deadline = start + timeout

        while time.monotonic() < deadline:
            while b'\x7e' not in self._pend:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([self._transport.fileno()], [], [], remaining)
                if not ready:
                    break
                data = self._transport.read(0x10000)
                if not data:
                    raise EOFError("DIAG transport closed")
                self._pend += data
            if b'\x7e' not in self._pend:
                break

            frame, self._pend = self._pend.split(b'\x7e', 1)
            try:
                p = self._hdlc_decapsulate(frame + b'\x7e')
            except AssertionError:
                continue
            op, d = p[0], p[1:]
            if op != DIAG_LOG_F:
                continue
            try:
                _pending, log_type, _log_time, _payload = parse_outer_frame(d)
            except (ValueError, Exception):
                continue
            frames_seen += 1
            if log_type in wanted:
                observed.add(log_type)

        return {
            "observed_codes": sorted(observed),
            "frames_seen": frames_seen,
            "duration_s": round(time.monotonic() - start, 3),
        }

    def close(self) -> None:
        """Close the underlying transport."""
        try:
            self._transport.close()
        except Exception:
            pass
