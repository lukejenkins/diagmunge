# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""diagmunge.munge.replay — GNSS-free offline DIAG replay core.

Reads DLF or raw-HDLC captures into ``(log_code, ts64, payload)`` records and
replays them to JSONL through a caller-INJECTED ``dispatch`` + ``code_filter``.
The core has zero knowledge of any specific log-code family (GNSS, RRC, …):
callers wire in their own parser dispatch. Record iteration leans on ``diaggrok``
(the inward dep); no third-party imports at module top level.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable, Iterable, Iterator

from diaggrok.dlf import UnsupportedFormatError, detect_format as _diaggrok_detect_format
from diaggrok.dlf import iter_log_records as _iter_dlf
from diaggrok.hdlc import (
    HdlcStats,
    iter_log_records,
    iter_log_records_stream,
    log_crc_report,
)


def iter_dlf_records(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(log_code, ts64, payload)`` for every DLF record (via diaggrok)."""
    yield from _iter_dlf(data)


def iter_hdlc_records(data: bytes, verify_crc: bool = False) -> Iterator[tuple[int, int, bytes]]:
    """Yield records from a raw HDLC DIAG stream; log a CRC report on exhaustion."""
    stats = HdlcStats()
    try:
        yield from iter_log_records(data, verify_crc=verify_crc, stats=stats)
    finally:
        log_crc_report(stats)


def iter_hdlc_records_stream(chunks: Iterable[bytes], verify_crc: bool = False) -> Iterator[tuple[int, int, bytes]]:
    """Streaming twin of :func:`iter_hdlc_records` — bounded to one in-flight frame."""
    stats = HdlcStats()
    try:
        yield from iter_log_records_stream(chunks, verify_crc=verify_crc, stats=stats)
    finally:
        log_crc_report(stats)


def read_chunks(input_arg: str, chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield byte chunks from stdin (``"-"``) or a path, low-latency (read1)."""
    if input_arg == "-":
        def _gen_stdin():
            stream = sys.stdin.buffer
            while True:
                chunk = stream.read1(chunk_size)
                if not chunk:
                    break
                yield chunk
        return _gen_stdin()

    p = Path(input_arg)
    if not p.exists():
        raise FileNotFoundError(input_arg)
    if p.is_dir():
        raise IsADirectoryError(input_arg)

    def _gen_file():
        with open(input_arg, "rb", buffering=0) as raw:
            while True:
                chunk = raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    return _gen_file()


def detect_format(data: bytes) -> str:
    """Classify ``data`` as ``"dlf"`` or raw-HDLC ``"bin"`` via diaggrok's detector."""
    fmt = _diaggrok_detect_format(data)
    if fmt == "dlf":
        return "dlf"
    if fmt == "hdlc":
        return "bin"
    raise UnsupportedFormatError(f"replay does not handle format={fmt}")


def replay_to_jsonl(
    records: Iterable[tuple[int, int, bytes]],
    *,
    dispatch: Callable[[int, int, bytes], object],
    code_filter: set[int],
    out,
    streaming: bool = False,
    on_parsed: Callable[[dict], None] | None = None,
) -> dict:
    """Replay ``records`` to JSONL on ``out`` via an injected ``dispatch``.

    For each ``(log_code, ts64, payload)``: skip codes not in ``code_filter``;
    call ``dispatch`` (exceptions counted as ``parse_errors``); skip ``None``;
    write ``json.dumps(packet.to_dict())`` + newline; flush per record when
    ``streaming``; invoke ``on_parsed(pkt_dict)`` if given. Returns the stats
    dict ``{records_total, records_matched, parsed, parse_errors}``.
    """
    stats = {"records_total": 0, "records_matched": 0, "parsed": 0, "parse_errors": 0}
    for log_code, ts64, payload in records:
        stats["records_total"] += 1
        if log_code not in code_filter:
            continue
        stats["records_matched"] += 1
        try:
            packet = dispatch(log_code, ts64, payload)
        except Exception:
            stats["parse_errors"] += 1
            continue
        if packet is None:
            continue
        pkt_dict = packet.to_dict()
        out.write(json.dumps(
            pkt_dict,
            default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o),
        ) + "\n")
        stats["parsed"] += 1
        if streaming:
            out.flush()
        if on_parsed is not None:
            on_parsed(pkt_dict)
    return stats
