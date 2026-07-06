#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""
hdlc_to_dlf.py — convert raw HDLC DIAG stream to DLF record format.

Reads raw HDLC-framed bytes (as produced by diaggulp.py or by
``diag_mdlog`` on the modem itself) and writes QCSuper-compatible DLF
records that apps/diaggpsd/dlf_to_jsonl.py can parse.

The HDLC parse + opcode classification lives in
``diaggrok.hdlc.iter_log_records`` so this script and
``dlf_to_jsonl.py --format bin`` stay in lockstep.

DLF record format (same as QCSuper):
    2B  rec_len (total including header, LE)
    2B  log_code (LE)
    8B  timestamp (Qualcomm 64-bit, LE)
    rec_len-12  payload

Supported LOG carriers:
    * opcode 0x10 — legacy DIAG_LOG_F, the default carrier on every
      Qualcomm chipset for most log code families.
    * opcode 0x98 — DIAG_MULTI_RADIO_CMD_F wrapper with inner 0x10. This
      is a multi-RADIO routing wrapper (radio_id at byte 1, tx_mask at
      bytes 4:8), NOT an SDX72/5G-NR-specific construct. Confirmed in
      use on SDX72-class devices (Quectel RG650V, Snapdragon X72) for
      every LOG record, AND on SDX20 LTE-only chipsets (Telit LM960
      32.01.110, #N) for LTE Layer 2 codes (RLC/MAC/PDCP, code
      range 0xB0xx-0xB1xx) while higher-layer LTE + GNSS continue to
      come over bare 0x10. The wrapper appears whenever the kernel
      diag driver routes per-RAT subsystem logs through a multi-radio
      demuxer; chipset class is not a sufficient predictor.

Other opcodes (0x9E secure log, 0x80 subsys cmd, 0x99 QSR4 F3) are
counted and reported but not extracted — 0x9E needs Qualcomm QCAT to
decrypt, and 0x80/0x99 aren't LOG packets.

Pipeline usage:
    diaggulp.py /dev/ttyUSB2 | hdlc_to_dlf.py - capture.dlf
    hdlc_to_dlf.py raw_capture.bin - | dlf_to_jsonl.py - parsed.jsonl
    diaggulp.py /dev/ttyUSB2 | hdlc_to_dlf.py - - | dlf_to_jsonl.py - out.jsonl

Use "-" for stdin/stdout.

Input-format detection (``--input-format``, default ``auto``):
    The tool sniffs the first 64 KiB for 0x7E delimiters and falls back to
    a DLF-record-shape double-check when none are present (#N, #N).
    Pass ``--input-format=hdlc`` to bypass detection for captures whose
    first frame legitimately exceeds 64 KiB, or ``--input-format=dlf`` to
    declare DLF-framed input up front and skip straight to the
    ``dlf_to_jsonl.py`` redirection message.
"""

from __future__ import annotations

import signal
import struct
import sys
from collections import Counter
from pathlib import Path

from diaggrok.hdlc import (
    HdlcStats,
    _MULTI_RADIO_WRAPPER_OFFSET,
    _extract_log_f,
    crc16_ccitt,
    hdlc_unescape,
    iter_log_records,
    log_crc_report,
)


_DLF_PROBE_BYTES = 65536


def _looks_like_dlf(data: bytes, mode: str) -> bool:
    """Heuristic: is ``data`` more likely a DLF stream than HDLC?

    Two modes:

    * ``"dlf"`` — caller declared DLF. Always returns True (no probing).
    * ``"auto"`` — probe the first 64 KiB for any 0x7E delimiter. HDLC
      streams reliably have 0x7E every ~100-500 bytes; absence across
      64 KiB means either DLF or a single legitimate HDLC frame larger
      than the probe window. To disambiguate we then check whether the
      first two ``<H`` length-prefixes parse as plausible DLF records.

    The probe window was bumped from 4 KiB (#N) to 64 KiB (#N) after
    a GnssDemodTracking burst ~10 KiB long false-positived as DLF. A
    single HDLC frame larger than 64 KiB is implausible in practice; if
    one is encountered, ``--input-format=hdlc`` bypasses this check.
    """
    if mode == "dlf":
        return True

    probe = data[:_DLF_PROBE_BYTES]
    if not probe or 0x7E in probe:
        return False
    if len(data) < 12:
        return False
    rec_len = struct.unpack_from("<H", data, 0)[0]
    if not (12 <= rec_len <= 8192 and len(data) >= rec_len + 2):
        return False
    next_len = struct.unpack_from("<H", data, rec_len)[0]
    return 12 <= next_len <= 8192


def write_dlf(out, log_code: int, ts64: int, payload: bytes) -> None:
    """Write one DLF record to a binary output stream.

    Header + payload are built as a single buffer and emitted in one
    ``out.write()`` call so a SIGINT landing mid-record cannot truncate the
    file to a bare 12-byte header with zero payload bytes (#N).
    """
    rec_len = 12 + len(payload)
    ts_lo = ts64 & 0xFFFFFFFF
    ts_hi = (ts64 >> 32) & 0xFFFFFFFF
    out.write(struct.pack("<HHII", rec_len, log_code, ts_lo, ts_hi) + payload)


# SIGINT is handled cooperatively in main(): the handler sets _STOP_REQUESTED
# and the record loop exits at the next record boundary. This avoids
# KeyboardInterrupt firing between two writes of the same record (#N).
_STOP_REQUESTED = False


def _install_sigint_handler() -> None:
    def _handler(signum, frame):  # noqa: ARG001 — signal-handler signature
        global _STOP_REQUESTED
        _STOP_REQUESTED = True

    signal.signal(signal.SIGINT, _handler)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="hdlc_to_dlf.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help='Raw HDLC file (or "-" for stdin)')
    parser.add_argument("output", help='DLF output file (or "-" for stdout)')
    parser.add_argument(
        "--verify-crc",
        action="store_true",
        help="Validate CRC-16 on each frame; skip bad frames (#N)",
    )
    parser.add_argument(
        "--opcode-stats",
        action="store_true",
        help="Print per-opcode frame/byte counts to stderr after extraction",
    )
    parser.add_argument(
        "--retention-report",
        action="store_true",
        help=(
            "Print a per-log-code scan→emit retention report to stderr after "
            "extraction. Useful for diagnosing CRC or filter mis-configurations "
            "that drop legitimate log records (#N). Doubles the scan cost "
            "because it iterates the HDLC stream twice."
        ),
    )
    parser.add_argument(
        "--input-format",
        choices=("auto", "hdlc", "dlf"),
        default="auto",
        help=(
            "Bypass the HDLC/DLF heuristic when the caller knows the format "
            "(#N). 'auto' (default) probes the leading bytes for 0x7E "
            "delimiters and falls back to a DLF-shape double-check. 'hdlc' "
            "skips detection and processes as HDLC unconditionally — use "
            "when the heuristic false-positives on captures whose first "
            "frame is larger than the probe window (e.g., a GnssDemodTracking "
            "burst >64 KiB with no 0x7E inside). 'dlf' fails immediately "
            "with the same redirection message the auto-detect emits."
        ),
    )
    args = parser.parse_args()

    if args.input == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.input).read_bytes()

    if args.input_format != "hdlc" and _looks_like_dlf(data, args.input_format):
        print(
            "hdlc_to_dlf: ERROR — input appears to be DLF-framed, not HDLC "
            "(no 0x7E delimiters in first 64 KiB, and the first two 2-byte "
            "length prefixes parse as plausible DLF records).\n"
            "  This is the format produced by `diag_socket_log` over adb "
            "reverse tunnels (see #N, AGENTS.md §5 for RM520N-GL R03A03).\n"
            "  If this capture really is HDLC with a single first frame "
            ">64 KiB, re-run with --input-format=hdlc to bypass detection "
            "(#N).\n"
            "  Otherwise, skip this tool and pipe the capture directly to:\n"
            "    apps/diaggpsd/dlf_to_jsonl.py --format bin "
            f"{args.input} <out.jsonl>",
            file=sys.stderr,
        )
        return 2

    if args.output == "-":
        out = sys.stdout.buffer
    else:
        out = open(args.output, "wb")

    _install_sigint_handler()

    stats = HdlcStats()
    unique_codes: set[int] = set()
    emitted_codes: dict[int, int] = {}
    stopped = False
    try:
        for log_code, ts64, payload in iter_log_records(
            data, verify_crc=args.verify_crc, stats=stats
        ):
            if _STOP_REQUESTED:
                stopped = True
                break
            write_dlf(out, log_code, ts64, payload)
            unique_codes.add(log_code)
            emitted_codes[log_code] = emitted_codes.get(log_code, 0) + 1
    finally:
        if args.output != "-":
            out.close()

    log_crc_report(stats)
    wrap_note = (
        f" ({stats.log_records_from_wrapper} via 0x98 wrapper)"
        if stats.log_records_from_wrapper
        else ""
    )
    print(
        f"hdlc_to_dlf: {stats.log_records} LOG records, "
        f"{len(unique_codes)} unique codes{wrap_note}",
        file=sys.stderr,
    )
    if args.opcode_stats:
        print("hdlc_to_dlf: opcode breakdown:", file=sys.stderr)
        for line in stats.summary_lines():
            print(line, file=sys.stderr)
    # 0x80 QShrink4 sequence-gap detection (#N). The compressed bodies
    # are opaque without the firmware hash DB, but the wrapper counter
    # lets us flag dropped/reordered batches. Surfaced whenever any 0x80
    # frame was seen, independent of --opcode-stats — a batch drop is a
    # capture-quality signal worth always reporting.
    gap_lines = stats.subsys_0x80_gap_lines()
    if gap_lines:
        print("hdlc_to_dlf: 0x80 sequence-gap report:", file=sys.stderr)
        for line in gap_lines:
            print(line, file=sys.stderr)
    if args.retention_report:
        _print_retention_report(data, emitted_codes, args.verify_crc)
    if stopped:
        print(
            "hdlc_to_dlf: SIGINT received — stopped cleanly at record "
            "boundary (#N).",
            file=sys.stderr,
        )
        return 130
    return 0


def _print_retention_report(
    data: bytes, emitted_codes: dict[int, int], crc_verified: bool
) -> None:
    """Print a per-log-code scan-vs-emit retention histogram to stderr.

    Rescans the raw HDLC input to count every log code that ``iter_log_records``
    would see *without* CRC filtering (the "scanned" count), then compares
    against the codes actually emitted to the output DLF (the "emitted" count,
    supplied by the caller). The difference surfaces frames that were present
    in the input but rejected downstream — almost always CRC failures in
    practice (#N).

    The retention report doubles the scan cost because it iterates the HDLC
    stream a second time, so it is opt-in behind ``--retention-report``.
    """
    scanned_codes: dict[int, int] = {}
    non_log_opcodes: Counter = Counter()
    short_frames = 0

    for raw_frame in data.split(b"\x7e"):
        if len(raw_frame) < 4:
            continue
        frame = hdlc_unescape(raw_frame)
        if len(frame) < 3:
            short_frames += 1
            continue
        opcode = frame[0]
        body = frame[:-2]  # strip the presumed trailing CRC16
        if opcode == 0x10:
            rec = _extract_log_f(body)
            if rec is not None:
                scanned_codes[rec[0]] = scanned_codes.get(rec[0], 0) + 1
            continue
        wrap_off = _MULTI_RADIO_WRAPPER_OFFSET.get(opcode)
        if wrap_off is not None and len(body) > wrap_off:
            rec = _extract_log_f(body[wrap_off:])
            if rec is not None:
                scanned_codes[rec[0]] = scanned_codes.get(rec[0], 0) + 1
            continue
        non_log_opcodes[opcode] += 1

    total_scanned = sum(scanned_codes.values())
    total_emitted = sum(emitted_codes.values())
    drop_total = total_scanned - total_emitted

    print("hdlc_to_dlf: retention report (#N)", file=sys.stderr)
    print(
        f"  scanned_log_records = {total_scanned:,}  "
        f"emitted_log_records = {total_emitted:,}  "
        f"dropped = {drop_total:,} "
        f"({drop_total*100/max(1,total_scanned):.1f}%)",
        file=sys.stderr,
    )
    print(
        f"  non_LOG_opcodes (unused, expected loss): "
        f"{sum(non_log_opcodes.values()):,} frames across "
        f"{len(non_log_opcodes)} opcodes",
        file=sys.stderr,
    )
    if short_frames:
        print(f"  short_frames (<3 B, skipped): {short_frames:,}", file=sys.stderr)
    if crc_verified and drop_total > 0:
        # When --verify-crc is on, any dropped LOG record failed CRC.
        print(
            "  NOTE: --verify-crc was ON, so the dropped count above is the "
            "CRC-bad LOG-record count. If this is surprisingly high (e.g. "
            "100%), the source capture's CRC framing may differ from the "
            "CRC-16-CCITT (poly 0x1021, init 0, xorOut 0xFFFF) expected "
            "here — #N, observed on diaggulp output from SDX55/SDX62.",
            file=sys.stderr,
        )

    all_codes = sorted(set(scanned_codes) | set(emitted_codes))
    # Full per-code table (top N worst-retention for readability)
    rows = []
    for code in all_codes:
        scan = scanned_codes.get(code, 0)
        emit = emitted_codes.get(code, 0)
        ratio = emit / scan if scan > 0 else 0.0
        rows.append((code, scan, emit, ratio))
    # Sort by absolute loss, descending
    rows.sort(key=lambda r: (r[1] - r[2]), reverse=True)
    print("  per-code retention (top 20 by absolute loss):", file=sys.stderr)
    print(
        f"    {'code':>7}  {'scanned':>10}  {'emitted':>10}  {'retention':>10}",
        file=sys.stderr,
    )
    for code, scan, emit, ratio in rows[:20]:
        print(
            f"    0x{code:04X}  {scan:>10,}  {emit:>10,}  {ratio*100:>9.1f}%",
            file=sys.stderr,
        )


if __name__ == "__main__":
    sys.exit(main())
