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
    8B  timestamp (DIAG 64-bit, LE)
    rec_len-12  payload

Supported LOG carriers:
    * opcode 0x10 — legacy DIAG_LOG_F, the default carrier on every
      chipset for most log code families.
    * opcode 0x98 — DIAG_MULTI_RADIO_CMD_F wrapper with inner 0x10. This
      is a multi-RADIO routing wrapper (radio_id at byte 1, tx_mask at
      bytes 4:8), NOT an SDX72/5G-NR-specific construct. Confirmed in
      use on SDX72-class devices (e.g. Quectel RG650V) for
      every LOG record, AND on SDX20 LTE-only chipsets (Telit LM960
      32.01.110) for LTE Layer 2 codes (RLC/MAC/PDCP, code
      range 0xB0xx-0xB1xx) while higher-layer LTE + GNSS continue to
      come over bare 0x10. The wrapper appears whenever the kernel
      diag driver routes per-RAT subsystem logs through a multi-radio
      demuxer; chipset class is not a sufficient predictor.

Other opcodes (0x9E secure log, 0x80 subsys cmd, 0x79/0x99 F3) are
counted and reported but not extracted — 0x9E needs the vendor log viewer
to decrypt, and 0x80/0x79/0x99 aren't LOG packets.

⛔ **This transform is LOSSY for F3, and the output looks fine anyway.**
``0x79``/``0x99`` F3 frames (bare or ``0x98``-wrapped) have no
representation in flat DLF, so converting an F3-bearing capture and
**archiving the result** destroys the firmware's own debug prints — the
project's field-labelling oracle. The converted file still scans, still
reports ``format: dlf``, and still has the right record and code counts;
only ``f3: null`` on a rescan reveals it. One such archived conversion
discards every resolved ``0x99`` frame the capture held.

The trap sits on the end of a command the docs actively recommend:
``--verify-crc`` is the usual way to CRC-check a capture, and it emits a
``.dlf`` byproduct. Archiving that
byproduct instead of the raw HDLC is one keystroke.

Guards, mirroring the at-rest diaggulp normalizer's Gate 0:

* any **file** output that drops F3 prints a loud stderr warning naming
  the frame count (free — the counts come from the conversion walk);
* an output under ``CAPTURES_ROOT`` — i.e. plainly being archived — is
  **refused** (exit 3) unless ``--allow-f3-loss``.

``--verify-crc`` to a throwaway path stays quiet and costs nothing extra.
To keep the F3, run an F3 extractor such as ``diag_f3_extract.py`` first
(persists ``<cap>.f3.jsonl``), or simply archive the raw HDLC.

Pipeline usage:
    diaggulp.py /dev/ttyUSB2 | hdlc_to_dlf.py - capture.dlf
    hdlc_to_dlf.py raw_capture.bin - | dlf_to_jsonl.py - parsed.jsonl
    diaggulp.py /dev/ttyUSB2 | hdlc_to_dlf.py - - | dlf_to_jsonl.py - out.jsonl

Use "-" for stdin/stdout.

Input-format detection (``--input-format``, default ``auto``):
    The tool sniffs the first 64 KiB for 0x7E delimiters and falls back to
    a DLF-record-shape double-check when none are present.
    Pass ``--input-format=hdlc`` to bypass detection for captures whose
    first frame legitimately exceeds 64 KiB, or ``--input-format=dlf`` to
    declare DLF-framed input up front and skip straight to the
    ``dlf_to_jsonl.py`` redirection message.
"""

from __future__ import annotations

import shutil
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

# --- F3-loss guard -------------------------------------------------
#
# The re-frame below keeps ONLY 0x10 LOG records. F3 message frames
# (``0x79`` plaintext DIAG_EXT_MSG_F / ``0x99`` QSR4-terse, bare or
# ``0x98``-wrapped) have no representation in flat DLF, so converting an
# F3-bearing capture and archiving the result destroys the F3 ground truth —
# the firmware's own debug prints, this project's field-labelling oracle.
#
# The at-rest diaggulp normalizer has a hard **Gate 0** against exactly this
#. The same lossy transform is reachable here, and ``--verify-crc`` is
# the *usual* CRC check, which emits a ``.dlf`` byproduct. Archiving that byproduct instead
# of the raw HDLC is a one-keystroke, entirely silent mistake: the result still
# scans, still reports ``format: dlf``, still has the right record count. Only
# ``f3: null`` in the rescan gives it away, and by then the only fix is to
# re-take the capture.
#
# Two tiers, deliberately not one:
#   * a file output that drops F3  -> loud stderr WARNING (free: the counts are
#     already in HdlcStats from the conversion walk itself)
#   * an output under CAPTURES_ROOT, i.e. plainly being ARCHIVED -> refuse
#     unless --allow-f3-loss, checked BEFORE any bytes are written
# ``--verify-crc`` to a throwaway path is the common, harmless case and stays
# quiet.
_F3_EXT_MSG_F = 0x79    # plaintext DIAG_EXT_MSG_F (self-decoding, no qdb)
_F3_QSR4_TERSE = 0x99   # QShrink-4.0 hashed terse frame (qdb-resolved)


def _dropped_f3_frame_count(stats: HdlcStats) -> int:
    """Count F3 frames this HDLC->flat-DLF re-frame drops, from an HdlcStats.

    Mirrors the at-rest diaggulp normalizer's dropped-F3 count: sums
    the bare ``0x79``/``0x99`` frames plus the ``0x98``-wrapped inner
    ``0x79``/``0x99``. ``0x98`` itself is NOT counted — a wrapper around an
    inner ``0x10`` LOG survives the re-frame; only its inner F3 is at risk, and
    that lives in ``inner_0x98_opcodes``. Counting the wrapper would badly
    overstate the loss on SDX72-class parts, where *every* frame is wrapped.

    Prefers the CRC-verified counters when the walk checked CRC:
    ``opcode_frames`` tallies the first byte of every 0x7E-delimited fragment,
    valid frame or not, which for a rare opcode can be almost entirely noise.
    Falls back to the raw counters when nobody checked, since an overcount here
    only makes the guard more conservative — it never hides a real loss.
    """
    if stats.crc_checked:
        outer, inner = stats.opcode_frames_crc_ok, stats.inner_0x98_opcodes_crc_ok
    else:
        outer, inner = stats.opcode_frames, stats.inner_0x98_opcodes
    return (
        int(outer.get(_F3_EXT_MSG_F, 0))
        + int(outer.get(_F3_QSR4_TERSE, 0))
        + int(inner.get(_F3_EXT_MSG_F, 0))
        + int(inner.get(_F3_QSR4_TERSE, 0))
    )


#: Mirrors the F3 extractor's compression suffixes. Kept as a literal rather
#: than imported because the extractor is not an installable package and
#: diagmunge must stay importable on its own.
_COMPRESSION_SUFFIXES = (".zst", ".gz", ".bz2", ".xz")

# --- compressed input ----------------------------------------------
#
# Read raw, a ``.bin.zst`` splits its zstd bytes on 0x7E, ~100% of the
# "frames" fail CRC, and the tool exits 0 with a 0-record DLF that a corpus
# scanner then records as ``records=0``. Sniffed by MAGIC, not suffix,
# so stdin and mis-named files are covered and a raw capture that merely ends
# in ``.zst`` is still read raw. gzip/bz2/xz are stdlib; zstd needs the
# ``zstandard`` package, imported lazily so the core stays dependency-free.
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"


class _InputError(Exception):
    """Input cannot be read as a capture; message is printed, exit 2."""


def _decompress_zstd(raw: bytes) -> bytes:
    try:
        import zstandard
    except ImportError as exc:
        raise _InputError(
            "hdlc_to_dlf: ERROR — input is zstd-compressed but the "
            f"'zstandard' package is not importable ({exc}).\n"
            "  Install it (pip install zstandard), or decompress first:\n"
            "    zstd -d <capture>.bin.zst"
        ) from None
    import io

    # read_across_frames: a capture may be a concatenation of zstd frames.
    reader = zstandard.ZstdDecompressor().stream_reader(
        io.BytesIO(raw), read_across_frames=True
    )
    chunks = []
    try:
        while chunk := reader.read(1 << 20):
            chunks.append(chunk)
    except zstandard.ZstdError as exc:
        raise _InputError(
            f"hdlc_to_dlf: ERROR — zstd input failed to decompress: {exc}"
        ) from None
    return b"".join(chunks)


def _maybe_decompress(raw: bytes) -> tuple[bytes, str | None]:
    """Return ``(data, codec)``; ``codec`` is None when ``raw`` is uncompressed."""
    if raw.startswith(_ZSTD_MAGIC):
        return _decompress_zstd(raw), "zstd"
    if raw.startswith(_GZIP_MAGIC):
        import gzip

        return gzip.decompress(raw), "gzip"
    if raw.startswith(_BZ2_MAGIC):
        import bz2

        return bz2.decompress(raw), "bz2"
    if raw.startswith(_XZ_MAGIC):
        import lzma

        try:
            return lzma.decompress(raw), "xz"
        except lzma.LZMAError as exc:
            raise _InputError(
                f"hdlc_to_dlf: ERROR — xz input failed to decompress: {exc}"
            ) from None
    return raw, None


# A CRC-verified walk this bad that also yields nothing is not a capture with
# damage — it is not HDLC at all. Real captures run ~0.003% bad.
_CRC_BAD_REFUSE_FRACTION = 0.99


def _persisted_f3_sidecar(input_path: str) -> Path | None:
    """The persisted ``.f3.jsonl`` for ``input_path``, if one exists.

    Gate 0's remediation says "persist the F3 first, then convert". If the
    gate's predicate came purely from the capture's own frames, following that
    remediation to completion would leave the refusal byte-identical — the only
    way through would be ``--allow-f3-loss``, the flag whose whole job is to
    mark the case where F3 is being thrown away, and the flag would stop
    distinguishing the safe operator from the unsafe one.

    Naming follows the F3 extractor's default output path: the capture's
    compression suffix is dropped before ``.f3.jsonl`` is appended, so
    ``foo.bin.zst`` pairs with ``foo.bin.f3.jsonl``. Both the plain and the
    ``.zst``-compressed sidecar count — the corpus policy compresses
    ``.f3.jsonl`` at ``-19 --long=27``, so a check that only stat'd the plain
    path would resume refusing the moment a capture was archived *correctly*.

    A zero-byte sidecar does not count: that is an extraction that died, and
    honouring it would open the gate while nothing was actually saved.
    """
    if input_path == "-":
        return None
    try:
        src = Path(input_path).expanduser()
        stems = [src.name]
        for suf in _COMPRESSION_SUFFIXES:
            if src.name.endswith(suf):
                stems.append(src.name[: -len(suf)])
                break
        for stem in stems:
            for suffix in (".f3.jsonl", ".f3.jsonl.zst"):
                cand = src.with_name(stem + suffix)
                if cand.is_file() and cand.stat().st_size > 0:
                    return cand
    except Exception:
        return None
    return None


def _is_archival_output(output: str) -> bool:
    """True when ``output`` names a file inside the capture corpus.

    An output under ``CAPTURES_ROOT`` is being *archived*, not inspected — the
    case where losing F3 is permanent. ``-`` (stdout) is never archival.

    Import is local and failure-tolerant on purpose: diagmunge depends on
    diaggrok for HDLC, but a missing/misconfigured corpus root must not break
    a plain conversion. On any error the answer is "not archival", which
    degrades to the warning tier rather than a spurious refusal.
    """
    if output == "-":
        return False
    try:
        from diaggrok.paths import CAPTURES_ROOT

        return Path(output).expanduser().resolve().is_relative_to(
            Path(CAPTURES_ROOT).expanduser().resolve()
        )
    except Exception:
        return False


def _looks_like_dlf(data: bytes, mode: str) -> bool:
    """Heuristic: is ``data`` more likely a DLF stream than HDLC?

    Two modes:

    * ``"dlf"`` — caller declared DLF. Always returns True (no probing).
    * ``"auto"`` — probe the first 64 KiB for any 0x7E delimiter. HDLC
      streams reliably have 0x7E every ~100-500 bytes; absence across
      64 KiB means either DLF or a single legitimate HDLC frame larger
      than the probe window. To disambiguate we then check whether the
      first two ``<H`` length-prefixes parse as plausible DLF records.

    The probe window was bumped from 4 KiB to 64 KiB after
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
    file to a bare 12-byte header with zero payload bytes.
    """
    rec_len = 12 + len(payload)
    ts_lo = ts64 & 0xFFFFFFFF
    ts_hi = (ts64 >> 32) & 0xFFFFFFFF
    out.write(struct.pack("<HHII", rec_len, log_code, ts_lo, ts_hi) + payload)


# SIGINT is handled cooperatively in main(): the handler sets _STOP_REQUESTED
# and the record loop exits at the next record boundary. This avoids
# KeyboardInterrupt firing between two writes of the same record.
_STOP_REQUESTED = False


def _install_sigint_handler() -> None:
    def _handler(signum, frame):  # noqa: ARG001 — signal-handler signature
        global _STOP_REQUESTED
        _STOP_REQUESTED = True

    signal.signal(signal.SIGINT, _handler)


def _carry_anchor_sidecar(input_path: str, output_path: str) -> bool:
    """Copy ``<input>.anchors.json`` to ``<output>.anchors.json``.

    ``diaggulp.py`` names its anchor sidecar after its own ``-o`` target,
    so an HDLC capture converted here leaves the sidecar behind under the
    ``.hdlc`` spelling while every downstream consumer looks for the
    ``.dlf`` one. The failure is silent —
    ``diaggrok_at_correlate.py --auto-align`` just drops from rung 1
    (``anchor_pair``) to rung 3 (``record_boundary``), which still
    "succeeds" with a worse scale/offset.

    Never overwrites an existing destination: if the caller already put a
    sidecar next to the output, that one is authoritative. Returns True
    only when a copy was actually made.
    """
    if input_path == "-" or output_path == "-":
        return False  # nothing to name a sidecar after
    src = Path(input_path + ".anchors.json")
    dst = Path(output_path + ".anchors.json")
    if not src.exists() or dst.exists() or src.resolve() == dst.resolve():
        return False
    try:
        shutil.copy2(src, dst)
    except OSError as exc:
        print(
            f"hdlc_to_dlf: ⚠️  could not carry anchor sidecar {src} -> {dst}: "
            f"{exc}",
            file=sys.stderr,
        )
        return False
    print(f"hdlc_to_dlf: carried anchor sidecar -> {dst}", file=sys.stderr)
    return True


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
        help="Validate CRC-16 on each frame; skip bad frames",
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
            "that drop legitimate log records. Doubles the scan cost "
            "because it iterates the HDLC stream twice."
        ),
    )
    parser.add_argument(
        "--input-format",
        choices=("auto", "hdlc", "dlf"),
        default="auto",
        help=(
            "Bypass the HDLC/DLF heuristic when the caller knows the format "
            ". 'auto' (default) probes the leading bytes for 0x7E "
            "delimiters and falls back to a DLF-shape double-check. 'hdlc' "
            "skips detection and processes as HDLC unconditionally — use "
            "when the heuristic false-positives on captures whose first "
            "frame is larger than the probe window (e.g., a GnssDemodTracking "
            "burst >64 KiB with no 0x7E inside). 'dlf' fails immediately "
            "with the same redirection message the auto-detect emits."
        ),
    )
    parser.add_argument(
        "--allow-f3-loss",
        action="store_true",
        help=(
            "Permit converting an F3-bearing capture when the output lands "
            "under CAPTURES_ROOT. The re-frame keeps only 0x10 LOG "
            "records, so archiving the result destroys the capture's F3 "
            "ground truth — refused by default for archival outputs. Extract "
            "F3 to a persisted .f3.jsonl first (e.g. diag_f3_extract.py). "
            "Non-archival outputs are never refused, only warned about."
        ),
    )
    args = parser.parse_args()

    if args.input == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(args.input).read_bytes()
    try:
        data, codec = _maybe_decompress(raw)
    except _InputError as exc:
        print(exc, file=sys.stderr)
        return 2
    except (OSError, EOFError, ValueError) as exc:
        # gzip.BadGzipFile is an OSError, a truncated gzip/bz2 stream is
        # EOFError, a corrupt bz2 stream is OSError/ValueError. xz and zstd
        # errors are converted to _InputError where they are raised.
        print(
            f"hdlc_to_dlf: ERROR — input looks compressed but failed to "
            f"decompress: {exc}",
            file=sys.stderr,
        )
        return 2
    if codec is not None:
        print(
            f"hdlc_to_dlf: decompressed {codec} input "
            f"({len(raw):,} -> {len(data):,} bytes)",
            file=sys.stderr,
        )
    del raw

    if args.input_format != "hdlc" and _looks_like_dlf(data, args.input_format):
        print(
            "hdlc_to_dlf: ERROR — input appears to be DLF-framed, not HDLC "
            "(no 0x7E delimiters in first 64 KiB, and the first two 2-byte "
            "length prefixes parse as plausible DLF records).\n"
            "  This is the format produced by `diag_socket_log` over adb "
            "reverse tunnels (seen on RM520N-GL R03A03).\n"
            "  If this capture really is HDLC with a single first frame "
            ">64 KiB, re-run with --input-format=hdlc to bypass detection "
            ".\n"
            "  Otherwise, skip this tool and pipe the capture directly to:\n"
            "    apps/diaggpsd/dlf_to_jsonl.py --format bin "
            f"{args.input} <out.jsonl>",
            file=sys.stderr,
        )
        return 2

    # Gate 0 — refuse an F3-destroying conversion into the corpus.
    # Only runs for archival outputs, so the common --verify-crc-to-a-scratch-
    # path case pays nothing: this pre-scan is a second HDLC iteration, and it
    # has to be a PRE-scan because a refusal must land before any bytes are
    # written. Non-archival outputs get the free post-hoc warning instead.
    if _is_archival_output(args.output) and not args.allow_f3_loss:
        probe = HdlcStats()
        for _ in iter_log_records(data, verify_crc=args.verify_crc, stats=probe):
            pass
        dropped_f3 = _dropped_f3_frame_count(probe)
        # A persisted sidecar satisfies the gate. Without this the
        # remediation printed below is unreachable advice and every operator,
        # careful or not, ends up at --allow-f3-loss.
        if dropped_f3 and _persisted_f3_sidecar(args.input) is None:
            print(
                f"hdlc_to_dlf: ERROR — refusing to write an F3-destroying "
                f"conversion into the capture corpus.\n"
                f"  This capture carries {dropped_f3:,} F3 message frame(s) "
                f"(0x79/0x99, bare or 0x98-wrapped). The HDLC->flat-DLF "
                f"re-frame keeps only 0x10 LOG records, so every one of them "
                f"would be silently discarded, and the capture's F3 ground "
                f"truth with them.\n"
                f"  The result would look fine: same record count, same code "
                f"count, format: dlf. Only `f3: null` on a rescan gives it "
                f"away.\n"
                f"  Fix — persist the F3 first, then re-run this exact "
                f"command; the sidecar clears this gate:\n"
                f"    diag_f3_extract.py {args.input}\n"
                f"  Or, if you only want the CRC check, write the byproduct "
                f"somewhere outside CAPTURES_ROOT:\n"
                f"    hdlc_to_dlf.py --verify-crc {args.input} <scratch-dir>/crc.dlf\n"
                f"  Or pass --allow-f3-loss to override deliberately.",
                file=sys.stderr,
            )
            return 3

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

    _carry_anchor_sidecar(args.input, args.output)

    log_crc_report(stats)
    # Backstop: whatever the cause (an unsniffed codec, a truncated
    # header, the wrong file), a CRC walk this bad that yields nothing is not a
    # damaged capture, and a 0-record DLF left behind with exit 0 reads as
    # success to every downstream tool.
    crc_total = stats.crc_ok + stats.crc_bad
    if (
        not stopped
        and stats.log_records == 0
        and crc_total
        and stats.crc_bad / crc_total >= _CRC_BAD_REFUSE_FRACTION
    ):
        if args.output != "-":
            Path(args.output).unlink(missing_ok=True)
        print(
            f"hdlc_to_dlf: ERROR — {stats.crc_bad:,}/{crc_total:,} frames "
            f"failed CRC and 0 LOG records were recovered; the input is not "
            f"HDLC (compressed with an unrecognised codec? the wrong file?).\n"
            f"  No output was kept"
            + ("" if args.output == "-" else f" ({args.output} removed)")
            + ".",
            file=sys.stderr,
        )
        return 4
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
    # F3-loss warning. Free — these counts were populated by the
    # conversion walk above, no rescan. Gated on a FILE output: piping to
    # stdout is inspection, and the docstring already says 0x99 is "counted and
    # reported but not extracted". A file is the thing that gets archived.
    dropped_f3 = _dropped_f3_frame_count(stats)
    if dropped_f3 and args.output != "-":
        # When the F3 is already banked, the loss is expected rather than a
        # hazard, so the warning says which artifact holds it instead of
        # repeating advice the operator has already followed.
        sidecar = _persisted_f3_sidecar(args.input)
        if sidecar is not None:
            tail = (
                f"  F3 already persisted at {sidecar} — the .dlf will not "
                f"carry it, and that is expected. Still keep the raw capture: "
                f"the sidecar holds decoded F3, not the original frames."
            )
        else:
            tail = (
                f"  ⛔ Do NOT archive {args.output} in place of the raw HDLC — "
                f"it scans clean (same record count, format: dlf) but its F3 "
                f"ground truth is gone. Keep the raw capture, "
                f"or persist the F3 first:\n"
                f"    diag_f3_extract.py {args.input}"
            )
        print(
            f"hdlc_to_dlf: ⚠️  WARNING — {dropped_f3:,} F3 message frame(s) "
            f"(0x79/0x99, bare or 0x98-wrapped) were DISCARDED. Flat DLF has "
            f"no representation for F3; only 0x10 LOG records survive.\n"
            + tail,
            file=sys.stderr,
        )
    if args.opcode_stats:
        print("hdlc_to_dlf: opcode breakdown:", file=sys.stderr)
        for line in stats.summary_lines():
            print(line, file=sys.stderr)
    # 0x80 QShrink4 sequence-gap detection. The compressed bodies
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
            "boundary.",
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
    practice.

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

    print("hdlc_to_dlf: retention report", file=sys.stderr)
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
            "here (observed on diaggulp output from SDX55/SDX62).",
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
