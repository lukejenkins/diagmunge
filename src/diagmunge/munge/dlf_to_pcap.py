#!/usr/bin/env python3
"""dlf_to_pcap.py — write a Wireshark-readable pcap from a DIAG capture.

The public diagmunge front-end for DIAG → pcap (the offline sibling of
diaggulp's live --pcap-out). Decodes a DIAG/HDLC/DLF capture with diaggrok's
MIT/Apache-clean parsers and encapsulates GSMTAP-eligible records (LTE RRC/NAS)
into a classic .pcap on UDP/4729, plus a sibling Exported-PDU .nr.pcap for NR
signalling (NR RRC/NAS, link type 252). No qcsuper/SCAT source is read — those
tools are an output oracle only.

Usage:
    diagmunge-dlf-to-pcap capture.dlf
    diagmunge-dlf-to-pcap capture.hdlc.zst -o out.pcap
    diagmunge-dlf-to-pcap capture.dlf --log-code 0xB0C0
"""
from __future__ import annotations

import argparse
import bz2
import gzip
import lzma
import sys
from pathlib import Path

import diaggrok
from diaggrok import exported_pdu, gsmtap
from diaggrok.dlf import iter_records, UnsupportedFormatError, UnknownFormatError
from diaggrok.pcap import PcapWriter, udp4_frame
from diaggrok.ts64_cal import build_calibrator

_FRAME_STEP_S = 0.001  # 1 ms between successive synthetic-timestamp frames
_COMPRESSION_SUFFIXES = (".gz", ".bz2", ".xz", ".zst")
_CAPTURE_SUFFIXES = (".dlf", ".hdlc", ".bin", ".qmdl", ".qmdl2")


class PcapSink:
    """Encode one parsed DIAG record to a pcap frame in the right framing.

    GSMTAP-eligible codes (LTE) are UDP/4729-wrapped and written to ``writer``;
    Exported-PDU-eligible codes (NR) are written to ``nr_writer`` as raw
    Exported-PDU blocks. The two eligible-code sets are disjoint (LTE vs NR).
    This is the single seam shared by the offline batch driver and diaggulp's
    live path, so the two cannot drift.
    """

    def __init__(self, writer, *, nr_writer=None):
        self._writer = writer
        self._nr_writer = nr_writer
        self._nr_eligible = (exported_pdu.eligible_codes()
                             if nr_writer is not None else frozenset())
        self.written = 0
        self.nr_written = 0
        self.encode_skipped = 0
        self.nr_encode_skipped = 0
        self.by_sub: dict[int, int] = {}
        self.by_nr: dict[str, int] = {}

    def is_nr(self, log_code: int) -> bool:
        return self._nr_writer is not None and log_code in self._nr_eligible

    def write_record(self, log_code: int, ts_unix: float, record) -> bool:
        """Encode ``record`` and write one frame; return True if a frame was
        written, False if the encoder declined (empty PDU / unknown channel)."""
        if self.is_nr(log_code):
            frame = exported_pdu.encode(log_code, record)
            if frame is None:
                self.nr_encode_skipped += 1
                return False
            self._nr_writer.write_frame(ts_unix, frame.to_bytes())
            self.nr_written += 1
            self.by_nr[frame.dissector_name] = self.by_nr.get(frame.dissector_name, 0) + 1
            return True
        frame = gsmtap.encode(log_code, record)
        if frame is None:
            self.encode_skipped += 1
            return False
        self._writer.write_frame(
            ts_unix, udp4_frame(frame.to_bytes(), dst_port=gsmtap.GSMTAP_UDP_PORT))
        self.written += 1
        self.by_sub[frame.sub_type] = self.by_sub.get(frame.sub_type, 0) + 1
        return True


def _frame_ts(ts64, *, calibrator, base_epoch, counter):
    """Wall-clock UTC for a frame: calibrated ts64->UTC when available, else the
    synthetic ``base_epoch + counter * step`` monotonic fallback."""
    if calibrator is not None and calibrator.is_calibrated:
        unix = calibrator.ts64_to_unix(ts64)
        if unix is not None:
            return unix
    return base_epoch + counter * _FRAME_STEP_S


def diag_to_pcap(data, writer, wanted, base_epoch=0.0, nr_writer=None,
                 calibrator=None):
    """Decode ``data`` and write GSMTAP (LTE) + Exported-PDU (NR) frames.

    Returns a stats dict: eligible/parse_failed/written/encode_skipped/
    nr_written/nr_encode_skipped plus by_sub/by_nr breakdowns.
    """
    sink = PcapSink(writer, nr_writer=nr_writer)
    stats = {"eligible": 0, "parse_failed": 0}
    for log_code, ts64, payload in iter_records(data):
        if log_code not in wanted:
            continue
        stats["eligible"] += 1
        record = diaggrok.parse(log_code, ts64, payload)
        if record is None:
            stats["parse_failed"] += 1
            continue
        counter = sink.nr_written if sink.is_nr(log_code) else sink.written
        ts_unix = _frame_ts(ts64, calibrator=calibrator,
                            base_epoch=base_epoch, counter=counter)
        sink.write_record(log_code, ts_unix, record)
    stats.update(
        written=sink.written, encode_skipped=sink.encode_skipped,
        nr_written=sink.nr_written, nr_encode_skipped=sink.nr_encode_skipped,
        by_sub=sink.by_sub, by_nr=sink.by_nr)
    return stats


def _read_capture(path: Path) -> bytes:
    name = path.name
    if name.endswith(".bz2"):
        with bz2.open(path, "rb") as f:
            return f.read()
    if name.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return f.read()
    if name.endswith(".xz"):
        with lzma.open(path, "rb") as f:
            return f.read()
    if name.endswith(".zst"):
        import zstandard
        with open(path, "rb") as f:
            return zstandard.ZstdDecompressor().stream_reader(f).read()
    return path.read_bytes()


def _default_output(path: Path) -> Path:
    name = path.name
    for suffix in _COMPRESSION_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    for suffix in _CAPTURE_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return path.parent / (name + ".diaggrok.pcap")


def _nr_output(gsmtap_out: Path) -> Path:
    """``foo.diaggrok.pcap`` -> ``foo.diaggrok.nr.pcap`` (sibling NR pcap).

    NR rides Exported-PDU (link type 252), which cannot share a pcap file with
    the GSMTAP path's Ethernet link type. Shared with diaggulp's live path.
    """
    name = gsmtap_out.name
    if name.endswith(".pcap"):
        name = name[: -len(".pcap")]
    return gsmtap_out.parent / (name + ".nr.pcap")


def _open_outputs(out_path: Path, *, with_nr=True):
    """Open the GSMTAP writer (+ optional NR sibling). Returns
    (writer, nr_writer, files, nr_path)."""
    f = open(out_path, "wb")
    writer = PcapWriter(f)
    files = [f]
    nr_writer = None
    nr_path = None
    if with_nr:
        nr_path = _nr_output(out_path)
        nrf = open(nr_path, "wb")
        nr_writer = PcapWriter(nrf, linktype=exported_pdu.DLT_WIRESHARK_UPPER_PDU)
        files.append(nrf)
    return writer, nr_writer, files, nr_path


def _finalize_outputs(files, nr_path, nr_written) -> None:
    """Close writers; remove a header-only NR sibling (no NR frames)."""
    for fh in files:
        fh.close()
    if nr_path is not None and nr_written == 0:
        try:
            nr_path.unlink()
        except OSError:
            pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="DIAG/HDLC/DLF capture (optionally compressed)")
    ap.add_argument("-o", "--output",
                    help="output .pcap (default <capture>.diaggrok.pcap)")
    ap.add_argument("--log-code", action="append", metavar="CODE",
                    help="restrict to this hex log code (repeatable); "
                         "default = all pcap-eligible codes")
    ap.add_argument("--synthetic-time", action="store_true",
                    help="force synthetic monotonic frame timestamps; skip the "
                         "GNSS ts64->UTC calibration")
    args = ap.parse_args(argv)

    cap = Path(args.capture)
    if not cap.exists():
        print(f"dlf_to_pcap: capture not found: {cap}", file=sys.stderr)
        return 2

    if args.log_code:
        try:
            wanted = frozenset(int(c, 16) for c in args.log_code)
        except ValueError:
            print(f"dlf_to_pcap: invalid --log-code: {args.log_code}", file=sys.stderr)
            return 2
        unknown = wanted - gsmtap.eligible_codes() - exported_pdu.eligible_codes()
        if unknown:
            codes = ", ".join(f"0x{c:04X}" for c in sorted(unknown))
            print(f"dlf_to_pcap: warning: no encoder for {codes}", file=sys.stderr)
    else:
        wanted = gsmtap.eligible_codes() | exported_pdu.eligible_codes()

    out = Path(args.output) if args.output else _default_output(cap)

    try:
        data = _read_capture(cap)
    except Exception as exc:  # noqa: BLE001 — surface any read/decompress error
        print(f"dlf_to_pcap: failed to read {cap}: {exc}", file=sys.stderr)
        return 1

    try:
        base_epoch = cap.stat().st_mtime
    except OSError:
        base_epoch = 0.0

    calibrator = None
    if not args.synthetic_time:
        calibrator = build_calibrator(iter_records(data))

    writer, nr_writer, files, nr_path = _open_outputs(out)
    try:
        stats = diag_to_pcap(data, writer, wanted, base_epoch=base_epoch,
                             nr_writer=nr_writer, calibrator=calibrator)
    except (UnsupportedFormatError, UnknownFormatError) as exc:
        _finalize_outputs(files, nr_path, 0)
        print(f"dlf_to_pcap: cannot decode {cap}: {exc}", file=sys.stderr)
        return 1
    _finalize_outputs(files, nr_path, stats["nr_written"])

    if stats["written"] == 0:
        print(f"dlf_to_pcap: WARNING: no GSMTAP frames written (header-only "
              f"pcap) -> {out}", file=sys.stderr)
    sub = ", ".join(f"sub{s}={n}" for s, n in sorted(stats["by_sub"].items())) or "none"
    print(f"dlf_to_pcap: {stats['written']} frames -> {out} "
          f"(eligible={stats['eligible']}, parse_failed={stats['parse_failed']}, "
          f"encode_skipped={stats['encode_skipped']}; {sub})", file=sys.stderr)
    if stats["nr_written"]:
        nr = ", ".join(f"{k}={v}" for k, v in sorted(stats["by_nr"].items()))
        print(f"dlf_to_pcap: {stats['nr_written']} NR frames -> {nr_path} ({nr})",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
