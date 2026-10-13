# SPDX-License-Identifier: Apache-2.0
"""hdlc_to_dlf must not parse compressed bytes as HDLC.

A ``.bin.zst`` input read raw is a silent misparse: the zstd bytes split on
``0x7E``, ~100% of the "frames" fail CRC, and the tool exits **0** having
written a 0-record DLF. ``diag_scan`` then sidecars it as ``records=0``.
Sibling tools (``diag_scan``, ``diag_f3_extract``, ``post_capture``) accept
``.zst`` transparently, so passing one here was an easy mistake.

Two halves under test:

* compressed input (zstd / gzip / bz2 / xz, sniffed by magic, so stdin and
  mis-named files are covered too) is decompressed and converts identically
  to the raw capture;
* independently, a CRC-verified walk that is ≥99% bad **and** yields 0 LOG
  records is a non-zero exit with no output file left behind — whatever the
  cause, an empty DLF that looks like success is the failure mode.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import subprocess
import sys
from pathlib import Path
from struct import pack

import pytest

from diaggrok.hdlc import crc16_ccitt

MODULE = "diagmunge.munge.hdlc_to_dlf"


def _escape(raw: bytes) -> bytes:
    out = bytearray()
    for b in raw:
        if b in (0x7D, 0x7E):
            out += bytes((0x7D, b ^ 0x20))
        else:
            out.append(b)
    return bytes(out)


def _frame(body: bytes, *, good_crc: bool = True) -> bytes:
    crc = crc16_ccitt(body) ^ (0 if good_crc else 0xFFFF)
    return b"\x7e" + _escape(body + pack("<H", crc)) + b"\x7e"


def _log_body(log_code: int, payload: bytes = b"\xaa\xbb\xcc\xdd") -> bytes:
    inner = 12 + len(payload)
    return pack("<BBHHHQ", 0x10, 0, inner, inner, log_code,
                0x1122334455667788) + payload


def _capture(n: int = 20) -> bytes:
    return b"".join(_frame(_log_body(0xB0C0 + (i % 3))) for i in range(n))


def _run(src: Path, out: Path, *extra: str, stdin: bytes | None = None):
    argv = [sys.executable, "-m", MODULE,
            "-" if stdin is not None else str(src), str(out), *extra]
    return subprocess.run(argv, capture_output=True, input=stdin,
                          env={"PATH": "/usr/bin:/bin"})


def _zstd(data: bytes) -> bytes:
    zstandard = pytest.importorskip("zstandard")
    return zstandard.ZstdCompressor().compress(data)


COMPRESSORS = {
    "zst": _zstd,
    "gz": gzip.compress,
    "bz2": bz2.compress,
    "xz": lzma.compress,
}


@pytest.fixture
def baseline(tmp_path) -> bytes:
    """The DLF the RAW capture converts to — the oracle for every codec."""
    src = tmp_path / "raw.bin"
    src.write_bytes(_capture())
    out = tmp_path / "raw.dlf"
    res = _run(src, out, "--verify-crc")
    assert res.returncode == 0, res.stderr
    data = out.read_bytes()
    assert data, "positive control: the raw capture must convert to a non-empty DLF"
    return data


@pytest.mark.parametrize("codec", sorted(COMPRESSORS))
def test_compressed_input_converts_identically_to_raw(tmp_path, baseline, codec):
    src = tmp_path / f"cap.bin.{codec}"
    src.write_bytes(COMPRESSORS[codec](_capture()))
    out = tmp_path / "cap.dlf"
    res = _run(src, out, "--verify-crc")
    assert res.returncode == 0, res.stderr
    assert out.read_bytes() == baseline
    assert b"decompress" in res.stderr.lower(), "say that the input was decompressed"


def test_compressed_input_is_sniffed_not_suffix_matched(tmp_path, baseline):
    """A zstd stream on stdin (no suffix at all) is still decompressed."""
    out = tmp_path / "stdin.dlf"
    res = _run(tmp_path / "unused", out, "--verify-crc", stdin=_zstd(_capture()))
    assert res.returncode == 0, res.stderr
    assert out.read_bytes() == baseline


def test_misnamed_raw_capture_with_zst_suffix_is_read_raw(tmp_path, baseline):
    """The suffix alone does not trigger decompression — the magic does."""
    src = tmp_path / "actually_raw.bin.zst"
    src.write_bytes(_capture())
    out = tmp_path / "out.dlf"
    res = _run(src, out, "--verify-crc")
    assert res.returncode == 0, res.stderr
    assert out.read_bytes() == baseline


def test_zst_without_zstandard_refuses_instead_of_misparsing(tmp_path):
    """No ``zstandard`` installed -> a clear error, never the raw-zstd misparse."""
    src = tmp_path / "cap.bin.zst"
    src.write_bytes(_zstd(_capture()))
    out = tmp_path / "out.dlf"
    shim = tmp_path / "shim"
    shim.mkdir()
    # A module that raises on import shadows the real package.
    (shim / "zstandard.py").write_text("raise ImportError('blocked by test')\n")
    res = subprocess.run(
        [sys.executable, "-m", MODULE, str(src), str(out), "--verify-crc"],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(shim)},
    )
    assert res.returncode == 2, res.stderr
    assert "zstandard" in res.stderr and "zstd -d" in res.stderr
    assert not out.exists(), "nothing may be written on refusal"


# --- the CRC-bad backstop --------------------------------------------------

def test_all_crc_bad_zero_records_is_nonzero_exit_and_no_output(tmp_path):
    """The raw-zstd misparse shape with any cause: ≥99% CRC-bad and 0 LOG records."""
    cap = b"".join(_frame(_log_body(0xB0C0), good_crc=False) for _ in range(200))
    src = tmp_path / "garbage.bin"
    src.write_bytes(cap)
    out = tmp_path / "out.dlf"
    res = _run(src, out, "--verify-crc")
    assert res.returncode == 4, res.stderr
    assert b"ERROR" in res.stderr
    assert not out.exists(), "an empty DLF that looks like success must not be left behind"


def test_partial_crc_damage_still_succeeds(tmp_path):
    """Control: real captures carry some CRC damage; that is not this failure."""
    cap = (b"".join(_frame(_log_body(0xB0C0), good_crc=False) for _ in range(50))
           + _capture(5))
    src = tmp_path / "damaged.bin"
    src.write_bytes(cap)
    out = tmp_path / "out.dlf"
    res = _run(src, out, "--verify-crc")
    assert res.returncode == 0, res.stderr
    assert out.stat().st_size > 0


def test_backstop_does_not_fire_without_verify_crc(tmp_path):
    """No CRC walk -> no CRC verdict; an F3-only/empty capture keeps exit 0."""
    src = tmp_path / "empty.bin"
    src.write_bytes(b"\x7e\x7e")
    res = _run(src, tmp_path / "out.dlf")
    assert res.returncode == 0, res.stderr
