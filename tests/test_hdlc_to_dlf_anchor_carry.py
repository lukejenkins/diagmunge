# SPDX-License-Identifier: Apache-2.0
"""Tests for hdlc_to_dlf carrying the anchor sidecar across conversion.

``diaggulp.py`` names its ``.anchors.json`` sidecar after its own ``-o``
target. ``/modem-diag-at-correlate`` captures to **HDLC** and converts here
afterward, so the sidecar lands as ``<base>.hdlc.anchors.json`` while every
downstream consumer looks for ``<base>.dlf.anchors.json``.

Nothing errored when that happened. ``diaggrok_at_correlate.py --auto-align``
simply fell from rung 1 (``anchor_pair``) to rung 3 (``record_boundary``) —
measured on one RM500Q-AE capture as 23,132 matched DIAG x AT pairs instead of
24,477, with a worse scale/offset. Both runs reported success.

The non-overwrite case is the load-bearing one: a caller that already placed a
sidecar next to the output has better information than we do, and clobbering it
with the input's would be a data-loss bug introduced by a data-loss fix.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from struct import pack

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


def _log_frame(log_code: int = 0xB0C0) -> bytes:
    payload = b"\xaa\xbb"
    inner = 12 + len(payload)
    body = pack("<BBHHHQ", 0x10, 0, inner, inner, log_code,
                0x1122334455667788) + payload
    return b"\x7e" + _escape(body + pack("<H", crc16_ccitt(body))) + b"\x7e"


def _sidecar_bytes(marker: str) -> str:
    return json.dumps({
        "version": 1,
        "method": "diag_verno_response",
        "tool": "diaggulp.py",
        "marker": marker,
        "anchors": [
            {"kind": "start", "host_mono_ns": 1_000_000_000},
            {"kind": "end", "host_mono_ns": 2_000_000_000},
        ],
    })


def _convert(tmp_path: Path, *, with_sidecar: bool = True,
             dst_sidecar: str | None = None) -> tuple[Path, Path]:
    src = tmp_path / "diag_capture.hdlc"
    dst = tmp_path / "diag_capture.dlf"
    src.write_bytes(_log_frame())
    if with_sidecar:
        (tmp_path / "diag_capture.hdlc.anchors.json").write_text(
            _sidecar_bytes("from-hdlc"), encoding="utf-8")
    if dst_sidecar is not None:
        (tmp_path / "diag_capture.dlf.anchors.json").write_text(
            dst_sidecar, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", MODULE, str(src), str(dst)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return dst, tmp_path / "diag_capture.dlf.anchors.json"


def test_sidecar_is_carried_to_the_output_name(tmp_path: Path):
    """The whole point: after conversion the .dlf spelling exists."""
    dst, dst_sidecar = _convert(tmp_path)
    assert dst.exists()
    assert dst_sidecar.exists()
    assert json.loads(dst_sidecar.read_text())["marker"] == "from-hdlc"


def test_the_source_sidecar_is_kept_not_moved(tmp_path: Path):
    """Copy, not rename — the raw HDLC capture stays self-describing."""
    _convert(tmp_path)
    assert (tmp_path / "diag_capture.hdlc.anchors.json").exists()


def test_an_existing_destination_sidecar_is_never_overwritten(tmp_path: Path):
    """A sidecar already at the output name wins.

    It was placed by someone with more context than this conversion has;
    silently replacing it would trade one wrong alignment for another.
    """
    _, dst_sidecar = _convert(tmp_path, dst_sidecar=_sidecar_bytes("pre-existing"))
    assert json.loads(dst_sidecar.read_text())["marker"] == "pre-existing"


def test_no_source_sidecar_is_not_an_error(tmp_path: Path):
    """Captures taken with --anchor-frame=none have nothing to carry."""
    dst, dst_sidecar = _convert(tmp_path, with_sidecar=False)
    assert dst.exists()
    assert not dst_sidecar.exists()


def test_stdout_output_carries_nothing(tmp_path: Path):
    """There is no output path to name a sidecar after."""
    src = tmp_path / "diag_capture.hdlc"
    src.write_bytes(_log_frame())
    (tmp_path / "diag_capture.hdlc.anchors.json").write_text(
        _sidecar_bytes("from-hdlc"), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", MODULE, str(src), "-"],
        capture_output=True,
    )
    assert proc.returncode == 0
    assert list(tmp_path.glob("*.anchors.json")) == [
        tmp_path / "diag_capture.hdlc.anchors.json"
    ]
