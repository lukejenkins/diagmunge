# SPDX-License-Identifier: Apache-2.0
"""Tests for hdlc_to_dlf's F3-loss guard.

The HDLC->flat-DLF re-frame keeps only ``0x10`` LOG records, so an F3-bearing
capture converted and then **archived** loses its F3 ground truth silently —
the converted file scans clean (same record count, ``format: dlf``) and only
``f3: null`` on a rescan reveals it. The at-rest normalizer refuses this
; ``hdlc_to_dlf`` must too, because it sits on the end
of ``--verify-crc``, the CRC check the docs actively recommend.

Two tiers under test, and the split matters as much as the guard:

* **archival** output (under ``CAPTURES_ROOT``) -> refuse, exit 3, nothing
  written;
* any other **file** output -> convert normally, but warn loudly;
* **stdout** -> silent, because piping is inspection, not archiving.

The F3-free control cases are the important half: a guard that fires on
captures with no F3 to lose would make ``--verify-crc`` unusable.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from struct import pack

import pytest

from diaggrok.hdlc import crc16_ccitt

MODULE = "diagmunge.munge.hdlc_to_dlf"

# The archival tier needs a corpus root (``diaggrok.paths.CAPTURES_ROOT``).
# A diaggrok without that module has no corpus, so every output is "not
# archival" and the guard stays at the warning tier by design. The tests that
# assert the archival REFUSAL only mean something where the module exists.
needs_corpus_root = pytest.mark.skipif(
    importlib.util.find_spec("diaggrok.paths") is None,
    reason="diaggrok.paths absent: no capture corpus, so no archival tier")

_F3_EXT_MSG_F = 0x79
_F3_QSR4_TERSE = 0x99
_MULTI_RADIO = 0x98


def _escape(raw: bytes) -> bytes:
    out = bytearray()
    for b in raw:
        if b in (0x7D, 0x7E):
            out += bytes((0x7D, b ^ 0x20))
        else:
            out.append(b)
    return bytes(out)


def _frame(body: bytes) -> bytes:
    """One delimited HDLC frame carrying ``body`` with a valid CRC."""
    return b"\x7e" + _escape(body + pack("<H", crc16_ccitt(body))) + b"\x7e"


def _log_body(log_code: int, ts64: int = 0x1122334455667788,
              payload: bytes = b"\xaa\xbb") -> bytes:
    inner = 12 + len(payload)
    return pack("<BBHHHQ", 0x10, 0, inner, inner, log_code, ts64) + payload


def _f3_body(opcode: int, n: int = 16) -> bytes:
    """A bare F3 frame (0x79 plaintext or 0x99 QSR4-terse)."""
    return bytes([opcode] + [0x00] * n)


def _wrapped_body(inner_opcode: int, n: int = 16) -> bytes:
    """A 0x98 DIAG_MULTI_RADIO_CMD_F wrapper whose inner opcode is at byte 8.

    SDX72-class parts wrap *every* frame, so a top-level-only opcode tally
    misses all of their F3 — the exact hole ``inner_0x98_opcodes`` exists to
    close.
    """
    return bytes([_MULTI_RADIO, 0, 0, 0, 0, 0, 0, 0, inner_opcode] + [0x00] * n)


def _run(tmp_path: Path, capture: bytes, out, *extra: str,
         captures_root: Path | None = None):
    """Invoke the CLI in a subprocess so argv/exit-code behaviour is real."""
    src = tmp_path / "capture.hdlc"
    src.write_bytes(capture)
    env = {"PATH": "/usr/bin:/bin"}
    if captures_root is not None:
        env["CHP_CAPTURES_ROOT"] = str(captures_root)
    return subprocess.run(
        [sys.executable, "-m", MODULE, str(src), str(out), *extra],
        capture_output=True, text=True, env=env,
    )


# --- the loss itself -------------------------------------------------------

def test_f3_bearing_file_output_warns_but_still_converts(tmp_path):
    """A non-archival file output is warned about, not refused.

    Converting to a scratch path is the common, legitimate case
    (``--verify-crc`` diagnostics). It must keep working — but silently is
    what lets F3 loss go unnoticed, so it warns.
    """
    cap = (_frame(_log_body(0xB0C0)) + _frame(_f3_body(_F3_QSR4_TERSE))
           + _frame(_log_body(0xB0C1)))
    out = tmp_path / "out.dlf"
    res = _run(tmp_path, cap, out, captures_root=tmp_path / "corpus")

    assert res.returncode == 0
    assert out.exists() and out.stat().st_size > 0, "conversion must still happen"
    assert "WARNING" in res.stderr
    assert "F3 message frame" in res.stderr
    assert "diag_f3_extract.py" in res.stderr, "must name the remedy, not just the loss"


def test_warning_counts_bare_and_wrapped_f3_together(tmp_path):
    """0x98-wrapped inner F3 counts too — a top-level tally would miss it all."""
    cap = (_frame(_log_body(0xB0C0))
           + _frame(_f3_body(_F3_EXT_MSG_F))
           + _frame(_f3_body(_F3_QSR4_TERSE))
           + _frame(_wrapped_body(_F3_QSR4_TERSE))
           + _frame(_wrapped_body(_F3_EXT_MSG_F)))
    res = _run(tmp_path, cap, tmp_path / "out.dlf", captures_root=tmp_path / "corpus")

    assert res.returncode == 0
    assert "4 F3 message frame" in res.stderr, res.stderr


def test_wrapper_around_inner_log_is_not_counted_as_f3_loss(tmp_path):
    """A 0x98 wrapping an inner 0x10 SURVIVES the re-frame — not a loss.

    Counting the wrapper itself would report catastrophic phantom loss on
    SDX72-class parts, where every record is wrapped.
    """
    cap = _frame(_log_body(0xB0C0)) + _frame(_wrapped_body(0x10))
    res = _run(tmp_path, cap, tmp_path / "out.dlf", captures_root=tmp_path / "corpus")

    assert res.returncode == 0
    assert "WARNING" not in res.stderr, res.stderr


# --- the archival gate -----------------------------------------------------

@needs_corpus_root
def test_archival_output_with_f3_is_refused(tmp_path):
    """Output under CAPTURES_ROOT is being archived — refuse, write nothing."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    cap = _frame(_log_body(0xB0C0)) + _frame(_f3_body(_F3_QSR4_TERSE))
    out = corpus / "wardriving" / "sess" / "out.dlf"
    out.parent.mkdir(parents=True)

    res = _run(tmp_path, cap, out, captures_root=corpus)

    assert res.returncode == 3
    assert not out.exists(), "a refusal must leave no partial artifact behind"
    assert "refusing" in res.stderr.lower()
    assert "diag_f3_extract.py" in res.stderr


def test_archival_refusal_is_overridable(tmp_path):
    """--allow-f3-loss is a deliberate, on-the-record override."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    cap = _frame(_log_body(0xB0C0)) + _frame(_f3_body(_F3_QSR4_TERSE))
    out = corpus / "out.dlf"

    res = _run(tmp_path, cap, out, "--allow-f3-loss", captures_root=corpus)

    assert res.returncode == 0
    assert out.exists() and out.stat().st_size > 0
    # Overriding the gate does not buy silence — the warning tier still fires.
    assert "WARNING" in res.stderr


def test_archival_output_without_f3_is_not_refused(tmp_path):
    """The control that keeps the gate honest: no F3 to lose, no refusal."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    cap = _frame(_log_body(0xB0C0)) + _frame(_log_body(0xB0C1))
    out = corpus / "out.dlf"

    res = _run(tmp_path, cap, out, captures_root=corpus)

    assert res.returncode == 0
    assert out.exists()
    assert "refusing" not in res.stderr.lower()
    assert "WARNING" not in res.stderr


# --- the remediation must actually clear the gate -------------------
#
# The gate's advice is "persist the F3 first, then convert". If the predicate
# were a pure function of the capture's own frames, following that advice to
# completion would change nothing and the operator would be funnelled into
# --allow-f3-loss — the flag that is supposed to mark the *unsafe* case. These
# tests pin the sidecar as a first-class way through.

def _persist_sidecar(src: Path, suffix: str = ".f3.jsonl",
                     body: bytes = b'{"ok":1}\n') -> Path:
    side = src.with_name(src.name + suffix)
    side.write_bytes(body)
    return side


def test_persisted_f3_sidecar_clears_the_archival_gate(tmp_path):
    """Doing the thing the error message tells you to do must work."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    cap = _frame(_log_body(0xB0C0)) + _frame(_f3_body(_F3_QSR4_TERSE))
    src = tmp_path / "capture.hdlc"
    src.write_bytes(cap)
    _persist_sidecar(src)
    out = corpus / "out.dlf"

    res = subprocess.run(
        [sys.executable, "-m", MODULE, str(src), str(out)],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "CHP_CAPTURES_ROOT": str(corpus)},
    )

    assert res.returncode == 0, res.stderr
    assert out.exists() and out.stat().st_size > 0
    assert "refusing" not in res.stderr.lower()
    # Still says the .dlf won't carry F3 — the loss is real, just expected now.
    assert "WARNING" in res.stderr
    assert "already persisted" in res.stderr, res.stderr


def test_compressed_sidecar_also_clears_the_gate(tmp_path):
    """`.f3.jsonl.zst` counts — the corpus compresses sidecars at -19.

    A gate that only stats the plain path would start refusing again the
    moment the capture is archived *correctly*, which is exactly backwards.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    cap = _frame(_log_body(0xB0C0)) + _frame(_f3_body(_F3_QSR4_TERSE))
    src = tmp_path / "capture.hdlc"
    src.write_bytes(cap)
    _persist_sidecar(src, ".f3.jsonl.zst", b"\x28\xb5\x2f\xfd\x00")
    out = corpus / "out.dlf"

    res = subprocess.run(
        [sys.executable, "-m", MODULE, str(src), str(out)],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "CHP_CAPTURES_ROOT": str(corpus)},
    )

    assert res.returncode == 0, res.stderr
    assert out.exists()


@needs_corpus_root
def test_empty_sidecar_does_not_clear_the_gate(tmp_path):
    """A 0-byte sidecar is a failed extraction, not a persisted one.

    Accepting it would let a crashed/interrupted ``diag_f3_extract`` open the
    gate — the guard would then be strictly worse than useless, because it
    would read as "F3 is safe" while nothing was saved.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    cap = _frame(_log_body(0xB0C0)) + _frame(_f3_body(_F3_QSR4_TERSE))
    src = tmp_path / "capture.hdlc"
    src.write_bytes(cap)
    _persist_sidecar(src, ".f3.jsonl", b"")
    out = corpus / "out.dlf"

    res = subprocess.run(
        [sys.executable, "-m", MODULE, str(src), str(out)],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "CHP_CAPTURES_ROOT": str(corpus)},
    )

    assert res.returncode == 3
    assert not out.exists()


def test_sidecar_lookup_drops_a_compression_suffix(tmp_path):
    """``foo.bin.zst`` -> ``foo.bin.f3.jsonl``, matching diag_f3_extract.

    ``tools/diag_f3_extract.default_out_path`` strips the compression suffix
    before appending, so a gate that only tried ``<input> + '.f3.jsonl'``
    would miss the sidecar the remediation actually wrote.
    """
    from diagmunge.munge.hdlc_to_dlf import _persisted_f3_sidecar

    src = tmp_path / "cap.bin.zst"
    src.write_bytes(b"x")
    assert _persisted_f3_sidecar(str(src)) is None

    side = tmp_path / "cap.bin.f3.jsonl"
    side.write_bytes(b'{"ok":1}\n')
    assert _persisted_f3_sidecar(str(src)) == side


def test_sidecar_lookup_is_never_consulted_for_stdin(tmp_path):
    """Reading from ``-`` has no path to hang a sidecar off."""
    from diagmunge.munge.hdlc_to_dlf import _persisted_f3_sidecar

    assert _persisted_f3_sidecar("-") is None


# --- quiet paths -----------------------------------------------------------

def test_f3_free_capture_is_silent(tmp_path):
    """--verify-crc on an F3-free capture must stay exactly as quiet as before."""
    cap = _frame(_log_body(0xB0C0)) + _frame(_log_body(0xB0C1))
    res = _run(tmp_path, cap, tmp_path / "out.dlf", "--verify-crc",
               captures_root=tmp_path / "corpus")

    assert res.returncode == 0
    assert "WARNING" not in res.stderr
    assert "F3" not in res.stderr


def test_stdout_output_does_not_warn(tmp_path):
    """Piping is inspection, not archiving — and the docstring already says
    0x99 is 'counted and reported but not extracted'."""
    cap = _frame(_log_body(0xB0C0)) + _frame(_f3_body(_F3_QSR4_TERSE))
    src = tmp_path / "capture.hdlc"
    src.write_bytes(cap)
    res = subprocess.run(
        [sys.executable, "-m", MODULE, str(src), "-"],
        capture_output=True, env={"PATH": "/usr/bin:/bin",
                                  "CHP_CAPTURES_ROOT": str(tmp_path / "corpus")},
    )

    assert res.returncode == 0
    assert b"WARNING" not in res.stderr


# --- helper-level invariants ----------------------------------------------

def test_is_archival_output_handles_stdout_and_bad_roots(monkeypatch):
    """`-` is never archival, and a broken corpus root degrades to 'no'.

    A missing/misconfigured CAPTURES_ROOT must not turn a plain conversion
    into a spurious refusal — failing open here only drops the gate to the
    warning tier.
    """
    from diagmunge.munge.hdlc_to_dlf import _is_archival_output

    assert _is_archival_output("-") is False
    monkeypatch.setenv("CHP_CAPTURES_ROOT", "/nonexistent/captures-root")
    assert _is_archival_output("out.dlf") is False


def test_dropped_f3_count_prefers_crc_verified_counters():
    """With CRC checked, the census must use the CRC-valid shadow counters.

    ``opcode_frames`` tallies the first byte of every 0x7E-delimited fragment,
    valid or not; for a rare opcode that is almost all noise. Using it
    when a CRC-verified tally exists would overstate the loss.
    """
    from collections import Counter

    from diaggrok.hdlc import HdlcStats
    from diagmunge.munge.hdlc_to_dlf import _dropped_f3_frame_count

    stats = HdlcStats()
    stats.opcode_frames = Counter({_F3_QSR4_TERSE: 5000})
    stats.opcode_frames_crc_ok = Counter({_F3_QSR4_TERSE: 7})
    stats.crc_checked = True
    assert _dropped_f3_frame_count(stats) == 7

    stats.crc_checked = False
    assert _dropped_f3_frame_count(stats) == 5000, "falls back when nobody checked"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))
