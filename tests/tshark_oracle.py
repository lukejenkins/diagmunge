"""tshark-oracle helper shared by the GSMTAP and Exported-PDU dissection tests.

Deliberately NOT in ``conftest.py``: pytest's default ``prepend`` import mode
puts every test directory on ``sys.path``, so a bare ``from conftest import ...``
resolves to whichever ``conftest`` module was imported first — in a whole-repo
run that is ``tools/tests/conftest.py``, and collection dies. A uniquely-named
module is the only import that is stable across run scopes.
"""
from __future__ import annotations

import os
import subprocess
import tempfile


def _tshark_version() -> str:
    """First line of ``tshark -v``, or a marker if it cannot be obtained.

    Recorded in every failure message: when a host-dependent failure is
    reported, the question is "which tshark saw what", and a bare assert that
    emits only the mismatch cannot answer it.
    """
    try:
        out = subprocess.run(["tshark", "-v"], capture_output=True,
                             text=True, timeout=30)
        first = (out.stdout or out.stderr).strip().splitlines()
        return first[0] if first else "<tshark -v printed nothing>"
    except Exception as exc:                      # pragma: no cover - defensive
        return f"<tshark -v failed: {exc!r}>"


def run_stock_tshark(pcap, field: str = "frame.protocols"):
    """Dissect ``pcap`` with tshark under a guaranteed-EMPTY Wireshark profile.

    Every tshark-oracle test in this suite claims to prove dissection on *stock
    tshark with no plugin/profile*. tshark reads the invoking user's personal
    Wireshark config directory by default, so on any host where a human has run
    Wireshark that claim was an assumption, not a precondition the test
    established.

    It is not a theoretical gap. The Exported-PDU oracles name their dissector
    inside the frame and are structurally immune, but the GSMTAP oracle rides
    UDP/4729 and depends on the ``udp.port`` → ``gsmtap`` binding — which is a
    *user preference*. A single ``decode_as_entries`` line (one click of
    Analyze → Decode As in the GUI) unbinds it and turns the test red with the
    encoder and the pcap both perfectly correct: the frame dissects as
    ``eth:ethertype:ip:udp:data``. That is a host-dependent red that does not
    reproduce on another machine.

    Pointing ``WIRESHARK_CONFIG_DIR`` at an empty directory makes the docstring
    true. Note it must be *set to an empty dir*, not unset — unsetting it falls
    back to the user's real profile, which is the thing being excluded.
    """
    with tempfile.TemporaryDirectory(prefix="ws-empty-profile-") as cfg:
        env = {**os.environ, "WIRESHARK_CONFIG_DIR": cfg}
        argv = ["tshark", "-r", str(pcap), "-T", "fields", "-e", field]
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=60, env=env)


def run_stock_tshark_json(pcap):
    """``tshark -T json`` of ``pcap`` under the same EMPTY profile.

    Returns the JSON parsed as nested ``(key, value)`` pair lists: tshark
    repeats keys inside one object (``per.optional_field_bit``), and a dict
    would keep only the last. For value-level oracles.
    """
    import json
    with tempfile.TemporaryDirectory(prefix="ws-empty-profile-") as cfg:
        env = {**os.environ, "WIRESHARK_CONFIG_DIR": cfg}
        out = subprocess.run(["tshark", "-r", str(pcap), "-T", "json"],
                             capture_output=True, text=True, timeout=120,
                             env=env, check=True)
    return json.loads(out.stdout, object_pairs_hook=lambda kv: kv)


def assert_tshark_dissects(pcap, expected: str, field: str = "frame.protocols"):
    """Assert stock tshark reports ``expected`` in ``field`` for ``pcap``.

    The failure message carries the tshark version, the exit status and the
    protocol chain actually observed, so a red on a host the author cannot
    reach is a diagnosis rather than a bare ``AssertionError``.
    """
    out = run_stock_tshark(pcap, field=field)
    if expected in out.stdout:
        return out
    try:
        size = os.path.getsize(pcap)
    except OSError as exc:                        # pragma: no cover - defensive
        size = f"<unreadable: {exc!r}>"
    raise AssertionError(
        f"stock tshark did not report {expected!r} in {field}.\n"
        f"  tshark:     {_tshark_version()}\n"
        f"  returncode: {out.returncode}\n"
        f"  {field}:    {out.stdout.strip()!r}\n"
        f"  stderr:     {out.stderr.strip()!r}\n"
        f"  pcap:       {pcap} ({size} bytes)\n"
        "  (run under an EMPTY WIRESHARK_CONFIG_DIR, so a host Wireshark "
        "profile is already excluded as a cause.)"
    )
