"""Interleaved-stream detection in ``Dge1SeqTracker``.

A ``diaggulp --transport udp-listen`` socket bound to ``0.0.0.0`` receives EVERY
DGE1 datagram reaching the port — and the RIS-9260 emits **two** independent
DGE1 sequence streams from one source (a ``.255`` broadcast plus a second egress
to a non-broadcast dst). DGE1 framing carries no stream ID, so a single tracker
flip-flops between the two baselines (~155M and ~641M in the incident) and books
a ~486M phantom forward gap on the switch: ``received=34625
missing=487459810``, i.e. 99.99% "loss" while a co-window pcap was clean.

486M datagrams at 1412 B is ~686 GB "lost" in a 25 s window — physically
impossible on the link. That impossibility is the detectable signal: a real
lossy stream books many *small* gaps; interleaving books a few *astronomical*
ones. This suite pins that a forward gap at/above the plausibility floor is
reclassified as a **stream discontinuity** (delivered, NOT counted as loss) and
surfaced as ``suspect_interleaved`` — rather than silently merged into a
catastrophic phantom-gap count.

The load-bearing other half: a genuine single stream, with contiguous seqs OR a
plausible sub-floor gap, must be **byte-identical** to plain single-stream accounting —
``suspect_interleaved`` stays False and ``missing`` is unchanged. The floor is
what separates the two, so both directions are asserted.
"""
from __future__ import annotations

from diagmunge import Dge1SeqTracker


def _feed_track(seqs, restart_at=()):
    """Drive track() over a seq list; return the tracker after."""
    t = Dge1SeqTracker()
    for i, s in enumerate(seqs):
        t.track(s, restart=(i in restart_at))
    return t


# --- baseline: single stream must be UNCHANGED (the byte-identical half) ------
def test_contiguous_single_stream_is_clean():
    t = _feed_track(range(1000, 1000 + 500))
    r = t.gap_report()
    assert r["received"] == 500
    assert r["missing"] == 0
    assert r["suspect_interleaved"] is False
    assert r["stream_switches"] == 0


def test_a_plausible_forward_gap_is_still_counted_as_loss():
    """A sub-floor gap is real loss and stays counted — the detector must not
    swallow ordinary drops. 5000 << the 2**24 floor."""
    t = _feed_track([100, 101, 102, 5103])  # gap of 5000 at the 4th datagram
    r = t.gap_report()
    assert r["missing"] == 5000
    assert r["suspect_interleaved"] is False
    assert r["stream_switches"] == 0


# --- the interleave pathology: huge gap is a stream switch, not 486M of loss --
def test_a_gap_at_the_floor_is_reclassified_not_booked_as_loss():
    base_a = 155_196_914
    base_b = 641_632_047          # forward gap 486,435,133 >> 2**24 floor
    t = _feed_track([base_a, base_b])
    r = t.gap_report()
    assert r["received"] == 2, "both datagrams are delivered"
    assert r["missing"] == 0, "the 486M gap is a discontinuity, not loss"
    assert r["stream_switches"] == 1
    assert r["suspect_interleaved"] is True
    assert r["max_gap"] > 480_000_000  # the ~486M jump, well above the 2**24 floor


def test_two_interleaved_streams_do_not_produce_catastrophic_loss():
    """The incident shape: two baselines alternating on one socket. Without
    detection this reports missing ~486M (loss_pct ~99.99); with it, missing must be sane
    (nowhere near the seq-space distance) and the report must flag it."""
    base_a, base_b = 155_196_914, 641_632_047
    seqs = []
    for k in range(200):
        seqs.append(base_a + k)
        seqs.append(base_b + k)
    t = _feed_track(seqs)
    r = t.gap_report()
    assert r["suspect_interleaved"] is True
    # The whole point: missing is no longer the ~486M phantom.
    assert r["missing"] < 1_000_000
    assert r["loss_pct"] < 100.0
    assert r["max_gap"] > 480_000_000  # the ~486M jump, well above the 2**24 floor


def test_report_carries_the_new_diagnostic_keys():
    r = Dge1SeqTracker().gap_report()
    for key in ("max_gap", "stream_switches", "suspect_interleaved"):
        assert key in r, f"gap_report() missing {key}"
    # Empty tracker: no data, nothing suspected.
    assert r["suspect_interleaved"] is False
    assert r["max_gap"] == 0
    assert r["stream_switches"] == 0


# --- the reorder-buffer path (feed) must reclassify the huge gap too ----------
def test_feed_path_also_reclassifies_the_huge_gap():
    base_a, base_b = 155_196_914, 641_632_047
    t = Dge1SeqTracker(reorder_window=64)
    t.feed(b"a", base_a, restart=False)
    t.feed(b"b", base_b, restart=False)
    t.flush()
    r = t.gap_report()
    assert r["missing"] == 0
    assert r["stream_switches"] == 1
    assert r["suspect_interleaved"] is True


def test_restart_flag_is_not_counted_as_a_stream_switch():
    """A diagbarf re-spawn (RESTART) legitimately re-baselines; it must not be
    conflated with the interleave signal even when the jump is huge."""
    t = Dge1SeqTracker()
    t.track(155_196_914, restart=False)
    t.track(641_632_047, restart=True)   # explicit re-baseline, not interleave
    r = t.gap_report()
    assert r["restarts"] == 1
    assert r["stream_switches"] == 0
    assert r["suspect_interleaved"] is False
    assert r["missing"] == 0
