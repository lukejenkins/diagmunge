# diagmunge

> Part of the **[cellular `diag*` toolkit](https://github.com/lukejenkins/cellular#the-diag-toolkit)**: start there for how the capture/decode pieces fit together.

Shared **Qualcomm DIAG transport core + offline format-munge tools**: a
permissively-licensed (Apache-2.0) way to arm the DIAG log mask, pump raw
HDLC frames over serial, raw-fd, TCP, or UDP, and munge DIAG capture
formats (HDLC ↔ DLF ↔ JSONL) offline. It is the transport foundation
shared by the capture/daemon siblings in this constellation, and stands
on its own as a DIAG transport core you can build on.

## Public API

```python
import diagmunge

client = diagmunge.DiagClient.from_tcp_server(host, port)   # or .from_serial(port)
for frame in client.iter_frames():
    ...
```

Re-exported at the top level: `DiagClient`, `Dge1SeqTracker`,
`parse_dge1_header`, and the `DIAG_*` opcode constants. Internal transport
classes live in `diagmunge.transport`.

## The munge tools (`diagmunge.munge`)

Offline DIAG format converters, each a self-contained CLI:

| Tool | Purpose |
|------|---------|
| `python -m diagmunge.munge.hdlc_to_dlf` | raw HDLC stream → DLF record format |
| `python -m diagmunge.munge.capture_dlf_from_diag` | subscribe to log codes on a live device, capture frames → DLF |
| `python -m diagmunge.munge.dlf_to_pcap` | DIAG capture → Wireshark pcap: GSMTAP/LTE on UDP/4729, plus a sibling `.nr.pcap` (Exported-PDU/NR signalling) |
| `diagmunge.munge.replay` (library) | offline DLF/HDLC replay core: `replay_to_jsonl(dispatch=…, code_filter=…)` with an injected dispatch |

Console entry points `diagmunge-hdlc-to-dlf`, `diagmunge-capture-dlf`, and
`diagmunge-dlf-to-pcap` are declared for installed use. The munge tools
decode via `diaggrok` (the `munge` extra); a bare `import diagmunge` never
pulls it in.

### `dlf_to_pcap`: DIAG capture to a Wireshark pcap

Reads a DIAG/HDLC/DLF capture and encapsulates the signalling records into
a Wireshark-readable pcap. LTE RRC/NAS records become GSMTAP frames on
UDP/4729 in `<capture>.diaggrok.pcap`; NR RRC/NAS records become
Exported-PDU blocks in a sibling `<capture>.diaggrok.nr.pcap` (a separate
file because NR uses a different pcap link type). Frame timestamps come
from the capture's GNSS ts64→UTC calibration when present, with a
synthetic monotonic fallback.

```bash
diagmunge-dlf-to-pcap capture.dlf
diagmunge-dlf-to-pcap capture.hdlc.zst -o out.pcap
diagmunge-dlf-to-pcap capture.dlf --log-code 0xB0C0
```

The encapsulation is clean-room, built on the public Osmocom GSMTAP and
Wireshark Exported-PDU header layouts; `tshark` is used only as an output
oracle in the tests, never as a source.

## Installation

Neither `diagmunge` nor `diaggrok` is on PyPI yet; install straight
from GitHub:

```bash
pip install "diagmunge @ git+https://github.com/lukejenkins/diagmunge@main"
# with extras:
pip install "diagmunge[munge] @ git+https://github.com/lukejenkins/diagmunge@main"
```

## Dependencies

The core transport (TCP / UDP / raw-fd) is **stdlib-only**. Optional
extras cover the lazy integrations:

| Extra | Pulls | Used by |
|-------|-------|---------|
| `diagmunge[serial]` | `pyserial` | `DiagClient.from_serial()` |
| `diagmunge[decode]` | `diaggrok` | `DiagClient.observe_codes()` |
| `diagmunge[munge]` | `diaggrok` | the `diagmunge.munge` CLI tools |

`import diagmunge` never requires any of them; all are imported lazily
at their call sites. Because `diaggrok` is not on PyPI yet, the `decode`
and `munge` extras resolve it via a git+https direct URL
(`git+https://github.com/lukejenkins/diaggrok@main`) until further
notice.

## Constellation position

```
                 diaggrok   (pure DECODE library; never depends on diagmunge)
                    ▲  (lazy: observe_codes -> diaggrok.frame.parse_outer_frame)
                    │
                 diagmunge  (this: shared DiagClient transport + munge tools)
                 ▲   ▲   ▲
                 │   │   └── diaggpsd
                 │   └────── diaggulp  (consumes diagmunge transport)
                 └────────── other tools/consumers
```

Dependency edges point inward. `diagmunge -> diaggrok` (lazy) is the only
cross-package edge; the reverse never exists.

## Roadmap

The semantic/foreign-format converters belong here too; that is the
*munge* in diagmunge. GSMTAP pcap output has now landed (`dlf_to_pcap`,
above); the remaining converters (WiGLE, Kismet, RINEX) are still to
follow.
