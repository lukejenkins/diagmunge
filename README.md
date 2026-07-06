# diagmunge

Shared **Qualcomm DIAG transport core + offline format-munge tools** — a
permissively-licensed (Apache-2.0) way to arm the DIAG log mask, pump raw
HDLC frames over serial, raw-fd, TCP, or UDP, and munge DIAG capture
formats (HDLC ↔ DLF ↔ JSONL) offline. It is the transport foundation
shared by the capture/daemon siblings in this constellation, and exists
as a first-party, non-GPL alternative to existing DIAG client tooling.

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

## The munge tools — `diagmunge.munge`

Offline DIAG format converters, each a self-contained CLI:

| Tool | Purpose |
|------|---------|
| `python -m diagmunge.munge.hdlc_to_dlf` | raw HDLC stream → DLF record format |
| `python -m diagmunge.munge.capture_dlf_from_diag` | subscribe to log codes on a live device, capture frames → DLF |
| `diagmunge.munge.replay` (library) | offline DLF/HDLC replay core — `replay_to_jsonl(dispatch=…, code_filter=…)` with an injected dispatch |

Console entry points `diagmunge-hdlc-to-dlf` and `diagmunge-capture-dlf`
are declared for installed use. The munge tools decode via `diaggrok`
(the `munge` extra); a bare `import diagmunge` never pulls it in.

## Installation

Neither `diagmunge` nor `diaggrok` is on PyPI yet — install straight
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

`import diagmunge` never requires any of them — all are imported lazily
at their call sites. Because `diaggrok` is not on PyPI yet, the `decode`
and `munge` extras resolve it via a git+https direct URL
(`git+https://github.com/lukejenkins/diaggrok@main`) until further
notice.

## Constellation position

```
                 diaggrok   (pure DECODE library — never depends on diagmunge)
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

The semantic/foreign-format converters (WiGLE, Kismet, GSMTAP, RINEX)
belong here too — that is the *munge* in diagmunge. They haven't been
carved in yet; today the package ships the transport core plus the
DIAG-native format tools listed above, with the converters to follow.
