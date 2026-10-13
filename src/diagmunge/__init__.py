# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""diagmunge — shared DIAG transport core (+ future format-munge tools).

Flat top-level API: the DIAG transport (`DiagClient`, its five transports, the
DGE1 datagram helpers, and the DIAG_* opcode constants) is re-exported here from
the internal `diagmunge.transport` module.

Dependency direction is inward-only: `diagmunge` depends (lazily) on `diaggrok`,
never the reverse. `import diagmunge` needs zero third-party packages — the
serial transport (`pyserial`) and the decode helper (`diaggrok`) are imported
lazily at call sites and declared as optional extras (`diagmunge[serial]`,
`diagmunge[decode]`).
"""

from .transport import (
    DIAG_BAD_CMD_F,
    DIAG_LOG_CONFIG_F,
    DIAG_LOG_F,
    DIAG_NV_WRITE_F,
    DIAG_SPC_F,
    DIAG_SUBSYS_CMD_F,
    DIAG_VERNO_F,
    DiagClient,
    Dge1SeqTracker,
    bad_cmd_hint,
    parse_dge1_header,
    resync_frame_boundary,
)

__all__ = [
    "DiagClient",
    "Dge1SeqTracker",
    "parse_dge1_header",
    "bad_cmd_hint",
    "resync_frame_boundary",
    "DIAG_VERNO_F",
    "DIAG_BAD_CMD_F",
    "DIAG_LOG_F",
    "DIAG_LOG_CONFIG_F",
    "DIAG_NV_WRITE_F",
    "DIAG_SUBSYS_CMD_F",
    "DIAG_SPC_F",
]
