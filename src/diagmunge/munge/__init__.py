# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""diagmunge.munge — offline DIAG format-munge CLI tools.

Each tool is a self-contained module with a ``main() -> int`` entry point,
invoked via ``python -m diagmunge.munge.<tool>``. Submodules are deliberately
NOT imported here: ``hdlc_to_dlf`` imports ``diaggrok`` at module top level, and
keeping the subpackage import-lazy preserves the core-transport invariant that a
bare ``import diagmunge`` needs zero diaggrok.

Tools: ``hdlc_to_dlf``, ``capture_dlf_from_diag``; ``replay``, the
GNSS-free replay core behind diaggpsd's dlf_to_jsonl CLI. The at-rest
diaggulp normalizer is not here — it depends on capture-IO infrastructure
outside this neutral package.
"""
