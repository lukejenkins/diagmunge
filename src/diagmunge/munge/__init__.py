# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""diagmunge.munge — offline DIAG format-munge CLI tools.

Each tool is a self-contained module with a ``main() -> int`` entry point,
invoked via ``python -m diagmunge.munge.<tool>``. Submodules are deliberately
NOT imported here: ``hdlc_to_dlf`` imports ``diaggrok`` at module top level, and
keeping the subpackage import-lazy preserves the core-transport invariant that a
bare ``import diagmunge`` needs zero diaggrok.

Landed: ``hdlc_to_dlf``, ``capture_dlf_from_diag`` (#N); ``replay`` (#N,
the GNSS-free replay core behind diaggpsd's dlf_to_jsonl CLI).
``normalize_diaggulp_at_rest`` stays private in ``tools/`` — it depends on private
capture-IO infrastructure outside this neutral package (#N).
"""
