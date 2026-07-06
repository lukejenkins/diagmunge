#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""Capture raw DIAG log frames to a DLF file.

Subscribes to a set of log codes on the modem's DIAG port and writes
every received log frame into DLF format (u16 rec_len + u16 log_code +
u64 ts64 + payload) — the same format `tools/decode_dlf.py` and the
diaggrok integration tests consume.

Reuses `diagmunge` (the shared DIAG transport) for HDLC framing and log-mask setup. The
inner DIAG frame layout (`inner_len u16, log_type u16, log_time u64,
payload`) happens to be byte-identical to the DLF record layout, so the
script writes the inner segment verbatim per frame.

Example:

    .venv/bin/python tools/capture_dlf_from_diag.py \\
        --diag-port /dev/serial/by-path/pci-0000:00:14.0-usb-0:3.3:1.0-port0 \\
        --codes 0x1837,0x1384,0x1476,0x1477,0x1478,0x1480 \\
        --duration 30 \\
        --output capture_0x1837.dlf
"""
from __future__ import annotations

import argparse
import select
import time
from pathlib import Path
from struct import unpack_from

from diagmunge import DiagClient, DIAG_LOG_F

# Vendor SPC bodies to try, in order, when --spc auto is requested. The EG25/EC25
# MDM9607 family gates LOG_CONFIG behind an SPC unlock (#N).
_SPC_AUTO = ["000000", "0000"]


def parse_codes(csv: str) -> list[int]:
    out: list[int] = []
    for tok in csv.split(','):
        tok = tok.strip()
        if not tok:
            continue
        out.append(int(tok, 16) if tok.lower().startswith('0x') else int(tok))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--diag-port', required=True, help='DIAG serial device path')
    ap.add_argument('--codes', required=True, help='Comma-separated log codes (hex or decimal)')
    ap.add_argument('--duration', type=float, default=30.0, help='Capture duration in seconds')
    ap.add_argument('--output', required=True, help='Output DLF path')
    ap.add_argument('--spc', default=None,
                    help='Send an SPC unlock (opcode 0x46) before subscribing. '
                         'Use a literal 6-char code (e.g. 000000), or "auto" to '
                         'try known vendor SPCs. Needed on EG25/EC25-class modems '
                         'that gate LOG_CONFIG behind SPC (#N).')
    args = ap.parse_args()

    codes = parse_codes(args.codes)
    want = set(codes)
    print(f'[cap] opening DIAG {args.diag_port}', flush=True)
    diag = DiagClient.from_serial(port=args.diag_port)

    if args.spc:
        spcs = _SPC_AUTO if args.spc.lower() == 'auto' else [args.spc]
        if any(diag.unlock_spc(s) for s in spcs):
            print('[cap] SPC unlock accepted', flush=True)
        else:
            print('[cap] WARNING: no SPC accepted; continuing (modem may not gate LOG_CONFIG)', flush=True)

    print(f'[cap] clearing all log masks', flush=True)
    diag.subscribe_logs([])

    print(f'[cap] subscribing to {len(codes)} code(s): {[hex(c) for c in codes]}', flush=True)
    diag.subscribe_logs(codes)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    deadline = time.monotonic() + args.duration
    written = 0
    per_code: dict[int, int] = {}
    other = 0

    print(f'[cap] capturing for {args.duration:.1f}s -> {out_path}', flush=True)
    with out_path.open('wb') as fh:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                # Peek at fd with select so we can honor the deadline.
                ready, _, _ = select.select([diag._transport.fileno()], [], [], min(remaining, 0.5))
                if not ready:
                    continue
                opcode, payload = diag.recv()
            except EOFError:
                print('[cap] DIAG transport closed early', flush=True)
                break
            if opcode != DIAG_LOG_F:
                continue
            if len(payload) < 15:
                continue
            # payload = pending_msgs(1) + outer_len(2) + inner(inner_len+log_type+log_time+body)
            inner = payload[3:]
            if len(inner) < 12:
                continue
            inner_len, log_type, _ts_lo, _ts_hi = unpack_from('<HHII', inner)
            if inner_len != len(inner):
                continue
            if log_type in want:
                fh.write(inner)
                written += 1
                per_code[log_type] = per_code.get(log_type, 0) + 1
            else:
                other += 1

    print(f'[cap] wrote {written} records to {out_path} ({out_path.stat().st_size} bytes)')
    for code in sorted(per_code):
        print(f'       0x{code:04x}: {per_code[code]} records')
    print(f'[cap] dropped {other} unsolicited frames')

    print('[cap] clearing masks', flush=True)
    diag.subscribe_logs([])
    return 0 if written > 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
