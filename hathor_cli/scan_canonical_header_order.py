# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pre-check for the canonical-header-order rule (PR 3 of the shielded-tx split).

Scans every vertex in a node's storage and reports any whose ``vertex.headers``
list is NOT in strictly ascending header-ID order. The check mirrors what
``VertexVerifier.verify_headers`` will enforce once PR 3 lands:

    sorted_strict_asc([int.from_bytes(h.get_header_id(), 'big') for h in headers])

Header IDs in scope (post-shielded testnet):

    0x10  NANO_HEADER
    0x11  FEE_HEADER
    0x12  SHIELDED_OUTPUTS_HEADER
    0x13  UNSHIELD_BALANCE_HEADER
    0x14  MINT_HEADER
    0x15  MELT_HEADER

If the scan finds zero violators, PR 3 can ship the rule unconditionally.
Otherwise it must be gated behind a Feature Activation at a future activation
height — never retroactively invalidate finalized history.

Why scan voided txs too:
    A tx that lost a conflict today can re-enter the best chain via reorg
    later. If the new rule rejects it on re-validation, the reorg breaks.
    Conservative: every tx that was ever validly written must pass.

Usage
-----
The scan must run against a node DB whose settings register ALL header types
— otherwise the parser refuses to deserialize shielded txs at storage-load
time. On the post-shielded testnet that's already the case.

Run as a normal hathor-cli subcommand (no node startup; same bootstrap path
as ``db_export``):

    poetry run hathor-cli scan_canonical_header_order \\
        --testnet \\
        --data /path/to/testnet-data \\
        --out /tmp/canonical_header_violators.jsonl

Or, while iterating a partial dataset for a quick check:

    poetry run hathor-cli scan_canonical_header_order \\
        --testnet \\
        --data /path/to/testnet-data \\
        --scan-limit 500000 \\
        --scan-progress-every 50000

Exit codes:
    0  no violators found, rule is safe to ship unconditionally
    1  one or more violators found, rule must be gated behind FA
"""

from __future__ import annotations

import json
import sys
import time
from argparse import ArgumentParser, FileType
from typing import TYPE_CHECKING

from hathor_cli.run_node import RunNode

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction
    from hathor.transaction.headers import VertexBaseHeader


def _header_id_int(header: 'VertexBaseHeader') -> int:
    """Mirror VertexVerifier._get_header_order verbatim."""
    return int.from_bytes(header.get_header_id(), 'big')


def _is_canonical(ids: list[int]) -> bool:
    """Strictly ascending — duplicates also disallowed (one-of-each per type)."""
    return all(ids[i] > ids[i - 1] for i in range(1, len(ids)))


def _format_header_seq(headers: list['VertexBaseHeader']) -> list[str]:
    return [f'{type(h).__name__}(0x{_header_id_int(h):02x})' for h in headers]


class ScanCanonicalHeaderOrder(RunNode):
    def start_manager(self) -> None:
        # Suppress node startup; we only need storage.
        pass

    def register_signal_handlers(self) -> None:
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument(
            '--out',
            type=FileType('w'),
            default=None,
            help='write violators as JSON Lines to this path (default: stdout only)',
        )
        parser.add_argument(
            '--scan-progress-every',
            type=int,
            default=250_000,
            help='print a progress line every N vertices scanned (default 250000)',
        )
        parser.add_argument(
            '--scan-limit',
            type=int,
            default=None,
            help='stop after scanning this many vertices (debug; default: scan everything)',
        )
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        # Don't register HTTP/sysctl resources — pure read-only scan.
        super().prepare(register_resources=False)

    def run(self) -> None:
        out_fh = self._args.out
        progress_every = self._args.scan_progress_every
        limit = self._args.scan_limit

        scanned = 0
        multi_header = 0
        violators = 0
        start = time.monotonic()
        last_progress = start

        try:
            total = self.tx_storage.get_vertices_count()
        except Exception:
            total = None

        self.log.info(
            'scan starting',
            data=getattr(self._args, 'data', None),
            total_estimated=total,
        )

        try:
            for vertex in self.tx_storage.get_all_transactions():  # type: BaseTransaction
                scanned += 1

                # Only Transactions carry these headers in practice. Cheap
                # check; keep it general so a future Block subtype with
                # headers also gets scanned.
                headers = getattr(vertex, 'headers', None)
                if headers and len(headers) > 1:
                    multi_header += 1
                    ids = [_header_id_int(h) for h in headers]
                    if not _is_canonical(ids):
                        violators += 1
                        record = {
                            'tx_id': vertex.hash_hex,
                            'timestamp': vertex.timestamp,
                            'vertex_class': type(vertex).__name__,
                            'vertex_version': int(vertex.version),
                            'observed_header_sequence': _format_header_seq(headers),
                            'observed_ids_hex': [f'0x{i:02x}' for i in ids],
                            'canonical_ids_hex': [f'0x{i:02x}' for i in sorted(ids)],
                        }
                        line = json.dumps(record)
                        print(line)
                        if out_fh is not None:
                            out_fh.write(line + '\n')
                            out_fh.flush()

                now = time.monotonic()
                if (now - last_progress) >= 5.0 or (scanned % progress_every == 0):
                    elapsed = now - start
                    rate = scanned / elapsed if elapsed > 0 else 0
                    self.log.info(
                        'scan progress',
                        scanned=scanned,
                        multi_header=multi_header,
                        violators=violators,
                        elapsed_s=round(elapsed, 1),
                        rate_per_s=round(rate),
                    )
                    last_progress = now

                if limit is not None and scanned >= limit:
                    self.log.info('scan stopped at --scan-limit', limit=limit)
                    break
        finally:
            if out_fh is not None:
                out_fh.close()

        elapsed = time.monotonic() - start
        self.log.info(
            'scan complete',
            scanned=scanned,
            multi_header=multi_header,
            violators=violators,
            elapsed_s=round(elapsed, 1),
        )

        if violators == 0:
            print(
                'OK: canonical-header-order rule is safe to ship unconditionally.',
                file=sys.stderr,
            )
            sys.exit(0)
        else:
            print(
                'FAIL: canonical-header-order rule must be gated behind a Feature '
                f'Activation (found {violators:,} non-canonical txs).',
                file=sys.stderr,
            )
            sys.exit(1)


def main() -> None:
    ScanCanonicalHeaderOrder().run()


if __name__ == '__main__':
    main()
