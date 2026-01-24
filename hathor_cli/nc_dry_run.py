# Copyright 2025 Hathor Labs
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

"""CLI command for dry-running NC block execution."""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser
from typing import TYPE_CHECKING, Optional

from hathor_cli.run_node import RunNode

if TYPE_CHECKING:
    from hathor.nanocontracts.execution.dry_run_block_executor import DryRunResult


class NcDryRun(RunNode):
    """Dry-run NC block execution from the CLI."""

    def start_manager(self) -> None:
        """Don't start the manager."""
        pass

    def register_signal_handlers(self) -> None:
        """Don't register signal handlers."""
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            '--block-hash',
            type=str,
            help='Hash of the block to dry-run',
        )
        group.add_argument(
            '--tx-hash',
            type=str,
            help='Hash of the NC transaction (will dry-run its first_block)',
        )
        parser.add_argument(
            '--output',
            type=str,
            default=None,
            help='Output file path (defaults to stdout)',
        )
        parser.add_argument(
            '--format',
            choices=['json', 'text'],
            default='json',
            help='Output format (json or text)',
        )
        parser.add_argument(
            '--include-changes',
            action='store_true',
            help='Include storage state changes in call records',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show verbose output (for text format)',
        )
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=False)

    def run(self) -> None:
        from hathor.nanocontracts.execution.dry_run_block_executor import NCDryRunBlockExecutor
        from hathor.transaction import Block

        block_hash_arg: Optional[str] = self._args.block_hash
        tx_hash_arg: Optional[str] = self._args.tx_hash
        output_format: str = self._args.format
        include_changes: bool = self._args.include_changes
        verbose: bool = self._args.verbose
        output_path: Optional[str] = self._args.output

        block: Block
        target_tx_hash: Optional[bytes] = None

        if tx_hash_arg:
            # Get transaction and find its first_block
            try:
                tx_hash_bytes = bytes.fromhex(tx_hash_arg)
            except ValueError:
                self.log.error(f'Invalid tx_hash: {tx_hash_arg}')
                sys.exit(1)

            try:
                tx = self.tx_storage.get_transaction(tx_hash_bytes)
            except Exception:
                self.log.error(f'Transaction not found: {tx_hash_arg}')
                sys.exit(1)

            if not tx.is_nano_contract():
                self.log.error('Transaction is not a nano contract')
                sys.exit(1)

            tx_meta = tx.get_metadata()
            if tx_meta.first_block is None:
                self.log.error('Transaction has no first_block')
                sys.exit(1)

            try:
                block = self.tx_storage.get_block(tx_meta.first_block)
            except Exception:
                self.log.error(f'Block not found: {tx_meta.first_block.hex()}')
                sys.exit(1)

            target_tx_hash = tx_hash_bytes
        else:
            # Get block directly
            assert block_hash_arg is not None
            try:
                block_hash_bytes = bytes.fromhex(block_hash_arg)
            except ValueError:
                self.log.error(f'Invalid block_hash: {block_hash_arg}')
                sys.exit(1)

            try:
                block = self.tx_storage.get_block(block_hash_bytes)
            except Exception:
                self.log.error(f'Block not found: {block_hash_arg}')
                sys.exit(1)

        # Validate block state
        block_meta = block.get_metadata()
        if block_meta.voided_by:
            self.log.error('Block is not on best chain (voided)')
            sys.exit(1)

        if block.is_genesis:
            self.log.error('Cannot dry-run genesis block')
            sys.exit(1)

        # Execute dry run using shared executor
        dry_run_executor: NCDryRunBlockExecutor = NCDryRunBlockExecutor(
            self.manager.consensus_algorithm._block_executor
        )
        result = dry_run_executor.execute(
            block,
            include_changes=include_changes,
            target_tx_hash=target_tx_hash,
        )

        # Log warning if roots don't match
        if not result.root_id_matches:
            self.log.warn(
                'Non-deterministic execution detected',
                computed_root=result.final_block_root_id.hex(),
                expected_root=result.expected_block_root_id.hex(),
            )

        # Output results
        if output_format == 'json':
            output_str = json.dumps(result.dict(), indent=2)
        else:
            output_str = format_dry_run_text(result, verbose=verbose)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(output_str)
            self.log.info(f'Output written to {output_path}')
        else:
            print(output_str)


def format_dry_run_text(result: 'DryRunResult', verbose: bool = False) -> str:
    """
    Format a DryRunResult as human-readable text.

    Args:
        result: The dry run result to format.
        verbose: Whether to include verbose output (tracebacks, changes).

    Returns:
        Formatted text string.
    """
    from hathor.nanocontracts.execution.dry_run_block_executor import ExecutionStatus

    lines: list[str] = []

    # Header
    lines.append(f"Block: {result.block_hash.hex()} (height: {result.block_height})")
    lines.append(f"Initial Root:  {result.initial_block_root_id.hex()}")
    lines.append(f"Final Root:    {result.final_block_root_id.hex()}")
    lines.append(f"Expected Root: {result.expected_block_root_id.hex()}")

    if result.root_id_matches:
        lines.append('Root Match:    OK')
    else:
        lines.append('Root Match:    MISMATCH (non-deterministic execution detected!)')
        if result.warning:
            lines.append(f"WARNING: {result.warning}")
    lines.append('')

    # Execution order
    lines.append(f'Execution Order: {len(result.nc_sorted_calls)} transactions')
    for i, tx_hash in enumerate(result.nc_sorted_calls, 1):
        lines.append(f'  {i}. {tx_hash.hex()}')
    lines.append('')

    # Transaction details
    for i, tx in enumerate(result.transactions, 1):
        lines.append(f"--- Transaction {i}/{len(result.transactions)}: {tx.tx_hash.hex()} ---")
        lines.append(f"RNG Seed: {tx.rng_seed.hex()}")
        lines.append(f"Status: {tx.execution_status.upper()}")

        if tx.execution_status == ExecutionStatus.FAILURE:
            lines.append(f"Exception: {tx.exception_type or 'Unknown'} - {tx.exception_message or ''}")
            if verbose and tx.traceback:
                lines.append('Traceback:')
                for tb_line in tx.traceback.split('\n'):
                    lines.append(f'  {tb_line}')

        for j, call in enumerate(tx.call_records, 1):
            lines.append('')
            lines.append(f"  Call #{j}: {call.method_name} ({call.type}, depth={call.depth})")
            lines.append(f"    Contract: {call.contract_id.hex()}")
            lines.append(f"    Blueprint: {call.blueprint_id.hex()}")

            if call.index_updates:
                lines.append('    Index Updates:')
                for update in call.index_updates:
                    update_type = update.get('type', 'UNKNOWN')
                    if update_type == 'update_token_balance':
                        token = update.get('token_uid', 'N/A')
                        amount = update.get('amount', 'N/A')
                        lines.append(f"      - {update_type}: token={token}, amount={amount}")
                    else:
                        lines.append(f"      - {update}")

            if call.changes and verbose:
                lines.append('    Changes:')
                for change in call.changes:
                    lines.append(f"      - {change['key']}: {change['value']}")

        if tx.events:
            lines.append('  Events:')
            for event in tx.events:
                lines.append(f"    - nc_id={event['nc_id']}, data={event['data']}")

        lines.append('')

    return '\n'.join(lines)


def main():
    NcDryRun().run()
