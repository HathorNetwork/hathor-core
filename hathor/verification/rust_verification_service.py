#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""A VerificationService that runs the migrated stateless checks in Rust.

All migrated checks for a vertex are computed with a **single** FFI call
(``htr_lib.verify_vertex_stateless``): the vertex fields are marshalled once, the GIL is released, and the
checks run in parallel on the shared rayon pool. The results are then consumed at each check's position in
the canonical Python check sequence — interleaved with the not-yet-migrated checks, which simply call the
Python verifiers — so the *surfaced* error (the first failure in Python order, with its exact exception
type) is identical to the pure-Python service.

Python remains the authoritative consensus reference: the mode comes from the script-verification pool, and
in SHADOW_RUST mode the Python service runs first and stays authoritative while the Rust path runs alongside
with any disagreement logged and counted.

Notes on what deliberately stays on the Python verifier methods:
- ``verify_pow``: the target is one float expression and the comparison is trivial, so there is no CPU to
  win; routing through ``verifiers.vertex.verify_pow`` also preserves subclass overrides such as the
  simulator's no-op ``SimulatorVertexVerifier.verify_pow``.
- Everything not yet migrated (number of inputs, tokens, block data, headers, nano/OCB checks, ...).
"""

from __future__ import annotations

from dataclasses import dataclass

import htr_lib
from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts import NCStorageFactory, OnChainBlueprint
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.exceptions import InexistentInput, TooManySigOps
from hathor.transaction.poa import PoaBlock
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.verification.script_verification_pool import ScriptVerificationPool, raise_rust_error
from hathor.verification.verification_params import VerificationParams
from hathor.verification.verification_service import VerificationService
from hathor.verification.vertex_verifiers import VertexVerifiers

# Check identifiers, matching htr-rs/crates/htr-lib/src/verify/mod.rs.
CHECK_POW = 0
CHECK_OUTPUTS = 1
CHECK_OUTPUT_TOKEN_INDEXES = 2
CHECK_SIGOPS_OUTPUT = 3


@dataclass(slots=True, frozen=True, kw_only=True)
class StatelessVertexCheckData:
    """The per-vertex data for one combined Rust call; Rust extracts these fields by name
    (`VertexCheckData` in htr-rs/crates/htr-lib/src/verify/mod.rs)."""
    outputs: list[tuple[int, bytes, int]]  # (value, script, token_data)
    tokens_count: int
    vertex_hash: bytes
    pow_target_be: bytes  # minimal big-endian; empty while CHECK_POW stays on the Python path
    max_num_outputs: int
    max_output_script_size: int
    max_tx_sigops_output: int
    max_multisig_pubkeys: int
    enable_checkdatasig_count: bool


class _RustCheckResults:
    """Results of one combined Rust call, consumed at each check's position in the canonical Python
    sequence so that the surfaced error is order-identical to the Python path."""

    __slots__ = ('_results',)

    def __init__(self, results: dict[int, tuple[str, str] | None]) -> None:
        self._results = results

    def consume(self, check: int) -> None:
        error = self._results[check]
        if error is not None:
            raise_rust_error(error[0], error[1])


class RustVerificationService(VerificationService):
    __slots__ = ('_script_verification_pool',)

    def __init__(
        self,
        *,
        settings: HathorSettings,
        verifiers: VertexVerifiers,
        tx_storage: TransactionStorage | None = None,
        nc_storage_factory: NCStorageFactory | None = None,
        script_verification_pool: ScriptVerificationPool,
    ) -> None:
        super().__init__(
            settings=settings,
            verifiers=verifiers,
            tx_storage=tx_storage,
            nc_storage_factory=nc_storage_factory,
        )
        self._script_verification_pool = script_verification_pool

    @override
    def verify_without_storage(self, vertex: BaseTransaction, params: VerificationParams) -> None:
        pool = self._script_verification_pool
        if pool.rust_verification:
            self._verify_without_storage_rust(vertex, params)
        elif pool.shadow_rust_verification:
            pool.run_shadow_check(
                'verify_without_storage',
                lambda: VerificationService.verify_without_storage(self, vertex, params),
                lambda: self._verify_without_storage_rust(vertex, params),
            )
        else:
            super().verify_without_storage(vertex, params)

    def _run_rust_checks(
        self,
        vertex: BaseTransaction,
        params: VerificationParams,
        checks: list[int],
    ) -> _RustCheckResults:
        """Marshal the vertex once and run all requested checks in a single GIL-released Rust call."""
        tokens = getattr(vertex, 'tokens', None) or []
        data = StatelessVertexCheckData(
            outputs=[(output.value, output.script, output.token_data) for output in vertex.outputs],
            tokens_count=len(tokens),
            vertex_hash=vertex.hash,
            pow_target_be=b'',  # CHECK_POW stays on the Python verifier path (see module docstring)
            max_num_outputs=self._settings.MAX_NUM_OUTPUTS,
            max_output_script_size=self._settings.MAX_OUTPUT_SCRIPT_SIZE,
            max_tx_sigops_output=self._settings.MAX_TX_SIGOPS_OUTPUT,
            max_multisig_pubkeys=self._settings.MAX_MULTISIG_PUBKEYS,
            enable_checkdatasig_count=params.features.count_checkdatasig_op,
        )
        raw = htr_lib.verify_vertex_stateless(checks, data, self._script_verification_pool.num_workers)
        return _RustCheckResults(dict(zip(checks, raw)))

    def _verify_without_storage_rust(self, vertex: BaseTransaction, params: VerificationParams) -> None:
        """Mirror of `VerificationService.verify_without_storage`, consuming the Rust results in the
        canonical check order."""
        from typing_extensions import assert_never

        if vertex.hash in self._settings.SKIP_VERIFICATION:
            return

        if vertex.has_fees():
            self._verify_without_storage_fee_header(vertex)

        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self.verifiers.vertex.verify_pow(vertex)
                self._verify_without_storage_base_block_rust(vertex, params)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self.verifiers.vertex.verify_pow(vertex)
                self._verify_without_storage_base_block_rust(vertex, params)
            case TxVersion.POA_BLOCK:
                assert type(vertex) is PoaBlock
                self._verify_without_storage_base_block_rust(vertex, params)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._verify_without_storage_tx_rust(vertex, params)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._verify_without_storage_tx_rust(vertex, params)
            case TxVersion.ON_CHAIN_BLUEPRINT:
                assert type(vertex) is OnChainBlueprint
                self._verify_without_storage_tx_rust(vertex, params)
                self.verifiers.on_chain_blueprint.verify_pubkey_is_allowed(vertex)
                self.verifiers.on_chain_blueprint.verify_nc_signature(vertex)
                self.verifiers.on_chain_blueprint.verify_code(vertex)
            case _:  # pragma: no cover
                assert_never(vertex.version)

        if vertex.is_nano_contract():
            assert self._settings.ENABLE_NANO_CONTRACTS
            self._verify_without_storage_nano_header(vertex, params)

    def _verify_without_storage_base_block_rust(self, block: Block, params: VerificationParams) -> None:
        results = self._run_rust_checks(block, params, [CHECK_OUTPUTS, CHECK_SIGOPS_OUTPUT])
        self.verifiers.block.verify_no_inputs(block)
        results.consume(CHECK_OUTPUTS)
        self.verifiers.block.verify_output_token_indexes(block)
        self.verifiers.block.verify_data(block)
        results.consume(CHECK_SIGOPS_OUTPUT)

    @override
    def _verify_sigops_input(self, tx: Transaction, params: VerificationParams) -> None:
        pool = self._script_verification_pool
        if pool.rust_verification:
            self._verify_sigops_input_rust(tx, params)
        elif pool.shadow_rust_verification:
            pool.run_shadow_check(
                'verify_sigops_input',
                lambda: VerificationService._verify_sigops_input(self, tx, params),
                lambda: self._verify_sigops_input_rust(tx, params),
            )
        else:
            super()._verify_sigops_input(tx, params)

    def _verify_sigops_input_rust(self, tx: Transaction, params: VerificationParams) -> None:
        """`TransactionVerifier.verify_sigops_input` with the counting in Rust: Python fetches the spent
        outputs (storage), one Rust call counts every (input_data, spent_script) pair, and the results are
        merged in per-input order so fetch errors and counting errors interleave exactly like the Python
        loop (a fetch failure at input i stops the loop: later inputs are never counted, and counting
        errors of earlier inputs surface first)."""
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        pairs: list[tuple[bytes, bytes]] = []
        fetch_error: InexistentInput | None = None
        for tx_input in tx.inputs:
            try:
                spent_tx = tx.get_spent_tx(tx_input)
            except TransactionDoesNotExist:
                fetch_error = InexistentInput('Input tx does not exist: {}'.format(tx_input.tx_id.hex()))
                break
            if tx_input.index >= len(spent_tx.outputs):
                fetch_error = InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                    tx_input.tx_id.hex(), tx_input.index))
                break
            pairs.append((tx_input.data, spent_tx.resolve_spent_output(tx_input.index).script))

        n_txops = 0
        if pairs:
            results = htr_lib.count_sigops_inputs(
                pairs,
                self._settings.MAX_MULTISIG_PUBKEYS,
                params.features.count_checkdatasig_op,
                self._script_verification_pool.num_workers,
            )
            for error, count in results:
                if error is not None:
                    raise_rust_error(error[0], error[1])
                n_txops += count

        if fetch_error is not None:
            raise fetch_error
        if n_txops > self._settings.MAX_TX_SIGOPS_INPUT:
            raise TooManySigOps(
                'TX[{}]: Max number of sigops for inputs exceeded ({})'.format(tx.hash_hex, n_txops))

    def _verify_without_storage_tx_rust(self, tx: Transaction, params: VerificationParams) -> None:
        results = self._run_rust_checks(
            tx, params, [CHECK_OUTPUTS, CHECK_OUTPUT_TOKEN_INDEXES, CHECK_SIGOPS_OUTPUT],
        )
        if self._settings.CONSENSUS_ALGORITHM.is_pow():
            self.verifiers.vertex.verify_pow(tx)
        self.verifiers.tx.verify_number_of_inputs(tx)
        results.consume(CHECK_OUTPUTS)
        results.consume(CHECK_OUTPUT_TOKEN_INDEXES)
        results.consume(CHECK_SIGOPS_OUTPUT)
        self.verifiers.tx.verify_tokens(tx, params)
