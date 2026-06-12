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
from typing import TYPE_CHECKING, Sequence

import htr_lib
from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts import NCStorageFactory, OnChainBlueprint
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.exceptions import InexistentInput, TooManySigOps
from hathor.transaction.poa import PoaBlock
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.verification.script_verification_pool import (
    ScriptVerificationJob,
    ScriptVerificationPool,
    raise_rust_error,
)
from hathor.verification.verification_params import VerificationParams
from hathor.verification.verification_service import VerificationService
from hathor.verification.vertex_verifiers import VertexVerifiers

if TYPE_CHECKING:
    from twisted.internet.defer import Deferred

# Check identifiers, matching htr-rs/crates/htr-lib/src/verify/mod.rs.
CHECK_POW = 0
CHECK_OUTPUTS = 1
CHECK_OUTPUT_TOKEN_INDEXES = 2
CHECK_SIGOPS_OUTPUT = 3
CHECK_NO_INPUTS = 4
CHECK_BLOCK_DATA = 5
CHECK_BLOCK_TOKEN_INDEXES = 6
CHECK_NUMBER_OF_INPUTS = 7

def defer_stateless_precompute(
    reactor: object,
    service: 'RustVerificationService',
    vertices: Sequence[BaseTransaction],
    params: VerificationParams,
    *,
    include_scripts: bool = False,
) -> 'Deferred[None]':
    """Run `service.precompute_stateless_batch` on the reactor's thread pool when the reactor
    supports threads (production: the Rust call releases the GIL, so verification of the batch
    overlaps reactor work), or synchronously otherwise (tests with simulated clocks; the call
    still amortizes the FFI and parallelizes across vertices via rayon)."""
    import functools

    from twisted.internet import interfaces
    from twisted.internet.defer import succeed
    from twisted.internet.threads import deferToThreadPool

    call = functools.partial(
        service.precompute_stateless_batch, vertices, params, include_scripts=include_scripts,
    )
    if interfaces.IReactorThreads.providedBy(reactor) and getattr(reactor, 'running', False):
        return deferToThreadPool(reactor, reactor.getThreadPool(), call)
    call()
    result: Deferred[None] = succeed(None)
    return result


# htr_lib.verify_scripts_from_bytes per-tx statuses
_PIPELINE_EVALUATED = 0
_PIPELINE_UNRESOLVED = 1
_PIPELINE_PARSE_FAILED = 2

# the canonical check sets per vertex kind, in request order
_BLOCK_CHECKS = [CHECK_NO_INPUTS, CHECK_OUTPUTS, CHECK_BLOCK_TOKEN_INDEXES, CHECK_BLOCK_DATA, CHECK_SIGOPS_OUTPUT]
_TX_CHECKS = [CHECK_NUMBER_OF_INPUTS, CHECK_OUTPUTS, CHECK_OUTPUT_TOKEN_INDEXES, CHECK_SIGOPS_OUTPUT]


@dataclass(slots=True, frozen=True, kw_only=True)
class StatelessVertexCheckData:
    """The per-vertex data for one combined Rust call; Rust extracts these fields by name
    (`VertexCheckData` in htr-rs/crates/htr-lib/src/verify/mod.rs)."""
    outputs: list[tuple[int, bytes, int]]  # (value, script, token_data)
    tokens_count: int
    vertex_hash: bytes
    pow_target_be: bytes  # minimal big-endian; empty while CHECK_POW stays on the Python path
    inputs_count: int
    min_inputs: int
    is_genesis: bool
    block_data_len: int
    max_num_inputs: int
    block_data_max_size: int
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
    __slots__ = ('_script_verification_pool', '_precomputed', '_wire_bytes')

    # FIFO cap for the wire-bytes cache: entries are normally consumed by the next batch
    # precompute and discarded with it; the cap only bounds vertices that never reach a batch
    # (e.g. relayed vertices rejected early).
    _WIRE_BYTES_CAP = 16384

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
        # results of a batched stateless pre-verification keyed by vertex hash, holding the params
        # they were computed under; consumed (popped) by _run_rust_checks, leftovers discarded by
        # the call sites in a finally block (discard_precomputed)
        self._precomputed: dict[bytes, tuple[VerificationParams, _RustCheckResults]] = {}
        # original wire bytes per vertex hash, captured by verify_bytes so the batched script
        # pipeline can hand them straight to Rust without re-serializing
        self._wire_bytes: dict[bytes, bytes] = {}

    @override
    def verify_bytes(self, data: bytes, *, storage: TransactionStorage | None = None) -> BaseTransaction:
        vertex = super().verify_bytes(data, storage=storage)
        if self._script_verification_pool.rust_verification:
            self._wire_bytes[vertex.hash] = data
            while len(self._wire_bytes) > self._WIRE_BYTES_CAP:
                self._wire_bytes.pop(next(iter(self._wire_bytes)))
        return vertex

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
        """Return this vertex's stateless check results: either precomputed by a batch call
        (`precompute_stateless_batch`) or from a fresh single-vertex GIL-released Rust call."""
        precomputed = self._precomputed.pop(vertex.hash, None)
        if precomputed is not None:
            stored_params, results = precomputed
            # params identity guard: a vertex could concurrently arrive through another path (e.g.
            # real-time relay during a sync batch) whose params differ — only consume results
            # precomputed for this exact verification stage
            if stored_params is params:
                return results
        data = self._build_check_data(vertex, params)
        raw = htr_lib.verify_vertex_stateless(checks, data, self._script_verification_pool.num_workers)
        return _RustCheckResults(dict(zip(checks, raw)))

    def _build_check_data(self, vertex: BaseTransaction, params: VerificationParams) -> StatelessVertexCheckData:
        """Marshal one vertex's fields for the Rust stateless checks."""
        tokens = getattr(vertex, 'tokens', None) or []
        min_inputs = vertex.get_minimum_number_of_inputs() if isinstance(vertex, Transaction) else 0
        return StatelessVertexCheckData(
            outputs=[(output.value, output.script, output.token_data) for output in vertex.outputs],
            tokens_count=len(tokens),
            vertex_hash=vertex.hash,
            pow_target_be=b'',  # CHECK_POW stays on the Python verifier path (see module docstring)
            inputs_count=len(getattr(vertex, 'inputs', None) or []),
            min_inputs=min_inputs,
            is_genesis=vertex.is_genesis,
            block_data_len=len(getattr(vertex, 'data', None) or b''),
            max_num_inputs=self._settings.MAX_NUM_INPUTS,
            block_data_max_size=self._settings.BLOCK_DATA_MAX_SIZE,
            max_num_outputs=self._settings.MAX_NUM_OUTPUTS,
            max_output_script_size=self._settings.MAX_OUTPUT_SCRIPT_SIZE,
            max_tx_sigops_output=self._settings.MAX_TX_SIGOPS_OUTPUT,
            max_multisig_pubkeys=self._settings.MAX_MULTISIG_PUBKEYS,
            enable_checkdatasig_count=params.features.count_checkdatasig_op,
        )

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

    @staticmethod
    def _checks_for(vertex: BaseTransaction) -> list[int] | None:
        """The rust check ids for this vertex kind (in request order), or None for unknown versions."""
        match vertex.version:
            case TxVersion.REGULAR_BLOCK | TxVersion.MERGE_MINED_BLOCK | TxVersion.POA_BLOCK:
                return _BLOCK_CHECKS
            case TxVersion.REGULAR_TRANSACTION | TxVersion.TOKEN_CREATION_TRANSACTION | TxVersion.ON_CHAIN_BLUEPRINT:
                return _TX_CHECKS
            case _:
                return None

    def precompute_stateless_batch(
        self,
        vertices: Sequence[BaseTransaction],
        params: VerificationParams,
        *,
        include_scripts: bool = False,
    ) -> None:
        """Run the stateless checks — and, when ``include_scripts`` is set, the input-script
        evaluations — for a whole batch of vertices, each as one GIL-released Rust call
        (parallel across vertices/inputs), and stash the per-vertex results for later
        consumption by the serial verification of each vertex. Safe to call from a worker
        thread: the Rust calls release the GIL, and the results dicts are only read by the
        reactor after this returns.

        ``include_scripts`` must be set only by stages whose downstream verification actually
        runs ``verify_inputs`` (the full-validation stage at block connect): the tx-streaming
        stage only runs ``verify_basic``, and script results stashed there would be discarded
        unconsumed — evaluating every script twice. Script jobs are built for every input whose
        spent tx is resolvable — from the batch itself (spend chains during sync) or from
        storage; a tx with any unresolvable input is simply skipped (the fresh path at connect
        time keeps its exact error semantics).

        Pair with `discard_precomputed` in a finally block so entries for vertices that never
        reach their stateless checks (earlier failures) do not accumulate."""
        pool = self._script_verification_pool
        if not pool.rust_verification:
            return
        items = []
        keyed = []
        for vertex in vertices:
            checks = self._checks_for(vertex)
            if checks is None or vertex.is_genesis or vertex.hash in self._settings.SKIP_VERIFICATION:
                continue
            items.append((checks, self._build_check_data(vertex, params)))
            keyed.append((vertex.hash, checks))
        if items:
            raw_batch = htr_lib.verify_vertices_stateless_batch(items, pool.num_workers)
            for (vertex_hash, checks), raw in zip(keyed, raw_batch):
                self._precomputed[vertex_hash] = (params, _RustCheckResults(dict(zip(checks, raw))))
        if include_scripts:
            self._precompute_scripts_batch(vertices, params)

    def _precompute_scripts_batch(self, vertices: Sequence[BaseTransaction], params: VerificationParams) -> None:
        """Evaluate the input scripts of every eligible tx in the batch and stash the raw
        per-input results in the script pool (consumed by
        `TransactionVerifier._verify_inputs_parallel` via `run_jobs_with_cache`).

        The whole pipeline — parse, sighash, dependency resolution, evaluation — runs in Rust
        (`htr_lib.verify_scripts_from_bytes`): spent txs are resolved from the batch's own
        bytes, then natively from RocksDB through the shared handle. Dependencies Rust cannot
        see (unflushed entries in the Python storage cache) are supplied in a second call, and
        anything still unresolved or unparseable (header-carrying txs, …) falls back to the
        Python job-building path — so coverage and rejection semantics are unchanged."""
        pool = self._script_verification_pool
        opcodes_version = int(params.features.opcodes_version)
        eligible = [
            vertex for vertex in vertices
            if isinstance(vertex, Transaction) and not vertex.is_genesis and vertex.inputs
        ]
        if not eligible:
            return

        payloads = [self._wire_bytes.get(vertex.hash) or bytes(vertex) for vertex in eligible]
        outcomes = self._run_scripts_pipeline(payloads, [], opcodes_version)

        # Second pass: supply the dependencies Rust could not see, from the Python storage
        # layer (its cache holds recently-saved txs that are not flushed to RocksDB yet).
        missing: set[bytes] = set()
        for status, _, missing_hashes in outcomes:
            if status == _PIPELINE_UNRESOLVED:
                missing.update(missing_hashes)
        supplied = self._fetch_dep_bytes(missing)
        if supplied:
            retry_indices = [
                index for index, (status, _, _) in enumerate(outcomes) if status == _PIPELINE_UNRESOLVED
            ]
            retry_outcomes = self._run_scripts_pipeline(
                [payloads[index] for index in retry_indices], supplied, opcodes_version,
            )
            for index, outcome in zip(retry_indices, retry_outcomes):
                outcomes[index] = outcome

        fallback: list[BaseTransaction] = []
        for vertex, (status, results, _) in zip(eligible, outcomes):
            if status == _PIPELINE_EVALUATED:
                by_index = dict(enumerate(results))
                pool.stash_script_results(vertex.hash, opcodes_version, by_index)
            else:
                fallback.append(vertex)
        if fallback:
            self._precompute_scripts_python(fallback, vertices, params)

    def _run_scripts_pipeline(
        self,
        payloads: list[bytes],
        supplied: list[bytes],
        opcodes_version: int,
    ) -> list[tuple[int, list[tuple[str, str] | None], list[bytes]]]:
        """One fused Rust call: parse + sighash + dep resolution + script evaluation."""
        pool = self._script_verification_pool
        return htr_lib.verify_scripts_from_bytes(
            payloads,
            supplied,
            self._native_db(),
            'tx',
            opcodes_version,
            self._settings.MAX_SERIALIZED_VERTEX_SIZE,
            self._settings.MAX_MULTISIG_PUBKEYS,
            self._settings.MAX_MULTISIG_SIGNATURES,
            self._settings.P2PKH_VERSION_BYTE,
            pool.num_workers,
        )

    def _native_db(self) -> 'htr_lib.RocksDb | None':
        """The shared Rust RocksDB handle, when this node's storage is RocksDB-backed."""
        from hathor.storage import RocksDBStorage
        rocksdb_storage: RocksDBStorage | None = getattr(self._tx_storage, '_rocksdb_storage', None)
        if rocksdb_storage is None:
            return None
        return rocksdb_storage.get_db().inner

    def _fetch_dep_bytes(self, hashes: set[bytes]) -> list[bytes]:
        """Serialize the dependencies the Rust pipeline could not resolve, from the Python
        storage layer (cache-resident, unflushed txs). Hashes that do not exist are simply
        skipped: the affected txs fall back to the Python path / fresh evaluation."""
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        if not hashes or self._tx_storage is None:
            return []
        supplied = []
        for dep_hash in hashes:
            try:
                dep = self._tx_storage.get_transaction(dep_hash)
            except TransactionDoesNotExist:
                continue
            supplied.append(self._wire_bytes.get(dep_hash) or bytes(dep))
        return supplied

    def _precompute_scripts_python(
        self,
        fallback: list[BaseTransaction],
        all_vertices: Sequence[BaseTransaction],
        params: VerificationParams,
    ) -> None:
        """Python job-building path for txs the Rust pipeline could not cover (header-carrying
        vertices, deps only materializable in Python): builds `ScriptVerificationJob`s and runs
        one batched Rust evaluation over them."""
        pool = self._script_verification_pool
        opcodes_version = int(params.features.opcodes_version)
        by_hash = {vertex.hash: vertex for vertex in all_vertices}
        jobs: list[ScriptVerificationJob] = []
        owners: list[tuple[bytes, int]] = []
        for vertex in fallback:
            vertex_jobs = self._build_script_jobs(vertex, by_hash, params)
            if vertex_jobs is None:
                continue
            for job in vertex_jobs:
                jobs.append(job)
                owners.append((vertex.hash, job.input_index))
        if not jobs:
            return
        raw = pool._verify_scripts_batch_rust(jobs)
        per_tx: dict[bytes, dict[int, tuple[str, str] | None]] = {}
        for (tx_hash, input_index), item in zip(owners, raw):
            per_tx.setdefault(tx_hash, {})[input_index] = item
        for tx_hash, by_index in per_tx.items():
            pool.stash_script_results(tx_hash, opcodes_version, by_index)

    def _build_script_jobs(
        self,
        vertex: BaseTransaction,
        by_hash: dict[bytes, BaseTransaction],
        params: VerificationParams,
    ) -> 'list[ScriptVerificationJob] | None':
        """Build one script job per input of `vertex`, resolving spent txs from the batch or
        from storage. Returns None (skip: fresh evaluation at connect time) when the vertex is
        not a tx with inputs or any input is unresolvable; results are pure functions of the
        immutable tx/dep bytes plus the opcodes version, so precomputing is always safe."""
        from hathor.transaction.scripts.opcode import OpcodesVersion
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        from hathor.verification.script_verification_pool import build_script_verification_job

        if not isinstance(vertex, Transaction) or vertex.is_genesis or not vertex.inputs:
            return None
        opcodes_version = params.features.opcodes_version
        shared_outputs: tuple[tuple[int, bytes], ...] = (
            tuple((output.value, output.script) for output in vertex.outputs)
            if opcodes_version == OpcodesVersion.V1 else ()
        )
        jobs = []
        for index, txin in enumerate(vertex.inputs):
            spent_tx = by_hash.get(txin.tx_id)
            if spent_tx is None:
                if self._tx_storage is None:
                    return None
                try:
                    spent_tx = self._tx_storage.get_transaction(txin.tx_id)
                except TransactionDoesNotExist:
                    return None
            if txin.index >= len(spent_tx.outputs):
                return None
            jobs.append(build_script_verification_job(
                input_index=index,
                tx=vertex,
                txin=txin,
                spent_tx=spent_tx,
                opcodes_version=opcodes_version,
                shared_outputs=shared_outputs,
            ))
        return jobs

    def discard_precomputed(self, vertices: Sequence[BaseTransaction]) -> None:
        """Drop any unconsumed precomputed results (stateless and scripts) for these vertices."""
        for vertex in vertices:
            self._precomputed.pop(vertex.hash, None)
            self._script_verification_pool.discard_script_results(vertex.hash)
            self._wire_bytes.pop(vertex.hash, None)

    def _verify_without_storage_base_block_rust(self, block: Block, params: VerificationParams) -> None:
        results = self._run_rust_checks(block, params, _BLOCK_CHECKS)
        results.consume(CHECK_NO_INPUTS)
        results.consume(CHECK_OUTPUTS)
        results.consume(CHECK_BLOCK_TOKEN_INDEXES)
        results.consume(CHECK_BLOCK_DATA)
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
        results = self._run_rust_checks(tx, params, _TX_CHECKS)
        if self._settings.CONSENSUS_ALGORITHM.is_pow():
            self.verifiers.vertex.verify_pow(tx)
        results.consume(CHECK_NUMBER_OF_INPUTS)
        results.consume(CHECK_OUTPUTS)
        results.consume(CHECK_OUTPUT_TOKEN_INDEXES)
        results.consume(CHECK_SIGOPS_OUTPUT)
        self.verifiers.tx.verify_tokens(tx, params)
