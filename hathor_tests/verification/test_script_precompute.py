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

"""Differential tests for the batched script precompute: verifying a tx whose scripts were
pre-evaluated by `RustVerificationService._precompute_scripts_batch` (one Rust call for a whole
batch, results cached in the script pool) must surface the exact same outcome — same exception
type and message, same interleaving with precheck/conflict errors — as a fresh evaluation."""

import dataclasses
from typing import Callable

from hathor.conf.get_settings import get_global_settings
from hathor.feature_activation.utils import Features
from hathor.reactor import get_global_reactor
from hathor.transaction import Transaction
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.verification.rust_verification_service import RustVerificationService
from hathor.verification.script_verification_pool import ScriptVerificationMode, ScriptVerificationPool
from hathor.verification.transaction_verifier import TransactionVerifier
from hathor.verification.verification_params import VerificationParams
from hathor.verification.vertex_verifiers import VertexVerifiers
from hathor_tests import unittest
from hathor_tests.tx.test_parallel_script_verification import build_multisig_tx, build_p2pkh_tx, corrupt_signature

OPCODES_VERSION = OpcodesVersion.V2


def _make_params(opcodes_version: OpcodesVersion = OPCODES_VERSION) -> VerificationParams:
    features = dataclasses.replace(Features.all_enabled(), opcodes_version=opcodes_version)
    return VerificationParams(nc_block_root_id=None, features=features)


class ScriptPrecomputeTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        settings = get_global_settings()
        self.pool = ScriptVerificationPool(mode=ScriptVerificationMode.RUST, num_workers=2, min_inputs=1)
        self.pool.start()
        verifiers = VertexVerifiers.create_defaults(
            reactor=get_global_reactor(),
            settings=settings,
            daa_factory=None,  # type: ignore[arg-type]  # unused by these tests
            feature_service=None,  # type: ignore[arg-type]
            tx_storage=None,  # type: ignore[arg-type]
            blueprint_service=None,  # type: ignore[arg-type]
            script_verification_pool=self.pool,
        )
        self.service = RustVerificationService(
            settings=settings, verifiers=verifiers, script_verification_pool=self.pool,
        )

    def tearDown(self) -> None:
        self.pool.stop()
        super().tearDown()

    def _verify(self, tx: Transaction, opcodes_version: OpcodesVersion = OPCODES_VERSION) -> BaseException | None:
        try:
            TransactionVerifier._verify_inputs(
                self._settings, tx, opcodes_version, skip_script=False, script_pool=self.pool,
            )
        except BaseException as e:  # noqa: B036 - re-surfaced; the test asserts on type/message
            return e
        return None

    def _assert_precompute_equivalent(
        self,
        build: Callable[[], Transaction],
        *,
        mutate: Callable[[Transaction], None] | None = None,
        params: VerificationParams | None = None,
        verify_version: OpcodesVersion = OPCODES_VERSION,
        expect_cache_hit: bool = True,
    ) -> None:
        """Build a tx, optionally mutate it, and assert the precomputed path is outcome-identical
        to the fresh path. The spent tx is resolved from the batch itself (the service has no
        storage here), exercising the in-batch spend-chain case sync hits."""
        tx = build()
        if mutate is not None:
            mutate(tx)
        spent_tx = tx.storage._spent_tx  # type: ignore[union-attr]  # _StubStorage from the helpers

        fresh = self._verify(tx, verify_version)

        self.service._precompute_scripts_batch([spent_tx, tx], params or _make_params())
        assert tx.hash in self.pool._cached_script_results

        # the cached path must not make any fresh Rust script call
        import htr_lib
        calls = []
        original = htr_lib.verify_scripts_batch

        def counting(*args: object, **kwargs: object) -> object:
            calls.append(1)
            return original(*args, **kwargs)  # type: ignore[arg-type]

        htr_lib.verify_scripts_batch = counting  # type: ignore[assignment]
        try:
            cached = self._verify(tx, verify_version)
        finally:
            htr_lib.verify_scripts_batch = original

        assert (type(cached), str(cached)) == (type(fresh), str(fresh))
        assert tx.hash not in self.pool._cached_script_results, 'cache entry must be consumed (popped)'
        if expect_cache_hit:
            assert calls == [], 'precomputed results were not consumed'
        else:
            assert calls, 'expected a fresh Rust call (cache must be skipped)'

    def test_valid_p2pkh(self) -> None:
        self._assert_precompute_equivalent(lambda: build_p2pkh_tx([0, 1, 2]))

    def test_valid_multisig(self) -> None:
        self._assert_precompute_equivalent(lambda: build_multisig_tx(2))

    def test_invalid_signature(self) -> None:
        self._assert_precompute_equivalent(
            lambda: build_p2pkh_tx([0, 1, 2]),
            mutate=lambda tx: corrupt_signature(tx, 1),
        )

    def test_raise_kind_invalid_opcode(self) -> None:
        # input data with opcode 0x00 raises InvalidScriptError unwrapped out of run_jobs
        def mutate(tx: Transaction) -> None:
            tx.inputs[1].data = b'\x00'
        self._assert_precompute_equivalent(lambda: build_p2pkh_tx([0, 1]), mutate=mutate)

    def test_precheck_timestamp_wins_over_script_error(self) -> None:
        # tx.timestamp <= spent_tx.timestamp: the precheck stops scheduling at input 0, so the
        # corrupted script at input 1 must NOT surface — on either path.
        def mutate(tx: Transaction) -> None:
            corrupt_signature(tx, 1)
            tx.timestamp = 1000  # == SPENT_TIMESTAMP
            tx.update_hash()
            tx.clear_sighash_cache()
        self._assert_precompute_equivalent(lambda: build_p2pkh_tx([0, 1]), mutate=mutate)

    def test_conflicting_inputs(self) -> None:
        # two inputs spending the same output: ConflictingInputs at index 1 on both paths
        self._assert_precompute_equivalent(lambda: build_p2pkh_tx([0, 0]))

    def test_opcodes_version_mismatch_skips_cache(self) -> None:
        # precomputed under V2, verified under V1: the cache must be skipped (fresh call), and
        # the outcome must equal a fresh V1 evaluation
        self._assert_precompute_equivalent(
            lambda: build_p2pkh_tx([0]),
            params=_make_params(OpcodesVersion.V2),
            verify_version=OpcodesVersion.V1,
            expect_cache_hit=False,
        )

    def test_unresolvable_dep_skips_precompute(self) -> None:
        # the spent tx is neither in the batch nor in storage: no cache entry is created
        tx = build_p2pkh_tx([0])
        self.service._precompute_scripts_batch([tx], _make_params())
        assert tx.hash not in self.pool._cached_script_results

    def test_storage_resolved_dep(self) -> None:
        # the spent tx comes from the service's tx_storage instead of the batch
        tx = build_p2pkh_tx([0, 1])
        self.service._tx_storage = tx.storage  # the helpers' stub storage returns the spent tx
        try:
            jobs = self.service._build_script_jobs(tx, {}, _make_params())
            assert jobs is not None and len(jobs) == 2
        finally:
            self.service._tx_storage = None
