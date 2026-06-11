#  Copyright 2024 Hathor Labs
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

"""Equivalence tests for parallel input-script verification.

The parallel path (``TransactionVerifier._verify_inputs`` with a worker pool) must surface exactly the same
pass/fail result -- same exception type and message -- as the original serial loop, for every ordering of
per-input failures. We run each scenario through three executors (serial / threads / processes) and assert they
agree with the serial baseline.
"""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

from hathor.crypto.util import (
    decode_address,
    get_address_from_public_key,
    get_public_key_bytes_compressed,
)
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import ConflictingInputs, InvalidInputData, InvalidInputDataSize
from hathor.transaction.scripts import P2PKH, MultiSig, create_output_script
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.verification.script_verification_pool import (
    ScriptVerificationMode,
    ScriptVerificationPool,
    build_script_verification_job,
    execute_script_verification_job,
)
from hathor.verification.transaction_verifier import TransactionVerifier
from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script
from hathor_tests import unittest

OPCODES_VERSION = OpcodesVersion.V2
SPENT_TIMESTAMP = 1000
TX_TIMESTAMP = 2000
INPUT_VALUE = 100


class _StubStorage:
    """Minimal storage returning a single spent_tx for any input, so ``tx.get_spent_tx`` resolves."""
    def __init__(self, spent_tx: Transaction) -> None:
        self._spent_tx = spent_tx

    def get_transaction(self, tx_id: bytes) -> Transaction:
        return self._spent_tx


def _sign(tx: Transaction, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    hashed = hashlib.sha256(tx.get_sighash_all()).digest()
    return private_key.sign(hashed, ec.ECDSA(SHA256()))


def _finish(tx: Transaction, spent_tx: Transaction) -> Transaction:
    tx.storage = _StubStorage(spent_tx)  # type: ignore[assignment]
    tx.update_hash()
    tx.clear_sighash_cache()
    return tx


def build_p2pkh_tx(spent_indices: list[int]) -> Transaction:
    """Build a signed P2PKH tx with one input per entry in ``spent_indices`` (the spent output index)."""
    private_key = ec.generate_private_key(ec.SECP256K1())
    pubkey_bytes = get_public_key_bytes_compressed(private_key.public_key())
    output_script = P2PKH.create_output_script(get_address_from_public_key(private_key.public_key()))

    num_outputs = max(spent_indices) + 1
    spent_tx = Transaction(timestamp=SPENT_TIMESTAMP,
                           outputs=[TxOutput(INPUT_VALUE, output_script) for _ in range(num_outputs)])
    spent_tx.update_hash()
    # tx_id is part of the sighash, so inputs must reference spent_tx.hash before signing.
    tx = Transaction(
        timestamp=TX_TIMESTAMP,
        inputs=[TxInput(spent_tx.hash, index, b'') for index in spent_indices],
        outputs=[TxOutput(INPUT_VALUE, output_script)],
    )
    signature = _sign(tx, private_key)  # sighash excludes input data, so one signature is valid for every input
    for txin in tx.inputs:
        txin.data = P2PKH.create_input_data(pubkey_bytes, signature)
    return _finish(tx, spent_tx)


def build_multisig_tx(num_inputs: int) -> Transaction:
    """Build a signed 2-of-3 multisig tx with ``num_inputs`` inputs."""
    private_keys = [ec.generate_private_key(ec.SECP256K1()) for _ in range(3)]
    pubkeys = [get_public_key_bytes_compressed(k.public_key()) for k in private_keys]
    redeem_script = generate_multisig_redeem_script(2, pubkeys)
    output_script = create_output_script(decode_address(generate_multisig_address(redeem_script)))

    spent_tx = Transaction(timestamp=SPENT_TIMESTAMP,
                           outputs=[TxOutput(INPUT_VALUE, output_script) for _ in range(num_inputs)])
    spent_tx.update_hash()
    tx = Transaction(
        timestamp=TX_TIMESTAMP,
        inputs=[TxInput(spent_tx.hash, index, b'') for index in range(num_inputs)],
        outputs=[TxOutput(INPUT_VALUE, output_script)],
    )
    signatures = [_sign(tx, private_keys[0]), _sign(tx, private_keys[1])]
    for txin in tx.inputs:
        txin.data = MultiSig.create_input_data(redeem_script, signatures)
    return _finish(tx, spent_tx)


def corrupt_signature(tx: Transaction, index: int) -> None:
    """Replace input ``index``'s P2PKH data with a signature over the wrong message (fails verification)."""
    wrong_key = ec.generate_private_key(ec.SECP256K1())
    bad_signature = wrong_key.sign(hashlib.sha256(b'not the sighash').digest(), ec.ECDSA(SHA256()))
    pubkey_bytes = get_public_key_bytes_compressed(wrong_key.public_key())
    tx.inputs[index].data = P2PKH.create_input_data(pubkey_bytes, bad_signature)


class ParallelScriptVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self._pools = {
            'serial': None,
            'threads': ScriptVerificationPool(mode=ScriptVerificationMode.THREADS, num_workers=2, min_inputs=1),
            'processes': ScriptVerificationPool(mode=ScriptVerificationMode.PROCESSES, num_workers=2, min_inputs=1),
        }
        for pool in self._pools.values():
            if pool is not None:
                pool.start()

    def tearDown(self) -> None:
        for pool in self._pools.values():
            if pool is not None:
                pool.stop()
        super().tearDown()

    def _verify(self, tx: Transaction, pool: ScriptVerificationPool | None) -> BaseException | None:
        """Run input verification with the given pool and return the raised exception (or None on success).

        NOTE: do not name this ``_run`` -- that shadows Twisted trial's internal ``TestCase._run``.
        """
        try:
            TransactionVerifier._verify_inputs(
                self._settings, tx, OPCODES_VERSION, skip_script=False, script_pool=pool,
            )
        except BaseException as e:  # noqa: B036 - we re-surface it; the test asserts on type/message
            return e
        return None

    def _assert_equivalent(self, build, *, mutate=None) -> None:
        """Build a single tx, optionally mutate it, and assert all executors agree with the serial baseline.

        The same tx instance is shared across executors on purpose: verification is read-only on the tx (it only
        populates the idempotent sighash cache), and error messages embed the tx/spent_tx hashes -- so a fresh
        random tx per executor would spuriously differ.
        """
        tx = build()
        if mutate is not None:
            mutate(tx)
        outcomes = {name: self._verify(tx, pool) for name, pool in self._pools.items()}

        baseline = outcomes['serial']
        baseline_repr = (type(baseline), str(baseline))
        for name, outcome in outcomes.items():
            got = (type(outcome), str(outcome))
            self.assertEqual(got, baseline_repr, f'executor {name!r} disagreed with serial: {got} != {baseline_repr}')

    # --- valid transactions -----------------------------------------------------------------------------------

    def test_valid_p2pkh_multi_input(self) -> None:
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2, 3, 4]))

    def test_valid_multisig_multi_input(self) -> None:
        self._assert_equivalent(lambda: build_multisig_tx(4))

    def test_valid_single_input(self) -> None:
        self._assert_equivalent(lambda: build_p2pkh_tx([0]))

    # --- bad signature at each position -----------------------------------------------------------------------

    def test_bad_signature_first(self) -> None:
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2, 3]), mutate=lambda tx: corrupt_signature(tx, 0))

    def test_bad_signature_middle(self) -> None:
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2, 3]), mutate=lambda tx: corrupt_signature(tx, 2))

    def test_bad_signature_last(self) -> None:
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2, 3]), mutate=lambda tx: corrupt_signature(tx, 3))

    # --- size / timestamp -------------------------------------------------------------------------------------

    def test_oversized_input_data(self) -> None:
        def mutate(tx: Transaction) -> None:
            tx.inputs[1].data = b'\x00' * (self._settings.MAX_INPUT_DATA_SIZE + 1)
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2]), mutate=mutate)

    def test_timestamp_not_after_spent(self) -> None:
        def mutate(tx: Transaction) -> None:
            tx.timestamp = SPENT_TIMESTAMP  # not strictly greater than the spent tx's timestamp
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2]), mutate=mutate)

    # --- interleaving: which of two failures wins (lowest index) ----------------------------------------------

    def test_script_failure_beats_later_oversize(self) -> None:
        # bad script at index 0, oversized data at index 1 -> the script error (index 0) must win
        def mutate(tx: Transaction) -> None:
            corrupt_signature(tx, 0)
            tx.inputs[1].data = b'\x00' * (self._settings.MAX_INPUT_DATA_SIZE + 1)
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2]), mutate=mutate)
        # And confirm it is specifically the script error.
        tx = build_p2pkh_tx([0, 1, 2])
        mutate(tx)
        assert isinstance(self._verify(tx, self._pools['processes']), InvalidInputData)

    def test_earlier_oversize_beats_later_script_failure(self) -> None:
        # oversized data at index 1, bad script at index 2 -> the size error (index 1) must win
        def mutate(tx: Transaction) -> None:
            tx.inputs[1].data = b'\x00' * (self._settings.MAX_INPUT_DATA_SIZE + 1)
            corrupt_signature(tx, 2)
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 1, 2]), mutate=mutate)
        tx = build_p2pkh_tx([0, 1, 2])
        mutate(tx)
        assert isinstance(self._verify(tx, self._pools['processes']), InvalidInputDataSize)

    # --- conflicting inputs vs script failures ----------------------------------------------------------------

    def test_conflicting_inputs(self) -> None:
        # inputs 1 and 2 both spend output index 0 -> ConflictingInputs at index 2
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 0]))
        tx = build_p2pkh_tx([0, 0])
        assert isinstance(self._verify(tx, self._pools['processes']), ConflictingInputs)

    def test_script_failure_beats_later_conflict(self) -> None:
        # bad script at index 0; inputs 1 and 2 conflict -> script error (index 0) wins
        def mutate(tx: Transaction) -> None:
            corrupt_signature(tx, 0)
        self._assert_equivalent(lambda: build_p2pkh_tx([1, 0, 0]), mutate=mutate)
        tx = build_p2pkh_tx([1, 0, 0])
        mutate(tx)
        assert isinstance(self._verify(tx, self._pools['processes']), InvalidInputData)

    def test_conflict_beats_later_script_failure(self) -> None:
        # inputs 0 and 1 conflict (index 1); bad script at index 2 -> conflict (index 1) wins
        def mutate(tx: Transaction) -> None:
            corrupt_signature(tx, 2)
        self._assert_equivalent(lambda: build_p2pkh_tx([0, 0, 1]), mutate=mutate)
        tx = build_p2pkh_tx([0, 0, 1])
        mutate(tx)
        assert isinstance(self._verify(tx, self._pools['processes']), ConflictingInputs)


class ScriptVerificationPoolTest(unittest.TestCase):
    """Direct tests of the pool's job/threshold behavior, without the verifier."""

    def _jobs(self, tx: Transaction) -> list:
        return [
            build_script_verification_job(
                input_index=i, tx=tx, txin=txin, spent_tx=tx.get_spent_tx(txin),
                opcodes_version=OPCODES_VERSION, shared_outputs=(),
            )
            for i, txin in enumerate(tx.inputs)
        ]

    def test_min_inputs_threshold_runs_inline(self) -> None:
        # With min_inputs=4, a 2-input tx must NOT touch the executor; we detect this via a sentinel executor.
        tx = build_p2pkh_tx([0, 1])
        jobs = self._jobs(tx)
        pool = ScriptVerificationPool(mode=ScriptVerificationMode.THREADS, num_workers=2, min_inputs=4)
        pool.start()
        try:
            class _Boom:
                def submit(self, *a, **k):
                    raise AssertionError('executor must not be used below the min_inputs threshold')
            pool._executor = _Boom()  # type: ignore[assignment]
            results = pool.run_jobs(jobs)
        finally:
            pool._executor = None
            pool.stop()
        self.assertEqual(results, [None, None])

    def test_disabled_pool_runs_inline(self) -> None:
        tx = build_p2pkh_tx([0, 1, 2])
        jobs = self._jobs(tx)
        pool = ScriptVerificationPool(mode=ScriptVerificationMode.DISABLED, num_workers=0)
        pool.start()  # no-op when disabled
        self.assertFalse(pool.enabled)
        self.assertFalse(pool.started)
        self.assertEqual(pool.run_jobs(jobs), [None, None, None])

    def test_pool_reuse_and_restart(self) -> None:
        tx = build_p2pkh_tx([0, 1, 2, 3])
        jobs = self._jobs(tx)
        pool = ScriptVerificationPool(mode=ScriptVerificationMode.THREADS, num_workers=2, min_inputs=1)
        pool.start()
        try:
            for _ in range(5):
                self.assertEqual(pool.run_jobs(jobs), [None, None, None, None])
        finally:
            pool.stop()
        # restart and run again
        pool.start()
        try:
            self.assertEqual(pool.run_jobs(jobs), [None, None, None, None])
        finally:
            pool.stop()

    def test_job_detects_bad_signature(self) -> None:
        tx = build_p2pkh_tx([0, 1])
        corrupt_signature(tx, 1)
        jobs = self._jobs(tx)
        results = [execute_script_verification_job(job) for job in jobs]
        self.assertIsNone(results[0])
        self.assertIsNotNone(results[1])


if __name__ == '__main__':
    pytest.main([__file__])
