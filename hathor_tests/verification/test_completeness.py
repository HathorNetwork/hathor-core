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

"""Integration tests for the VerificationContext completeness mechanism.

These tests confirm that the dispatcher records the expected VerificationCheck
flags into metadata, and that simulating a "skipped check" bug (e.g., by
patching a verifier to return the empty flag) fires VerificationChecksMissingError.
"""

from unittest.mock import patch

from hathor.crypto.util import get_address_from_public_key
from hathor.manager import HathorManager
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import VerificationChecksMissingError
from hathor.transaction.scripts import P2PKH
from hathor.verification.transaction_verifier import TransactionVerifier
from hathor.verification.verification_check import VerificationCheck as VC
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, get_genesis_key


class VerificationContextCompletenessTest(unittest.TestCase):
    """End-to-end tests that validate_full / verify_basic + verify populate
    meta.verification_checks and that a missing flag is caught."""

    def setUp(self) -> None:
        super().setUp()
        self.manager: HathorManager = self.create_peer('network')

    def _get_valid_block(self) -> Block:
        block = Block(
            hash=b'some_hash',
            storage=self.manager.tx_storage,
            weight=1,
            outputs=[TxOutput(value=6400, script=b'')],
            parents=[
                self._settings.GENESIS_BLOCK_HASH,
                self._settings.GENESIS_TX1_HASH,
                self._settings.GENESIS_TX2_HASH,
            ],
        )
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        return block

    def _get_valid_tx(self) -> Transaction:
        # Mint rewards so the genesis block is unlockable.
        add_blocks_unlock_reward(self.manager)
        genesis_private_key = get_genesis_key()
        genesis_public_key = genesis_private_key.public_key()
        genesis_block = self.manager.tx_storage.get_transaction(self._settings.GENESIS_BLOCK_HASH)

        utxo = genesis_block.outputs[0]
        address = get_address_from_public_key(genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(utxo.value, script)
        _input = TxInput(self._settings.GENESIS_BLOCK_HASH, 0, b'')

        tx = Transaction(
            hash=b'some_hash',
            storage=self.manager.tx_storage,
            weight=1,
            inputs=[_input],
            outputs=[output],
            parents=[self._settings.GENESIS_TX1_HASH, self._settings.GENESIS_TX2_HASH],
        )
        tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)

        data_to_sign = tx.get_sighash_all()
        assert self.manager.wallet
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)
        return tx

    # --- block completeness ---

    def test_block_flags_recorded_after_verify_basic(self) -> None:
        """After verify_basic on a block, the basic-stage flags are in metadata."""
        block = self._get_valid_block()
        params = self.get_verification_params(self.manager)
        self.manager.verification_service.verify_basic(block, params)

        checks = block.get_metadata().verification_checks
        assert VC.VERSION_BASIC in checks
        assert VC.OLD_TIMESTAMP in checks
        assert VC.BLOCK_WEIGHT in checks
        assert VC.REWARD in checks
        assert VC.CHECKPOINTS in checks

    def test_block_flags_recorded_after_verify(self) -> None:
        """After verify on a block, the verify-stage flags are in metadata."""
        block = self._get_valid_block()
        params = self.get_verification_params(self.manager)
        self.manager.verification_service.verify(block, params)

        checks = block.get_metadata().verification_checks
        assert VC.HEADERS in checks
        assert VC.PARENTS in checks
        assert VC.HEIGHT in checks
        assert VC.MANDATORY_SIGNALING in checks
        assert VC.POW in checks
        assert VC.NO_INPUTS in checks
        assert VC.OUTPUTS in checks
        assert VC.BLOCK_DATA in checks
        assert VC.SIGOPS_OUTPUT in checks

    # --- transaction completeness ---

    def test_tx_balance_flag_recorded_after_verify(self) -> None:
        """After verify on a tx, BALANCE is in metadata (the flag this mechanism
        primarily protects — original 'skipped balance check' bug)."""
        tx = self._get_valid_tx()
        params = self.get_verification_params(self.manager)
        self.manager.verification_service.verify_basic(tx, params)
        self.manager.verification_service.verify(tx, params)

        checks = tx.get_metadata().verification_checks
        assert VC.BALANCE in checks
        assert VC.BALANCE_POSTPONED not in checks  # non-nano: never postponed
        assert VC.INPUTS in checks
        assert VC.VERSION in checks
        assert VC.SIGOPS_INPUT in checks
        assert VC.CONFLICT in checks

    # --- regression: simulated bug fires completeness error ---

    def test_broken_verify_sum_triggers_completeness_error(self) -> None:
        """Simulate a future bug where verify_sum silently returns no flag
        (representing someone stubbing or breaking the balance check). The
        completeness check on verify() must fire VerificationChecksMissingError."""
        tx = self._get_valid_tx()
        params = self.get_verification_params(self.manager)
        self.manager.verification_service.verify_basic(tx, params)

        # Patch verify_sum to be a no-op that returns no flag. The dispatcher
        # will record VerificationCheck(0) — effectively nothing. The any_of
        # group {BALANCE, BALANCE_POSTPONED} will be empty → error.
        with patch.object(TransactionVerifier, 'verify_sum', return_value=VC(0)):
            with self.assertRaises(VerificationChecksMissingError) as exc_ctx:
                self.manager.verification_service.verify(tx, params)

        message = str(exc_ctx.exception)
        assert 'BALANCE' in message

    def test_broken_verify_inputs_triggers_completeness_error(self) -> None:
        """Simulate a broken verify_inputs that succeeds (doesn't raise) but
        doesn't record its flag (e.g., a future refactor that removed the
        ctx.record call). The completeness check on verify() must fire."""
        tx = self._get_valid_tx()
        params = self.get_verification_params(self.manager)
        self.manager.verification_service.verify_basic(tx, params)

        # Replace verify_inputs with a no-op that ignores ctx entirely.
        # Because recording lives inside the verifier, stubbing the verifier
        # automatically omits the flag — the stronger defense.
        with patch.object(TransactionVerifier, 'verify_inputs', return_value=None):
            with self.assertRaises(VerificationChecksMissingError) as exc_ctx:
                self.manager.verification_service.verify(tx, params)

        assert 'INPUTS' in str(exc_ctx.exception)
