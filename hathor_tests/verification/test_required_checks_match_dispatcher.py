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

"""Dispatcher completeness cross-check.

The VerificationContext mechanism depends on `required_checks_for(...)` staying
in sync with what `verification_service.py` actually calls. If they drift, the
completeness check silently rubber-stamps whatever flags happen to be set.

This test enumerates (vertex type x conditional-params) combinations, runs the
real dispatcher, and asserts `ctx.checks_run` EXACTLY equals the required flag
set. Adding a new verifier call to the dispatcher without updating
`required_checks.py` (or vice-versa) will fail this test immediately.
"""

import dataclasses
from unittest.mock import patch

from hathor.crypto.util import get_address_from_public_key
from hathor.manager import HathorManager
from hathor.transaction import BaseTransaction, BitcoinAuxPow, Block, MergeMinedBlock, Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.verification.required_checks import Stage, required_checks_for
from hathor.verification.verification_check import VerificationCheck
from hathor.verification.verification_params import VerificationParams
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward, create_tokens, get_genesis_key


class RequiredChecksMatchDispatcherTest(unittest.TestCase):
    """For every supported vertex shape + params combination, verify that the
    dispatcher records EXACTLY the flag set declared by required_checks_for."""

    def setUp(self) -> None:
        super().setUp()
        self.manager: HathorManager = self.create_peer('network')
        self.service = self.manager.verification_service

    # --- fixtures ---

    def _valid_block(self) -> Block:
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

    def _valid_merge_mined_block(self) -> MergeMinedBlock:
        block = MergeMinedBlock(
            hash=b'some_hash',
            storage=self.manager.tx_storage,
            weight=1,
            outputs=[TxOutput(value=6400, script=b'')],
            aux_pow=BitcoinAuxPow.dummy(),
            parents=[
                self._settings.GENESIS_BLOCK_HASH,
                self._settings.GENESIS_TX1_HASH,
                self._settings.GENESIS_TX2_HASH,
            ],
        )
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        return block

    def _valid_tx(self) -> Transaction:
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

    def _valid_token_creation_tx(self) -> TokenCreationTransaction:
        add_blocks_unlock_reward(self.manager)
        assert self.manager.wallet
        tx = create_tokens(self.manager, self.manager.wallet.get_unused_address())
        tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        return tx

    # --- the core assertion ---

    def _assert_recorded_matches_required(
        self,
        vertex: BaseTransaction,
        params: VerificationParams,
        stage: Stage,
        run: str,
    ) -> None:
        """Run the dispatcher for `stage`, capture ctx.checks_run, and compare
        to required_checks_for(vertex, params, settings, stage).

        For `all_of`: recorded MUST be a superset (may record extra for clarity).
        For `any_of_groups`: recorded MUST intersect every group.
        The symmetric invariant: no flag in `all_of ∪ flatten(any_of_groups)`
        may be missing.
        """
        captured = {'ctx': None}

        original_persist = type(self.service)._persist_context

        def spy_persist(svc, v, ctx):
            # Capture the ctx before it's merged into meta. Only capture for
            # the vertex under test (the dispatcher may persist for sub-vertices
            # but we only care about the top-level verify_basic/verify call).
            if captured['ctx'] is None and v is vertex:
                captured['ctx'] = ctx
            return original_persist(svc, v, ctx)

        with patch.object(type(self.service), '_persist_context', spy_persist):
            if stage is Stage.VERIFY_BASIC:
                self.service.verify_basic(vertex, params)
            elif stage is Stage.VERIFY:
                # verify_basic must run first — verify() is documented to
                # require at_least_basic state. We run both and capture verify's ctx.
                self.service.verify_basic(vertex, params)
                captured['ctx'] = None  # reset — we want verify's ctx, not basic's
                self.service.verify(vertex, params)
            else:
                self.fail(f'unsupported stage for this test: {stage}')

        ctx = captured['ctx']
        assert ctx is not None, f'{run}: dispatcher never called _persist_context'

        required = required_checks_for(vertex, params, self._settings, stage)
        recorded = ctx.checks_run

        # all_of: every required flag must be recorded
        missing_all = required.all_of & ~recorded
        assert missing_all == VerificationCheck(0), (
            f'{run}: required_checks declares {required.all_of!r} but dispatcher '
            f'only recorded {recorded!r}. Missing: {missing_all!r}. '
            f'required_checks.py and verification_service.py have drifted.'
        )

        # any_of_groups: at least one flag from each group must be recorded
        for group in required.any_of_groups:
            assert (recorded & group) != VerificationCheck(0), (
                f'{run}: required_checks any-of group {group!r} has no match in '
                f'recorded {recorded!r}. Dispatcher must record at least one of these.'
            )

        # Inverse: dispatcher should NOT record flags that aren't in the required
        # set (neither all_of nor any group). If it does, required_checks is
        # incomplete — declare them.
        all_valid = required.all_of
        for group in required.any_of_groups:
            all_valid |= group
        unexpected = recorded & ~all_valid
        assert unexpected == VerificationCheck(0), (
            f'{run}: dispatcher recorded {unexpected!r} but required_checks '
            f'does not declare them. Add to required_checks_for, or remove '
            f'the record call from the verifier.'
        )

    # --- verify_basic stage combinations ---

    def test_block_verify_basic(self) -> None:
        block = self._valid_block()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(block, params, Stage.VERIFY_BASIC, 'block verify_basic')

    def test_block_verify_basic_skip_weight(self) -> None:
        block = self._valid_block()
        params = dataclasses.replace(
            self.get_verification_params(self.manager),
            skip_block_weight_verification=True,
        )
        self._assert_recorded_matches_required(
            block, params, Stage.VERIFY_BASIC, 'block verify_basic (skip_weight)'
        )

    def test_merge_mined_block_verify_basic(self) -> None:
        block = self._valid_merge_mined_block()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(
            block, params, Stage.VERIFY_BASIC, 'merge_mined verify_basic'
        )

    def test_tx_verify_basic(self) -> None:
        tx = self._valid_tx()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(tx, params, Stage.VERIFY_BASIC, 'tx verify_basic')

    def test_token_creation_tx_verify_basic(self) -> None:
        tx = self._valid_token_creation_tx()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(
            tx, params, Stage.VERIFY_BASIC, 'token_creation_tx verify_basic'
        )

    # --- verify stage combinations ---

    def test_block_verify(self) -> None:
        block = self._valid_block()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(block, params, Stage.VERIFY, 'block verify')

    def test_merge_mined_block_verify(self) -> None:
        block = self._valid_merge_mined_block()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(block, params, Stage.VERIFY, 'merge_mined verify')

    def test_tx_verify(self) -> None:
        tx = self._valid_tx()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(tx, params, Stage.VERIFY, 'tx verify')

    def test_tx_verify_without_reward_locked(self) -> None:
        tx = self._valid_tx()
        params = dataclasses.replace(
            self.get_verification_params(self.manager),
            reject_locked_reward=False,
        )
        self._assert_recorded_matches_required(
            tx, params, Stage.VERIFY, 'tx verify (no reject_locked_reward)'
        )

    def test_token_creation_tx_verify(self) -> None:
        tx = self._valid_token_creation_tx()
        params = self.get_verification_params(self.manager)
        self._assert_recorded_matches_required(
            tx, params, Stage.VERIFY, 'token_creation_tx verify'
        )
