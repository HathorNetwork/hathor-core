# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Generator

from twisted.internet.defer import inlineCallbacks

from hathor.checkpoint import Checkpoint
from hathor.dag_builder.artifacts import DAGArtifacts
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID, Blueprint, Context, fallback, public
from hathor.nanocontracts.exception import (
    BlueprintDoesNotExist,
    NanoContractDoesNotExist,
    NCFail,
    NCForbiddenAction,
    NCInvalidMethodCall,
    NCInvalidSeqnum,
    NCMethodNotFound,
    NCTxValidationError,
    OCBBlueprintNotConfirmed,
)
from hathor.nanocontracts.types import NCArgs
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import (
    CheckpointError,
    ConflictWithConfirmedTxError,
    InputVoidedAndConfirmed,
    InvalidToken,
    TimestampError,
    TooManyBetweenConflicts,
    TooManyTokens,
    TooManyWithinConflicts,
    UnusedTokensError,
)
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.verification.nano_header_verifier import MAX_SEQNUM_DIFF_MEMPOOL
from hathor.verification.transaction_verifier import MAX_BETWEEN_CONFLICTS, MAX_WITHIN_CONFLICTS
from hathor.verification.vertex_verifier import MAX_PAST_TIMESTAMP_ALLOWED
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.token_amount import UnsignedAmount


class MyTestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def fail(self, ctx: Context) -> None:
        raise NCFail('fail')


class MyOtherTestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_withdrawal=True)
    def nop(self, ctx: Context) -> None:
        pass

    @fallback(allow_withdrawal=True)
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> None:
        assert method_name == 'unknown'


class VertexHeadersTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = b'a' * 32
        self.other_blueprint_id = b'b' * 32
        self.manager = self.create_peer('unittests')
        self.manager.blueprint_service.register_blueprints({
            self.blueprint_id: MyTestBlueprint,
            self.other_blueprint_id: MyOtherTestBlueprint,
        })
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_vertex_too_old(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..30]
            b10 < dummy

            tx1.out[0] = 1 HTR
        ''')
        artifacts.propagate_with(self.manager, up_to='dummy')
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tx1.timestamp = int(self.manager.reactor.seconds()) - MAX_PAST_TIMESTAMP_ALLOWED
        self.dag_builder._exporter._vertex_resolver(tx1)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx1)
        assert isinstance(e.exception.__cause__, TimestampError)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tx1.timestamp = int(self.manager.reactor.seconds()) - MAX_PAST_TIMESTAMP_ALLOWED + 1
        self.dag_builder._exporter._vertex_resolver(tx1)

        self.manager.vertex_handler.on_new_mempool_transaction(tx1)

    def test_tokens(self) -> None:
        tx1_description = '\n'.join([
            f'tx1.out[{i}] = 1 TK_{i}' for i in range(15)
        ])
        tx2_description = '\n'.join([
            f'tx2.out[{i}] = 1 TK_{i}' for i in range(17)
        ])
        tx3_description = '\n'.join([
            f'tx3.out[{i}] = 1 TK_{i}' for i in range(9)
        ])
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..30]
            b10 < dummy

            {tx1_description}
            {tx2_description}
            {tx3_description}

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 TK_15

            tx3.nc_id = "{self.blueprint_id.hex()}"
            tx3.nc_method = initialize()
            tx3.nc_deposit = 1 TK_9

            b30 < tx1 < tx2 < tx3
        ''')
        artifacts.propagate_with(self.manager, up_to_before='tx2')
        tx1, tx2, tx3 = artifacts.get_typed_vertices(['tx1', 'tx2', 'tx3'], Transaction)
        tk_9, tk_15 = artifacts.get_typed_vertices(['TK_9', 'TK_15'], TokenCreationTransaction)

        assert len(tx1.tokens) == 16
        # assert tk_15.hash not in tx1.tokens
        assert tx1.get_metadata().voided_by is None

        # need to fix the timestamp to pass the old vertices mempool verification
        tx2.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx2)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2)
        assert isinstance(e.exception.__cause__, TooManyTokens)

        tx3_original_tokens = list(tx3.tokens)

        # add one duplicate token
        tx3.tokens.append(tx3.tokens[0])
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, InvalidToken)
        tx3.tokens = list(tx3_original_tokens)

        # add one unused token
        tx3.tokens.append(tk_15.hash)
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, UnusedTokensError)

    def _build_final_melt_setup(self) -> tuple[DAGArtifacts, Transaction]:
        """Build a DAG holding 100 TKA and a consensus-valid final-melt tx that lists TKA.

        The melt tx burns the full 100 TKA balance and the melt authority, withdrawing the 1 HTR deposit
        (1% of 100). It references TKA only through its inputs, with no TKA output, so listing TKA in the
        tokens list makes `verify_tokens` consider it unused. The DAG's `b31` is left unpropagated so
        tests can deliver the melt tx through the block-sync path.
        """
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..31]
            b10 < dummy

            tx1.out[0] = 100 TKA

            tx1 <-- b31
            tx1 < b31
        ''')
        artifacts.propagate_with(self.manager, up_to_before='b31')
        melt_tx = self._build_final_melt_tx(artifacts, list_token=True)
        return artifacts, melt_tx

    def _build_final_melt_tx(self, artifacts: DAGArtifacts, *, list_token: bool) -> Transaction:
        """Build the final-melt tx, listing the melted token in the tokens list or omitting it."""
        tka = artifacts.get_typed_vertex('TKA', TokenCreationTransaction)
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        melt_authority_index = next(
            index for index, output in enumerate(tka.outputs)
            if output.is_token_authority() and output.can_melt_token()
        )

        melt_tx = Transaction(
            inputs=[
                TxInput(tx1.hash, 0, b''),
                TxInput(tka.hash, melt_authority_index, b''),
            ],
            outputs=[TxOutput(UnsignedAmount.from_v1(1), tx1.outputs[0].script, 0)],
            parents=self.manager.get_new_tx_parents(),
            tokens=[tka.hash] if list_token else [],
            storage=self.manager.tx_storage,
            timestamp=int(self.manager.reactor.seconds()),
        )
        self.dag_builder._exporter.sign_all_inputs(melt_tx)
        melt_tx.weight = self.manager.daa_factory.minimum_tx_weight(melt_tx)
        self.dag_builder._exporter._vertex_resolver(melt_tx)
        return melt_tx

    def test_final_melt_rejected_at_mempool_entry(self) -> None:
        """A tokens-list entry referenced only by inputs is rejected at every mempool entry.

        A final melt references the melted token only through its inputs, so the tokens list decides
        admission: listing the token trips the unused-tokens check, while the same melt with the token
        omitted from the list is accepted.
        """
        artifacts, melt_tx = self._build_final_melt_setup()

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(melt_tx)
        assert isinstance(e.exception.__cause__, UnusedTokensError)
        assert str(e.exception.__cause__) == 'unused tokens are not allowed'
        assert not self.manager.tx_storage.transaction_exists(melt_tx.hash)

        clean_melt_tx = self._build_final_melt_tx(artifacts, list_token=False)
        assert self.manager.vertex_handler.on_new_mempool_transaction(clean_melt_tx)
        assert self.manager.tx_storage.transaction_exists(clean_melt_tx.hash)

    @inlineCallbacks
    def test_final_melt_accepted_inside_block(self) -> Generator:
        """A tx listing a token referenced only by inputs is admitted when it arrives inside a block."""
        artifacts, melt_tx = self._build_final_melt_setup()
        b31 = artifacts.get_typed_vertex('b31', Block)
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)

        # Align the melt tx with chain time: the block path has no freshness requirement, and b31 must
        # stay close to b30 to satisfy the max distance between blocks. The timestamp must still exceed
        # every parent's and every spent tx's.
        b30 = artifacts.get_typed_vertex('b30', Block)
        melt_tx_deps = list(melt_tx.parents) + [tx_input.tx_id for tx_input in melt_tx.inputs]
        melt_tx.timestamp = 1 + max(
            self.manager.tx_storage.get_transaction(vertex_id).timestamp for vertex_id in melt_tx_deps
        )
        self.dag_builder._exporter._vertex_resolver(melt_tx)

        # Make b31 confirm the melt tx by replacing its auto-filled tx parent (index 0 is the block
        # parent, and tx1 is kept as the other tx parent).
        other_parent_index = next(
            index for index, parent in enumerate(b31.parents)
            if index > 0 and parent != tx1.hash
        )
        b31.parents[other_parent_index] = melt_tx.hash
        b31.timestamp = max(b30.timestamp, melt_tx.timestamp) + 1
        self.dag_builder._exporter._vertex_resolver(b31)

        deferred = self.manager.vertex_handler.on_new_sync_block(b31, deps=[melt_tx])
        # `on_new_sync_block` schedules a zero-delay `deferLater` after each dep, which only fires when
        # the test clock ticks.
        self.clock.advance(0)
        success = yield deferred
        assert success

        stored_melt_tx = self.manager.tx_storage.get_transaction(melt_tx.hash)
        melt_meta = stored_melt_tx.get_metadata()
        assert melt_meta.validation.is_fully_connected()
        assert melt_meta.voided_by is None
        assert melt_meta.first_block == b31.hash

    def test_conflict_with_confirmed_tx(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..30]
            b10 < dummy

            tx1.out[0] <<< tx2 tx3
            tx2 <-- b30

            tx2 < b30 < tx3
        ''')
        artifacts.propagate_with(self.manager, up_to_before='tx3')
        b30 = artifacts.get_typed_vertex('b30', Block)
        tx2, tx3 = artifacts.get_typed_vertices(['tx2', 'tx3'], Transaction)

        assert tx2.get_metadata().voided_by is None
        assert tx2.get_metadata().first_block == b30.hash
        assert b30.get_metadata().voided_by is None

        # need to fix the timestamp to pass the old vertices mempool verification
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, ConflictWithConfirmedTxError)

    def test_conflict_with_confirmed_nc_fail_is_allowed(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..32]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx0.out[0] <<< tx_fail tx_ok

            tx_fail.nc_id = tx1
            tx_fail.nc_method = fail()

            tx1 <-- b30
            tx_fail <-- b31

            b31 < tx_ok
        ''')
        artifacts.propagate_with(self.manager, up_to_before='tx_ok')

        b31 = artifacts.get_typed_vertex('b31', Block)
        tx_fail = artifacts.get_typed_vertex('tx_fail', Transaction)
        tx_ok = artifacts.get_typed_vertex('tx_ok', Transaction)

        assert tx_fail.get_metadata().first_block == b31.hash
        assert tx_fail.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx_fail.get_metadata().voided_by == {tx_fail.hash, NC_EXECUTION_FAIL_ID}

        tx_ok.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx_ok)

        assert self.manager.vertex_handler.on_new_mempool_transaction(tx_ok)

        assert self.manager.tx_storage.transaction_exists(tx_ok.hash)
        mempool_hashes = {
            tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter_all(self.manager.tx_storage)
        }
        assert tx_ok.hash in mempool_hashes

    def test_mempool_tx_returns_after_reorg_with_confirmed_nc_fail_conflict(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..32]
            blockchain b31 a[32..32]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx0.out[0] <<< tx_fail tx_ok

            tx_fail.nc_id = tx1
            tx_fail.nc_method = fail()

            tx_ok.nc_id = tx1
            tx_ok.nc_method = nop()

            tx1 <-- b30
            tx_fail <-- b31
            tx_ok <-- b32

            b31 < tx_ok
            tx_ok < a32
            a32.weight = 10
        ''')
        artifacts.propagate_with(self.manager, up_to_before='tx_ok')

        b31 = artifacts.get_typed_vertex('b31', Block)
        b32 = artifacts.get_typed_vertex('b32', Block)
        a32 = artifacts.get_typed_vertex('a32', Block)
        tx_fail = artifacts.get_typed_vertex('tx_fail', Transaction)
        tx_ok = artifacts.get_typed_vertex('tx_ok', Transaction)

        assert tx_fail.get_metadata().first_block == b31.hash
        assert tx_fail.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx_fail.get_metadata().voided_by == {tx_fail.hash, NC_EXECUTION_FAIL_ID}

        # Align reactor time with the chain so mempool timestamp checks pass.
        self.clock.rightNow = b31.timestamp + 1

        old_tx_ok_hash = tx_ok.hash
        tx_ok.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx_ok)
        if old_tx_ok_hash != tx_ok.hash:
            # Keep b32 confirming tx_ok after the hash update.
            b32.parents = [tx_ok.hash if h == old_tx_ok_hash else h for h in b32.parents]
        # Ensure block timestamps are after tx_ok to satisfy parent timestamp checks.
        b32.timestamp = tx_ok.timestamp + 1
        a32.timestamp = tx_ok.timestamp + 2
        self.dag_builder._exporter._vertex_resolver(b32)
        self.dag_builder._exporter._vertex_resolver(a32)

        assert self.manager.vertex_handler.on_new_mempool_transaction(tx_ok)

        mempool_hashes = {
            tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter_all(self.manager.tx_storage)
        }
        assert tx_ok.hash in mempool_hashes

        assert self.manager.vertex_handler.on_new_relayed_block(b32)

        tx_ok_confirmed = self.manager.tx_storage.get_transaction(tx_ok.hash)
        assert tx_ok_confirmed.get_metadata().first_block == b32.hash
        mempool_hashes = {
            tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter_all(self.manager.tx_storage)
        }
        assert tx_ok.hash not in mempool_hashes

        assert self.manager.vertex_handler.on_new_relayed_block(a32)

        tx_ok_reorged = self.manager.tx_storage.get_transaction(tx_ok.hash)
        assert tx_ok_reorged.get_metadata().first_block is None
        mempool_hashes = {
            tx.hash for tx in self.manager.tx_storage.indexes.mempool_tips.iter_all(self.manager.tx_storage)
        }
        assert tx_ok.hash in mempool_hashes

    def test_too_many_between_conflicts(self) -> None:
        lines = [f'tx0.out[{i}] <<< txN tx{i + 1}' for i in range(0, MAX_BETWEEN_CONFLICTS + 1)]
        orders = [f'tx{i + 1} < txN' for i in range(0, MAX_BETWEEN_CONFLICTS + 1)]
        newline = '\n'
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..30]
            b10 < dummy

            {newline.join(lines)}
            {newline.join(orders)}
        ''')
        artifacts.propagate_with(self.manager, up_to_before='txN')
        txN = artifacts.get_typed_vertex('txN', Transaction)

        # need to fix the timestamp to pass the old vertices mempool verification
        txN.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(txN)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(txN)
        assert isinstance(e.exception.__cause__, TooManyBetweenConflicts)

    def test_too_many_within_conflicts(self) -> None:
        tx_list = [f'tx{i + 1}' for i in range(0, MAX_WITHIN_CONFLICTS + 1)]
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..30]
            b10 < dummy

            tx0.out[0] <<< {' '.join(tx_list)}

            {' < '.join(tx_list)}
        ''')
        artifacts.propagate_with(self.manager, up_to_before=tx_list[-1])
        txN = artifacts.get_typed_vertex(tx_list[-1], Transaction)

        # need to fix the timestamp to pass the old vertices mempool verification
        txN.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(txN)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(txN)
        assert isinstance(e.exception.__cause__, TooManyWithinConflicts)

    @inlineCallbacks
    def test_checkpoints(self) -> Generator:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..30]
            blockchain b4 c[5..5]

            b30 < c5
        ''')

        checkpoints = []
        for height in [1, 5, 10, 15, 20]:
            blk = artifacts.get_typed_vertex(f'b{height}', Block)
            checkpoints.append(Checkpoint(height=height, hash=blk.hash))

        assert self._settings is not None
        new_settings = self._settings.model_copy(update={'CHECKPOINTS': checkpoints})
        manager2 = self.create_peer('unittests', settings=new_settings)
        assert [(cp.height, cp.hash) for cp in manager2.checkpoints] == [(cp.height, cp.hash) for cp in checkpoints]
        artifacts.propagate_with(manager2, up_to='b30')

        c5 = artifacts.get_typed_vertex('c5', Block)
        c5.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(c5)
        with self.assertRaises(InvalidNewTransaction) as e:
            yield manager2.vertex_handler.on_new_sync_block(c5, deps=[])
        assert isinstance(e.exception.__cause__, CheckpointError)

    def test_nano_header_seqnum(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..32]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx2.nc_id = tx1
            tx2.nc_method = nop()
            tx2.nc_address = wallet1
            tx2.nc_seqnum = {MAX_SEQNUM_DIFF_MEMPOOL}

            tx3.nc_id = tx1
            tx3.nc_method = nop()
            tx3.nc_address = wallet1
            tx3.nc_seqnum = {MAX_SEQNUM_DIFF_MEMPOOL - 1}

            b30 < tx2 < tx3

            tx1 <-- b30
        ''')
        artifacts.propagate_with(self.manager, up_to='b30')

        b30 = artifacts.get_typed_vertex('b30', Block)
        nc_block_storage = self.manager.tx_storage.get_nc_block_storage(b30)

        tx2 = artifacts.get_typed_vertex('tx2', Transaction)
        tx2.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx2)
        assert nc_block_storage.get_address_seqnum(tx2.get_nano_header().nc_address) == -1
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2)
        assert isinstance(e.exception.__cause__, NCInvalidSeqnum)

        tx3 = artifacts.get_typed_vertex('tx3', Transaction)
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)
        assert nc_block_storage.get_address_seqnum(tx3.get_nano_header().nc_address) == -1
        self.manager.vertex_handler.on_new_mempool_transaction(tx3)

    def test_nano_header_method_call_no_fallback(self) -> None:
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = test_blueprint1.py, TestBlueprint1

            tx1.nc_id = ocb1
            tx1.nc_method = initialize(0)

            tx2.nc_id = tx1
            tx2.nc_method = nop()

            b10 < ocb1 < b11 < tx1 < b12 < tx2

            ocb1 <-- b11
            tx1 <-- b12
            tx2 <-- b13
        ''')
        artifacts.propagate_with(self.manager, up_to_before='ocb1')

        # blueprint does not exist
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tx1_copy = Transaction.create_from_struct(bytes(tx1))
        tx1_copy.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx1_copy)
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx1_copy)
        assert isinstance(e.exception.__cause__, NCTxValidationError)
        assert isinstance(e.exception.__cause__.__cause__, BlueprintDoesNotExist)

        # ---

        artifacts.propagate_with(self.manager, up_to='ocb1')

        # blueprint exists but it hasn't been confirmed yet
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx1_copy)
        assert isinstance(e.exception.__cause__, NCTxValidationError)
        assert isinstance(e.exception.__cause__.__cause__, OCBBlueprintNotConfirmed)

        # ---

        artifacts.propagate_with(self.manager, up_to='b11')

        # wrong nc_method_args_bytes
        tx1_copy.get_nano_header().nc_args_bytes = b'\0'
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx1_copy)
        assert isinstance(e.exception.__cause__, NCTxValidationError)
        assert isinstance(e.exception.__cause__.__cause__, NCFail)
        assert isinstance(e.exception.__cause__.__cause__.__cause__, TypeError)
        assert str(e.exception.__cause__.__cause__.__cause__) == 'too few arguments'

        # ---

        # contract does not exist
        tx2 = artifacts.get_typed_vertex('tx2', Transaction)
        tx2_copy = Transaction.create_from_struct(bytes(tx2))
        tx2_copy.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx2_copy)
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2_copy)
        assert isinstance(e.exception.__cause__, NCTxValidationError)
        assert isinstance(e.exception.__cause__.__cause__, NanoContractDoesNotExist)

        # ---

        # contract exists at the mempool but it hasn't been confirmed yet
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2_copy)
        assert isinstance(e.exception.__cause__, NCTxValidationError)
        assert isinstance(e.exception.__cause__.__cause__, NanoContractDoesNotExist)

        # ---

        artifacts.propagate_with(self.manager, up_to='b12')

        assert tx1.get_metadata().first_block is not None
        assert tx1.get_metadata().voided_by is None
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        # ---

        # contract exists and has been confirmed
        # try to call a view method
        tx2_copy.get_nano_header().nc_method = 'view'
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2_copy)
        assert isinstance(e.exception.__cause__, NCInvalidMethodCall)
        assert str(e.exception.__cause__) == 'method `view` is not a public method'

        # try to call an non-existent method
        tx2_copy.get_nano_header().nc_method = 'non_existent'
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2_copy)
        assert isinstance(e.exception.__cause__, NCMethodNotFound)
        assert str(e.exception.__cause__) == 'method `non_existent` not found and no fallback is provided'

        # ---

        artifacts.propagate_with(self.manager)

        assert tx2.get_metadata().first_block is not None
        assert tx2.get_metadata().voided_by is None
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS

    def test_nano_header_method_call_fallback(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            tx1.nc_id = "{self.other_blueprint_id.hex()}"
            tx1.nc_method = initialize(0)

            tx2.nc_id = tx1
            tx2.nc_method = unknown
            tx2.nc_args_bytes = "00"

            b10 < ocb1 < b11 < tx1 < b12 < tx2

            ocb1 <-- b11
            tx1 <-- b12
            tx2 <-- b13
        ''')
        artifacts.propagate_with(self.manager, up_to='b12')

        # contract has been confirmed
        # try to call an non-existent method but it will be accepted because the blueprint has fallback
        tx2 = artifacts.get_typed_vertex('tx2', Transaction)
        tx2_copy = Transaction.create_from_struct(bytes(tx2))
        tx2_copy.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx2_copy)
        self.manager.vertex_handler.on_new_mempool_transaction(tx2_copy)

    def test_spending_utxo_confirmed_and_voided(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..32]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx2.nc_id = tx1
            tx2.nc_method = fail()
            tx2.out[0] <<< tx3

            tx1 <-- b30
            tx2 <-- b31

            b31 < tx3
        ''')
        artifacts.propagate_with(self.manager, up_to='b31')

        b31 = artifacts.get_typed_vertex('b31', Block)
        assert b31.get_metadata().voided_by is None

        tx2 = artifacts.get_typed_vertex('tx2', Transaction)
        assert tx2.get_metadata().first_block == b31.hash
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx2.get_metadata().voided_by is not None

        tx3 = artifacts.get_typed_vertex('tx3', Transaction)
        assert tx3.inputs[0].tx_id == tx2.hash

        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, InputVoidedAndConfirmed)

    def test_allowed_actions(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..32]
            b10 < dummy

            tx1.nc_id = "{self.other_blueprint_id.hex()}"
            tx1.nc_method = initialize()

            tx2.nc_id = tx1
            tx2.nc_method = nop()
            tx2.nc_deposit = 1 HTR

            tx3.nc_id = tx1
            tx3.nc_method = unknown
            tx3.nc_args_bytes = "00"
            tx3.nc_deposit = 1 HTR

            tx4.nc_id = tx1
            tx4.nc_method = nop()
            tx4.nc_withdrawal = 1 HTR

            tx5.nc_id = tx1
            tx5.nc_method = unknown
            tx5.nc_args_bytes = "00"
            tx5.nc_withdrawal = 1 HTR

            tx1 <-- b30

            b30 < tx2 < tx3
        ''')
        artifacts.propagate_with(self.manager, up_to='b30')

        b30 = artifacts.get_typed_vertex('b30', Block)
        assert b30.get_metadata().voided_by is None

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        assert tx1.get_metadata().first_block == b30.hash
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        tx2 = artifacts.get_typed_vertex('tx2', Transaction)
        tx2.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx2)
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2)
        assert isinstance(e.exception.__cause__, NCTxValidationError)
        assert isinstance(e.exception.__cause__.__cause__, NCForbiddenAction)
        assert 'nop' in str(e.exception.__cause__.__cause__)

        tx3 = artifacts.get_typed_vertex('tx3', Transaction)
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, NCTxValidationError)
        assert isinstance(e.exception.__cause__.__cause__, NCForbiddenAction)
        assert 'fallback' in str(e.exception.__cause__.__cause__)

        tx4 = artifacts.get_typed_vertex('tx4', Transaction)
        tx4.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx4)
        self.manager.vertex_handler.on_new_mempool_transaction(tx4)

        tx5 = artifacts.get_typed_vertex('tx5', Transaction)
        tx5.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx5)
        self.manager.vertex_handler.on_new_mempool_transaction(tx5)

    def test_unseen_fee_token_on_mempool(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy

            FBT.token_version = fee
            FBT.fee = 1 HTR

            tx.out[0] = 123 FBT
            tx.fee = 100 DBT
        ''')

        dbt, tx = artifacts.get_typed_vertices(('DBT', 'tx'), Transaction)

        assert tx.has_fees()
        fees = tx.get_fee_header().fees
        assert len(fees) == 1
        fee_entry = fees[0]
        assert tx.get_token_uid(fee_entry.token_index) == dbt.hash

        artifacts.propagate_with(self.manager, up_to_before='tx')
        tx.timestamp = int(self.manager.reactor.seconds())
        assert self.manager.vertex_handler.on_new_mempool_transaction(tx)
