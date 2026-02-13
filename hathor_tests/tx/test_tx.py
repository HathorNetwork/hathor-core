import base64
import hashlib
from math import isinf, isnan
from unittest.mock import Mock, patch

import pytest

from hathor.crypto.util import decode_address, get_address_from_public_key, get_private_key_from_bytes
from hathor.daa import TestMode
from hathor.exception import InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import MAX_OUTPUT_VALUE, Block, Transaction, TxInput, TxOutput, Vertex
from hathor.transaction.exceptions import (
    BlockWithInputs,
    ConflictingInputs,
    DuplicatedParents,
    IncorrectParents,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidInputDataSize,
    InvalidOutputScriptSize,
    InvalidOutputValue,
    ParentDoesNotExist,
    PowError,
    TimestampError,
    TooFewInputs,
    TooManyInputs,
    TooManyOutputs,
    TooManySigOps,
    TransactionDataError,
    WeightError,
)
from hathor.transaction.scripts import P2PKH, parse_address_script
from hathor.transaction.util import int_to_bytes
from hathor.transaction.validation_state import ValidationState
from hathor.transaction.vertex_parser import vertex_deserializer, vertex_serializer  # noqa: F401
from hathor.verification.verification_params import VerificationParams
from hathor.wallet import Wallet
from hathor_tests import unittest
from hathor_tests.utils import (
    add_blocks_unlock_reward,
    add_new_transactions,
    create_script_with_sigops,
    get_genesis_key,
)


class TransactionTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.wallet = Wallet()

        # this makes sure we can spend the genesis outputs
        self.manager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)
        self._verifiers = self.manager.verification_service.verifiers
        self.tx_storage = self.manager.tx_storage

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = blocks[-1]

        self.verification_params = VerificationParams.default_for_mempool(best_block=Mock())

    def test_input_output_match_less_htr(self):
        genesis_block = self.genesis_blocks[0]

        _input = TxInput(genesis_block.hash, 0, b'')

        # spend less than what was generated
        value = genesis_block.outputs[0].value - 1
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)
        tx = Transaction(inputs=[_input], outputs=[output], storage=self.tx_storage)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        best_block = self.manager.tx_storage.get_best_block()
        block_storage = self.manager.get_nc_block_storage(best_block)
        with self.assertRaises(InputOutputMismatch):
            self._verifiers.tx.verify_sum(self._settings, tx, tx.get_complete_token_info(block_storage))

    def test_input_output_match_more_htr(self):
        genesis_block = self.genesis_blocks[0]

        _input = TxInput(genesis_block.hash, 0, b'')

        # spend more than what was generated
        value = genesis_block.outputs[0].value + 1
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)
        tx = Transaction(inputs=[_input], outputs=[output], storage=self.tx_storage)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        best_block = self.manager.tx_storage.get_best_block()
        block_storage = self.manager.get_nc_block_storage(best_block)
        with self.assertRaises(InputOutputMismatch):
            self._verifiers.tx.verify_sum(self._settings, tx, tx.get_complete_token_info(block_storage))

    def test_validation(self):
        # add 100 blocks and check that walking through get_next_block_best_chain yields the same blocks
        blocks = add_new_blocks(self.manager, 100, advance_clock=1)
        iblocks = iter(blocks)
        block_from_chain = self.last_block
        for _ in range(100):
            block_from_list = next(iblocks)
            block_from_chain = block_from_chain.get_next_block_best_chain()
            self.assertEqual(block_from_chain, block_from_list)
            self.assertTrue(block_from_chain.has_basic_block_parent())
        self.assertEqual(block_from_chain.get_next_block_best_chain(), None)

    def test_script(self):
        genesis_block = self.genesis_blocks[0]

        # random keys to be used
        random_priv = 'MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgMnAHVIyj7Hym2yI' \
                      'w+JcKEfdCHByIp+FHfPoIkcnjqGyhRANCAATX76SGshGeoacUcZDhXEzERt' \
                      'AHbd30CVpUg8RRnAIhaFcuMY3G+YFr/mReAPRuiLKCnolWz3kCltTtNj36rJyd'
        private_key_random = get_private_key_from_bytes(base64.b64decode(random_priv))

        # create input data with incorrect private key
        _input = TxInput(genesis_block.hash, 0, b'')
        value = genesis_block.outputs[0].value

        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        tx = Transaction(inputs=[_input], outputs=[output], storage=self.tx_storage,
                         timestamp=self.last_block.timestamp + 1)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, private_key_random)
        data_wrong = P2PKH.create_input_data(public_bytes, signature)
        _input.data = data_wrong

        with self.assertRaises(InvalidInputData):
            self._verifiers.tx.verify_inputs(tx, params=self.verification_params)

    def test_too_many_inputs(self):
        random_bytes = bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902')

        _input = TxInput(random_bytes, 0, random_bytes)
        inputs = [_input] * (self._settings.MAX_NUM_INPUTS + 1)

        tx = Transaction(inputs=inputs, storage=self.tx_storage)

        with self.assertRaises(TooManyInputs):
            self._verifiers.tx.verify_number_of_inputs(tx)

    def test_no_inputs(self):
        tx = Transaction(inputs=[], storage=self.tx_storage)

        with self.assertRaises(TooFewInputs):
            self._verifiers.tx.verify_number_of_inputs(tx)

    def test_too_many_outputs(self):
        random_bytes = bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902')

        output = TxOutput(1, random_bytes)
        outputs = [output] * (self._settings.MAX_NUM_OUTPUTS + 1)

        tx = Transaction(outputs=outputs, storage=self.tx_storage)

        with self.assertRaises(TooManyOutputs):
            self._verifiers.vertex.verify_number_of_outputs(tx)

    def _gen_tx_spending_genesis_block(self):
        parents = [tx.hash for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        _input = TxInput(genesis_block.hash, 0, b'')

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        tx = Transaction(nonce=100, inputs=[_input], outputs=[output], parents=parents, storage=self.tx_storage)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)

        tx.update_hash()
        return tx

    def test_struct(self):
        tx = self._gen_tx_spending_genesis_block()
        data = tx.get_struct()
        tx_read = vertex_deserializer.deserialize(data)

        self.assertEqual(tx, tx_read)

    def test_children_update(self):
        tx = self._gen_tx_spending_genesis_block()
        tx.get_metadata().validation = ValidationState.FULL

        # get info before update
        old_children_sets = []
        for parent in tx.get_parents():
            old_children_sets.append(set(parent.get_children()))

        # update metadata
        tx.init_static_metadata_from_storage(self._settings, self.tx_storage)
        tx.update_initial_metadata()

        # genesis transactions should have only this tx in their children set
        for old_children, parent in zip(old_children_sets, tx.get_parents()):
            self.assertEqual(set(parent.get_children()) - old_children, {tx.hash})

    def test_block_inputs(self):
        # a block with inputs should be invalid
        parents = [tx.hash for tx in self.genesis]
        genesis_block = self.genesis_blocks[0]

        tx_inputs = [TxInput(genesis_block.hash, 0, b'')]

        address = get_address_from_public_key(self.genesis_public_key)
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [TxOutput(100, output_script)]

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.tx_storage)

        block.inputs = tx_inputs

        self.manager.cpu_mining_service.resolve(block)

        with self.assertRaises(BlockWithInputs):
            self.manager.verification_service.verify(block, self.get_verification_params(self.manager))

    def test_merge_mined_no_magic(self):
        from hathor.merged_mining import MAGIC_NUMBER
        from hathor.transaction.aux_pow import BitcoinAuxPow
        from hathor.transaction.exceptions import AuxPowNoMagicError
        from hathor.transaction.merge_mined_block import MergeMinedBlock

        parent_block = self.genesis_blocks[0].hash
        parent_txs = [tx.hash for tx in self.genesis_txs]
        parents = [parent_block, *parent_txs]
        address = decode_address(self.get_address(1))
        outputs = [TxOutput(100, P2PKH.create_output_script(address))]

        b = MergeMinedBlock(
            hash=b'some_hash',
            timestamp=self.genesis_blocks[0].timestamp + 1,
            weight=1,
            outputs=outputs,
            parents=parents,
            storage=self.tx_storage,
            aux_pow=BitcoinAuxPow(
                b'\x00' * 32,
                b'\x00' * 42,  # no MAGIC_NUMBER
                b'\x00' * 18,
                [b'\x00' * 32],
                b'\x00' * 12,
            )
        )

        b.init_static_metadata_from_storage(self._settings, self.tx_storage)
        with self.assertRaises(AuxPowNoMagicError):
            self._verifiers.merge_mined_block.verify_aux_pow(b)

        # adding the MAGIC_NUMBER makes it work:
        b.aux_pow = b.aux_pow._replace(coinbase_head=b.aux_pow.coinbase_head + MAGIC_NUMBER)
        self._verifiers.merge_mined_block.verify_aux_pow(b)

    def test_merge_mined_multiple_magic(self):
        from hathor.merged_mining import MAGIC_NUMBER
        from hathor.transaction.aux_pow import BitcoinAuxPow
        from hathor.transaction.exceptions import AuxPowUnexpectedMagicError
        from hathor.transaction.merge_mined_block import MergeMinedBlock

        parent_block = self.genesis_blocks[0].hash
        parent_txs = [tx.hash for tx in self.genesis_txs]
        parents = [parent_block, *parent_txs]
        address1 = decode_address(self.get_address(1))
        address2 = decode_address(self.get_address(2))
        assert address1 != address2
        outputs1 = [TxOutput(100, P2PKH.create_output_script(address1))]
        outputs2 = [TxOutput(100, P2PKH.create_output_script(address2))]

        b1 = MergeMinedBlock(
            hash=b'some_hash1',
            timestamp=self.genesis_blocks[0].timestamp + 1,
            weight=1,
            outputs=outputs1,
            parents=parents,
            storage=self.tx_storage,
        )

        b2 = MergeMinedBlock(
            hash=b'some_hash2',
            timestamp=self.genesis_blocks[0].timestamp + 1,
            weight=1,
            outputs=outputs2,
            parents=parents,
            storage=self.tx_storage,
        )

        assert b1.get_mining_base_hash() != b2.get_mining_base_hash()

        header_head = b'\x00' * 32
        header_tail = b'\x00' * 12
        merkle_path = [b'\x00' * 32]
        coinbase_parts = [
            b'\x00' * 42,
            MAGIC_NUMBER,
            b1.get_mining_base_hash(),
            MAGIC_NUMBER,
            b2.get_mining_base_hash(),
            b'\x00' * 18,
        ]

        b1.aux_pow = BitcoinAuxPow(
            header_head,
            b''.join(coinbase_parts[:2]),
            b''.join(coinbase_parts[3:]),
            merkle_path,
            header_tail,
        )

        b2.aux_pow = BitcoinAuxPow(
            header_head,
            b''.join(coinbase_parts[:4]),
            b''.join(coinbase_parts[5:]),
            merkle_path,
            header_tail,
        )

        assert bytes(b1) != bytes(b2)
        assert b1.calculate_hash() == b2.calculate_hash()

        b1.init_static_metadata_from_storage(self._settings, self.tx_storage)
        b2.init_static_metadata_from_storage(self._settings, self.tx_storage)
        self._verifiers.merge_mined_block.verify_aux_pow(b1)  # OK
        with self.assertRaises(AuxPowUnexpectedMagicError):
            self._verifiers.merge_mined_block.verify_aux_pow(b2)

    def test_merge_mined_long_merkle_path(self):
        from hathor.merged_mining import MAGIC_NUMBER
        from hathor.transaction.aux_pow import BitcoinAuxPow
        from hathor.transaction.exceptions import AuxPowLongMerklePathError
        from hathor.transaction.merge_mined_block import MergeMinedBlock

        parents = [tx.hash for tx in self.genesis]
        address = decode_address(self.get_address(1))
        outputs = [TxOutput(100, P2PKH.create_output_script(address))]

        patch_path = 'hathor.feature_activation.feature_service.FeatureService.is_feature_active'

        def is_feature_active_false(self: FeatureService, *, vertex: Vertex, feature: Feature) -> bool:
            assert feature == Feature.INCREASE_MAX_MERKLE_PATH_LENGTH
            return False

        def is_feature_active_true(self: FeatureService, *, vertex: Vertex, feature: Feature) -> bool:
            assert feature == Feature.INCREASE_MAX_MERKLE_PATH_LENGTH
            return True

        b = MergeMinedBlock(
            timestamp=self.genesis_blocks[0].timestamp + 1,
            weight=1,
            outputs=outputs,
            parents=parents,
            aux_pow=BitcoinAuxPow(
                b'\x00' * 32,
                b'\x00' * 42 + MAGIC_NUMBER,
                b'\x00' * 18,
                [b'\x00' * 32] * (self._settings.OLD_MAX_MERKLE_PATH_LENGTH + 1),  # 1 too long
                b'\x00' * 12,
            )
        )

        # Test with the INCREASE_MAX_MERKLE_PATH_LENGTH feature disabled
        with patch(patch_path, is_feature_active_false):
            with self.assertRaises(AuxPowLongMerklePathError):
                self._verifiers.merge_mined_block.verify_aux_pow(b)

            # removing one path makes it work
            b.aux_pow.merkle_path.pop()
            self._verifiers.merge_mined_block.verify_aux_pow(b)

        b2 = MergeMinedBlock(
            timestamp=self.genesis_blocks[0].timestamp + 1,
            weight=1,
            outputs=outputs,
            parents=parents,
            aux_pow=BitcoinAuxPow(
                b'\x00' * 32,
                b'\x00' * 42 + MAGIC_NUMBER,
                b'\x00' * 18,
                [b'\x00' * 32] * (self._settings.NEW_MAX_MERKLE_PATH_LENGTH + 1),  # 1 too long
                b'\x00' * 12,
            )
        )

        # Test with the INCREASE_MAX_MERKLE_PATH_LENGTH feature enabled
        with patch(patch_path, is_feature_active_true):
            with self.assertRaises(AuxPowLongMerklePathError):
                self._verifiers.merge_mined_block.verify_aux_pow(b2)

            # removing one path makes it work
            b2.aux_pow.merkle_path.pop()
            self._verifiers.merge_mined_block.verify_aux_pow(b2)

    def test_block_outputs(self):
        from hathor.transaction.exceptions import TooManyOutputs

        # a block should have no more than MAX_NUM_OUTPUTS outputs
        parents = [tx.hash for tx in self.genesis]

        address = get_address_from_public_key(self.genesis_public_key)
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [TxOutput(100, output_script)] * (self._settings.MAX_NUM_OUTPUTS + 1)

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.tx_storage)

        with self.assertRaises(TooManyOutputs):
            self._verifiers.vertex.verify_outputs(block)

    def test_tx_number_parents(self):
        genesis_block = self.genesis_blocks[0]

        _input = TxInput(genesis_block.hash, 0, b'')

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        parents = [self.genesis_txs[0].hash]
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents,
                         storage=self.tx_storage, timestamp=self.last_block.timestamp + 1)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)

        # in first test, only with 1 parent
        self.manager.cpu_mining_service.resolve(tx)
        tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        with self.assertRaises(IncorrectParents):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

        # test with 3 parents
        parents = [tx.hash for tx in self.genesis]
        tx.parents = parents
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(IncorrectParents):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

        # 2 parents, 1 tx and 1 block
        parents = [self.genesis_txs[0].hash, self.genesis_blocks[0].hash]
        tx.parents = parents
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(IncorrectParents):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_block_unknown_parent(self):
        address = get_address_from_public_key(self.genesis_public_key)
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [TxOutput(100, output_script)]

        # Random unknown parent
        parents = [hashlib.sha256().digest()]

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.tx_storage)

        self.manager.cpu_mining_service.resolve(block)
        with self.assertRaises(ParentDoesNotExist):
            self.manager.verification_service.verify(block, self.get_verification_params(self.manager))

    def test_block_number_parents(self):
        address = get_address_from_public_key(self.genesis_public_key)
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [TxOutput(100, output_script)]

        parents = [tx.hash for tx in self.genesis_txs]

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.tx_storage)

        self.manager.cpu_mining_service.resolve(block)
        with self.assertRaises(IncorrectParents):
            self.manager.verification_service.verify(block, self.get_verification_params(self.manager))

    def test_tx_inputs_out_of_range(self):
        # we'll try to spend output 3 from genesis transaction, which does not exist
        parents = [tx.hash for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        _input = TxInput(genesis_block.hash, len(genesis_block.outputs) + 1, b'')
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents, storage=self.tx_storage)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        data = P2PKH.create_input_data(public_bytes, signature)
        tx.inputs[0].data = data

        # test with an inexistent index
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InexistentInput):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

        # now with index equals of len of outputs
        _input = [TxInput(genesis_block.hash, len(genesis_block.outputs), data)]
        tx.inputs = _input
        # test with an inexistent index
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InexistentInput):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

        # now with inexistent tx hash
        random_bytes = bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902')
        _input = [TxInput(random_bytes, 3, data)]
        tx.inputs = _input
        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(InexistentInput):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_tx_inputs_conflict(self):
        # the new tx inputs will try to spend the same output
        parents = [tx.hash for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        # We can't only duplicate the value because genesis is using the max value possible
        outputs = [TxOutput(value, script), TxOutput(value, script)]

        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(weight=1, inputs=[_input, _input], outputs=outputs, parents=parents,
                         storage=self.tx_storage, timestamp=self.last_block.timestamp + 1)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        self.manager.cpu_mining_service.resolve(tx)
        with self.assertRaises(ConflictingInputs):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_regular_tx(self):
        # this should succeed
        parents = [tx.hash for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents,
                         storage=self.tx_storage, timestamp=self.last_block.timestamp + 1)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        self.manager.cpu_mining_service.resolve(tx)
        tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_tx_weight_too_high(self):
        parents = [tx.hash for tx in self.genesis_txs]
        outputs = [TxOutput(1, b'')]
        inputs = [TxInput(b'', 0, b'')]
        tx = Transaction(weight=1, inputs=inputs, outputs=outputs, parents=parents,
                         storage=self.tx_storage, timestamp=self.last_block.timestamp + 1)
        tx.weight = self.manager.daa.minimum_tx_weight(tx)
        tx.weight += self._settings.MAX_TX_WEIGHT_DIFF + 0.1
        tx.update_hash()
        with self.assertRaises(WeightError):
            self._verifiers.tx.verify_weight(tx)

    def test_weight_nan(self):
        # this should succeed
        parents = [tx.hash for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(inputs=[_input], outputs=[output], parents=parents, storage=self.tx_storage)
        tx.weight = float('NaN')

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        tx.update_hash()
        self.assertTrue(isnan(tx.weight))
        with self.assertRaises(WeightError):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_weight_inf(self):
        # this should succeed
        parents = [tx.hash for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(inputs=[_input], outputs=[output], parents=parents, storage=self.tx_storage)
        tx.weight = float('inf')

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        tx.update_hash()
        self.assertTrue(isinf(tx.weight))
        with self.assertRaises(WeightError):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_tx_duplicated_parents(self):
        # the new tx will confirm the same tx twice
        parents = [self.genesis_txs[0].hash, self.genesis_txs[0].hash]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents,
                         storage=self.tx_storage, timestamp=self.last_block.timestamp + 1)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        self.manager.cpu_mining_service.resolve(tx)
        tx.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        with self.assertRaises(DuplicatedParents):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_update_timestamp(self):
        parents = [tx for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        # update based on input
        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=[p.hash for p in parents],
                         storage=self.tx_storage)

        input_timestamp = genesis_block.timestamp

        max_ts = max(input_timestamp, parents[0].timestamp, parents[1].timestamp)
        tx.update_timestamp(0)
        self.assertEquals(tx.timestamp, max_ts + 1)

        ts = max_ts + 20
        tx.update_timestamp(ts)
        self.assertEquals(tx.timestamp, ts)

    def test_propagation_error(self):
        manager = self.create_peer('testnet', unlock_wallet=True)
        manager.daa.TEST_MODE = TestMode.DISABLED

        # 1. propagate genesis
        genesis_block = self.genesis_blocks[0]
        genesis_block.storage = manager.tx_storage
        with self.assertRaises(InvalidNewTransaction):
            manager.propagate_tx(genesis_block)

        # 2. propagate block with weight 1
        block = manager.generate_mining_block()
        block.weight = 1
        self.manager.cpu_mining_service.resolve(block)
        with self.assertRaises(InvalidNewTransaction):
            manager.propagate_tx(block)

        # 3. propagate block with wrong amount of tokens
        block = manager.generate_mining_block()
        output = TxOutput(1, block.outputs[0].script)
        block.outputs = [output]
        self.manager.cpu_mining_service.resolve(block)
        with self.assertRaises(InvalidNewTransaction):
            manager.propagate_tx(block)

        # 4. propagate block from the future
        block = manager.generate_mining_block()
        block.timestamp = int(self.clock.seconds()) + self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED + 100
        manager.cpu_mining_service.resolve(block, update_time=False)
        with self.assertRaises(InvalidNewTransaction):
            manager.propagate_tx(block)

    def test_tx_methods(self):
        blocks = add_new_blocks(self.manager, 2, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        txs = add_new_transactions(self.manager, 2, advance_clock=1)

        # Validate __str__, __bytes__, __eq__
        tx = txs[0]
        tx2 = txs[1]
        str_tx = str(tx)
        self.assertTrue(isinstance(str_tx, str))
        self.assertEqual(bytes(tx), tx.get_struct())

        tx_equal = vertex_deserializer.deserialize(tx.get_struct())
        self.assertTrue(tx == tx_equal)
        self.assertFalse(tx == tx2)

        tx2_hash = tx2.hash
        tx2.hash = None
        self.assertFalse(tx == tx2)
        tx2.hash = tx2_hash

        # Validate is_genesis without storage
        tx_equal.storage = None
        self.assertFalse(tx_equal.is_genesis)

        # Pow error
        self._verifiers.vertex.verify_pow(tx2)
        tx2.weight = 100
        with self.assertRaises(PowError):
            self._verifiers.vertex.verify_pow(tx2)

        # Verify parent timestamps
        self._verifiers.vertex.verify_parents(tx2)
        tx2_timestamp = tx2.timestamp
        tx2.timestamp = 2
        with self.assertRaises(TimestampError):
            self._verifiers.vertex.verify_parents(tx2)
        tx2.timestamp = tx2_timestamp

        # Verify inputs timestamps
        self._verifiers.tx.verify_inputs(tx2, params=self.verification_params)
        tx2.timestamp = 2
        with self.assertRaises(TimestampError):
            self._verifiers.tx.verify_inputs(tx2, params=self.verification_params)
        tx2.timestamp = tx2_timestamp

        # Validate maximum distance between blocks
        block = blocks[0]
        block2 = blocks[1]
        block2.timestamp = block.timestamp + self._settings.MAX_DISTANCE_BETWEEN_BLOCKS
        self._verifiers.vertex.verify_parents(block2)
        block2.timestamp += 1
        with self.assertRaises(TimestampError):
            self._verifiers.vertex.verify_parents(block2)

    def test_block_big_nonce(self):
        block = self.genesis_blocks[0]

        # Integer with more than 4 bytes of representation
        start = 1 << (8 * 12)
        end = start + 1 << (8*4)

        hash = self.manager.cpu_mining_service.start_mining(block, start=start, end=end)
        assert hash is not None

        block.hash = hash
        cloned_block = block.clone()

        assert cloned_block == block

    def test_block_data(self):
        def add_block_with_data(data: bytes = b'') -> None:
            add_new_blocks(self.manager, 1, advance_clock=1, block_data=data)[0]

        add_block_with_data()
        add_block_with_data(b'Testing, testing 1, 2, 3...')
        add_block_with_data(100*b'a')

        with pytest.raises(InvalidNewTransaction) as e:
            add_block_with_data(101*b'a')

        assert isinstance(e.value.__cause__, TransactionDataError)

    def test_output_serialization(self):
        from hathor.serialization.encoding.output_value import MAX_OUTPUT_VALUE_32
        from hathor.transaction.base_transaction import MAX_OUTPUT_VALUE
        from hathor.transaction.util import bytes_to_output_value, output_value_to_bytes
        max_32 = output_value_to_bytes(MAX_OUTPUT_VALUE_32)
        self.assertEqual(len(max_32), 4)
        value, buf = bytes_to_output_value(max_32)
        self.assertEqual(value, MAX_OUTPUT_VALUE_32)

        over_32 = output_value_to_bytes(MAX_OUTPUT_VALUE_32 + 1)
        self.assertEqual(len(over_32), 8)
        value, buf = bytes_to_output_value(over_32)
        self.assertEqual(value, MAX_OUTPUT_VALUE_32 + 1)

        max_64 = output_value_to_bytes(MAX_OUTPUT_VALUE)
        self.assertEqual(len(max_64), 8)
        value, buf = bytes_to_output_value(max_64)
        self.assertEqual(value, MAX_OUTPUT_VALUE)

    def test_output_value(self):
        from hathor.transaction.util import bytes_to_output_value

        # first test using a small output value with 8 bytes. It should fail
        parents = [tx.hash for tx in self.genesis_txs]
        outputs = [TxOutput(1, b'')]
        tx = Transaction(outputs=outputs, parents=parents)
        original_struct = tx.get_struct()
        struct_bytes = tx.get_funds_struct()

        # we'll get the struct without the last output bytes and add it ourselves
        struct_bytes = struct_bytes[:-7]
        # add small value using 8 bytes and expect failure when trying to deserialize
        struct_bytes += (-1).to_bytes(8, byteorder='big', signed=True)
        struct_bytes += int_to_bytes(0, 1)
        struct_bytes += int_to_bytes(0, 2)
        struct_bytes += tx.get_graph_struct()
        struct_bytes += int_to_bytes(tx.nonce, tx.SERIALIZATION_NONCE_SIZE)

        len_difference = len(struct_bytes) - len(original_struct)
        assert len_difference == 4, 'new struct is incorrect, len difference={}'.format(len_difference)

        with self.assertRaises(ValueError):
            vertex_deserializer.deserialize(struct_bytes)

        # now use 8 bytes and make sure it's working
        outputs = [TxOutput(MAX_OUTPUT_VALUE, b'')]
        tx = Transaction(outputs=outputs, parents=parents)
        tx.update_hash()
        original_struct = tx.get_struct()
        tx2 = vertex_deserializer.deserialize(original_struct)
        tx2.update_hash()
        assert tx == tx2

        # Validating that all output values must be positive
        value = 1
        address = decode_address('WUDtnw3GYjvUnZmiHAmus6hhs9GoSUSJMG')
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)
        output.value = -1
        random_bytes = bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902')
        _input = TxInput(random_bytes, 0, random_bytes)
        tx = Transaction(inputs=[_input], outputs=[output], parents=parents, storage=self.tx_storage)
        with self.assertRaises(InvalidOutputValue):
            self.manager.cpu_mining_service.resolve(tx)

        # 'Manually resolving', to validate verify method
        tx.hash = bytes.fromhex('012cba011be3c29f1c406f9015e42698b97169dbc6652d1f5e4d5c5e83138858')
        with self.assertRaises(InvalidOutputValue):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

        # Invalid output value
        invalid_output = bytes.fromhex('ffffffff')
        with self.assertRaises(InvalidOutputValue):
            bytes_to_output_value(invalid_output)

        # Can't instantiate an output with negative value
        with self.assertRaises(InvalidOutputValue):
            TxOutput(-1, script)

    def test_tx_version_and_signal_bits(self):
        from hathor.transaction.base_transaction import TxVersion

        # test invalid type
        with self.assertRaises(AssertionError) as cm:
            TxVersion('test')

        self.assertEqual(str(cm.exception), "Value 'test' must be an integer")

        # test one byte max value
        with self.assertRaises(AssertionError) as cm:
            TxVersion(0x100)

        self.assertEqual(str(cm.exception), 'Value 0x100 must not be larger than one byte')

        # test invalid version
        with self.assertRaises(ValueError) as cm:
            TxVersion(10)

        self.assertEqual(str(cm.exception), 'Invalid version: 10')

        # test get the correct class
        version = TxVersion(0x00)
        self.assertEqual(version.get_cls(), Block)
        version = TxVersion(0x01)
        self.assertEqual(version.get_cls(), Transaction)

        # test Block.__init__() fails
        with self.assertRaises(AssertionError) as cm:
            Block(signal_bits=0x100)

        self.assertEqual(str(cm.exception), 'signal_bits 0x100 must not be larger than one byte')

        with self.assertRaises(AssertionError) as cm:
            Block(version=0x200)

        self.assertEqual(str(cm.exception), 'version 0x200 must not be larger than one byte')

        # test serialization doesn't mess up with version
        genesis_block = self.genesis_blocks[0]
        block = Block(
            signal_bits=0xF0,
            version=TxVersion.REGULAR_BLOCK,
            nonce=100,
            weight=1,
            parents=[genesis_block.hash]
        )
        block2 = block.clone()
        self.assertEqual(block.signal_bits, block2.signal_bits)
        self.assertEqual(block.version, block2.version)

    def test_output_sum_ignore_authority(self):
        # sum of tx outputs should ignore authority outputs
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output1 = TxOutput(5, script)   # regular utxo
        output2 = TxOutput(30, script, 0b10000001)   # authority utxo
        output3 = TxOutput(3, script)   # regular utxo
        tx = Transaction(outputs=[output1, output2, output3], storage=self.tx_storage)

        self.assertEqual(8, tx.sum_outputs)

    def _test_txout_script_limit(self, offset):
        genesis_block = self.genesis_blocks[0]
        _input = TxInput(genesis_block.hash, 0, b'')

        value = genesis_block.outputs[0].value
        script = b'*' * (self._settings.MAX_OUTPUT_SCRIPT_SIZE + offset)
        _output = TxOutput(value, script)

        tx = Transaction(inputs=[_input], outputs=[_output], storage=self.tx_storage)
        self._verifiers.vertex.verify_outputs(tx)
        self._verifiers.tx.verify_output_token_indexes(tx)

    def test_txout_script_limit_exceeded(self):
        with self.assertRaises(InvalidOutputScriptSize):
            self._test_txout_script_limit(offset=1)

    def test_txout_script_limit_success(self):
        self._test_txout_script_limit(offset=-1)
        self._test_txout_script_limit(offset=0)

    def _test_txin_data_limit(self, offset):
        genesis_block = self.genesis_blocks[0]
        data = b'*' * (self._settings.MAX_INPUT_DATA_SIZE + offset)
        _input = TxInput(genesis_block.hash, 0, data)

        value = genesis_block.outputs[0].value
        _output = TxOutput(value, b'')

        tx = Transaction(
            timestamp=int(self.manager.reactor.seconds()) + 1,
            inputs=[_input],
            outputs=[_output],
            storage=self.tx_storage
        )
        self._verifiers.tx.verify_inputs(tx, skip_script=True, params=self.verification_params)

    def test_txin_data_limit_exceeded(self):
        with self.assertRaises(InvalidInputDataSize):
            self._test_txin_data_limit(offset=1)

    def test_txin_data_limit_success(self):
        add_blocks_unlock_reward(self.manager)
        self._test_txin_data_limit(offset=-1)
        self._test_txin_data_limit(offset=0)

    def test_wallet_index(self):
        # First transaction: send tokens to output with address=address_b58
        parents = [tx.hash for tx in self.genesis_txs]
        genesis_block = self.genesis_blocks[0]

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script)

        address_b58 = parse_address_script(script).address
        # Get how many transactions wallet index already has for this address
        wallet_index_count = len(self.tx_storage.indexes.addresses.get_from_address(address_b58))

        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents,
                         storage=self.tx_storage, timestamp=self.last_block.timestamp + 1)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        self.manager.cpu_mining_service.resolve(tx)
        self.manager.propagate_tx(tx)

        # This transaction has an output to address_b58, so we need one more element on the index
        self.assertEqual(len(self.tx_storage.indexes.addresses.get_from_address(address_b58)), wallet_index_count + 1)

        # Second transaction: spend tokens from output with address=address_b58 and
        # send tokens to 2 outputs, one with address=address_b58 and another one
        # with address=new_address_b58, which is an address of a random wallet
        new_address_b58 = self.get_address(0)
        new_address = decode_address(new_address_b58)

        output1 = TxOutput(value - 100, script)
        script2 = P2PKH.create_output_script(new_address)
        output2 = TxOutput(100, script2)

        input1 = TxInput(tx.hash, 0, b'')
        tx2 = Transaction(weight=1, inputs=[input1], outputs=[output1, output2], parents=parents,
                          storage=self.tx_storage, timestamp=self.last_block.timestamp + 2)

        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        input1.data = P2PKH.create_input_data(public_bytes, signature)

        self.manager.cpu_mining_service.resolve(tx2)
        self.manager.propagate_tx(tx2)

        # tx2 has two outputs, for address_b58 and new_address_b58
        # So we must have one more element on address_b58 index and only one on new_address_b58
        self.assertEqual(len(self.tx_storage.indexes.addresses.get_from_address(address_b58)), wallet_index_count + 2)
        self.assertEqual(len(self.tx_storage.indexes.addresses.get_from_address(new_address_b58)), 1)

        # Third transaction: spend tokens from output with address=address_b58 and send
        # tokens to a new address = output3_address_b58, which is from a random wallet
        output3_address_b58 = self.get_address(1)
        output3_address = decode_address(output3_address_b58)
        script3 = P2PKH.create_output_script(output3_address)
        output3 = TxOutput(value-100, script3)

        input2 = TxInput(tx2.hash, 0, b'')
        tx3 = Transaction(weight=1, inputs=[input2], outputs=[output3], parents=parents,
                          storage=self.tx_storage, timestamp=self.last_block.timestamp + 3)

        data_to_sign = tx3.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        input2.data = P2PKH.create_input_data(public_bytes, signature)

        self.manager.cpu_mining_service.resolve(tx3)
        self.manager.propagate_tx(tx3)

        # tx3 has one output, for another new address (output3_address_b58) and it's spending an output of address_b58
        # So address_b58 index must have one more element and output3_address_b58 should have one element also
        # new_address_b58 was not spent neither received tokens, so didn't change
        self.assertEqual(len(self.tx_storage.indexes.addresses.get_from_address(address_b58)), wallet_index_count + 3)
        self.assertEqual(len(self.tx_storage.indexes.addresses.get_from_address(output3_address_b58)), 1)
        self.assertEqual(len(self.tx_storage.indexes.addresses.get_from_address(new_address_b58)), 1)

    def test_sighash_cache(self):
        from unittest import mock

        from hathor.transaction.vertex_parser import _transaction

        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(5, script)
        tx = Transaction(outputs=[output], storage=self.tx_storage)

        original = _transaction.serialize_tx_sighash
        with mock.patch.object(_transaction, 'serialize_tx_sighash', wraps=original) as mocked:
            for _ in range(10):
                tx.get_sighash_all()

            mocked.assert_called_once()

    def test_sighash_data_cache(self):
        from unittest import mock

        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(5, script)
        tx = Transaction(outputs=[output], storage=self.tx_storage)

        with mock.patch('hathor.transaction.vertex_parser.vertex_serializer.hashlib') as mocked:
            mocked.sha256.return_value.digest.return_value = b'\x00' * 32
            for _ in range(10):
                tx.get_sighash_all_data()

            mocked.sha256.assert_called_once()

    def test_sigops_output_single_above_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        _input = TxInput(genesis_block.hash, 0, b'')

        hscript = create_script_with_sigops(self._settings.MAX_TX_SIGOPS_OUTPUT + 1)
        output1 = TxOutput(value, hscript)
        tx = Transaction(inputs=[_input], outputs=[output1], storage=self.tx_storage)
        tx.update_hash()
        # This calls verify to ensure that verify_sigops_output is being called on verify
        with self.assertRaises(TooManySigOps):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_sigops_output_multi_above_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        _input = TxInput(genesis_block.hash, 0, b'')
        num_outputs = 5

        hscript = create_script_with_sigops((self._settings.MAX_TX_SIGOPS_OUTPUT + num_outputs) // num_outputs)
        output2 = TxOutput(value, hscript)
        tx = Transaction(inputs=[_input], outputs=[output2]*num_outputs, storage=self.tx_storage)
        tx.update_hash()
        with self.assertRaises(TooManySigOps):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_sigops_output_single_below_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        _input = TxInput(genesis_block.hash, 0, b'')

        hscript = create_script_with_sigops(self._settings.MAX_TX_SIGOPS_OUTPUT - 1)
        output3 = TxOutput(value, hscript)
        tx = Transaction(inputs=[_input], outputs=[output3], storage=self.tx_storage)
        tx.update_hash()
        self._verifiers.vertex.verify_sigops_output(tx)

    def test_sigops_output_multi_below_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        _input = TxInput(genesis_block.hash, 0, b'')
        num_outputs = 5

        hscript = create_script_with_sigops((self._settings.MAX_TX_SIGOPS_OUTPUT - 1) // num_outputs)
        output4 = TxOutput(value, hscript)
        tx = Transaction(inputs=[_input], outputs=[output4]*num_outputs, storage=self.tx_storage)
        tx.update_hash()
        self._verifiers.vertex.verify_sigops_output(tx)

    def test_sigops_input_single_above_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        _output = TxOutput(value, script)

        hscript = create_script_with_sigops(self._settings.MAX_TX_SIGOPS_INPUT + 1)
        input1 = TxInput(genesis_block.hash, 0, hscript)
        tx = Transaction(inputs=[input1], outputs=[_output], storage=self.tx_storage)
        tx.update_hash()
        with self.assertRaises(TooManySigOps):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_sigops_input_multi_above_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        _output = TxOutput(value, script)
        num_inputs = 5

        hscript = create_script_with_sigops((self._settings.MAX_TX_SIGOPS_INPUT + num_inputs) // num_inputs)
        input2 = TxInput(genesis_block.hash, 0, hscript)
        tx = Transaction(inputs=[input2]*num_inputs, outputs=[_output], storage=self.tx_storage)
        tx.update_hash()
        with self.assertRaises(TooManySigOps):
            self.manager.verification_service.verify(tx, self.get_verification_params(self.manager))

    def test_sigops_input_single_below_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        _output = TxOutput(value, script)

        hscript = create_script_with_sigops(self._settings.MAX_TX_SIGOPS_INPUT - 1)
        input3 = TxInput(genesis_block.hash, 0, hscript)
        tx = Transaction(inputs=[input3], outputs=[_output], storage=self.tx_storage)
        tx.update_hash()
        self._verifiers.tx.verify_sigops_input(tx)

    def test_sigops_input_multi_below_limit(self) -> None:
        genesis_block = self.genesis_blocks[0]
        value = genesis_block.outputs[0].value - 1
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        _output = TxOutput(value, script)
        num_inputs = 5

        hscript = create_script_with_sigops((self._settings.MAX_TX_SIGOPS_INPUT - 1) // num_inputs)
        input4 = TxInput(genesis_block.hash, 0, hscript)
        tx = Transaction(inputs=[input4]*num_inputs, outputs=[_output], storage=self.tx_storage)
        tx.update_hash()
        self._verifiers.tx.verify_sigops_input(tx)

    def test_compare_bytes_equal(self) -> None:
        # create some block
        [block1] = add_new_blocks(self.manager, 1, advance_clock=1)

        # clone it to make sure we have a new instance
        block2 = block1.clone()

        # the storage already has block1 and should correctly return True
        self.assertTrue(self.tx_storage.compare_bytes_with_local_tx(block2))

    def test_compare_bytes_different(self) -> None:
        # create some block
        [block1] = add_new_blocks(self.manager, 1, advance_clock=1)

        # clone it and change something, doesn't matter what it is
        # XXX: note the hash is not being update on purpose, we expect a failure even if the hash hasn't changed
        block2 = block1.clone()
        block2.weight += 1

        # the storage already has block1 and should correctly return False
        self.assertFalse(self.tx_storage.compare_bytes_with_local_tx(block2))

    def test_compare_bytes_partially_validated_equal(self) -> None:
        from hathor.transaction.validation_state import ValidationState

        # create some block, make it partially valid and save it
        [block1] = add_new_blocks(self.manager, 1, advance_clock=1)
        block1.set_validation(ValidationState.BASIC)
        with self.tx_storage.allow_partially_validated_context():
            self.tx_storage.save_transaction(block1)

        # clone it to make sure we have a new instance
        block2 = block1.clone()

        # the storage already has block1 and should correctly return True
        self.assertTrue(self.tx_storage.compare_bytes_with_local_tx(block2))

    def test_compare_bytes_partially_validated_different(self) -> None:
        from hathor.transaction.validation_state import ValidationState

        # create some block, make it partially valid and save it
        [block1] = add_new_blocks(self.manager, 1, advance_clock=1)
        block1.set_validation(ValidationState.BASIC)
        with self.tx_storage.allow_partially_validated_context():
            self.tx_storage.save_transaction(block1)

        # clone it and change something, doesn't matter what it is
        # XXX: note the hash is not being update on purpose, we expect a failure even if the hash hasn't changed
        block2 = block1.clone()
        block2.weight += 1

        # the storage already has block1 and should correctly return False
        self.assertFalse(self.tx_storage.compare_bytes_with_local_tx(block2))
