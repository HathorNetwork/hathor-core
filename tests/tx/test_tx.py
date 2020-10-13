import base64
import hashlib
from math import isinf, isnan

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_address_from_public_key, get_private_key_from_bytes
from hathor.manager import TestMode
from hathor.transaction import MAX_NUM_INPUTS, MAX_NUM_OUTPUTS, MAX_OUTPUT_VALUE, Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import (
    BlockWithInputs,
    ConflictingInputs,
    DuplicatedParents,
    IncorrectParents,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidOutputValue,
    NoInputError,
    ParentDoesNotExist,
    PowError,
    TimestampError,
    TooManyInputs,
    TooManyOutputs,
    TransactionDataError,
    WeightError,
)
from hathor.transaction.scripts import P2PKH, parse_address_script
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.transaction.util import int_to_bytes
from hathor.wallet import Wallet
from tests import unittest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, add_new_transactions, get_genesis_key

settings = HathorSettings()


class BasicTransaction(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.wallet = Wallet()
        self.tx_storage = TransactionMemoryStorage()
        self.genesis = self.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # this makes sure we can spend the genesis outputs
        self.manager = self.create_peer('testnet', tx_storage=self.tx_storage, unlock_wallet=True, wallet_index=True)
        blocks = add_blocks_unlock_reward(self.manager)
        self.last_block = blocks[-1]

    def test_input_output_match(self):
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

        with self.assertRaises(InputOutputMismatch):
            tx.verify_sum()

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
            tx.verify_inputs()

    def test_too_many_inputs(self):
        random_bytes = bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902')

        _input = TxInput(random_bytes, 0, random_bytes)
        inputs = [_input] * (MAX_NUM_INPUTS + 1)

        tx = Transaction(inputs=inputs, storage=self.tx_storage)

        with self.assertRaises(TooManyInputs):
            tx.verify_number_of_inputs()

    def test_no_inputs(self):
        tx = Transaction(inputs=[], storage=self.tx_storage)

        with self.assertRaises(NoInputError):
            tx.verify_number_of_inputs()

    def test_too_many_outputs(self):
        random_bytes = bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902')

        output = TxOutput(1, random_bytes)
        outputs = [output] * (MAX_NUM_OUTPUTS + 1)

        tx = Transaction(outputs=outputs, storage=self.tx_storage)

        with self.assertRaises(TooManyOutputs):
            tx.verify_number_of_outputs()

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
        tx_read = Transaction.create_from_struct(data)

        self.assertEqual(tx, tx_read)

    def test_children_update(self):
        tx = self._gen_tx_spending_genesis_block()

        # get info before update
        children_len = []
        for parent in tx.get_parents():
            metadata = parent.get_metadata()
            children_len.append(len(metadata.children))

        # update metadata
        tx.update_initial_metadata()

        # genesis transactions should have only this tx in their children set
        for old_len, parent in zip(children_len, tx.get_parents()):
            metadata = parent.get_metadata()
            self.assertEqual(len(metadata.children) - old_len, 1)
            self.assertEqual(metadata.children.pop(), tx.hash)

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

        block.resolve()

        with self.assertRaises(BlockWithInputs):
            block.verify()

    def test_block_outputs(self):
        from hathor.transaction import MAX_NUM_OUTPUTS
        from hathor.transaction.exceptions import TooManyOutputs

        # a block should have no more than MAX_NUM_OUTPUTS outputs
        parents = [tx.hash for tx in self.genesis]

        address = get_address_from_public_key(self.genesis_public_key)
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [TxOutput(100, output_script)] * (MAX_NUM_OUTPUTS + 1)

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.tx_storage)

        with self.assertRaises(TooManyOutputs):
            block.verify_outputs()

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
        tx.resolve()
        with self.assertRaises(IncorrectParents):
            tx.verify()

        # test with 3 parents
        parents = [tx.hash for tx in self.genesis]
        tx.parents = parents
        tx.resolve()
        with self.assertRaises(IncorrectParents):
            tx.verify()

        # 2 parents, 1 tx and 1 block
        parents = [self.genesis_txs[0].hash, self.genesis_blocks[0].hash]
        tx.parents = parents
        tx.resolve()
        with self.assertRaises(IncorrectParents):
            tx.verify()

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

        block.resolve()
        with self.assertRaises(ParentDoesNotExist):
            block.verify()

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

        block.resolve()
        with self.assertRaises(IncorrectParents):
            block.verify()

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
        tx.resolve()
        with self.assertRaises(InexistentInput):
            tx.verify()

        # now with index equals of len of outputs
        _input = [TxInput(genesis_block.hash, len(genesis_block.outputs), data)]
        tx.inputs = _input
        # test with an inexistent index
        tx.resolve()
        with self.assertRaises(InexistentInput):
            tx.verify()

        # now with inexistent tx hash
        random_bytes = bytes.fromhex('0000184e64683b966b4268f387c269915cc61f6af5329823a93e3696cb0fe902')
        _input = [TxInput(random_bytes, 3, data)]
        tx.inputs = _input
        tx.resolve()
        with self.assertRaises(InexistentInput):
            tx.verify()

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

        tx.resolve()
        with self.assertRaises(ConflictingInputs):
            tx.verify()

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

        tx.resolve()
        tx.verify()

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
            tx.verify()

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
            tx.verify()

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

        tx.resolve()
        with self.assertRaises(DuplicatedParents):
            tx.verify()

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
        manager.test_mode = TestMode.DISABLED

        # 1. propagate genesis
        genesis_block = self.genesis_blocks[0]
        genesis_block.storage = manager.tx_storage
        self.assertFalse(manager.propagate_tx(genesis_block))

        # 2. propagate block with weight 1
        block = manager.generate_mining_block()
        block.weight = 1
        block.resolve()
        self.assertFalse(manager.propagate_tx(block))

        # 3. propagate block with wrong amount of tokens
        block = manager.generate_mining_block()
        output = TxOutput(1, block.outputs[0].script)
        block.outputs = [output]
        block.resolve()
        self.assertFalse(manager.propagate_tx(block))

        # 4. propagate block from the future
        block = manager.generate_mining_block()
        block.timestamp = int(self.clock.seconds()) + settings.MAX_FUTURE_TIMESTAMP_ALLOWED + 100
        block.resolve(update_time=False)
        self.assertFalse(manager.propagate_tx(block))

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

        tx_equal = Transaction.create_from_struct(tx.get_struct())
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
        tx2.verify_pow()
        tx2.weight = 100
        with self.assertRaises(PowError):
            tx2.verify_pow()

        # Verify parent timestamps
        tx2.verify_parents()
        tx2_timestamp = tx2.timestamp
        tx2.timestamp = 2
        with self.assertRaises(TimestampError):
            tx2.verify_parents()
        tx2.timestamp = tx2_timestamp

        # Verify inputs timestamps
        tx2.verify_inputs()
        tx2.timestamp = 2
        with self.assertRaises(TimestampError):
            tx2.verify_inputs()
        tx2.timestamp = tx2_timestamp

        # Validate maximum distance between blocks
        block = blocks[0]
        block2 = blocks[1]
        block2.timestamp = block.timestamp + settings.MAX_DISTANCE_BETWEEN_BLOCKS
        block2.verify_parents()
        block2.timestamp += 1
        with self.assertRaises(TimestampError):
            block2.verify_parents()

    def test_block_big_nonce(self):
        block = self.genesis_blocks[0]

        # Integer with more than 4 bytes of representation
        start = 1 << (8 * 12)
        end = start + 1 << (8*4)

        hash = block.start_mining(start, end)
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
        with self.assertRaises(TransactionDataError):
            add_block_with_data(101*b'a')

    def test_output_serialization(self):
        from hathor.transaction.base_transaction import (
            _MAX_OUTPUT_VALUE_32,
            MAX_OUTPUT_VALUE,
            bytes_to_output_value,
            output_value_to_bytes,
        )
        max_32 = output_value_to_bytes(_MAX_OUTPUT_VALUE_32)
        self.assertEqual(len(max_32), 4)
        value, buf = bytes_to_output_value(max_32)
        self.assertEqual(value, _MAX_OUTPUT_VALUE_32)

        over_32 = output_value_to_bytes(_MAX_OUTPUT_VALUE_32 + 1)
        self.assertEqual(len(over_32), 8)
        value, buf = bytes_to_output_value(over_32)
        self.assertEqual(value, _MAX_OUTPUT_VALUE_32 + 1)

        max_64 = output_value_to_bytes(MAX_OUTPUT_VALUE)
        self.assertEqual(len(max_64), 8)
        value, buf = bytes_to_output_value(max_64)
        self.assertEqual(value, MAX_OUTPUT_VALUE)

    def test_output_value(self):
        from hathor.transaction.base_transaction import bytes_to_output_value

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
            Transaction.create_from_struct(struct_bytes)

        # now use 8 bytes and make sure it's working
        outputs = [TxOutput(MAX_OUTPUT_VALUE, b'')]
        tx = Transaction(outputs=outputs, parents=parents)
        tx.update_hash()
        original_struct = tx.get_struct()
        tx2 = Transaction.create_from_struct(original_struct)
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
            tx.resolve()

        # 'Manually resolving', to validate verify method
        tx.hash = bytes.fromhex('012cba011be3c29f1c406f9015e42698b97169dbc6652d1f5e4d5c5e83138858')
        with self.assertRaises(InvalidOutputValue):
            tx.verify()

        # Invalid output value
        invalid_output = bytes.fromhex('ffffffff')
        with self.assertRaises(InvalidOutputValue):
            bytes_to_output_value(invalid_output)

        # Can't instantiate an output with negative value
        with self.assertRaises(AssertionError):
            TxOutput(-1, script)

    def test_tx_version(self):
        from hathor.transaction.base_transaction import TxVersion

        # test the 1st byte of version field is ignored
        version = TxVersion(0xFF00)
        self.assertEqual(version.get_cls(), Block)
        version = TxVersion(0xFF01)
        self.assertEqual(version.get_cls(), Transaction)

        # test serialization doesn't mess up with version
        block = Block(
            version=0xFF00,
            nonce=100,
            weight=1)
        block2 = block.clone()
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

    def _spend_reward_tx(self, manager, reward_block):
        value = reward_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        input_ = TxInput(reward_block.hash, 0, b'')
        output = TxOutput(value, script)
        tx = Transaction(
            weight=1,
            timestamp=int(manager.reactor.seconds()) + 1,
            inputs=[input_],
            outputs=[output],
            parents=manager.get_new_tx_parents(),
            storage=manager.tx_storage,
        )
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        input_.data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        return tx

    def test_reward_lock(self):
        from hathor.transaction.exceptions import RewardLocked

        # add block with a reward we can spend
        reward_block = self.manager.generate_mining_block(address=get_address_from_public_key(self.genesis_public_key))
        reward_block.resolve()
        self.assertTrue(self.manager.propagate_tx(reward_block))
        # reward cannot be spent while not enough blocks are added
        for _ in range(settings.REWARD_SPEND_MIN_BLOCKS):
            tx = self._spend_reward_tx(self.manager, reward_block)
            with self.assertRaises(RewardLocked):
                tx.verify()
            add_new_blocks(self.manager, 1, advance_clock=1)
        # now it should be spendable
        tx = self._spend_reward_tx(self.manager, reward_block)
        self.assertTrue(self.manager.propagate_tx(tx, fails_silently=False))

    def test_reward_lock_timestamp(self):
        from hathor.transaction.exceptions import RewardLocked

        # add block with a reward we can spend
        reward_block = self.manager.generate_mining_block(address=get_address_from_public_key(self.genesis_public_key))
        reward_block.resolve()
        self.assertTrue(self.manager.propagate_tx(reward_block))

        # we add enough blocks that this output could be spent based on block height
        blocks = add_blocks_unlock_reward(self.manager)

        # tx timestamp is equal to the block that unlock the spent rewards. It should
        # be greater, so it'll fail
        tx = self._spend_reward_tx(self.manager, reward_block)
        tx.timestamp = blocks[-1].timestamp
        tx.resolve()
        with self.assertRaises(RewardLocked):
            tx.verify()

        # we can fix it be incrementing the timestamp
        tx._height_cache = None
        tx.timestamp = blocks[-1].timestamp + 1
        tx.resolve()
        tx.verify()

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
        wallet_index_count = len(self.tx_storage.wallet_index.index[address_b58])

        _input = TxInput(genesis_block.hash, 0, b'')
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents,
                         storage=self.tx_storage, timestamp=self.last_block.timestamp + 1)

        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        _input.data = P2PKH.create_input_data(public_bytes, signature)

        tx.resolve()
        self.manager.propagate_tx(tx)

        # This transaction has an output to address_b58, so we need one more element on the index
        self.assertEqual(len(self.tx_storage.wallet_index.index[address_b58]), wallet_index_count + 1)

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

        tx2.resolve()
        self.manager.propagate_tx(tx2)

        # tx2 has two outputs, for address_b58 and new_address_b58
        # So we must have one more element on address_b58 index and only one on new_address_b58
        self.assertEqual(len(self.tx_storage.wallet_index.index[address_b58]), wallet_index_count + 2)
        self.assertEqual(len(self.tx_storage.wallet_index.index[new_address_b58]), 1)

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

        tx3.resolve()
        self.manager.propagate_tx(tx3)

        # tx3 has one output, for another new address (output3_address_b58) and it's spending an output of address_b58
        # So address_b58 index must have one more element and output3_address_b58 should have one element also
        # new_address_b58 was not spent neither received tokens, so didn't change
        self.assertEqual(len(self.tx_storage.wallet_index.index[address_b58]), wallet_index_count + 3)
        self.assertEqual(len(self.tx_storage.wallet_index.index[output3_address_b58]), 1)
        self.assertEqual(len(self.tx_storage.wallet_index.index[new_address_b58]), 1)

    def test_sighash_cache(self):
        from unittest import mock

        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(5, script)
        tx = Transaction(outputs=[output], storage=self.tx_storage)

        with mock.patch('hathor.transaction.transaction.bytearray') as mocked:
            for _ in range(10):
                tx.get_sighash_all()

            mocked.assert_called_once()

    def test_sighash_data_cache(self):
        from unittest import mock

        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(5, script)
        tx = Transaction(outputs=[output], storage=self.tx_storage)

        with mock.patch('hathor.transaction.transaction.hashlib') as mocked:
            for _ in range(10):
                tx.get_sighash_all_data()

            mocked.sha256.assert_called_once()


if __name__ == '__main__':
    unittest.main()
