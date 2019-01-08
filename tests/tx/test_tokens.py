from tests import unittest
import os
import json
import base64

from hathor.transaction import Transaction, Block, TxInput, TxOutput
from hathor.transaction.exceptions import InputOutputMismatch, BlockWithTokensError, InvalidToken
from hathor.transaction.scripts import P2PKH
from hathor.crypto.util import get_private_key_from_bytes, get_public_key_from_bytes, get_address_from_public_key

from twisted.internet.task import Clock

import time


class TokenTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet', unlock_wallet=True)
        self.clock = Clock()
        self.clock.advance(time.time())
        self.manager.reactor = self.clock

        self.genesis = self.manager.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        self.address_b58 = self.manager.wallet.get_unused_address()
        self.address = self.manager.wallet.decode_address(self.address_b58)

        # read genesis keys
        filepath = os.path.join(os.getcwd(), 'hathor/wallet/genesis_keys.json')
        dict_data = None
        with open(filepath, 'r') as json_file:
            dict_data = json.loads(json_file.read())
        b64_private_key = dict_data['private_key']
        b64_public_key = dict_data['public_key']
        private_key_bytes = base64.b64decode(b64_private_key)
        public_key_bytes = base64.b64decode(b64_public_key)
        self.genesis_private_key = get_private_key_from_bytes(private_key_bytes)
        self.genesis_public_key = get_public_key_from_bytes(public_key_bytes)

    def _create_token(self):
        """Creates a new token and propagates a tx with the following UTXOs:
        1. some tokens (already mint some tokens so they can be transferred);
        2. mint authority;
        3. melt authority;

        :return: the propagated transaction so others can spend their outputs
        """
        genesis_block = self.genesis_blocks[0]
        wallet = self.manager.wallet

        _input1 = TxInput(genesis_block.hash, 0, b'')

        script = P2PKH.create_output_script(self.address)
        value = genesis_block.outputs[0].value
        output = TxOutput(value, script, 0)

        parents = [tx.hash for tx in self.genesis_txs]
        tx = Transaction(
            weight=1,
            inputs=[_input1],
            parents=parents,
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )

        # create token
        token_masks = TxOutput.TOKEN_CREATION_MASK | TxOutput.TOKEN_MINT_MASK | TxOutput.TOKEN_MELT_MASK
        new_token_uid = tx.create_token_uid(0)
        tx.tokens.append(new_token_uid)
        token_output = TxOutput(token_masks, script, 0b10000001)

        # finish and propagate tx
        tx.outputs = [token_output, output]
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        tx.verify()
        self.manager.propagate_tx(tx)
        self.clock.advance(8)

        # mint tokens
        parents = self.manager.get_new_tx_parents()
        _input1 = TxInput(tx.hash, 0, b'')
        # mint 300 tokens
        token_output1 = TxOutput(300, script, 0b00000001)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        token_output3 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output1, token_output2, token_output3],
            parents=parents,
            tokens=[new_token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx2.resolve()
        tx2.verify()
        self.manager.propagate_tx(tx2)
        self.clock.advance(8)
        return tx2

    def test_tokens_in_block(self):
        # a block with tokens should be invalid
        parents = [tx.hash for tx in self.genesis]
        genesis_block = self.genesis_blocks[0]

        address = get_address_from_public_key(self.genesis_public_key)
        output_script = P2PKH.create_output_script(address)
        tx_outputs = [
            TxOutput(100, output_script, 1)
        ]

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            height=genesis_block.height+1,
            weight=1,               # low weight so we don't waste time with PoW
            storage=self.manager.tx_storage
        )

        block.tokens = [bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')]
        block.resolve()
        with self.assertRaises(BlockWithTokensError):
            block.verify()

        block.tokens = []
        block.resolve()
        with self.assertRaises(BlockWithTokensError):
            block.verify()

    def test_tx_token_outputs(self):
        genesis_block = self.genesis_blocks[0]

        _input = TxInput(genesis_block.hash, 0, b'')

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script, 1)

        parents = [tx.hash for tx in self.genesis_txs]
        tx = Transaction(
            weight=1,
            inputs=[_input],
            outputs=[output],
            parents=parents,
            storage=self.manager.tx_storage
        )

        # no token uids in list
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

        # with 1 token uid in list
        tx.tokens = [bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')]
        output.token_data = 2
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

        # try hathor authority UTXO
        output = TxOutput(value, script, 0b10000000)
        tx.outputs = [output]
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

    def test_token_uid_creation(self):
        genesis_block = self.genesis_blocks[0]

        _input = TxInput(genesis_block.hash, 0, b'')

        value = genesis_block.outputs[0].value
        address = get_address_from_public_key(self.genesis_public_key)
        script = P2PKH.create_output_script(address)
        output = TxOutput(value, script, 0)

        parents = [tx.hash for tx in self.genesis_txs]
        tx = Transaction(
            weight=1,
            inputs=[_input],
            parents=parents,
            storage=self.manager.tx_storage
        )

        # incorrect token uid
        new_token_uid = bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')
        tx.tokens = [new_token_uid]
        token_output = TxOutput(TxOutput.TOKEN_CREATION_MASK, script, 0b10000001)
        tx.outputs = [token_output, output]
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

        # token creation with no corresponding input
        new_token_uid = tx.create_token_uid(0)
        tx.tokens = [new_token_uid]
        token_output = TxOutput(TxOutput.TOKEN_CREATION_MASK, script, 0b10000001)
        tx.outputs = [output, token_output]
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

        # token creation without creation flag
        new_token_uid = tx.create_token_uid(0)
        tx.tokens = [new_token_uid]
        token_output = TxOutput(TxOutput.TOKEN_MINT_MASK | TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        tx.outputs = [token_output, output]
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

        # correct token uid
        new_token_uid = tx.create_token_uid(0)
        tx.tokens = [new_token_uid]
        token_output = TxOutput(TxOutput.TOKEN_CREATION_MASK, script, 0b10000001)
        tx.outputs = [token_output, output]
        data_to_sign = tx.get_sighash_all(clear_input_data=True)
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        tx.verify()

    def test_token_transfer(self):
        wallet = self.manager.wallet
        tx = self._create_token()
        token_uid = tx.tokens[0]
        utxo = tx.outputs[0]

        parents = self.manager.get_new_tx_parents()
        _input1 = TxInput(tx.hash, 0, b'')
        script = P2PKH.create_output_script(self.address)

        # regular transfer
        token_output = TxOutput(utxo.value, script, 1)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx2.resolve()
        tx2.verify()

        # missing tokens
        token_output = TxOutput(utxo.value - 1, script, 1)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx3.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx3.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx3.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx3.verify()

    def test_token_mint(self):
        wallet = self.manager.wallet
        tx = self._create_token()
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # mint tokens and transfer mint authority
        _input1 = TxInput(tx.hash, 1, b'')
        token_output1 = TxOutput(10000000, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output1, token_output2],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx2.resolve()
        tx2.verify()

        # try to mint using melt authority UTXO
        _input1 = TxInput(tx.hash, 2, b'')
        token_output = TxOutput(10000000, script, 1)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx3.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx3.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx3.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx3.verify()

    def test_token_melt(self):
        wallet = self.manager.wallet
        tx = self._create_token()
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 2, b'')
        token_output1 = TxOutput(tx.outputs[0].value - 1, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx2.inputs[0].data = data
        tx2.inputs[1].data = data
        tx2.resolve()
        tx2.verify()

        # try to melt using mint authority UTXO
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 1, b'')
        token_output = TxOutput(tx.outputs[0].value - 1, script, 1)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx3.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx3.inputs[0].data = data
        tx3.inputs[1].data = data
        tx3.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx3.verify()

    def test_token_transfer_authority(self):
        wallet = self.manager.wallet
        tx = self._create_token()
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # input with mint and output with melt
        _input1 = TxInput(tx.hash, 1, b'')
        token_output = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx2.resolve()
        with self.assertRaises(InvalidToken):
            tx2.verify()

        # input with melt and output with mint
        _input1 = TxInput(tx.hash, 2, b'')
        token_output = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx3.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx3.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx3.resolve()
        with self.assertRaises(InvalidToken):
            tx3.verify()


if __name__ == '__main__':
    unittest.main()
