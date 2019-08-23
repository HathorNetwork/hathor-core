from hathor.crypto.util import decode_address
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import BlockWithTokensError, InputOutputMismatch, InvalidToken
from hathor.transaction.scripts import P2PKH
from hathor.transaction.util import get_deposit_amount, get_withdraw_amount
from tests import unittest
from tests.utils import create_tokens, get_genesis_key


class TokenTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)

        self.genesis = self.manager.tx_storage.get_all_genesis()
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        self.address_b58 = self.manager.wallet.get_unused_address()
        self.address = decode_address(self.address_b58)

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

    def test_tokens_in_block(self):
        # a block with tokens should be invalid
        parents = [tx.hash for tx in self.genesis]

        output_script = P2PKH.create_output_script(self.address)
        tx_outputs = [TxOutput(100, output_script, 1)]

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.manager.tx_storage)

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
        script = P2PKH.create_output_script(self.address)
        output = TxOutput(value, script, 1)

        parents = [tx.hash for tx in self.genesis_txs]
        tx = Transaction(weight=1, inputs=[_input], outputs=[output], parents=parents, storage=self.manager.tx_storage)

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
        script = P2PKH.create_output_script(self.address)
        output = TxOutput(value, script, 0)

        parents = [tx.hash for tx in self.genesis_txs]
        tx = Transaction(weight=1, inputs=[_input], parents=parents, storage=self.manager.tx_storage)

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
        tx = create_tokens(self.manager, self.address_b58)
        token_uid = tx.tokens[0]
        utxo = tx.outputs[0]

        parents = self.manager.get_new_tx_parents()
        _input1 = TxInput(tx.hash, 0, b'')
        script = P2PKH.create_output_script(self.address)

        # regular transfer
        token_output = TxOutput(utxo.value, script, 1)
        tx2 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx2.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx2.resolve()
        tx2.verify()

        # missing tokens
        token_output = TxOutput(utxo.value - 1, script, 1)
        tx3 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx3.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx3.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx3.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx3.verify()

    def test_token_mint(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # mint tokens and transfer mint authority
        mint_amount = 10000000
        deposit_amount = get_deposit_amount(mint_amount)
        _input1 = TxInput(tx.hash, 1, b'')
        _input2 = TxInput(tx.hash, 3, b'')
        token_output1 = TxOutput(mint_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        deposit_output = TxOutput(tx.outputs[3].value - deposit_amount, script, 0)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, deposit_output],
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
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # check tokens index
        tokens_index = self.manager.tx_storage.tokens_index.tokens[token_uid]
        self.assertIn((tx2.hash, 1), tokens_index.mint)
        self.assertIn((tx.hash, 2), tokens_index.melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(tokens_index.mint))
        self.assertEqual(1, len(tokens_index.melt))
        # check total amount of tokens
        self.assertEqual(500 + mint_amount, tokens_index.total)

        # try to mint 1 token unit without deposit
        mint_amount = 1
        _input1 = TxInput(tx.hash, 1, b'')
        token_output1 = TxOutput(mint_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1],
            outputs=[token_output1, token_output2],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx3.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx3.inputs[0].data = data
        tx3.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx3.verify()

        # try to mint and deposit less tokens than necessary
        mint_amount = 10000000
        deposit_amount = get_deposit_amount(mint_amount) - 1
        _input1 = TxInput(tx.hash, 1, b'')
        _input2 = TxInput(tx.hash, 3, b'')
        token_output1 = TxOutput(mint_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        deposit_output = TxOutput(tx.outputs[3].value - deposit_amount, script, 0)
        tx4 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, deposit_output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx4.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx4.inputs[0].data = data
        tx4.inputs[1].data = data
        tx4.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx4.verify()

        # try to mint using melt authority UTXO
        _input1 = TxInput(tx.hash, 2, b'')
        token_output = TxOutput(10000000, script, 1)
        tx5 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx5.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx5.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx5.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx5.verify()

    def test_token_melt(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # melt tokens and transfer melt authority
        melt_amount = 100
        new_amount = tx.outputs[0].value - melt_amount
        withdraw_amount = get_withdraw_amount(melt_amount)
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 2, b'')
        token_output1 = TxOutput(new_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        withdraw_output = TxOutput(withdraw_amount, script, 0)
        tx2 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, withdraw_output],
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
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # check tokens index
        tokens_index = self.manager.tx_storage.tokens_index.tokens[token_uid]
        self.assertIn((tx.hash, 1), tokens_index.mint)
        self.assertIn((tx2.hash, 1), tokens_index.melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(tokens_index.mint))
        self.assertEqual(1, len(tokens_index.melt))
        # check total amount of tokens
        self.assertEqual(new_amount, tokens_index.total)

        # melt tokens and withdraw more than what's allowed
        melt_amount = 100
        withdraw_amount = get_withdraw_amount(melt_amount)
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 2, b'')
        token_output1 = TxOutput(tx.outputs[0].value - melt_amount, script, 1)
        token_output2 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        withdraw_output = TxOutput(withdraw_amount + 1, script, 0)
        tx3 = Transaction(
            weight=1,
            inputs=[_input1, _input2],
            outputs=[token_output1, token_output2, withdraw_output],
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

        # try to melt using mint authority UTXO
        _input1 = TxInput(tx.hash, 0, b'')
        _input2 = TxInput(tx.hash, 1, b'')
        token_output = TxOutput(tx.outputs[0].value - 1, script, 1)
        tx4 = Transaction(weight=1, inputs=[_input1, _input2], outputs=[token_output], parents=parents,
                          tokens=[token_uid], storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx4.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx4.inputs[0].data = data
        tx4.inputs[1].data = data
        tx4.resolve()
        with self.assertRaises(InputOutputMismatch):
            tx4.verify()

    def test_token_transfer_authority(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # input with mint and output with melt
        _input1 = TxInput(tx.hash, 1, b'')
        token_output = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        tx2 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx2.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx2.resolve()
        with self.assertRaises(InvalidToken):
            tx2.verify()

        # input with melt and output with mint
        _input1 = TxInput(tx.hash, 2, b'')
        token_output = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        tx3 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx3.get_sighash_all(clear_input_data=True)
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx3.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx3.resolve()
        with self.assertRaises(InvalidToken):
            tx3.verify()

    def test_token_index_with_conflict(self, mint_amount=0):
        # create a new token and have a mint operation done. The tx that mints the
        # tokens has the following outputs:
        # 0. minted tokens
        # 1. mint authority;
        # 2. melt authority
        tx = create_tokens(self.manager, self.address_b58, mint_amount=100)
        token_uid = tx.tokens[0]
        tokens_index = self.manager.tx_storage.tokens_index.tokens[token_uid]
        self.assertIn((tx.hash, 1), tokens_index.mint)
        self.assertIn((tx.hash, 2), tokens_index.melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(tokens_index.mint))
        self.assertEqual(1, len(tokens_index.melt))
        # check total amount of tokens
        self.assertEqual(100, tokens_index.total)

        # create conflicting tx by changing parents
        tx2 = Transaction.create_from_struct(tx.get_struct())
        tx2.parents = [tx.parents[1], tx.parents[0]]
        tx2.weight = 3
        tx2.resolve()
        self.assertNotEqual(tx.hash, tx2.hash)
        self.assertTrue(tx2.weight > tx.weight)

        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # new tx should be on tokens index. Old tx should not be present
        self.assertIn((tx2.hash, 1), tokens_index.mint)
        self.assertIn((tx2.hash, 2), tokens_index.melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(tokens_index.mint))
        self.assertEqual(1, len(tokens_index.melt))
        # should have same number of tokens
        self.assertEqual(100, tokens_index.total)


if __name__ == '__main__':
    unittest.main()
