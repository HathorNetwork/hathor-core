from struct import error as StructError

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import BlockWithTokensError, InputOutputMismatch, InvalidToken, TransactionDataError
from hathor.transaction.scripts import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.util import get_deposit_amount, get_withdraw_amount, int_to_bytes
from tests import unittest
from tests.utils import add_blocks_unlock_reward, create_tokens, get_genesis_key

settings = HathorSettings()


class TokenTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)

        self.genesis = list(self.manager.tx_storage.get_all_genesis())
        self.genesis.sort(key=lambda t: t.timestamp)
        self.genesis_blocks = [tx for tx in self.genesis if tx.is_block]
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

        self.address_b58 = self.manager.wallet.get_unused_address()
        self.address = decode_address(self.address_b58)

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # add some blocks so we can spend the genesis outputs
        add_blocks_unlock_reward(self.manager)

    def test_tokens_in_block(self):
        # a block with token index > 1 should be invalid
        parents = [tx.hash for tx in self.genesis]

        output_script = P2PKH.create_output_script(self.address)
        tx_outputs = [TxOutput(100, output_script, 1)]

        block = Block(
            nonce=100,
            outputs=tx_outputs,
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.manager.tx_storage)

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
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

        # with 1 token uid in list
        tx.tokens = [bytes.fromhex('0023be91834c973d6a6ddd1a0ae411807b7c8ef2a015afb5177ee64b666ce602')]
        output.token_data = 2
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
            tx.verify()

        # try hathor authority UTXO
        output = TxOutput(value, script, 0b10000000)
        tx.outputs = [output]
        data_to_sign = tx.get_sighash_all()
        public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
        tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx.resolve()
        with self.assertRaises(InvalidToken):
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
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        tx2.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
        tx2.resolve()
        tx2.verify()

        # missing tokens
        token_output = TxOutput(utxo.value - 1, script, 1)
        tx3 = Transaction(weight=1, inputs=[_input1], outputs=[token_output], parents=parents, tokens=[token_uid],
                          storage=self.manager.tx_storage, timestamp=int(self.clock.seconds()))
        data_to_sign = tx3.get_sighash_all()
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
        data_to_sign = tx2.get_sighash_all()
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
        data_to_sign = tx3.get_sighash_all()
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
        data_to_sign = tx4.get_sighash_all()
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
        data_to_sign = tx5.get_sighash_all()
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
        data_to_sign = tx2.get_sighash_all()
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
        data_to_sign = tx3.get_sighash_all()
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
        data_to_sign = tx4.get_sighash_all()
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
        data_to_sign = tx2.get_sighash_all()
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
        data_to_sign = tx3.get_sighash_all()
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
        # 3. HTR deposit change
        tx = create_tokens(self.manager, self.address_b58, mint_amount=100)
        token_uid = tx.tokens[0]
        tokens_index = self.manager.tx_storage.tokens_index.tokens[tx.tokens[0]]
        self.assertIn((tx.hash, 1), tokens_index.mint)
        self.assertIn((tx.hash, 2), tokens_index.melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(tokens_index.mint))
        self.assertEqual(1, len(tokens_index.melt))
        # check total amount of tokens
        self.assertEqual(100, tokens_index.total)

        # new tx minting tokens
        mint_amount = 300
        deposit_amount = get_deposit_amount(mint_amount)
        script = P2PKH.create_output_script(self.address)
        # inputs
        mint_input = TxInput(tx.hash, 1, b'')
        melt_input = TxInput(tx.hash, 2, b'')
        deposit_input = TxInput(tx.hash, 3, b'')
        # outputs
        mint_output = TxOutput(mint_amount, script, 1)
        authority_output1 = TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001)
        authority_output2 = TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001)
        deposit_output = TxOutput(tx.outputs[3].value - deposit_amount, script, 0)
        tx2 = Transaction(
            weight=1,
            inputs=[mint_input, melt_input, deposit_input],
            outputs=[authority_output1, authority_output2, mint_output, deposit_output],
            parents=self.manager.get_new_tx_parents(),
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        # sign inputs
        wallet = self.manager.wallet
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx2.inputs[0].data = data
        tx2.inputs[1].data = data
        tx2.inputs[2].data = data
        tx2.resolve()
        tx2.verify()
        self.manager.propagate_tx(tx2)
        self.run_to_completion()

        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(tokens_index.mint))
        self.assertEqual(1, len(tokens_index.melt))
        self.assertIn((tx2.hash, 0), tokens_index.mint)
        self.assertIn((tx2.hash, 1), tokens_index.melt)
        # check total amount of tokens has been updated
        self.assertEqual(400, tokens_index.total)

        # create conflicting tx by changing parents
        tx3 = Transaction.create_from_struct(tx2.get_struct())
        tx3.parents = [tx.parents[1], tx.parents[0]]
        tx3.weight = 3
        tx3.resolve()
        self.assertNotEqual(tx3.hash, tx2.hash)
        self.assertTrue(tx3.weight > tx2.weight)
        self.manager.propagate_tx(tx3)
        self.run_to_completion()

        # new tx should be on tokens index. Old tx should not be present
        self.assertIn((tx3.hash, 0), tokens_index.mint)
        self.assertIn((tx3.hash, 1), tokens_index.melt)
        # there should only be one element on the indexes for the token
        self.assertEqual(1, len(tokens_index.mint))
        self.assertEqual(1, len(tokens_index.melt))
        # should have same amount of tokens
        self.assertEqual(400, tokens_index.total)

    def test_token_info(self):
        def update_tx(tx):
            """ sighash_all data changes with token name or symbol, so we have to compute signature again
            """
            data_to_sign = tx.get_sighash_all()
            public_bytes, signature = self.manager.wallet.get_input_aux_data(data_to_sign, self.genesis_private_key)
            tx.inputs[0].data = P2PKH.create_input_data(public_bytes, signature)
            tx.resolve()

        # test token name and symbol
        tx = create_tokens(self.manager, self.address_b58)

        # max token name length
        tx.token_name = 'a' * settings.MAX_LENGTH_TOKEN_NAME
        update_tx(tx)
        tx.verify()

        # max token symbol length
        tx.token_symbol = 'a' * settings.MAX_LENGTH_TOKEN_SYMBOL
        update_tx(tx)
        tx.verify()

        # long token name
        tx.token_name = 'a' * (settings.MAX_LENGTH_TOKEN_NAME + 1)
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            tx.verify()

        # long token symbol
        tx.token_name = 'ValidName'
        tx.token_symbol = 'a' * (settings.MAX_LENGTH_TOKEN_SYMBOL + 1)
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            tx.verify()

        # Hathor token name
        tx.token_name = settings.HATHOR_TOKEN_NAME
        tx.token_symbol = 'TST'
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            tx.verify()

        # Hathor token symbol
        tx.token_name = 'Test'
        tx.token_symbol = settings.HATHOR_TOKEN_SYMBOL
        update_tx(tx)
        with self.assertRaises(TransactionDataError):
            tx.verify()

        # Token name unicode
        tx.token_name = 'Test ∞'
        tx.token_symbol = 'TST'
        token_info = tx.serialize_token_info()
        TokenCreationTransaction.deserialize_token_info(token_info)
        update_tx(tx)
        tx.verify()

        # Token symbol unicode
        tx.token_name = 'Test Token'
        tx.token_symbol = 'TST∞'
        token_info = tx.serialize_token_info()
        TokenCreationTransaction.deserialize_token_info(token_info)
        update_tx(tx)
        tx.verify()

    def test_token_mint_zero(self):
        # try to mint 0 tokens
        with self.assertRaises(InvalidToken):
            create_tokens(self.manager, self.address_b58, mint_amount=0)

    def test_token_struct(self):
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        tx2 = TokenCreationTransaction.create_from_struct(tx.get_struct())
        self.assertEqual(tx.hash, tx2.hash)

    def test_unknown_authority(self):
        wallet = self.manager.wallet
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        token_uid = tx.tokens[0]
        parents = self.manager.get_new_tx_parents()
        script = P2PKH.create_output_script(self.address)

        # try an unknown authority
        input1 = TxInput(tx.hash, 1, b'')
        input2 = TxInput(tx.hash, 2, b'')
        output = TxOutput((TxOutput.ALL_AUTHORITIES << 1), script, 0b10000001)
        tx2 = Transaction(
            weight=1,
            inputs=[input1, input2],
            outputs=[output],
            parents=parents,
            tokens=[token_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds())
        )
        data_to_sign = tx2.get_sighash_all()
        public_bytes, signature = wallet.get_input_aux_data(data_to_sign, wallet.get_private_key(self.address_b58))
        data = P2PKH.create_input_data(public_bytes, signature)
        tx2.inputs[0].data = data
        tx2.inputs[1].data = data
        tx2.resolve()
        with self.assertRaises(InvalidToken):
            tx2.verify()

    def test_token_info_serialization(self):
        tx = create_tokens(self.manager, self.address_b58, mint_amount=500)
        info = tx.serialize_token_info()
        # try with version 2
        info2 = bytes([0x02]) + info[1:]
        with self.assertRaises(ValueError):
            TokenCreationTransaction.deserialize_token_info(info2)

    def test_token_info_not_utf8(self):
        token_name = 'TestCoin'
        token_symbol = 'TST'

        # Token version 1; Name length; Name; Symbol length; Symbol
        bytes1 = (bytes([0x01]) + int_to_bytes(len(token_name), 1) + token_name.encode('utf-8')
                  + int_to_bytes(len(token_symbol), 1) + token_symbol.encode('utf-8'))

        name, symbol, _ = TokenCreationTransaction.deserialize_token_info(bytes1)

        self.assertEqual(name, token_name)
        self.assertEqual(symbol, token_symbol)

        encoded_name = token_name.encode('utf-16')
        bytes2 = (bytes([0x01]) + int_to_bytes(len(encoded_name), 1) + encoded_name
                  + int_to_bytes(len(token_symbol), 1) + token_symbol.encode('utf-8'))

        with self.assertRaises(StructError):
            TokenCreationTransaction.deserialize_token_info(bytes2)

        encoded_symbol = token_symbol.encode('utf-16')
        bytes3 = (bytes([0x01]) + int_to_bytes(len(token_name), 1) + token_name.encode('utf-8')
                  + int_to_bytes(len(encoded_symbol), 1) + encoded_symbol)

        with self.assertRaises(StructError):
            TokenCreationTransaction.deserialize_token_info(bytes3)

    def test_block_with_htr_authority(self):
        parents = [tx.hash for tx in self.genesis]

        output_script = P2PKH.create_output_script(self.address)
        output = TxOutput(0b11, output_script, 0b10000000)
        self.assertTrue(output.is_token_authority())

        block = Block(
            nonce=100,
            outputs=[output],
            parents=parents,
            weight=1,  # low weight so we don't waste time with PoW
            storage=self.manager.tx_storage)

        block.resolve()
        with self.assertRaises(InvalidToken):
            block.verify()


if __name__ == '__main__':
    unittest.main()
