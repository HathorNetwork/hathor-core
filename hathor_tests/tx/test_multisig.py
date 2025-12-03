import base58

from hathor.crypto.util import decode_address, get_private_key_from_bytes, get_public_key_bytes_compressed
from hathor.exception import InvalidNewTransaction
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import ScriptError
from hathor.transaction.scripts import P2PKH, MultiSig, create_output_script, parse_address_script, script_eval
from hathor.wallet.base_wallet import WalletBalance, WalletOutputInfo
from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script, generate_signature
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


class MultisigTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.network = 'testnet'
        self.manager = self.create_peer(self.network, unlock_wallet=True)

        self.public_keys = [
            bytes.fromhex('0250bf5890c9c6e9b4ab7f70375d31b827d45d0b7b4e3ba1918bcbe71b412c11d7'),
            bytes.fromhex('02d83dd1e9e0ac7976704eedab43fe0b79309166a47d70ec3ce8bbb08b8414db46'),
            bytes.fromhex('02358c539fa7474bf12f774749d0e1b5a9bc6e50920464818ebdb0043b143ae2ba')
        ]

        self.private_keys = [
            '3081de304906092a864886f70d01050d303c301b06092a864886f70d01050c300e04089abeae5e8a8f75d302020800301d060960'
            '864801650304012a0410abbde27221fd302280c13fca7887c85e048190c41403f39b1e9bbc5b6b7c3be4729c054fae9506dc0f83'
            '61adcff0ea393f0bb3ca9f992fc2eea83d532691bc9a570ed7fb9e939e6d1787881af40b19fb467f06595229e29b5a6268d831f0'
            '287530c7935d154deac61dd4ced988166f9c98054912935b607e2fb332e11c95b30ea4686eb0bda7dd57ed1eeb25b07cea9669dd'
            'e5210528a00653159626a5baa61cdee7f4',
            '3081de304906092a864886f70d01050d303c301b06092a864886f70d01050c300e040817ca6c6c47ade0de02020800301d060960'
            '864801650304012a041003746599b1d7dde5b875e4d8e2c4c157048190a25ccabb17e603260f8a1407bdca24904b6ae0aa9ae225'
            'd87552e5a9aa62d98b35b2c6c78f33cb051f3a3932387b4cea6f49e94f14ee856d0b630d77c1299ad7207b0be727d338cf92a3ff'
            'fe232aff59764240aff84e079a5f6fb3355048ac15703290a005a9a033fdcb7fcf582a5ddf6fd7b7c1193bd7912cd275a88a8a68'
            '23b6c3ed291b4a3f4724875a3ae058054c',
            '3081de304906092a864886f70d01050d303c301b06092a864886f70d01050c300e0408089f48fbf59fa92902020800301d060960'
            '864801650304012a041072f553e860b77654fd5fb80e5891e7c90481900fde272b88f9a70e7220b2d5adeda1ed29667527caedc2'
            '385be7f9e0d63defdde20557e90726e102f879eaf2233cceca8d4af239d5b2a159467255446f001c99b69e570bb176b95248fc21'
            'cb752d463b494c2195411639989086336a530d1f4eae91493faf89368f439991baa947ebeca00be7f5099ed69606dc78a4cc384d'
            '41542350a9054c5fa1295305dfc37e5989'
        ]

        self.redeem_script = generate_multisig_redeem_script(2, self.public_keys)

        self.multisig_address_b58 = generate_multisig_address(self.redeem_script)
        self.multisig_address = decode_address(self.multisig_address_b58)
        self.address = decode_address(self.manager.wallet.get_unused_address())
        self.outside_address = decode_address(self.get_address(0))

    def test_spend_multisig(self):
        # Adding funds to the wallet
        blocks = add_new_blocks(self.manager, 2, advance_clock=15)
        add_blocks_unlock_reward(self.manager)
        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, sum(blk.outputs[0].value for blk in blocks)))

        first_block_amount = blocks[0].outputs[0].value

        # First we send tokens to a multisig address
        outputs = [
            WalletOutputInfo(address=self.multisig_address, value=first_block_amount,
                             timelock=int(self.clock.seconds()) + 15)
        ]

        tx1 = self.manager.wallet.prepare_transaction_compute_inputs(Transaction, outputs, self.manager.tx_storage)
        tx1.weight = 10
        tx1.parents = self.manager.get_new_tx_parents()
        tx1.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx1)
        self.manager.propagate_tx(tx1)
        self.clock.advance(10)

        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, first_block_amount))

        # Then we create a new tx that spends this tokens from multisig wallet
        tx = Transaction.create_from_struct(tx1.get_struct())
        tx.weight = 10
        tx.parents = self.manager.get_new_tx_parents()
        tx.timestamp = int(self.clock.seconds())

        multisig_script = create_output_script(self.multisig_address)

        multisig_output = TxOutput(200, multisig_script)
        wallet_output = TxOutput(300, create_output_script(self.address))
        outside_output = TxOutput(first_block_amount - 200 - 300, create_output_script(self.outside_address))

        tx.outputs = [multisig_output, wallet_output, outside_output]

        tx_input = TxInput(tx1.hash, 0, b'')
        tx.inputs = [tx_input]

        signatures = []
        for private_key_hex in self.private_keys[:2]:
            signature = generate_signature(tx, bytes.fromhex(private_key_hex), password=b'1234')
            signatures.append(signature)

        input_data = MultiSig.create_input_data(self.redeem_script, signatures)
        tx.inputs[0].data = input_data

        self.manager.cpu_mining_service.resolve(tx)
        # Transaction is still locked
        with self.assertRaises(InvalidNewTransaction):
            self.manager.propagate_tx(tx)

        self.clock.advance(6)
        tx.timestamp = int(self.clock.seconds())
        self.manager.cpu_mining_service.resolve(tx)

        # First we try to propagate with a P2PKH input
        private_key_obj = get_private_key_from_bytes(bytes.fromhex(self.private_keys[0]), password=b'1234')
        pubkey_obj = private_key_obj.public_key()
        public_key_compressed = get_public_key_bytes_compressed(pubkey_obj)
        p2pkh_input_data = P2PKH.create_input_data(public_key_compressed, signatures[0])
        tx2 = Transaction.create_from_struct(tx.get_struct())
        tx2.inputs[0].data = p2pkh_input_data
        self.manager.cpu_mining_service.resolve(tx2)
        with self.assertRaises(InvalidNewTransaction):
            self.manager.propagate_tx(tx2)

        # Now we propagate the correct
        self.assertTrue(self.manager.propagate_tx(tx))

        self.assertEqual(self.manager.wallet.balance[self._settings.HATHOR_TOKEN_UID],
                         WalletBalance(0, first_block_amount + 300))

        # Testing the MultiSig class methods
        cls_script = parse_address_script(multisig_script)
        self.assertTrue(isinstance(cls_script, MultiSig))
        self.assertEqual(cls_script.address, self.multisig_address_b58)

        expected_dict = {'type': 'MultiSig', 'address': self.multisig_address_b58, 'timelock': None}
        self.assertEqual(cls_script.to_human_readable(), expected_dict)

        script_eval(tx, tx_input, tx1)

        # Script error
        with self.assertRaises(ScriptError):
            create_output_script(base58.b58decode('55d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'))
