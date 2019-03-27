from hathor.conf import HathorSettings
from hathor.manager import TestMode
from hathor.transaction.genesis import get_genesis_transactions
from tests import unittest
from tests.utils import get_genesis_key

settings = HathorSettings()


def get_genesis_output():
    # use this if to calculate the genesis output. We have to do it if:
    # - we change genesis priv/pub keys
    # - there's some change to the way we calculate hathor addresses
    from hathor.transaction.scripts import P2PKH
    from hathor.crypto.util import get_address_from_public_key
    # read genesis keys
    genesis_private_key = get_genesis_key()
    address = get_address_from_public_key(genesis_private_key.public_key())
    return P2PKH.create_output_script(address).hex()


class GenesisTest(unittest.TestCase):
    def test_pow(self):
        super().setUp()
        genesis = get_genesis_transactions(None)

        for g in genesis:
            self.assertEqual(g.calculate_hash(), g.hash)
            self.assertIsNone(g.verify_pow())

    def test_output(self):
        # Test if block output is valid
        genesis = get_genesis_transactions(None)

        for g in genesis:
            if g.is_block:
                for output in g.outputs:
                    self.assertEqual(output.script.hex(), get_genesis_output())

    def test_genesis_tokens(self):
        genesis_blocks = [tx for tx in get_genesis_transactions(None) if tx.is_block]
        genesis_block = genesis_blocks[0]

        self.assertEqual(settings.GENESIS_TOKENS, sum([output.value for output in genesis_block.outputs]))

    def test_genesis_weight(self):
        genesis_blocks = [tx for tx in get_genesis_transactions(None) if tx.is_block]
        genesis_block = genesis_blocks[0]

        genesis_txs = [tx for tx in get_genesis_transactions(None) if not tx.is_block]
        genesis_tx = genesis_txs[0]

        network = 'testnet'
        manager = self.create_peer(network, unlock_wallet=True)

        # Validate the block and tx weight
        # in test mode weight is always 1
        self.assertEqual(manager.calculate_block_difficulty(genesis_block), 1)
        self.assertEqual(manager.minimum_tx_weight(genesis_tx), 1)
        manager.test_mode = TestMode.DISABLED
        self.assertEqual(manager.calculate_block_difficulty(genesis_block), genesis_block.weight)
        self.assertEqual(manager.minimum_tx_weight(genesis_tx), genesis_tx.weight)
