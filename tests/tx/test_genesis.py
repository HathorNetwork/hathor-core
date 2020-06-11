from hathor.conf import HathorSettings
from hathor.manager import TestMode
from hathor.transaction.storage import TransactionMemoryStorage
from tests import unittest

settings = HathorSettings()


def get_genesis_output():
    import base58

    from hathor.transaction.scripts import P2PKH
    if settings.NETWORK_NAME == 'mainnet':
        address = 'HJB2yxxsHtudGGy3jmVeadwMfRi2zNCKKD'
    elif settings.NETWORK_NAME.startswith('testnet'):
        address = 'WdmDUMp8KvzhWB7KLgguA2wBiKsh4Ha8eX'
    elif settings.NETWORK_NAME == 'unittests':
        address = 'HVayMofEDh4XGsaQJeRJKhutYxYodYNop6'
    else:
        raise ValueError('Network unknown.')

    address_bytes = base58.b58decode(address)
    return P2PKH.create_output_script(address_bytes).hex()


class GenesisTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.storage = TransactionMemoryStorage()

    def test_pow(self):
        genesis = self.storage.get_all_genesis()
        for g in genesis:
            self.assertEqual(g.calculate_hash(), g.hash)
            self.assertIsNone(g.verify_pow())

    def test_verify(self):
        genesis = self.storage.get_all_genesis()
        for g in genesis:
            g.verify_without_storage()

    def test_output(self):
        # Test if block output is valid
        genesis = self.storage.get_all_genesis()
        for g in genesis:
            if g.is_block:
                for output in g.outputs:
                    self.assertEqual(output.script.hex(), get_genesis_output())

    def test_genesis_tokens(self):
        genesis = self.storage.get_all_genesis()
        genesis_blocks = [tx for tx in genesis if tx.is_block]
        genesis_block = genesis_blocks[0]

        self.assertEqual(settings.GENESIS_TOKENS, sum([output.value for output in genesis_block.outputs]))

    def test_genesis_weight(self):
        genesis = self.storage.get_all_genesis()
        genesis_blocks = [tx for tx in genesis if tx.is_block]
        genesis_block = genesis_blocks[0]

        genesis_txs = [tx for tx in genesis if not tx.is_block]
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
