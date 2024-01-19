from unittest.mock import Mock

from hathor.conf import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm, TestMode
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.verification.verification_service import VerificationService
from hathor.verification.vertex_verifier import VertexVerifier
from hathor.verification.vertex_verifiers import VertexVerifiers
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
        self._daa = DifficultyAdjustmentAlgorithm(settings=self._settings)
        verifiers = VertexVerifiers.create_defaults(settings=self._settings, daa=self._daa, feature_service=Mock())
        self._verification_service = VerificationService(verifiers=verifiers)
        self.storage = TransactionMemoryStorage()

    def test_pow(self):
        verifier = VertexVerifier(settings=self._settings, daa=self._daa)
        genesis = self.storage.get_all_genesis()
        for g in genesis:
            self.assertEqual(g.calculate_hash(), g.hash)
            self.assertIsNone(verifier.verify_pow(g))

    def test_verify(self):
        genesis = self.storage.get_all_genesis()
        for g in genesis:
            self._verification_service.verify_without_storage(g)

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

        # Validate the block and tx weight
        # in test mode weight is always 1
        self._daa.TEST_MODE = TestMode.TEST_ALL_WEIGHT
        self.assertEqual(self._daa.calculate_block_difficulty(genesis_block), 1)
        self.assertEqual(self._daa.minimum_tx_weight(genesis_tx), 1)

        self._daa.TEST_MODE = TestMode.DISABLED
        self.assertEqual(self._daa.calculate_block_difficulty(genesis_block), genesis_block.weight)
        self.assertEqual(self._daa.minimum_tx_weight(genesis_tx), genesis_tx.weight)
