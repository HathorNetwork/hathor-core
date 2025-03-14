from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCInvalidPubKey, NCInvalidSignature, NCMethodNotFound, NCSerializationError
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.storage import NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import NCActionType, public, view
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import TokenAuthorityNotAllowed
from hathor.transaction.headers import NanoHeader
from hathor.transaction.validation_state import ValidationState
from hathor.wallet import KeyPair
from tests import unittest
from tests.nanocontracts.utils import TestRunner


class MyBlueprint(Blueprint):
    a: str
    b: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.a = a
        self.b = b

    @public
    def withdraw(self, ctx: Context) -> None:
        pass


class NCNanoContractTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })

        self.manager = self.create_peer('testnet')
        self.manager.tx_storage.nc_catalog = self.catalog

    def test_token_creation(self):
        dag_builder = self.get_dag_builder(self.manager)
        vertices = dag_builder.build_from_str(f'''
            blockchain genesis b[1..40]
            b30 < dummy

            tx1.nc_id = "{self.myblueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.out[1] = 100 TKA

            TKA.nc_id = tx1
            TKA.nc_method = withdraw()
            TKA.nc_withdraw = 1 HTR

            b31 --> tx1
        ''')

        for node, vertex in vertices.list:
            assert self.manager.on_new_tx(vertex, fails_silently=False)
