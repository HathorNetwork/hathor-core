from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.exception import NCInvalidPubKey, NCInvalidSignature, NCMethodNotFound, NCSerializationError
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.nanocontract import NanoContract
from hathor.nanocontracts.storage import NCMemoryStorage
from hathor.nanocontracts.types import Context, NCActionType, public
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import TokenAuthorityNotAllowed
from hathor.transaction.validation_state import ValidationState
from hathor.wallet import KeyPair
from tests import unittest


class MyBlueprint(Blueprint):
    a: str
    b: int

    @public
    def initialize(self, ctx: Context, a: str, b: int) -> None:
        self.a = a
        self.b = b

    @public
    def inc_b(self, ctx: Context) -> None:
        self.b += 1

    def get_a(self) -> str:
        return self.a

    def get_b(self) -> int:
        return self.b


class NCNanoContractTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = False

    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })

        self.peer = self.create_peer('testnet')
        self.peer.tx_storage.nc_catalog = self.catalog

        self.genesis = self.peer.tx_storage.get_all_genesis()
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def _create_nc(self, nc_id, nc_method, nc_args, *, parents=None, timestamp=0):
        if parents is None:
            parents = []

        tx_storage = self.peer.tx_storage

        nc = NanoContract(weight=1, inputs=[], outputs=[], parents=parents, storage=tx_storage, timestamp=timestamp)
        self._fill_nc(nc, nc_id, nc_method, nc_args)
        return nc

    def _fill_nc(self, nc, nc_id, nc_method, nc_args):
        nc.nc_id = nc_id
        nc.nc_method = nc_method

        method = getattr(MyBlueprint, nc_method, None)
        if method is not None:
            method_parser = NCMethodParser(method)
            nc.nc_args_bytes = method_parser.serialize_args(nc_args)
        else:
            nc.nc_args_bytes = b''

        key = KeyPair.create(b'123')
        privkey = key.get_private_key(b'123')
        pubkey = privkey.public_key()
        nc.nc_pubkey = get_public_key_bytes_compressed(pubkey)

        data = nc.get_sighash_all_data()
        nc.nc_signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))

        self.peer.cpu_mining_service.resolve(nc)

    def _get_nc(self, *, parents=None, timestamp=0):
        return self._create_nc(self.myblueprint_id, 'initialize', ['string', 1], parents=parents, timestamp=timestamp)

    def test_serialization(self):
        nc = self._get_nc()

        nc_bytes = bytes(nc)
        nc2 = NanoContract.create_from_struct(nc_bytes, verbose=print)
        self.assertEqual(nc_bytes, bytes(nc2))

        nc2 = NanoContract.create_from_struct(nc_bytes)
        self.assertEqual(nc_bytes, bytes(nc2))

        self.assertEqual(nc.nc_id, nc2.nc_id)
        self.assertEqual(nc.nc_method, nc2.nc_method)
        self.assertEqual(nc.nc_args_bytes, nc2.nc_args_bytes)
        self.assertEqual(nc.nc_pubkey, nc2.nc_pubkey)
        self.assertEqual(nc.nc_signature, nc2.nc_signature)

    def test_verify_method_and_args(self):
        nc = self._get_nc()
        self.peer.verification_service.verifiers.nano_contract.verify_nc_method_and_args(nc)

    def test_verify_method_and_args_fails_nc_args(self):
        nc = self._get_nc()
        nc.nc_args_bytes = b''
        with self.assertRaises(NCSerializationError):
            self.peer.verification_service.verifiers.nano_contract.verify_nc_method_and_args(nc)

    def test_verify_signature_success(self):
        nc = self._get_nc()
        nc.clear_sighash_cache()
        self.peer.verification_service.verifiers.nano_contract.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_id(self):
        nc = self._get_nc()
        nc.nc_id = b'a' * 32
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidSignature):
            self.peer.verification_service.verifiers.nano_contract.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_method(self):
        nc = self._get_nc()
        nc.nc_method = 'other_nc_method'
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidSignature):
            self.peer.verification_service.verifiers.nano_contract.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_args_bytes(self):
        nc = self._get_nc()
        nc.nc_args_bytes = b'other_nc_args_bytes'
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidSignature):
            self.peer.verification_service.verifiers.nano_contract.verify_nc_signature(nc)

    def test_verify_signature_fails_invalid_nc_pubkey(self):
        nc = self._get_nc()
        nc.nc_pubkey = b'invalid-pubkey'
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidPubKey):
            self.peer.verification_service.verifiers.nano_contract.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_pubkey(self):
        key = KeyPair.create(b'xyz')
        privkey = key.get_private_key(b'xyz')
        pubkey = privkey.public_key()

        nc = self._get_nc()
        nc.nc_pubkey = get_public_key_bytes_compressed(pubkey)
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidSignature):
            self.peer.verification_service.verifiers.nano_contract.verify_nc_signature(nc)

    def test_get_related_addresses(self):
        nc = self._get_nc()
        related_addresses = set(nc.get_related_addresses())
        address = get_address_b58_from_public_key_bytes(nc.nc_pubkey)
        self.assertIn(address, related_addresses)

    def test_execute_success(self):
        nc_storage = NCMemoryStorage()

        nc = self._get_nc()
        nc.execute(nc_storage)

        self.assertEqual('string', nc.call_private_method(nc_storage, 'get_a'))
        self.assertEqual(1, nc.call_private_method(nc_storage, 'get_b'))

        runner = nc.get_runner(nc_storage)
        self.assertEqual('string', runner.call_private_method('get_a'))
        self.assertEqual(1, runner.call_private_method('get_b'))

        self.assertEqual('string', nc_storage.get('a'))
        self.assertEqual(1, nc_storage.get('b'))

    def test_dag_create_nano(self):
        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        nc = self._get_nc(parents=parents, timestamp=timestamp)
        self.peer.verification_service.verify(nc)
        self.assertTrue(self.peer.on_new_tx(nc, fails_silently=False))
        return nc

    def test_dag_call_public_method(self):
        nc = self.test_dag_create_nano()

        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        nc2 = self._create_nc(nc_id=nc.hash, nc_method='inc_b', nc_args=[], parents=parents, timestamp=timestamp)
        self.assertTrue(self.peer.on_new_tx(nc2, fails_silently=False))

    def test_dag_call_initialize(self):
        nc = self.test_dag_create_nano()

        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        nc2 = self._create_nc(
            nc_id=nc.hash,
            nc_method='initialize',
            nc_args=['a', 2],
            parents=parents,
            timestamp=timestamp
        )
        with self.assertRaises(InvalidNewTransaction):
            # BlueprintDoesNotExist
            self.peer.on_new_tx(nc2, fails_silently=False)

    def test_verify_method_and_args_fails_method_not_found(self):
        nc = self.test_dag_create_nano()

        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        nc2 = self._create_nc(nc_id=nc.hash, nc_method='not_found', nc_args=[], parents=parents, timestamp=timestamp)
        with self.assertRaises(NCMethodNotFound):
            self.peer.verification_service.verifiers.nano_contract.verify_nc_method_and_args(nc2)

        with self.assertRaises(InvalidNewTransaction):
            self.peer.on_new_tx(nc2, fails_silently=False)

    def test_get_context(self):
        tx_storage = self.peer.tx_storage

        # Incomplete transaction. It will be used as input of nc2.
        outputs = [
            TxOutput(100, b'', 0),  # HTR
            TxOutput(200, b'', 1),  # TOKEN A
            TxOutput(300, b'', 2),  # TOKEN B
        ]
        tokens = [b'token-a', b'token-b']
        tx = Transaction(outputs=outputs, tokens=tokens)
        tx.get_metadata().validation = ValidationState.FULL
        tx.update_hash()
        tx_storage.save_transaction(tx)

        # Incomplete nanocontract transaction.
        inputs = [
            TxInput(tx.hash, 0, b''),
            TxInput(tx.hash, 1, b''),
            TxInput(tx.hash, 2, b''),
        ]
        outputs = [
            TxOutput(10, b'', 0),   # HTR
            TxOutput(250, b'', 1),  # TOKEN A
            TxOutput(300, b'', 2),  # TOKEN B
        ]
        nc2 = NanoContract(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            tokens=tokens,
            storage=tx_storage,
        )
        nc2.update_hash()
        context = nc2.get_context()
        self.assertEqual(2, len(context.actions))

        action1 = context.actions[b'token-a']
        self.assertEqual(action1.type, NCActionType.WITHDRAWAL)
        self.assertEqual(action1.amount, 50)

        action2 = context.actions[b'\0']
        self.assertEqual(action2.type, NCActionType.DEPOSIT)
        self.assertEqual(action2.amount, 90)

    def test_no_authorities(self):
        tx_storage = self.peer.tx_storage

        # Incomplete transaction. It will be used as input of nc.
        inputs = []
        outputs = [
            TxOutput(TxOutput.TOKEN_MINT_MASK, b'', TxOutput.TOKEN_AUTHORITY_MASK | 1),  # TOKEN A
        ]
        tokens = [b'token-a']
        tx = Transaction(inputs=inputs, outputs=outputs, tokens=tokens)
        tx.get_metadata().validation = ValidationState.FULL
        tx.update_hash()
        tx.get_metadata().validation = ValidationState.FULL
        tx_storage.save_transaction(tx)

        # Incomplete nanocontract transaction with a token authority on one output.
        nc = NanoContract(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            tokens=tokens,
            storage=tx_storage,
        )
        with self.assertRaises(TokenAuthorityNotAllowed):
            self.peer.verification_service.verifiers.nano_contract.verify_no_authorities(nc)

        # Incomplete nanocontract transaction with a token authority on one input.
        inputs = [
            TxInput(tx.hash, 0, b''),
        ]
        outputs = []
        nc = NanoContract(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            tokens=tokens,
            storage=tx_storage,
        )
        with self.assertRaises(TokenAuthorityNotAllowed):
            self.peer.verification_service.verifiers.nano_contract.verify_no_authorities(nc)
