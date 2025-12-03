from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import (
    decode_address,
    get_address_b58_from_bytes,
    get_address_from_public_key_bytes,
    get_public_key_bytes_compressed,
)
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCInvalidSignature
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.nc_types import make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.types import (
    NCActionType,
    NCDepositAction,
    NCWithdrawalAction,
    TokenUid,
    VertexId,
    public,
    view,
)
from hathor.nanocontracts.utils import sign_openssl, sign_openssl_multisig
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import (
    EqualVerifyFailed,
    FinalStackInvalid,
    InvalidScriptError,
    MissingStackItems,
    TooManySigOps,
)
from hathor.transaction.headers import NanoHeader
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.scripts import P2PKH, HathorScript, Opcode
from hathor.transaction.validation_state import ValidationState
from hathor.verification.nano_header_verifier import MAX_NC_SCRIPT_SIGOPS_COUNT, MAX_NC_SCRIPT_SIZE
from hathor.wallet import KeyPair
from hathor_tests import unittest

STR_NC_TYPE = make_nc_type(str)
INT_NC_TYPE = make_nc_type(int)


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

    @view
    def get_a(self) -> str:
        return self.a

    @view
    def get_b(self) -> int:
        return self.b


class NCNanoContractTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.myblueprint_id = VertexId(b'x' * 32)
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })
        self.nc_seqnum = 0

        self.peer = self.create_peer('unittests')
        self.peer.tx_storage.nc_catalog = self.catalog

        self.genesis = self.peer.tx_storage.get_all_genesis()
        self.genesis_txs = [tx for tx in self.genesis if not tx.is_block]

    def _create_nc(
        self,
        nc_id: VertexId,
        nc_method: str,
        nc_args: list[Any],
        *,
        parents: list[bytes] | None = None,
        timestamp: int = 0,
    ) -> Transaction:

        if parents is None:
            parents = []

        tx_storage = self.peer.tx_storage

        nc = Transaction(weight=1, inputs=[], outputs=[], parents=parents, storage=tx_storage, timestamp=timestamp)
        self._fill_nc(nc, nc_id, nc_method, nc_args)
        return nc

    def _fill_nc(self, nc: Transaction, nc_id: VertexId, nc_method: str, nc_args: list[Any]) -> None:
        method = getattr(MyBlueprint, nc_method, None)
        if method is not None:
            method_parser = Method.from_callable(method)
            nc_args_bytes = method_parser.serialize_args_bytes(nc_args)
        else:
            nc_args_bytes = b''

        key = KeyPair.create(b'123')
        privkey = key.get_private_key(b'123')

        nano_header = NanoHeader(
            tx=nc,
            nc_seqnum=self.nc_seqnum,
            nc_id=nc_id,
            nc_method=nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_address=b'',
            nc_script=b'',
            nc_actions=[],
        )
        nc.headers.append(nano_header)
        self.nc_seqnum += 1

        sign_openssl(nano_header, privkey)
        self.peer.cpu_mining_service.resolve(nc)

    def _get_nc(self, *, parents: list[bytes] | None = None, timestamp: int = 0) -> Transaction:
        return self._create_nc(self.myblueprint_id, 'initialize', ['string', 1], parents=parents, timestamp=timestamp)

    def test_serialization(self) -> None:
        nc = self._get_nc()

        nc_bytes = bytes(nc)
        nc2 = Transaction.create_from_struct(nc_bytes, verbose=print)
        self.assertEqual(nc_bytes, bytes(nc2))

        nc2 = Transaction.create_from_struct(nc_bytes)
        self.assertEqual(nc_bytes, bytes(nc2))

        nc_header = nc.get_nano_header()
        nc2_header = nc2.get_nano_header()

        self.assertEqual(nc_header.nc_seqnum, nc2_header.nc_seqnum)
        self.assertEqual(nc_header.nc_id, nc2_header.nc_id)
        self.assertEqual(nc_header.nc_method, nc2_header.nc_method)
        self.assertEqual(nc_header.nc_args_bytes, nc2_header.nc_args_bytes)
        self.assertEqual(nc_header.nc_actions, nc2_header.nc_actions)
        self.assertEqual(nc_header.nc_address, nc2_header.nc_address)
        self.assertEqual(nc_header.nc_script, nc2_header.nc_script)

    def test_serialization_skip_signature(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        sighash_bytes = nano_header.get_sighash_bytes()
        deserialized, buf = NanoHeader.deserialize(Transaction(), sighash_bytes)

        assert len(buf) == 0
        assert deserialized.nc_seqnum == nano_header.nc_seqnum
        assert deserialized.nc_id == nano_header.nc_id
        assert deserialized.nc_method == nano_header.nc_method
        assert deserialized.nc_args_bytes == nano_header.nc_args_bytes
        assert deserialized.nc_actions == nano_header.nc_actions
        assert deserialized.nc_address == nano_header.nc_address
        assert deserialized.nc_script == b''

    def test_verify_signature_success(self) -> None:
        nc = self._get_nc()
        nc.clear_sighash_cache()
        self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_id(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        nano_header.nc_id = b'a' * 32
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidSignature):
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_method(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        nano_header.nc_method = 'other_nc_method'
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidSignature):
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_args_bytes(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        nano_header.nc_args_bytes = b'other_nc_args_bytes'
        nc.clear_sighash_cache()
        with self.assertRaises(NCInvalidSignature):
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_fails_invalid_nc_address(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        nano_header.nc_address = b'invalid-address'
        nc.clear_sighash_cache()
        with pytest.raises(NCInvalidSignature, match=f'invalid address: {nano_header.nc_address.hex()}'):
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_fails_invalid_nc_script(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        nano_header.nc_script = b'invalid-script'
        nc.clear_sighash_cache()
        with pytest.raises(InvalidScriptError, match='Invalid Opcode'):
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_fails_wrong_nc_address(self) -> None:
        key = KeyPair.create(b'xyz')
        privkey = key.get_private_key(b'xyz')
        pubkey = privkey.public_key()
        pubkey_bytes = get_public_key_bytes_compressed(pubkey)

        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        nano_header.nc_address = get_address_from_public_key_bytes(pubkey_bytes)
        nc.clear_sighash_cache()
        with pytest.raises(NCInvalidSignature) as e:
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)
        assert isinstance(e.value.__cause__, EqualVerifyFailed)

    def test_verify_signature_fails_wrong_pubkey(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()

        key = KeyPair.create(b'xyz')
        privkey = key.get_private_key(b'xyz')
        pubkey = privkey.public_key()
        pubkey_bytes = get_public_key_bytes_compressed(pubkey)
        nano_header.nc_address = get_address_from_public_key_bytes(pubkey_bytes)

        nc.clear_sighash_cache()
        data = nc.get_sighash_all_data()
        signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
        nano_header.nc_script = P2PKH.create_input_data(public_key_bytes=pubkey_bytes, signature=signature)

        # First, it's passing with the key from above
        self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

        # We change the script to use a new pubkey, but with the same signature
        key = KeyPair.create(b'wrong')
        privkey = key.get_private_key(b'wrong')
        pubkey = privkey.public_key()
        pubkey_bytes = get_public_key_bytes_compressed(pubkey)
        nano_header.nc_script = P2PKH.create_input_data(public_key_bytes=pubkey_bytes, signature=signature)

        with pytest.raises(NCInvalidSignature) as e:
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)
        assert isinstance(e.value.__cause__, EqualVerifyFailed)

    def test_verify_signature_fails_wrong_signature(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()

        key = KeyPair.create(b'xyz')
        privkey = key.get_private_key(b'xyz')
        pubkey = privkey.public_key()
        pubkey_bytes = get_public_key_bytes_compressed(pubkey)
        nano_header.nc_address = get_address_from_public_key_bytes(pubkey_bytes)

        nc.clear_sighash_cache()
        data = nc.get_sighash_all_data()
        signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
        nano_header.nc_script = P2PKH.create_input_data(public_key_bytes=pubkey_bytes, signature=signature)

        # First, it's passing with the key from above
        self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

        # We change the script to use a new signature, but with the same pubkey
        key = KeyPair.create(b'wrong')
        privkey = key.get_private_key(b'wrong')
        signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
        nano_header.nc_script = P2PKH.create_input_data(public_key_bytes=pubkey_bytes, signature=signature)

        with pytest.raises(NCInvalidSignature) as e:
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)
        assert isinstance(e.value.__cause__, FinalStackInvalid)
        assert 'Stack left with False value' in e.value.__cause__.args[0]

    def test_verify_signature_fails_nc_script_too_large(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        nano_header.nc_script = b'\x00' * (MAX_NC_SCRIPT_SIZE + 1)

        with pytest.raises(NCInvalidSignature, match='nc_script larger than max: 1025 > 1024'):
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_fails_nc_script_too_many_sigops(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()

        script = HathorScript()
        for _ in range(MAX_NC_SCRIPT_SIGOPS_COUNT + 1):
            script.addOpcode(Opcode.OP_CHECKSIG)

        nano_header.nc_script = script.data

        with pytest.raises(TooManySigOps, match='sigops count greater than max: 21 > 20'):
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

    def test_verify_signature_multisig(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()

        keys: list[tuple[ec.EllipticCurvePrivateKey, bytes]] = []
        for i in range(3):
            password = i.to_bytes()
            key = KeyPair.create(password)
            privkey = key.get_private_key(password)
            pubkey = privkey.public_key()
            pubkey_bytes = get_public_key_bytes_compressed(pubkey)
            keys.append((privkey, pubkey_bytes))

        # 3 keys are accepted
        redeem_pubkey_bytes = [x[1] for x in keys]

        # Test fails because requires 2 signatures, but only has 1
        nc.clear_sighash_cache()
        sign_openssl_multisig(
            nano_header,
            required_count=2,
            redeem_pubkey_bytes=redeem_pubkey_bytes,
            sign_privkeys=[keys[0][0]],
        )
        with pytest.raises(NCInvalidSignature) as e:
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)
        assert isinstance(e.value.__cause__, MissingStackItems)
        assert e.value.__cause__.args[0] == 'OP_CHECKMULTISIG: not enough signatures on the stack'

        # Test fails because requires 1 signature, but used wrong privkey
        nc.clear_sighash_cache()
        sign_openssl_multisig(
            nano_header,
            required_count=1,
            redeem_pubkey_bytes=redeem_pubkey_bytes,
            sign_privkeys=[KeyPair.create(b'invalid').get_private_key(b'invalid')],
        )
        with pytest.raises(NCInvalidSignature) as e:
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)
        assert isinstance(e.value.__cause__, FinalStackInvalid)
        assert 'Stack left with False value' in e.value.__cause__.args[0]

        # Test passes because requires 2 signatures, and signed with 2 correct privkeys
        nc.clear_sighash_cache()
        sign_openssl_multisig(
            nano_header,
            required_count=2,
            redeem_pubkey_bytes=redeem_pubkey_bytes,
            sign_privkeys=[x[0] for x in keys[:2]],
        )
        self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)

        # Test fails because the address was changed
        nc.clear_sighash_cache()
        nano_header.nc_address = decode_address(self.peer.wallet.get_unused_address())
        with pytest.raises(NCInvalidSignature) as e:
            self.peer.verification_service.verifiers.nano_header.verify_nc_signature(nc)
        assert isinstance(e.value.__cause__, EqualVerifyFailed)

    def test_get_related_addresses(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        related_addresses = set(nc.get_related_addresses())
        address = get_address_b58_from_bytes(nano_header.nc_address)
        self.assertIn(address, related_addresses)

    def create_nano(self) -> Transaction:
        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        nc = self._get_nc(parents=parents, timestamp=timestamp)
        self.assertTrue(self.peer.on_new_tx(nc))
        return nc

    def test_dag_call_public_method(self) -> None:
        nc = self.create_nano()

        parents = [tx.hash for tx in self.genesis_txs]
        timestamp = 1 + max(tx.timestamp for tx in self.genesis)

        nc2 = self._create_nc(
            nc_id=VertexId(nc.hash),
            nc_method='inc_b',
            nc_args=[],
            parents=parents,
            timestamp=timestamp,
        )
        self.assertTrue(self.peer.on_new_tx(nc2))

    def test_get_context(self) -> None:
        tx_storage = self.peer.tx_storage

        # Incomplete transaction. It will be used as input of nc2.
        outputs = [
            TxOutput(100, b'', 0),  # HTR
            TxOutput(200, b'', 1),  # TOKEN A
            TxOutput(300, b'', 2),  # TOKEN B
        ]
        tokens = [b'token-a', b'token-b']
        tx = Transaction(outputs=outputs, tokens=tokens)
        tx.parents = [tx.hash for tx in self.genesis_txs]
        tx.get_metadata().validation = ValidationState.FULL
        tx.update_hash()
        tx.init_static_metadata_from_storage(self._settings, tx_storage)
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
        nc2 = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            tokens=tokens,
            storage=tx_storage,
        )
        nc2.headers.append(NanoHeader(
            tx=nc2,
            nc_seqnum=0,
            nc_id=b'',
            nc_method='',
            nc_args_bytes=b'',
            nc_address=b'\x00' * 25,
            nc_script=b'',
            nc_actions=[
                NanoHeaderAction(
                    type=NCActionType.WITHDRAWAL,
                    token_index=1,
                    amount=50,
                ),
                NanoHeaderAction(
                    type=NCActionType.DEPOSIT,
                    token_index=0,
                    amount=90,
                ),
            ],
        ))
        nc2.update_hash()
        nc2_nano_header = nc2.get_nano_header()
        context = nc2_nano_header.get_context()
        self.assertEqual(2, len(context.actions))

        action1 = context.get_single_action(TokenUid(b'token-a'))
        assert isinstance(action1, NCWithdrawalAction)
        self.assertEqual(action1.amount, 50)

        action2 = context.get_single_action(TokenUid(b'\0'))
        assert isinstance(action2, NCDepositAction)
        self.assertEqual(action2.amount, 90)

        def _to_frozenset(x: list[dict]) -> set[frozenset]:
            return {frozenset(d.items()) for d in x}

        expected_json_actions = [{
            'type': 'withdrawal',
            'token_uid': b'token-a'.hex(),
            'amount': 50,
        }, {
            'type': 'deposit',
            'token_uid': b'\0'.hex(),
            'amount': 90,
        }]
        data = context.to_json()
        json_actions = data['actions']
        self.assertEqual(_to_frozenset(json_actions), _to_frozenset(expected_json_actions))
