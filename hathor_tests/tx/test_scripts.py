import struct
from unittest.mock import Mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_address_from_public_key, get_hash160, get_public_key_bytes_compressed
from hathor.transaction.exceptions import (
    DataIndexError,
    EqualVerifyFailed,
    FinalStackInvalid,
    InvalidScriptError,
    InvalidStackData,
    MissingStackItems,
    OracleChecksigFailed,
    OutOfData,
    ScriptError,
    TimeLocked,
    VerifyFailed,
)
from hathor.transaction.scripts import P2PKH, HathorScript, MultiSig, Opcode, create_base_script, create_output_script
from hathor.transaction.scripts.construct import SigopCounter, get_pushdata, re_compile
from hathor.transaction.scripts.execute import (
    Stack,
    UtxoScriptExtras,
    binary_to_int,
    decode_opn,
    evaluate_final_stack,
    get_data_bytes,
    get_data_single_byte,
    get_data_value,
    get_script_op,
)
from hathor.transaction.scripts.opcode import (
    OpcodesVersion,
    op_checkdatasig,
    op_checkmultisig,
    op_checksig,
    op_data_greaterthan,
    op_data_match_interval,
    op_data_match_value,
    op_data_strequal,
    op_dup,
    op_equal,
    op_equalverify,
    op_find_p2pkh,
    op_greaterthan_timestamp,
    op_hash160,
    op_integer,
    op_pushdata,
    op_pushdata1,
)
from hathor.transaction.scripts.script_context import ScriptContext
from hathor.wallet import HDWallet
from hathor_tests import unittest
from hathor_tests.utils import BURN_ADDRESS, get_genesis_key


class TestScripts(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        tx_storage = self.create_tx_storage()

        self.genesis_blocks = [tx for tx in tx_storage.get_all_genesis() if tx.is_block]
        self.genesis_txs = [tx for tx in tx_storage.get_all_genesis() if not tx.is_block]

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

        # force checkdatasig count to be enabled
        self.counter = SigopCounter(
            max_multisig_pubkeys=self._settings.MAX_MULTISIG_PUBKEYS,
            enable_checkdatasig_count=True,
        )
        self.counter_old = SigopCounter(
            max_multisig_pubkeys=self._settings.MAX_MULTISIG_PUBKEYS,
            enable_checkdatasig_count=False,
        )

    def test_data_pattern(self) -> None:
        # up to 75 bytes, no Opcode is needed
        s = HathorScript()
        re_match = re_compile('^DATA_75$')
        data = [0x00] * 75
        s.pushData(bytes(data))
        self.assertEqual(76, len(s.data))   # data_len + data
        match = re_match.search(s.data)
        self.assertIsNotNone(match)
        # for now, we also accept <= 75 bytes with OP_PUSHDATA1
        match = re_match.search(bytes([Opcode.OP_PUSHDATA1]) + s.data)
        self.assertIsNotNone(match)

        # with more, use OP_PUSHDATA1
        s = HathorScript()
        re_match = re_compile('^DATA_76$')
        data = [0x00] * 76
        s.pushData(bytes(data))
        self.assertEqual(78, len(s.data))   # OP_PUSHDATA1 + data_len + data
        match = re_match.search(s.data)
        self.assertIsNotNone(match)
        # test without PUSHDATA1 opcode. Should fail
        match = re_match.search(s.data[1:])
        self.assertIsNone(match)

        # DATA_ between other opcodes
        s = HathorScript()
        re_match = re_compile('^OP_HASH160 (DATA_20) OP_EQUALVERIFY$')
        data = [0x00] * 20
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(bytes(data))
        s.addOpcode(Opcode.OP_EQUALVERIFY)
        match = re_match.search(s.data)
        self.assertIsNotNone(match)

        # wrong length
        s = HathorScript()
        re_match = re_compile('^DATA_20$')
        data = [0x00] * 20
        s.pushData(bytes(data))
        s.data = s.data.replace(b'\x14', b'\x15')
        match = re_match.search(s.data)
        self.assertIsNone(match)

    def test_push_integers(self) -> None:
        # 1 byte
        s = HathorScript()
        s.pushData(255)
        n = get_pushdata(s.data)
        self.assertEqual(1, len(n))
        self.assertEqual(255, binary_to_int(n))

        # 2 bytes
        s = HathorScript()
        s.pushData(65535)
        n = get_pushdata(s.data)
        self.assertEqual(2, len(n))
        self.assertEqual(65535, binary_to_int(n))

        # 4 bytes
        s = HathorScript()
        s.pushData(4294967295)
        n = get_pushdata(s.data)
        self.assertEqual(4, len(n))
        self.assertEqual(4294967295, binary_to_int(n))

        # 8 bytes
        s = HathorScript()
        s.pushData(4294967296)
        n = get_pushdata(s.data)
        self.assertEqual(8, len(n))
        self.assertEqual(4294967296, binary_to_int(n))

    def test_pushdata(self) -> None:
        stack: Stack = []
        random_bytes = b'a' * 50
        s = HathorScript()
        s.pushData(random_bytes)

        op_pushdata(0, s.data, stack)

        self.assertEqual(random_bytes, stack.pop())

        with self.assertRaises(OutOfData):
            op_pushdata(0, s.data[:-1], stack)

    def test_pushdata1(self) -> None:
        stack: Stack = []
        random_bytes = b'a' * 100
        s = HathorScript()
        s.pushData(random_bytes)

        op_pushdata1(0, s.data, stack)

        self.assertEqual(random_bytes, stack.pop())

        with self.assertRaises(OutOfData):
            op_pushdata1(0, s.data[:1], stack)
        with self.assertRaises(OutOfData):
            op_pushdata1(0, s.data[:-1], stack)

    def test_dup(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_dup(ScriptContext(stack=[], logs=[], extras=Mock()))

        stack: Stack = [1]
        op_dup(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack[-1], stack[-2])

    def test_equalverify(self) -> None:
        elem = b'a'
        with self.assertRaises(MissingStackItems):
            op_equalverify(ScriptContext(stack=[elem], logs=[], extras=Mock()))

        # no exception should be raised
        op_equalverify(ScriptContext(stack=[elem, elem], logs=[], extras=Mock()))

        with self.assertRaises(EqualVerifyFailed):
            op_equalverify(ScriptContext(stack=[elem, b'aaaa'], logs=[], extras=Mock()))

    def test_checksig_raise_on_uncompressed_pubkey(self) -> None:
        """ Uncompressed pubkeys shoud not be accepted, even if they solve the signature
        """
        block = self.genesis_blocks[0]

        from hathor.transaction import Transaction, TxInput, TxOutput
        txin = TxInput(tx_id=block.hash, index=0, data=b'')
        txout = TxOutput(value=block.outputs[0].value, script=b'')
        tx = Transaction(inputs=[txin], outputs=[txout])

        import hashlib
        data_to_sign = tx.get_sighash_all()
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = self.genesis_private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pubkey_uncompressed = self.genesis_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        # ScriptError if pubkey is not a valid compressed public key
        # with wrong signature
        with self.assertRaises(ScriptError):
            op_checksig(ScriptContext(stack=[b'123', pubkey_uncompressed], logs=[], extras=Mock()))
        # or with rigth one
        # this will make sure the signature is not made when parameters are wrong
        with self.assertRaises(ScriptError):
            op_checksig(ScriptContext(stack=[signature, pubkey_uncompressed], logs=[], extras=Mock()))

    def test_checksig_check_for_compressed_pubkey(self) -> None:
        """ Compressed pubkeys bytes representation always start with a byte 2 or 3
            - test for invalid bytes starting with bytes 2 and 3
            - test for bytes not starting with byte 2 or 3
        """
        # ScriptError if pubkey is not a public key but starts with 2 or 3
        with self.assertRaises(ScriptError):
            op_checksig(ScriptContext(stack=[b'\x0233', b'\x0233'], logs=[], extras=Mock()))
        with self.assertRaises(ScriptError):
            op_checksig(ScriptContext(stack=[b'\x0321', b'\x0321'], logs=[], extras=Mock()))

        # ScriptError if pubkey does not start with 2 or 3
        with self.assertRaises(ScriptError):
            op_checksig(ScriptContext(stack=[b'\x0123', b'\x0123'], logs=[], extras=Mock()))
        with self.assertRaises(ScriptError):
            op_checksig(ScriptContext(stack=[b'\x0423', b'\x0423'], logs=[], extras=Mock()))

    def test_checksig(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_checksig(ScriptContext(stack=[1], logs=[], extras=Mock()))

        block = self.genesis_blocks[0]

        from hathor.transaction import Transaction, TxInput, TxOutput
        txin = TxInput(tx_id=block.hash, index=0, data=b'')
        txout = TxOutput(value=block.outputs[0].value, script=b'')
        tx = Transaction(inputs=[txin], outputs=[txout])

        import hashlib
        data_to_sign = tx.get_sighash_all()
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = self.genesis_private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        pubkey_bytes = get_public_key_bytes_compressed(self.genesis_public_key)

        extras = UtxoScriptExtras(tx=tx, txin=Mock(), spent_tx=Mock(), version=OpcodesVersion.V2)

        # wrong signature puts False (0) on stack
        stack: Stack = [b'aaaaaaaaa', pubkey_bytes]
        op_checksig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(0, stack.pop())

        stack = [signature, pubkey_bytes]
        op_checksig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(1, stack.pop())

    def test_checksig_cache(self) -> None:
        block = self.genesis_blocks[0]

        from hathor.transaction import Transaction, TxInput, TxOutput
        txin = TxInput(tx_id=block.hash, index=0, data=b'')
        txout = TxOutput(value=block.outputs[0].value, script=b'')
        tx = Transaction(inputs=[txin], outputs=[txout])

        import hashlib
        data_to_sign = tx.get_sighash_all()
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = self.genesis_private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        pubkey_bytes = get_public_key_bytes_compressed(self.genesis_public_key)

        extras = UtxoScriptExtras(tx=tx, txin=Mock(), spent_tx=Mock(), version=OpcodesVersion.V2)

        stack: Stack = [signature, pubkey_bytes]
        self.assertIsNone(tx._sighash_data_cache)
        op_checksig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertIsNotNone(tx._sighash_data_cache)
        self.assertEqual(1, stack.pop())

    def test_hash160(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_hash160(ScriptContext(stack=[], logs=[], extras=Mock()))

        elem = b'aaaaaaaa'
        hash160 = get_hash160(elem)
        stack: Stack = [elem]
        op_hash160(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(hash160, stack.pop())

    def test_checkdatasig_raise_on_uncompressed_pubkey(self) -> None:
        block = self.genesis_blocks[0]
        data = b'some_random_data'

        from hathor.transaction import Transaction, TxInput, TxOutput
        txin = TxInput(tx_id=block.hash, index=0, data=b'')
        txout = TxOutput(value=block.outputs[0].value, script=b'')
        tx = Transaction(inputs=[txin], outputs=[txout])

        import hashlib
        data_to_sign = tx.get_sighash_all()
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = self.genesis_private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pubkey_uncompressed = self.genesis_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        # ScriptError if pubkey is not a valid compressed public key
        # with wrong signature
        stack: Stack = [data, b'123', pubkey_uncompressed]
        with self.assertRaises(ScriptError):
            op_checkdatasig(ScriptContext(stack=stack, logs=[], extras=Mock()))
        # or with rigth one
        # this will make sure the signature is not made when parameters are wrong
        stack = [data, signature, pubkey_uncompressed]
        with self.assertRaises(ScriptError):
            op_checkdatasig(ScriptContext(stack=stack, logs=[], extras=Mock()))

    def test_checkdatasig_check_for_compressed_pubkey(self) -> None:
        # ScriptError if pubkey is not a public key but starts with 2 or 3
        with self.assertRaises(ScriptError):
            op_checkdatasig(ScriptContext(stack=[b'\x0233', b'\x0233', b'\x0233'], logs=[], extras=Mock()))
        with self.assertRaises(ScriptError):
            op_checkdatasig(ScriptContext(stack=[b'\x0321', b'\x0321', b'\x0321'], logs=[], extras=Mock()))

        # ScriptError if pubkey is not a public key
        with self.assertRaises(ScriptError):
            op_checkdatasig(ScriptContext(stack=[b'\x0123', b'\x0123', b'\x0123'], logs=[], extras=Mock()))

    def test_checkdatasig(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_checkdatasig(ScriptContext(stack=[1, 1], logs=[], extras=Mock()))

        data = b'some_random_data'
        signature = self.genesis_private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        pubkey_bytes = get_public_key_bytes_compressed(self.genesis_public_key)

        stack: Stack = [data, signature, pubkey_bytes]
        # no exception should be raised and data is left on stack
        op_checkdatasig(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(data, stack.pop())

        stack = [b'data_not_matching', signature, pubkey_bytes]
        with self.assertRaises(OracleChecksigFailed):
            op_checkdatasig(ScriptContext(stack=stack, logs=[], extras=Mock()))

    def test_get_data_value(self) -> None:
        value0 = b'value0'
        value1 = b'vvvalue1'
        value2 = b'vvvvvalue2'

        data = (bytes([len(value0)]) + value0 + bytes([len(value1)]) + value1 + bytes([len(value2)]) + value2)

        self.assertEqual(get_data_value(0, data), value0)
        self.assertEqual(get_data_value(1, data), value1)
        self.assertEqual(get_data_value(2, data), value2)

        with self.assertRaises(DataIndexError):
            get_data_value(5, data)

        with self.assertRaises(OutOfData):
            get_data_value(2, data[:-1])

    def test_data_strequal(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_data_strequal(ScriptContext(stack=[1, 1], logs=[], extras=Mock()))

        value0 = b'value0'
        value1 = b'vvvalue1'
        value2 = b'vvvvvalue2'

        data = (bytes([len(value0)]) + value0 + bytes([len(value1)]) + value1 + bytes([len(value2)]) + value2)

        stack: Stack = [data, 0, value0]
        op_data_strequal(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), data)

        stack = [data, 1, value0]
        with self.assertRaises(VerifyFailed):
            op_data_strequal(ScriptContext(stack=stack, logs=[], extras=Mock()))

        stack = [data, b'\x00', value0]
        with self.assertRaises(VerifyFailed):
            op_data_strequal(ScriptContext(stack=stack, logs=[], extras=Mock()))

    def test_data_greaterthan(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_data_greaterthan(ScriptContext(stack=[1, 1], logs=[], extras=Mock()))

        value0 = struct.pack('!I', 1000)
        value1 = struct.pack('!I', 1)

        data = (bytes([len(value0)]) + value0 + bytes([len(value1)]) + value1)

        stack: Stack = [data, 0, struct.pack('!I', 999)]
        op_data_greaterthan(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), data)

        stack = [data, 1, struct.pack('!I', 0)]
        op_data_greaterthan(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), data)

        with self.assertRaises(VerifyFailed):
            stack = [data, 1, struct.pack('!I', 1)]
            op_data_greaterthan(ScriptContext(stack=stack, logs=[], extras=Mock()))

        stack = [data, 1, b'not_an_int']
        with self.assertRaises(VerifyFailed):
            op_data_greaterthan(ScriptContext(stack=stack, logs=[], extras=Mock()))

        stack = [data, b'\x00', struct.pack('!I', 0)]
        with self.assertRaises(VerifyFailed):
            op_data_greaterthan(ScriptContext(stack=stack, logs=[], extras=Mock()))

    def test_data_match_interval(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_data_match_interval([1, b'2'])

        value0 = struct.pack('!I', 1000)
        data = (bytes([len(value0)]) + value0)

        stack: Stack = [data, 0, 'key1', struct.pack('!I', 1000), 'key2', struct.pack('!I', 1005), 'key3', bytes([2])]
        op_data_match_interval(stack)
        self.assertEqual(stack.pop(), 'key1')
        self.assertEqual(len(stack), 0)

        stack = [data, 0, 'key1', struct.pack('!I', 100), 'key2', struct.pack('!I', 1005), 'key3', bytes([2])]
        op_data_match_interval(stack)
        self.assertEqual(stack.pop(), 'key2')
        self.assertEqual(len(stack), 0)

        stack = [data, 0, 'key1', struct.pack('!I', 100), 'key2', struct.pack('!I', 900), 'key3', bytes([2])]
        op_data_match_interval(stack)
        self.assertEqual(stack.pop(), 'key3')
        self.assertEqual(len(stack), 0)

        # missing 1 item on stack
        stack = [data, 0, struct.pack('!I', 100), 'key2', struct.pack('!I', 900), 'key3', bytes([2])]
        with self.assertRaises(MissingStackItems):
            op_data_match_interval(stack)

        # value should be an integer
        stack = [data, 0, 'key1', struct.pack('!I', 100), 'key2', b'not_an_int', 'key3', bytes([2])]
        with self.assertRaises(VerifyFailed):
            op_data_match_interval(stack)

    def test_data_match_value(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_data_match_value(ScriptContext(stack=[1, b'2'], logs=[], extras=Mock()))

        value0 = struct.pack('!I', 1000)
        data = (bytes([len(value0)]) + value0)

        stack: Stack = [data, 0, 'key1', struct.pack('!I', 1000), 'key2', struct.pack('!I', 1005), 'key3', bytes([2])]
        op_data_match_value(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), 'key2')
        self.assertEqual(len(stack), 0)

        stack = [data, 0, 'key1', struct.pack('!I', 999), 'key2', struct.pack('!I', 1000), 'key3', bytes([2])]
        op_data_match_value(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), 'key3')
        self.assertEqual(len(stack), 0)

        # missing 1 item on stack
        stack = [data, 0, 'key1', struct.pack('!I', 1000), 'key2', struct.pack('!I', 1000), bytes([2])]
        with self.assertRaises(MissingStackItems):
            op_data_match_value(ScriptContext(stack=stack, logs=[], extras=Mock()))

        # no value matches
        stack = [data, 0, 'key1', struct.pack('!I', 999), 'key2', struct.pack('!I', 1111), 'key3', bytes([2])]
        op_data_match_value(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), 'key1')
        self.assertEqual(len(stack), 0)

        # value should be an integer
        stack = [data, 0, 'key1', struct.pack('!I', 100), 'key2', b'not_an_int', 'key3', bytes([2])]
        with self.assertRaises(VerifyFailed):
            op_data_match_value(ScriptContext(stack=stack, logs=[], extras=Mock()))

    def test_find_p2pkh(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_find_p2pkh(ScriptContext(stack=[], logs=[], extras=Mock()))

        addr1 = '15d14K5jMqsN2uwUEFqiPG5SoD7Vr1BfnH'
        addr2 = '1K35zJQeYrVzQAW7X3s7vbPKmngj5JXTBc'
        addr3 = '1MnHN3D41yaMN5WLLKPARRdF77USvPLDfy'

        import base58
        out1 = P2PKH.create_output_script(base58.b58decode(addr1))
        out2 = P2PKH.create_output_script(base58.b58decode(addr2))
        out3 = P2PKH.create_output_script(base58.b58decode(addr3))

        # read genesis keys
        genesis_address = get_address_from_public_key(self.genesis_public_key)
        out_genesis = P2PKH.create_output_script(genesis_address)

        from hathor.transaction import Transaction, TxInput, TxOutput
        spent_tx = Transaction(outputs=[TxOutput(1, b'nano_contract_code')])
        txin = TxInput(b'dont_care', 0, b'data')

        # try with just 1 output
        stack: Stack = [genesis_address]
        tx = Transaction(outputs=[TxOutput(1, out_genesis)])
        extras = UtxoScriptExtras(tx=tx, txin=txin, spent_tx=spent_tx, version=OpcodesVersion.V2)
        op_find_p2pkh(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(stack.pop(), 1)

        # several outputs and correct output among them
        stack = [genesis_address]
        tx = Transaction(outputs=[TxOutput(1, out1), TxOutput(1, out2), TxOutput(1, out_genesis), TxOutput(1, out3)])
        extras = UtxoScriptExtras(tx=tx, txin=txin, spent_tx=spent_tx, version=OpcodesVersion.V2)
        op_find_p2pkh(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(stack.pop(), 1)

        # several outputs without correct amount output
        stack = [genesis_address]
        tx = Transaction(outputs=[TxOutput(1, out1), TxOutput(1, out2), TxOutput(2, out_genesis), TxOutput(1, out3)])
        extras = UtxoScriptExtras(tx=tx, txin=txin, spent_tx=spent_tx, version=OpcodesVersion.V2)
        with self.assertRaises(VerifyFailed):
            op_find_p2pkh(ScriptContext(stack=stack, logs=[], extras=extras))

        # several outputs without correct address output
        stack = [genesis_address]
        tx = Transaction(outputs=[TxOutput(1, out1), TxOutput(1, out2), TxOutput(1, out3)])
        extras = UtxoScriptExtras(tx=tx, txin=txin, spent_tx=spent_tx, version=OpcodesVersion.V2)
        with self.assertRaises(VerifyFailed):
            op_find_p2pkh(ScriptContext(stack=stack, logs=[], extras=extras))

    def test_greaterthan_timestamp(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_greaterthan_timestamp(ScriptContext(stack=[], logs=[], extras=Mock()))

        timestamp = 1234567

        from hathor.transaction import Transaction
        tx = Transaction()

        stack: Stack = [struct.pack('!I', timestamp)]
        extras = UtxoScriptExtras(tx=tx, txin=Mock(), spent_tx=Mock(), version=OpcodesVersion.V2)

        with self.assertRaises(TimeLocked):
            tx.timestamp = timestamp - 1
            op_greaterthan_timestamp(ScriptContext(stack=list(stack), logs=[], extras=extras))

        with self.assertRaises(TimeLocked):
            tx.timestamp = timestamp
            op_greaterthan_timestamp(ScriptContext(stack=list(stack), logs=[], extras=extras))

        tx.timestamp = timestamp + 1
        op_greaterthan_timestamp(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(len(stack), 0)

    def test_checkmultisig(self) -> None:
        with self.assertRaises(MissingStackItems):
            op_checkmultisig(ScriptContext(stack=[], logs=[], extras=Mock()))

        block = self.genesis_blocks[0]

        from hathor.transaction import Transaction, TxInput, TxOutput
        txin = TxInput(tx_id=block.hash, index=0, data=b'')
        txout = TxOutput(value=block.outputs[0].value, script=b'')
        tx = Transaction(inputs=[txin], outputs=[txout])

        data_to_sign = tx.get_sighash_all()
        extras = UtxoScriptExtras(tx=tx, txin=Mock(), spent_tx=Mock(), version=OpcodesVersion.V2)

        wallet = HDWallet()
        wallet._manually_initialize()
        assert wallet.mnemonic is not None
        wallet.words = wallet.mnemonic.generate()
        wallet._manually_initialize()

        keys_count = 3
        keys = []

        for i in range(keys_count):
            privkey = list(wallet.keys.values())[i]
            keys.append({
                'privkey': privkey,
                'pubkey': privkey.sec(),
                'signature': wallet.get_input_aux_data(data_to_sign, privkey)[1]
            })

        wrong_privkey = list(wallet.keys.values())[3]
        wrong_key = {
            'privkey': wrong_privkey,
            'pubkey': wrong_privkey.sec(),
            'signature': wallet.get_input_aux_data(data_to_sign, wrong_privkey)[1]
        }

        # All signatures match
        stack: Stack = [
            keys[0]['signature'], keys[2]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3
        ]
        op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(1, stack.pop())

        # New set of valid signatures
        stack = [
            keys[0]['signature'], keys[1]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3
        ]
        op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(1, stack.pop())

        # Changing the signatures but they match
        stack = [
            keys[1]['signature'], keys[2]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3
        ]
        op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(1, stack.pop())

        # Signatures are valid but in wrong order
        stack = [
            keys[1]['signature'], keys[0]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3
        ]
        op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(0, stack.pop())

        # Adding wrong signature, so we get error
        stack = [
            keys[0]['signature'], wrong_key['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3
        ]
        op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(0, stack.pop())

        # Adding same signature twice, so we get error
        stack = [
            keys[0]['signature'], keys[0]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3
        ]
        op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))
        self.assertEqual(0, stack.pop())

        # Adding less signatures than required, so we get error
        stack = [keys[0]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3]
        with self.assertRaises(MissingStackItems):
            op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))

        # Quantity of signatures is more than it should
        stack = [
            keys[0]['signature'], keys[1]['signature'], 3, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3
        ]
        with self.assertRaises(MissingStackItems):
            op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))

        # Quantity of pubkeys is more than it should
        stack = [
            keys[0]['signature'], keys[1]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 4
        ]
        with self.assertRaises(InvalidStackData):
            op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))

        # Exception pubkey_count should be integer
        stack = [
            keys[0]['signature'], keys[1]['signature'], 2, keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], '3'
        ]
        with self.assertRaises(InvalidStackData):
            op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))

        # Exception not enough pub keys
        stack = [keys[0]['pubkey'], keys[1]['pubkey'], 3]
        with self.assertRaises(MissingStackItems):
            op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))

        # Exception stack empty after pubkeys
        stack = [keys[0]['pubkey'], keys[1]['pubkey'], keys[2]['pubkey'], 3]
        with self.assertRaises(MissingStackItems):
            op_checkmultisig(ScriptContext(stack=stack, logs=[], extras=extras))

    def test_equal(self) -> None:
        elem = b'a'
        with self.assertRaises(MissingStackItems):
            op_equal(ScriptContext(stack=[elem], logs=[], extras=Mock()))

        # no exception should be raised
        stack: Stack = [elem, elem]
        op_equal(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), 1)

        stack = [elem, b'aaaa']
        op_equal(ScriptContext(stack=stack, logs=[], extras=Mock()))
        self.assertEqual(stack.pop(), 0)

    def test_integer_opcode(self) -> None:
        stack: Stack

        # We have opcodes from OP_0 to OP_16
        for i in range(0, 17):
            stack = []
            op_integer(getattr(Opcode, 'OP_{}'.format(i)), stack)
            self.assertEqual(stack, [i])

        stack = []
        with self.assertRaises(ScriptError):
            op_integer(0, stack)

        with self.assertRaises(ScriptError):
            op_integer(0x61, stack)

    def test_decode_opn(self) -> None:
        for i in range(0, 17):
            n = decode_opn(getattr(Opcode, 'OP_{}'.format(i)))
            self.assertEqual(n, i)

        with self.assertRaises(InvalidScriptError):
            _ = decode_opn(0)

        with self.assertRaises(InvalidScriptError):
            _ = decode_opn(0x61)

    def test_final_stack(self) -> None:
        # empty stack is invalid
        stack: Stack = []
        with self.assertRaises(FinalStackInvalid):
            evaluate_final_stack(stack, [])

        # True in final stack is valid
        stack = [1]
        evaluate_final_stack(stack, [])

        # more than one item is invalid
        stack = [0, 0, 1]
        with self.assertRaises(FinalStackInvalid):
            evaluate_final_stack(stack, [])

        # False on stack should fail
        stack = [0]
        with self.assertRaises(FinalStackInvalid):
            evaluate_final_stack(stack, [])
        stack = [1, 1, 1, 0]
        with self.assertRaises(FinalStackInvalid):
            evaluate_final_stack(stack, [])

    def test_get_pushdata(self) -> None:
        s = [0] * 10
        s.insert(0, len(s))
        self.assertEqual(10, len(get_pushdata(bytes(s))))

        s = [0] * 100
        s.insert(0, len(s))
        s.insert(0, Opcode.OP_PUSHDATA1)
        self.assertEqual(100, len(get_pushdata(bytes(s))))

    def test_p2pkh_base_script(self) -> None:
        import base58

        addrs = [
            'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A',
            'HGov979VaeyMQ92ubYcnVooP6qPzUJU8Ro',
        ]

        for addr in addrs:
            script = create_base_script(addr)
            self.assertIsInstance(script, P2PKH)
            self.assertEqual(script.get_type(), 'P2PKH')
            self.assertEqual(script.get_address(), addr)
            self.assertEqual(script.get_timelock(), None)
            baddress = base58.b58decode(addr)
            script2 = create_output_script(baddress)
            self.assertEqual(script2, script.get_script())

    def test_multisig_base_script(self) -> None:
        import base58

        addrs = [
            'hJBjKVU5HqfbNbikgfdhDmmBe9TMwx9Eft',
        ]

        for addr in addrs:
            script = create_base_script(addr)
            self.assertIsInstance(script, MultiSig)
            self.assertEqual(script.get_type(), 'MultiSig')
            self.assertEqual(script.get_address(), addr)
            self.assertEqual(script.get_timelock(), None)
            baddress = base58.b58decode(addr)
            script2 = create_output_script(baddress)
            self.assertEqual(script2, script.get_script())

    def test_get_data_bytes(self) -> None:
        value0 = b'value0'
        value1 = b'vvvalue1'
        value2 = b'vvvvvalue2'

        # data = (bytes([len(value0)]) + value0 + bytes([len(value1)]) + value1 + bytes([len(value2)]) + value2)
        data0 = (bytes([len(value0)])+value0)
        data1 = (data0 + bytes([len(value1)]) + value1)
        data2 = (data1 + bytes([len(value2)]) + value2)

        # value0 is in all 3
        self.assertEqual(get_data_bytes(1, len(value0), data0), value0)
        self.assertEqual(get_data_bytes(1, len(value0), data1), value0)
        self.assertEqual(get_data_bytes(1, len(value0), data2), value0)

        # value1 is in data1 and data2
        self.assertEqual(get_data_bytes(1+len(data0), len(value1), data1), value1)
        self.assertEqual(get_data_bytes(1+len(data0), len(value1), data2), value1)

        # value2 is in data2 only
        self.assertEqual(get_data_bytes(1+len(data1), len(value2), data2), value2)

        with self.assertRaises(OutOfData):
            get_data_bytes(1, 10, data0)

        with self.assertRaises(OutOfData):
            get_data_bytes(7, 1, data0)

        with self.assertRaises(OutOfData):
            get_data_bytes(6, 2, data0)

        with self.assertRaises(OutOfData):
            get_data_bytes(-1, 1, data0)

    def test_get_data_single_byte(self) -> None:
        """
            - return data in `int` if success
            - OutOfData in case position > data_len
        """
        data = bytes([0x00, 0x01, 0x50, 0xFF])

        self.assertEqual(get_data_single_byte(0, data), 0x00)  # 0
        self.assertEqual(get_data_single_byte(1, data), 0x01)  # 1
        self.assertEqual(get_data_single_byte(2, data), 0x50)  # 80 -> OP_0
        self.assertEqual(get_data_single_byte(3, data), 0xFF)  # 255

        with self.assertRaises(OutOfData):
            get_data_single_byte(4, data)

        with self.assertRaises(OutOfData):
            get_data_single_byte(-1, data)

    def test_get_script_op(self) -> None:
        """
            - pushdata, pushdata1, OP_N, OP_X
            - OutOfData in case pos > data_len (tested in get_data_single_byte?)
            - make script and iterate on it to make sure each step is returned
        """
        # for opcode test
        script0 = HathorScript()
        solution0 = []
        # for pushdata stack test
        script1 = HathorScript()
        solution1 = []
        # for integer stack test
        script2 = HathorScript()
        solution2 = []
        # for opcode (non OP_N) stack test
        script3 = HathorScript()

        for i in range(1, 76):
            solution0.append(i)
            solution1.append(b'1'*i)
            script0.pushData(b'1'*i)
            script1.pushData(b'1'*i)
        for i in range(0, 17):
            opc = getattr(Opcode, 'OP_{}'.format(i))
            solution0.append(opc)
            solution2.append(int(opc) - int(Opcode.OP_0))
            script0.addOpcode(opc)
            script2.addOpcode(opc)
        for o in [
                Opcode.OP_DUP,
                Opcode.OP_EQUAL,
                Opcode.OP_EQUALVERIFY,
                Opcode.OP_CHECKSIG,
                Opcode.OP_HASH160,
                Opcode.OP_GREATERTHAN_TIMESTAMP,
                Opcode.OP_CHECKMULTISIG,
                Opcode.OP_CHECKDATASIG,
                Opcode.OP_DATA_STREQUAL,
                Opcode.OP_DATA_GREATERTHAN,
                Opcode.OP_FIND_P2PKH,
                Opcode.OP_DATA_MATCH_VALUE,
                ]:
            solution0.append(o)
            script0.addOpcode(o)
            script3.addOpcode(o)

        data0 = script0.data
        data1 = script1.data
        data2 = script2.data
        data3 = script3.data

        # test opcode recognition
        pos = i = 0
        while pos < len(data0):
            opcode, pos = get_script_op(pos, data0, None)
            self.assertEqual(opcode, solution0[i])
            i += 1

        # test for pushdata stack
        pos = i = 0
        stack: Stack = []
        while pos < len(data1):
            opcode, pos = get_script_op(pos, data1, stack)
            self.assertEqual(stack.pop(), solution1[i])
            i += 1

        # test for push integer stack
        pos = i = 0
        stack = []
        while pos < len(data2):
            opcode, pos = get_script_op(pos, data2, stack)
            self.assertEqual(stack.pop(), solution2[i])
            i += 1

        # test for opcode (non OP_N) stack test
        pos = i = 0
        stack = []
        while pos < len(data3):
            opcode, pos = get_script_op(pos, data3, stack)
            self.assertEqual(len(stack), 0)
            i += 1

        # try to get opcode outside of script
        with self.assertRaises(OutOfData):
            pos = len(data0)
            get_script_op(pos, data0, None)

        with self.assertRaises(OutOfData):
            pos = len(data0) + 1
            get_script_op(pos, data0, None)

    def test_count_sigops(self) -> None:
        script_0 = HathorScript()
        script_1 = HathorScript()
        script_10 = HathorScript()
        script_100 = HathorScript()

        script_0.addOpcode(Opcode.OP_0)
        self.assertEqual(self.counter.count_sigops(script_0.data), 0)
        #
        script_1.addOpcode(Opcode.OP_10)
        script_1.addOpcode(Opcode.OP_CHECKSIG)
        self.assertEqual(self.counter.count_sigops(script_1.data), 1)
        #
        script_10.addOpcode(Opcode.OP_10)
        script_10.addOpcode(Opcode.OP_CHECKMULTISIG)
        self.assertEqual(self.counter.count_sigops(script_10.data), 10)
        #
        for i in range(6):
            script_100.addOpcode(Opcode.OP_16)
            script_100.addOpcode(Opcode.OP_CHECKMULTISIG)
        for i in range(4):
            script_100.addOpcode(Opcode.OP_CHECKSIG)
        self.assertEqual(self.counter.count_sigops(script_100.data), 100)

    def test_count_checkdatasigops(self) -> None:
        script = HathorScript()
        for i in range(10):
            script.addOpcode(Opcode.OP_CHECKDATASIG)
        self.assertEqual(self.counter.count_sigops(script.data), 10)
        self.assertEqual(self.counter_old.count_sigops(script.data), 0)

    def test_get_sigops_count(self) -> None:
        multisig_script = MultiSig.create_output_script(BURN_ADDRESS)
        p2pkh_script = P2PKH.create_output_script(BURN_ADDRESS)

        redeem_script = HathorScript()
        redeem_script.addOpcode(Opcode.OP_9)
        redeem_script.addOpcode(Opcode.OP_CHECKMULTISIG)

        input_script = HathorScript()
        input_script.pushData(BURN_ADDRESS)
        input_script.addOpcode(Opcode.OP_CHECKSIG)
        input_script.pushData(redeem_script.data)

        # include redeem_script if output is MultiSig
        self.assertEqual(self.counter.get_sigops_count(input_script.data, multisig_script), 10)
        # if output is not MultiSig, count only input
        self.assertEqual(self.counter.get_sigops_count(input_script.data, p2pkh_script), 1)
        # if no output_script, count only input
        self.assertEqual(self.counter.get_sigops_count(input_script.data), 1)
