# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import unittest

from hathorlib import Block, TokenCreationTransaction, Transaction
from hathorlib.base_transaction import get_cls_from_tx_version, tx_or_block_from_bytes
from hathorlib.conf import HathorSettings
from hathorlib.scripts import create_output_script
from hathorlib.utils import decode_address

settings = HathorSettings()


class HathorCommonsTestCase(unittest.TestCase):
    def test_block_basics(self):
        data = bytes.fromhex('000001ffffffe8b789180000001976a9147fd4ae0e4fb2d2854e76d359029d8078bb9'
                             '9649e88ac40350000000000005e0f84a9000000000000000000000000000000278a7e')
        block = Block.create_from_struct(data)
        self.assertTrue(block.verify_pow())
        self.assertEqual(data, bytes(block))

        # These prints are here to test the methods.
        self.assertEqual(
            str(block),
            'Block(nonce=2591358, timestamp=1578075305, version=0, weight=21.000000, '
            'hash=000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc)'
        )
        self.assertEqual(
            repr(block),
            'Block(nonce=2591358, timestamp=1578075305, version=0, weight=21.000000, '
            'hash=000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc, '
            'inputs=[], outputs=[TxOutput(token_data=0b0, value=100000000000)], parents=[], data=)')
        self.assertEqual(block.get_struct_nonce().hex(), '00000000000000000000000000278a7e')

        block.nonce += 1
        block.update_hash()
        self.assertFalse(block.verify_pow())

    def test_tx_basics(self):
        data = bytes.fromhex('0001000102000001e0e88216036e4e52872ba60a96df7570c3e29cc30eda6dd92ea0fd'
                             '304c00006a4730450221009fa4798bb69f66035013063c13f1a970ec58111bcead277d'
                             '9c93e45c2b6885fe022012e039b26cc4a4cb0a8a5abb7deb7bb78610ed362bf422efa2'
                             '47db37c5a841e12102bc1213ea99ab55effcff760f94c09f8b1a0b7b990c01128d06b4'
                             'a8c5c5f41f8400089f0800001976a91438fb3bc92b76819e9c19ef7c079d327c8fcd19'
                             '9288ac02de2d3800001976a9148d880c42ddcf78a2da5d06558f13515508720b4088ac'
                             '403518509c63f9195ecfd7d40200001ea9d6e1d31da6893fcec594dc3fa8b6819ae126'
                             '8c190f7a1441302226e2000007d1c5add7b9085037cfc591f1008dff4fe8a9158fd1a4'
                             '840a6dd5d4e4e600d2da8d')
        tx = Transaction.create_from_struct(data)

        self.assertEqual(data, bytes(tx))
        self.assertTrue(tx.verify_pow())
        self.assertTrue(tx.is_transaction)
        self.assertFalse(tx.is_block)

        # These prints are here to test the methods.
        print(str(tx))
        print(repr(tx))

        tx.nonce += 1
        tx.update_hash()
        self.assertFalse(tx.verify_pow())

    def test_token_creation_basics(self):
        data = bytes.fromhex('00020104000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e1712af2a2fd'
                             '8900006a473045022100a445edb5cd6c79a0a7b5ed837582fd65b8d511ee60b64fd076'
                             'e07bd8f63f75a202202dca24320bffc4c3ca2a07cdfff38f7c839bde70ed49ef634ac6'
                             '588972836cab2103bfa995d676e3c0ed7b863c74cfef9683fab3163b42b6f21442326a'
                             '023fc57fba0000264800001976a9146876f9578221fdb678d4e8376503098a9228b132'
                             '88ac00004e2001001976a914031761ef85a24603203c97e75af355b83209f08f88ac00'
                             '00000181001976a9149f091256cb98649c7c35df0aad44d7805710691e88ac00000002'
                             '81001976a914b1d7a5ee505ad4d3b93ea1a5162ba83d5049ec4e88ac0109546f546865'
                             '4d6f6f6e04f09f9a804034a52aec6cece75e0fc0e30200001a72272f48339fcc5d5ec5'
                             'deaf197855964b0eb912e8c6eefe00928b6cf600001055641c20b71871ed2c5c7d4096'
                             'a34f40888d79c25bce74421646e732dc01ff7369')
        tx = TokenCreationTransaction.create_from_struct(data)

        self.assertEqual(data, bytes(tx))
        self.assertTrue(tx.verify_pow())
        self.assertTrue(tx.is_transaction)
        self.assertFalse(tx.is_block)

        # These prints are here to test the methods.
        self.assertEqual(
            str(tx),
            'TokenCreationTransaction(nonce=33518441, timestamp=1578090723, version=2, weight=20.645186, '
            'hash=00000828d80dd4cd809c959139f7b4261df41152f4cce65a8777eb1c3a1f9702, '
            'token_name=ToTheMoon, token_symbol=🚀, token_version=1)'
        )
        self.assertEqual(
            repr(tx),
            'TokenCreationTransaction(nonce=33518441, timestamp=1578090723, version=2, weight=20.645186, '
            'hash=00000828d80dd4cd809c959139f7b4261df41152f4cce65a8777eb1c3a1f9702, '
            'inputs=[TxInput(tx_id=000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e1712af2a2fd89, index=0)], '
            'outputs=[TxOutput(token_data=0b0, value=9800), TxOutput(token_data=0b1, value=20000), '
            'TxOutput(token_data=0b10000001, value=0b1), TxOutput(token_data=0b10000001, value=0b10)], '
            'parents=[\'00001a72272f48339fcc5d5ec5deaf197855964b0eb912e8c6eefe00928b6cf6\', '
            '\'00001055641c20b71871ed2c5c7d4096a34f40888d79c25bce74421646e732dc\'])'
        )

        tx.nonce += 1
        tx.update_hash()
        self.assertFalse(tx.verify_pow())

    def test_token_creation_with_fee_header(self):
        """Test TokenCreationTransaction with fee header"""
        from hathorlib.token_creation_tx import TokenCreationTransaction, TokenVersion

        data = bytes.fromhex(
            '0002010400000672c17c8fcf7277eece0b8cbe3f0efbdf6205e5e8554ccff5ca85ec8e49000069463044022070c5bfcd3b2f177'
            'c842de1937c8a089bec64ea2d27754056fb7d7882e731aad7022073b6811313a52f74a88cedbbb2d951ddd5c6d2bba97332eea74'
            '2e020d7717f04210299138e77a8039c31a112941480231cccefc9e627fef5ff4a391e7a2689b319d40000000900001976a914ba6'
            'a16b0ab2c2bf132e1cfbdc01ef86a8c749a7188ac0000006401001976a914ba6a16b0ab2c2bf132e1cfbdc01ef86a8c749a7188a'
            'c0000000181001976a914ba6a16b0ab2c2bf132e1cfbdc01ef86a8c749a7188ac0000000281001976a914ba6a16b0ab2c2bf132e'
            '1cfbdc01ef86a8c749a7188ac0209546f6b656e4e616d6503544b4e4031b96d6968b53e690472ad000000000011010000000001'
        )

        tx = TokenCreationTransaction.create_from_struct(data)

        # Verify the token version is FEE (2)
        self.assertEqual(tx.token_version, TokenVersion.FEE)

        # Verify the transaction can be serialized and deserialized correctly
        self.assertEqual(data, bytes(tx))

        # Verify basic transaction properties
        self.assertTrue(tx.is_transaction)
        self.assertFalse(tx.is_block)
        self.assertTrue(tx.has_fees())

        # Verify the fee header contains the expected fee entry
        fee_header = tx.get_fee_header()
        self.assertEqual(len(fee_header.fees), 1)
        self.assertEqual(fee_header.fees[0].token_index, 0)
        self.assertEqual(fee_header.fees[0].amount, 1)

        self.assertEqual(len(fee_header.get_fees()), 1)
        self.assertEqual(fee_header.get_fees()[0].amount, 1)
        self.assertEqual(fee_header.get_fees()[0].token_uid, settings.HATHOR_TOKEN_UID)

        # Verify the string representation includes token_version=2
        str_repr = str(tx)
        self.assertIn('token_version=2', str_repr)
        self.assertIn('token_name=TokenName', str_repr)
        self.assertIn('token_symbol=TKN', str_repr)

    def test_script_basics(self):
        create_output_script(decode_address('HVZjvL1FJ23kH3buGNuttVRsRKq66WHUVZ'))

    def test_standard_tx(self):
        data = bytes.fromhex('0001000102000001e0e88216036e4e52872ba60a96df7570c3e29cc30eda6dd92ea0fd'
                             '304c00006a4730450221009fa4798bb69f66035013063c13f1a970ec58111bcead277d'
                             '9c93e45c2b6885fe022012e039b26cc4a4cb0a8a5abb7deb7bb78610ed362bf422efa2'
                             '47db37c5a841e12102bc1213ea99ab55effcff760f94c09f8b1a0b7b990c01128d06b4'
                             'a8c5c5f41f8400089f0800001976a91438fb3bc92b76819e9c19ef7c079d327c8fcd19'
                             '9288ac02de2d3800001976a9148d880c42ddcf78a2da5d06558f13515508720b4088ac'
                             '403518509c63f9195ecfd7d40200001ea9d6e1d31da6893fcec594dc3fa8b6819ae126'
                             '8c190f7a1441302226e2000007d1c5add7b9085037cfc591f1008dff4fe8a9158fd1a4'
                             '840a6dd5d4e4e600d2da8d')

        tx = tx_or_block_from_bytes(data)
        self.assertTrue(tx.is_standard())

        # Change the first output to have script size bigger than allowed
        tx.outputs[0].script = b'x' * (settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE + 1)
        tx_bytes_big = bytes(tx)
        tx2 = tx_or_block_from_bytes(tx_bytes_big)
        self.assertFalse(tx2.is_standard())
        self.assertFalse(tx2.is_standard(std_max_output_script_size=settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE + 1))
        self.assertTrue(
            tx2.is_standard(
                std_max_output_script_size=settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE + 1, only_standard_script_type=False
            )
        )

        # Make first output non standard
        tx.outputs[0].script = b'x' * settings.PUSHTX_MAX_OUTPUT_SCRIPT_SIZE
        tx_bytes_non_standard = bytes(tx)
        tx3 = tx_or_block_from_bytes(tx_bytes_non_standard)
        self.assertFalse(tx3.is_standard())
        self.assertTrue(tx3.is_standard(only_standard_script_type=False))

    def test_tx_with_nano_and_fee_headers(self):
        """Test Transaction with NanoHeader and FeeHeader"""
        from hathorlib.headers import FeeHeader, NanoHeader

        data = bytes.fromhex(
            '0001010102a63cd61c1265d2ddcaf9e59072e999be92f1e8b3a9f80d3059667ebd07acff8200000b55'
            '0310ce5d2405848b90497875979809205758c3be336d58fa4b358e7400006946304402201ce9d15038'
            '2e74fb123fdb9b418372ab02f5e342eef77302711ba25bbad6fc2a022079552147f44d01fe5339e3e1'
            '1748b5fb7bce1f45389daf8314d60a50c87b3a2e21036acf7120c9c95d917ab44ebf223f9c9fe202c3'
            'f61a963469ac99dadbb7f066450000006401001976a914ce852b6869b2e6a78341beaf68e301784696'
            '605e88ac0000225f00001976a914cc62dd4e0d45b3c92768eb8d31d32ee203aa968088ac4034451999'
            '38bb1f694ac1350000000000100000096571b0cae543f7b16d395b19b655a1266210de1892fd127c3'
            '15aa04ff105046e6f6f700001000102010000006449ce852b6869b2e6a78341beaf68e30178469660'
            '5e819040746946304402201ce9d150382e74fb123fdb9b418372ab02f5e342eef77302711ba25bbad6'
            'fc2a022079552147f44d01fe5339e3e11748b5fb7bce1f45389daf8314d60a50c87b3a2e21036acf71'
            '20c9c95d917ab44ebf223f9c9fe202c3f61a963469ac99dadbb7f0664511010000000001'
        )

        tx = Transaction.create_from_struct(data)

        # Verify the transaction can be serialized and deserialized correctly
        self.assertEqual(data, bytes(tx))

        # Verify basic transaction properties
        self.assertTrue(tx.is_transaction)
        self.assertFalse(tx.is_block)
        self.assertTrue(tx.has_fees())
        self.assertTrue(tx.is_nano_contract())

        # Verify transaction structure
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(len(tx.outputs), 2)
        self.assertEqual(len(tx.tokens), 1)
        self.assertEqual(len(tx.headers), 2)

        # Verify the headers are of correct types
        nano_header = tx.get_nano_header()
        fee_header = tx.get_fee_header()
        self.assertIsInstance(nano_header, NanoHeader)
        self.assertIsInstance(fee_header, FeeHeader)

        # Verify the fee header contains the expected fee entry
        self.assertEqual(len(fee_header.fees), 1)
        self.assertEqual(fee_header.fees[0].token_index, 0)
        self.assertEqual(fee_header.fees[0].amount, 1)

        # Verify the nano header has expected method
        self.assertEqual(nano_header.nc_method, 'noop')

    def test_tx_with_unshield_balance_header(self):
        """Test Transaction with UnshieldBalanceHeader: serialization round-trip,
        parser dispatch, length validation, and accessors."""
        from hathorlib.headers import UnshieldBalanceHeader, VertexHeaderId
        from hathorlib.vertex_parser import VertexParser

        tx = Transaction()
        excess = bytes(range(32))
        header = UnshieldBalanceHeader(excess_blinding_factor=excess)

        # Wire format: header_id(1) | excess_blinding_factor(32)
        wire = header.serialize()
        self.assertEqual(len(wire), 33)
        self.assertEqual(wire[:1], VertexHeaderId.UNSHIELD_BALANCE_HEADER.value)
        self.assertEqual(wire[:1], b'\x13')
        self.assertEqual(wire[1:], excess)

        # Parser registry dispatches the correct class by header id.
        parser_cls = VertexParser.get_header_parser(b'\x13')
        self.assertIs(parser_cls, UnshieldBalanceHeader)

        # Deserialization recovers the header with no leftover bytes.
        parsed, leftover = parser_cls.deserialize(tx, wire)
        self.assertEqual(leftover, b'')
        self.assertEqual(parsed.excess_blinding_factor, excess)

        # Extra bytes after the header are returned as leftover.
        trailing = b'\xde\xad\xbe\xef'
        parsed2, leftover2 = parser_cls.deserialize(tx, wire + trailing)
        self.assertEqual(leftover2, trailing)
        self.assertEqual(parsed2.excess_blinding_factor, excess)

        # sighash bytes equal the full serialization (signature-bound).
        self.assertEqual(header.get_sighash_bytes(), wire)

        # Wrong scalar length is rejected at construction time.
        with self.assertRaises(ValueError):
            UnshieldBalanceHeader(excess_blinding_factor=b'\x00' * 31)

        # Truncated buffer is rejected at deserialization time.
        with self.assertRaises(ValueError):
            parser_cls.deserialize(tx, wire[:20])

        # Wrong header id byte is rejected.
        with self.assertRaises(ValueError):
            parser_cls.deserialize(tx, b'\x99' + excess)

        # Transaction accessor finds the header once attached.
        self.assertFalse(tx.has_unshield_balance())
        tx.headers.append(header)
        self.assertTrue(tx.has_unshield_balance())
        self.assertIs(tx.get_unshield_balance_header(), header)

    def test_tx_with_mint_melt_headers(self):
        """MintHeader / MeltHeader: entry (de)serialization round-trip through the
        module-level helpers, parser-registry dispatch, and entry validation.

        The header classes' deserialize/serialize/get_sighash_bytes are unused
        stubs that raise NotImplementedError: hathor-core drives (de)serialization
        through the framework free functions in `_mint_melt_header.py`, which
        delegate to `serialize_entries` / `deserialize_entries`.
        """
        from hathorlib.headers import (
            MeltHeader,
            MintHeader,
            MintMeltEntry,
            VertexHeaderId,
            deserialize_entries,
            serialize_entries,
        )
        from hathorlib.serialization import Deserializer, Serializer
        from hathorlib.vertex_parser import VertexParser

        tx = Transaction()
        cases = [
            (MintHeader, VertexHeaderId.MINT_HEADER.value, b'\x14', 'MintHeader'),
            (MeltHeader, VertexHeaderId.MELT_HEADER.value, b'\x15', 'MeltHeader'),
        ]
        for header_cls, id_value, id_byte, header_name in cases:
            self.assertEqual(id_value, id_byte)  # the enum value is the literal id byte
            entries = [MintMeltEntry(token_index=1, amount=1000), MintMeltEntry(token_index=3, amount=2 ** 63)]
            header = header_cls(entries=entries)

            # The parser registry still dispatches the correct class by header id.
            self.assertIs(VertexParser.get_header_parser(id_byte), header_cls)

            # Entries round-trip through the module-level helpers (the real path).
            # Entry block wire format: num_entries(1) | (token_index(1) | amount(8 BE))...
            serializer = Serializer.build_bytes_serializer()
            serialize_entries(serializer, entries)
            wire = bytes(serializer.finalize())
            self.assertEqual(wire[0], len(entries))
            self.assertEqual(len(wire), 1 + len(entries) * 9)

            deserializer = Deserializer.build_bytes_deserializer(wire)
            self.assertEqual(deserialize_entries(deserializer, header_name=header_name), entries)

            # The header class's (de)serialization methods are unused stubs.
            with self.assertRaises(NotImplementedError):
                header.serialize()
            with self.assertRaises(NotImplementedError):
                header.get_sighash_bytes()
            with self.assertRaises(NotImplementedError):
                header_cls.deserialize(tx, wire)

        # Entry validation at construction time: token_index in [1, 16], amount in [1, 2**64).
        with self.assertRaises(ValueError):
            MintMeltEntry(token_index=0, amount=1)
        with self.assertRaises(ValueError):
            MintMeltEntry(token_index=1, amount=0)
        with self.assertRaises(ValueError):
            MintMeltEntry(token_index=17, amount=1)

    def test_shielded_output_serialization_roundtrip(self):
        """serialize/deserialize round-trip for both output modes, incl. ephemeral present/absent.

        Pure bytes — no crypto library needed."""
        from hathorlib.serialization import Deserializer, Serializer
        from hathorlib.transaction.shielded_tx_output import (
            EPHEMERAL_PUBKEY_SIZE,
            AmountShieldedOutput,
            FullShieldedOutput,
            deserialize_shielded_output,
            serialize_shielded_output,
        )

        def roundtrip(out):
            serializer = Serializer.build_bytes_serializer()
            serialize_shielded_output(serializer, out)
            data = bytes(serializer.finalize())
            deserializer = Deserializer.build_bytes_deserializer(data)
            parsed = deserialize_shielded_output(deserializer)
            deserializer.finalize()  # asserts every byte consumed — guards over/under-read
            return data, parsed

        # AmountShielded, ephemeral absent: default is None and the wire writes 33 zero bytes.
        amount_absent = AmountShieldedOutput(
            commitment=b'\x11' * 33, range_proof=b'\x22' * 64, script=b'\x33' * 25, token_data=5,
        )
        self.assertIsNone(amount_absent.ephemeral_pubkey)
        data, parsed = roundtrip(amount_absent)
        self.assertEqual(data[-EPHEMERAL_PUBKEY_SIZE:], b'\x00' * EPHEMERAL_PUBKEY_SIZE)
        self.assertIsNone(parsed.ephemeral_pubkey)
        self.assertEqual(parsed, amount_absent)

        # AmountShielded, ephemeral present: preserved verbatim.
        eph = b'\x02' + b'\x44' * 32
        amount_present = AmountShieldedOutput(
            commitment=b'\x11' * 33, range_proof=b'\x22' * 64, script=b'\x33' * 25,
            token_data=5, ephemeral_pubkey=eph,
        )
        data2, parsed2 = roundtrip(amount_present)
        self.assertEqual(data2[-EPHEMERAL_PUBKEY_SIZE:], eph)
        self.assertEqual(parsed2.ephemeral_pubkey, eph)
        self.assertEqual(parsed2, amount_present)

        # FullShielded round-trip (asset_commitment + surjection_proof).
        full = FullShieldedOutput(
            commitment=b'\x55' * 33, range_proof=b'\x66' * 100, script=b'\x77' * 10,
            asset_commitment=b'\x88' * 33, surjection_proof=b'\x99' * 200,
        )
        _, parsed_full = roundtrip(full)
        self.assertEqual(parsed_full, full)
        self.assertIsNone(parsed_full.ephemeral_pubkey)

    def test_shielded_outputs_header_serialization_roundtrip(self):
        """ShieldedOutputsHeader round-trip + parser dispatch + leftover handling.

        Locks in the framework-based (de)serialization and the tx-less header construction."""
        from hathorlib.headers import ShieldedOutputsHeader, VertexHeaderId
        from hathorlib.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput
        from hathorlib.vertex_parser import VertexParser

        tx = Transaction()
        outputs = [
            AmountShieldedOutput(commitment=b'\x11' * 33, range_proof=b'\x22' * 64,
                                 script=b'\x33' * 25, token_data=5),
            FullShieldedOutput(commitment=b'\x55' * 33, range_proof=b'\x66' * 100, script=b'\x77' * 10,
                               asset_commitment=b'\x88' * 33, surjection_proof=b'\x99' * 200),
        ]
        header = ShieldedOutputsHeader(shielded_outputs=outputs)  # no tx field

        wire = header.serialize()
        self.assertEqual(wire[:1], VertexHeaderId.SHIELDED_OUTPUTS_HEADER.value)
        self.assertEqual(wire[:1], b'\x12')
        self.assertEqual(wire[1], len(outputs))  # count byte

        parser_cls = VertexParser.get_header_parser(b'\x12')
        self.assertIs(parser_cls, ShieldedOutputsHeader)

        # Deserialization recovers the outputs with no leftover.
        parsed, leftover = parser_cls.deserialize(tx, wire)
        self.assertEqual(leftover, b'')
        self.assertEqual(parsed.shielded_outputs, outputs)

        # Consumes exactly the header's bytes — trailing bytes are returned as leftover.
        trailing = b'\xde\xad\xbe\xef'
        parsed2, leftover2 = parser_cls.deserialize(tx, wire + trailing)
        self.assertEqual(leftover2, trailing)
        self.assertEqual(parsed2.shielded_outputs, outputs)

        # Transaction accessor finds the header once attached.
        self.assertFalse(tx.has_shielded_outputs())
        tx.headers.append(header)
        self.assertTrue(tx.has_shielded_outputs())
        self.assertIs(tx.get_shielded_outputs_header(), header)

    def test_tx_version_and_signal_bits(self):
        from hathorlib.base_transaction import TxVersion

        # test invalid type
        with self.assertRaises(AssertionError) as cm:
            TxVersion('test')

        self.assertEqual(str(cm.exception), "Value 'test' must be an integer")

        # test one byte max value
        with self.assertRaises(AssertionError) as cm:
            TxVersion(0x100)

        self.assertEqual(str(cm.exception), 'Value 0x100 must not be larger than one byte')

        # test invalid version
        with self.assertRaises(ValueError) as cm:
            TxVersion(10)

        self.assertEqual(str(cm.exception), 'Invalid version: 10')

        # test get the correct class
        version = TxVersion(0x00)
        self.assertEqual(get_cls_from_tx_version(version), Block)
        version = TxVersion(0x01)
        self.assertEqual(get_cls_from_tx_version(version), Transaction)

        # test serialization doesn't mess up with signal_bits and version
        data = bytes.fromhex('f00001ffffffe8b789180000001976a9147fd4ae0e4fb2d2854e76d359029d8078bb9'
                             '9649e88ac40350000000000005e0f84a9000000000000000000000000000000278a7e')
        block = Block.create_from_struct(data)
        block2 = block.clone()

        self.assertEqual(block.signal_bits, block2.signal_bits)
        self.assertEqual(block.version, block2.version)
