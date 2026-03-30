# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from hathorlib.exceptions import InvalidAddress
from hathorlib.utils.address import (
    decode_address,
    get_address_b58_from_bytes,
    get_address_b58_from_public_key,
    get_address_b58_from_public_key_bytes,
    get_address_b58_from_public_key_hash,
    get_address_b58_from_redeem_script_hash,
    get_address_from_public_key_hash,
    get_address_from_redeem_script_hash,
    get_checksum,
    get_hash160,
    get_public_key_bytes_compressed,
    get_public_key_from_bytes_compressed,
    is_pubkey_compressed,
)


class TestChecksum(unittest.TestCase):
    def test_checksum_deterministic(self) -> None:
        data = b'\x00' + b'\x01' * 20
        checksum = b'I\x0fU('
        checksum1 = get_checksum(data)
        checksum2 = get_checksum(data)
        self.assertEqual(checksum, checksum1)
        self.assertEqual(checksum1, checksum2)
        self.assertEqual(len(checksum1), 4)

    def test_different_data_different_checksum(self) -> None:
        c1 = get_checksum(b'\x00' * 21)
        c2 = get_checksum(b'\x01' * 21)
        self.assertNotEqual(c1, c2)


class TestDecodeAddress(unittest.TestCase):
    def test_valid_address_roundtrip(self) -> None:
        # Build a valid address from a known pubkey
        # private_bytes = '308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420e0a16e87ebe898762971ce1a9e340378604e6ecd5c1bc64d0ed0deb950488923a144034200047fe80ee4f43df6a778b383fbc9ba9a09b8b64c9dc42ad01cfa4b40073bcd4f29a404f08992f9d909364fc42d019e65c0036f6ddfb81986fca70ada8e37096203'
        pubkey_bytes = bytes.fromhex('037fe80ee4f43df6a778b383fbc9ba9a09b8b64c9dc42ad01cfa4b40073bcd4f29')
        expected_address_b58 = 'HSzGCLFukjR7AigSgfhTbvB8ABcPPfeHZC'
        pubkey = get_public_key_from_bytes_compressed(pubkey_bytes)
        address_b58 = get_address_b58_from_public_key(pubkey)

        self.assertEqual(expected_address_b58, address_b58)

        # Decode should succeed
        decoded = decode_address(address_b58)
        self.assertEqual(len(decoded), 25)

        # Re-encode should give the same b58
        re_encoded = get_address_b58_from_bytes(decoded)
        self.assertEqual(re_encoded, address_b58)

    def test_invalid_base58(self) -> None:
        with self.assertRaises(InvalidAddress):
            decode_address('0OIl')  # invalid base58 chars

    def test_wrong_size(self) -> None:
        import base58
        # Encode too-short data
        short_b58 = base58.b58encode(b'\x00' * 10).decode('utf-8')
        with self.assertRaises(InvalidAddress):
            decode_address(short_b58)

    def test_bad_checksum(self) -> None:
        import base58
        # Build valid address then corrupt checksum
        data = b'\x00' + b'\x01' * 20
        checksum = get_checksum(data)
        bad_checksum = bytes([checksum[0] ^ 0xFF]) + checksum[1:]
        bad_address = base58.b58encode(data + bad_checksum).decode('utf-8')
        with self.assertRaises(InvalidAddress):
            decode_address(bad_address)


class TestAddressFromPublicKeyHash(unittest.TestCase):
    def test_get_address_from_public_key_hash(self) -> None:
        pk_hash = b"\xe0\x84D'f8\xe4\xdf\xb4\x8e@lG\xef\xca}@\x9f\x92\x97"
        address = b"(\xe0\x84D'f8\xe4\xdf\xb4\x8e@lG\xef\xca}@\x9f\x92\x97\x8cM\x96s"
        gen_address = get_address_from_public_key_hash(pk_hash)
        self.assertEqual(address, gen_address)

    def test_get_address_b58_from_public_key_hash(self) -> None:
        pk_hash = b"\xe0\x84D'f8\xe4\xdf\xb4\x8e@lG\xef\xca}@\x9f\x92\x97"
        address_b58 = 'HSzGCLFukjR7AigSgfhTbvB8ABcPPfeHZC'
        b58 = get_address_b58_from_public_key_hash(pk_hash)
        self.assertIsInstance(b58, str)
        self.assertEqual(address_b58, b58)


class TestRedeemScriptHash(unittest.TestCase):
    def test_get_address_from_redeem_script_hash(self) -> None:
        # get_hash160(bytes.fromhex('01'))
        rs_hash = b'\xc5\x1bf\xbc\xed^D\x91\x00\x1b\xd7\x02f\x97p\xdc\xcfD\t\x82'
        expected_address = b'd\xc5\x1bf\xbc\xed^D\x91\x00\x1b\xd7\x02f\x97p\xdc\xcfD\t\x82\xfb?6\x8d'
        address = get_address_from_redeem_script_hash(rs_hash)
        self.assertEqual(address, expected_address)

    def test_get_address_b58_from_redeem_script_hash(self) -> None:
        # get_hash160(bytes.fromhex('01'))
        rs_hash = b'\xc5\x1bf\xbc\xed^D\x91\x00\x1b\xd7\x02f\x97p\xdc\xcfD\t\x82'
        address_b58 = 'hYmXQXXy8mtZ9JZKYBR61z5moGP7jJEuQp'
        b58 = get_address_b58_from_redeem_script_hash(rs_hash)
        self.assertIsInstance(b58, str)
        self.assertEqual(address_b58, b58)


class TestPubkeyCompressed(unittest.TestCase):
    def test_compressed_02(self) -> None:
        pubkey = b'\x02' + b'\x01' * 32
        self.assertTrue(is_pubkey_compressed(pubkey))

    def test_compressed_03(self) -> None:
        pubkey = b'\x03' + b'\x01' * 32
        self.assertTrue(is_pubkey_compressed(pubkey))

    def test_uncompressed_04(self) -> None:
        pubkey = b'\x04' + b'\x01' * 64
        self.assertFalse(is_pubkey_compressed(pubkey))

    def test_empty(self) -> None:
        self.assertFalse(is_pubkey_compressed(b''))


class TestHash160(unittest.TestCase):
    def test_deterministic(self) -> None:
        data = b'test_public_key'
        h1 = get_hash160(data)
        h2 = get_hash160(data)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 20)

    def test_known(self) -> None:
        expected = b'\xc5\x1bf\xbc\xed^D\x91\x00\x1b\xd7\x02f\x97p\xdc\xcfD\t\x82'
        data = bytes.fromhex('01')
        h = get_hash160(data)
        self.assertEqual(h, expected)


class TestPublicKeyConversion(unittest.TestCase):
    def test_compressed_roundtrip(self) -> None:
        pubkey_bytes = bytes.fromhex('037fe80ee4f43df6a778b383fbc9ba9a09b8b64c9dc42ad01cfa4b40073bcd4f29')
        pubkey = get_public_key_from_bytes_compressed(pubkey_bytes)
        compressed = get_public_key_bytes_compressed(pubkey)
        self.assertEqual(compressed, pubkey_bytes)

    def test_address_b58_from_public_key_bytes(self) -> None:
        pubkey_bytes = bytes.fromhex('037fe80ee4f43df6a778b383fbc9ba9a09b8b64c9dc42ad01cfa4b40073bcd4f29')
        b58 = get_address_b58_from_public_key_bytes(pubkey_bytes)
        self.assertEqual(b58, 'HSzGCLFukjR7AigSgfhTbvB8ABcPPfeHZC')
