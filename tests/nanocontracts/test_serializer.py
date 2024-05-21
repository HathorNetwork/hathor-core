import struct
from typing import Any, Optional

from hathor.nanocontracts.exception import UnknownFieldType
from hathor.nanocontracts.serializers import Deserializer, Serializer
from hathor.nanocontracts.types import SignedData
from tests import unittest


class NCSerializerTestCase(unittest.TestCase):
    def _run_test_signed(self, _type: Any, result: Any) -> None:
        from hathor.wallet import KeyPair

        serializer = Serializer()
        deserializer = Deserializer()

        result_bytes = serializer.from_type(_type, result)

        # Oracle's private key.
        key = KeyPair.create(b'my-key')
        script_input = key.p2pkh_create_input_data(b'my-key', result_bytes)
        signed_result: SignedData[_type] = SignedData(result, script_input)

        serialized_bytes = serializer.from_type(SignedData[_type], signed_result)
        signed_result2: SignedData[_type] = deserializer.from_type(SignedData[_type], serialized_bytes)

        self.assertEqual(signed_result.data, signed_result2.data)
        self.assertEqual(signed_result.script_input, signed_result2.script_input)

    def test_signed_bytes(self):
        self._run_test_signed(bytes, b'1x1')

    def test_signed_str(self):
        self._run_test_signed(str, '1x1')

    def test_signed_bool(self):
        self._run_test_signed(bool, True)

    def test_signed_invalid_type(self):
        with self.assertRaises(UnknownFieldType):
            self._run_test_signed(list, [])

    def test_invalid_bool(self):
        deserializer = Deserializer()
        with self.assertRaises(ValueError):
            deserializer.from_type(bool, b'\x02')

    def _run_test(self, _type, value):
        serializer = Serializer()
        value_bytes = serializer.from_type(_type, value)

        deserializer = Deserializer()
        value_out = deserializer.from_type(_type, value_bytes)

        self.assertEqual(value, value_out)

    def test_str_empty(self):
        self._run_test(str, '')

    def test_str_valid(self):
        self._run_test(str, 'hathor')

    def test_str_accents(self):
        self._run_test(str, 'áéíóúçãõ')

    def test_bytes_empty(self):
        self._run_test(bytes, b'')

    def test_bytes_valid(self):
        self._run_test(bytes, b'\x01\x02')

    def test_int_negative(self):
        self._run_test(int, -100)

    def test_int_zero(self):
        self._run_test(int, 0)

    def test_int_positive(self):
        self._run_test(int, 100)

    def test_int_too_big(self):
        with self.assertRaises(struct.error):
            self._run_test(int, 2**31)

    def test_float_valid(self):
        self._run_test(float, 1.23)

    def test_float_int_valid(self):
        self._run_test(float, 1)

    def test_optional_str_none(self):
        self._run_test(Optional[str], None)

    def test_optional_str_empty(self):
        self._run_test(Optional[str], '')

    def test_optional_str(self):
        self._run_test(Optional[str], 'hathor')

    def test_tuple(self):
        self._run_test(tuple[int, str, float, bytes], (1, 'a', 1.0, b'b'))

    def test_tuple_optional_str(self):
        _type = tuple[int, Optional[str]]
        self._run_test(_type, (1, 'a'))

    def test_tuple_optional_none(self):
        _type = tuple[int, Optional[str]]
        self._run_test(_type, (1, None))
