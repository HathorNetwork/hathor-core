from typing import Optional, TypeVar

from hathor.nanocontracts.nc_types import NCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.types import SignedData
from hathor_tests import unittest

T = TypeVar('T')


class NCSerializerTestCase(unittest.TestCase):
    def _run_test(self, type_: type[T], result: T) -> None:
        nc_type = make_nc_type(type_)
        result_bytes = nc_type.to_bytes(result)
        result2: T = nc_type.from_bytes(result_bytes)
        self.assertEqual(result, result2)

    def _run_test_signed(self, type_: type[T], result: T) -> None:
        from hathor.wallet import KeyPair

        nc_type = make_nc_type(type_)
        result_bytes = nc_type.to_bytes(result)
        result2: T = nc_type.from_bytes(result_bytes)
        self.assertEqual(result, result2)

        # Oracle's private key.
        key = KeyPair.create(b'my-key')
        script_input = key.p2pkh_create_input_data(b'my-key', result_bytes)
        # XXX: ignoring valid-type because type_ can and must be used with SignedData
        signed_result: SignedData[T] = SignedData[type_](result, script_input)  # type: ignore[valid-type]
        signeddata_nc_type = make_nc_type(SignedData[type_])  # type: ignore[valid-type]
        serialized_bytes = signeddata_nc_type.to_bytes(signed_result)
        signed_result2: SignedData[T] = signeddata_nc_type.from_bytes(serialized_bytes)
        self.assertEqual(signed_result.data, signed_result2.data)
        self.assertEqual(signed_result.script_input, signed_result2.script_input)

    def _run_test_nc_type(self, nc_type: NCType[T], result: T) -> None:
        result_bytes = nc_type.to_bytes(result)
        result2: T = nc_type.from_bytes(result_bytes)
        self.assertEqual(result, result2)

    def test_signed_bytes(self):
        self._run_test_signed(bytes, b'1x1')

    def test_signed_str(self):
        self._run_test_signed(str, '1x1')

    def test_signed_bool(self):
        self._run_test_signed(bool, True)

    def test_signed_invalid_type(self):
        # XXX: list must be given a type argument, otherwise we cannot choose the inner parser, which is needed
        #      even if the list is empty, in this test we're checking that it will error
        with self.assertRaises(TypeError):
            self._run_test_signed(list, [])

    def test_invalid_bool(self):
        from hathor.nanocontracts.nc_types import BoolNCType
        bool_nc_type = BoolNCType()
        with self.assertRaises(ValueError):
            bool_nc_type.from_bytes(b'\x02')

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
        from hathor.nanocontracts.nc_types import Int32NCType
        with self.assertRaises(ValueError):
            # this fails because Int32NCType's range is [-2**31, 2**31)
            self._run_test_nc_type(Int32NCType(), 2**31)
        # but this doesn't fail because int maps to VarInt32NCType
        self._run_test(int, 2**31)
        with self.assertRaises(ValueError):
            # which has a larger, but still limited range, so this will fail:
            self._run_test(int, 2**223)

    def test_optional_str_none(self):
        self._run_test(Optional[str], None)
        self._run_test(str | None, None)

    def test_optional_str_empty(self):
        self._run_test(Optional[str], '')
        self._run_test(str | None, '')

    def test_optional_str(self):
        self._run_test(Optional[str], 'hathor')
        self._run_test(str | None, 'hathor')

    def test_tuple(self):
        self._run_test(tuple[int, str, bytes], (1, 'a', b'b'))

    def test_tuple_optional_str(self):
        type_ = tuple[int, Optional[str]]
        self._run_test(type_, (1, 'a'))

    def test_tuple_optional_none(self):
        type_ = tuple[int, Optional[str]]
        self._run_test(type_, (1, None))
