import json
import struct
from typing import Optional

from hathor.conf import HathorSettings
from hathor.nanocontracts.api_arguments_parser import parse_arg
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCSerializationArgTooLong
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.types import SignedData, public
from tests import unittest

settings = HathorSettings()


class MyBlueprint:
    @public
    def initialize(self, ctx: Context, a: str, b: bytes, c: int, d: bool) -> None:
        pass

    @public
    def method_str(self, ctx: Context, x: str) -> None:
        pass

    @public
    def method_bytes(self, ctx: Context, x: bytes) -> None:
        pass

    @public
    def method_int(self, ctx: Context, x: int) -> None:
        pass

    @public
    def method_bool(self, ctx: Context, x: bool) -> None:
        pass

    @public
    def method_signed_str(self, ctx: Context, x: SignedData[str]) -> None:
        pass

    @public
    def method_no_ctx(self) -> None:
        pass

    @public
    def method_with_optional(self, ctx: Context, x: Optional[str]) -> None:
        pass

    @public
    def method_with_tuple(self, ctx: Context, x: tuple[str, int, int]) -> None:
        pass


class NCBlueprintTestCase(unittest.TestCase):
    def _run_test(self, method, _type, data):
        parser = NCMethodParser(method)

        # First, check arg types.
        arg_types = parser.get_method_args()
        expected_arg_types = [('x', _type)]
        self.assertEqual(expected_arg_types, arg_types)

        # Then, check serialization and deserialization.
        args_in = [data]
        serialized_args_in = parser.serialize_args(args_in)
        args_out = parser.parse_args_bytes(serialized_args_in)
        self.assertEqual(args_in, args_out)

    def test_type_str_wrong_type(self):
        with self.assertRaises(AssertionError):
            self._run_test(MyBlueprint.method_str, str, b'')

    def test_type_str_empty(self):
        self._run_test(MyBlueprint.method_str, str, '')

    def test_type_str_small(self):
        self._run_test(MyBlueprint.method_str, str, 'a')

    def test_type_str_long(self):
        # The str length uses 2 bytes after serialized.
        length = settings.NC_MAX_LENGTH_SERIALIZED_ARG - 2
        self._run_test(MyBlueprint.method_str, str, 'a' * length)

    def test_type_str_too_long(self):
        with self.assertRaises(NCSerializationArgTooLong):
            length = settings.NC_MAX_LENGTH_SERIALIZED_ARG + 1
            self._run_test(MyBlueprint.method_str, str, 'a' * length)

    def test_type_str_accents(self):
        self._run_test(MyBlueprint.method_str, str, 'áéíóú')

    def test_type_bytes_empty(self):
        self._run_test(MyBlueprint.method_bytes, bytes, b'')

    def test_type_bytes_small(self):
        self._run_test(MyBlueprint.method_bytes, bytes, b'a')

    def test_type_bytes_long(self):
        length = settings.NC_MAX_LENGTH_SERIALIZED_ARG - 2
        self._run_test(MyBlueprint.method_bytes, bytes, b'a' * length)

    def test_type_bytes_too_long(self):
        with self.assertRaises(NCSerializationArgTooLong):
            length = settings.NC_MAX_LENGTH_SERIALIZED_ARG + 1
            self._run_test(MyBlueprint.method_bytes, bytes, b'a' * length)

    def test_type_int_negative(self):
        self._run_test(MyBlueprint.method_int, int, -100)

    def test_type_int_zero(self):
        self._run_test(MyBlueprint.method_int, int, 0)

    def test_type_int_positive(self):
        self._run_test(MyBlueprint.method_int, int, 100)

    def test_type_int_too_big(self):
        with self.assertRaises(struct.error):
            self._run_test(MyBlueprint.method_int, int, 2**31)

    def test_type_int_too_small(self):
        with self.assertRaises(struct.error):
            self._run_test(MyBlueprint.method_int, int, -2**31 - 1)

    def test_type_int_wrong_type(self):
        with self.assertRaises(AssertionError):
            self._run_test(MyBlueprint.method_int, int, 1.)

    def test_type_bool_false(self):
        self._run_test(MyBlueprint.method_bool, bool, False)

    def test_type_bool_true(self):
        self._run_test(MyBlueprint.method_bool, bool, True)

    def test_type_optional_str_none(self):
        self._run_test(MyBlueprint.method_with_optional, Optional[str], None)

    def test_type_optional_str_empty(self):
        self._run_test(MyBlueprint.method_with_optional, Optional[str], '')

    def test_type_optional_str(self):
        self._run_test(MyBlueprint.method_with_optional, Optional[str], 'hathor')

    def test_type_tuple(self):
        self._run_test(MyBlueprint.method_with_tuple, tuple[str, int, int], ('x', 1, 2))

    def test_type_signed_str(self) -> None:
        x: SignedData[str] = SignedData('áéíóú', b'here-goes-the-signature')
        self._run_test(MyBlueprint.method_signed_str, SignedData[str], x)

    def test_basic_types(self):
        parser = NCMethodParser(MyBlueprint.initialize)

        # First, check arg types.
        arg_types = parser.get_method_args()
        expected_arg_types = [
            ('a', str),
            ('b', bytes),
            ('c', int),
            ('d', bool),
        ]
        self.assertEqual(expected_arg_types, arg_types)

        # Then, check serialization and deserialization.
        args_in = ['a', b'b', 1, True]
        serialized_args_in = parser.serialize_args(args_in)
        args_out = parser.parse_args_bytes(serialized_args_in)
        self.assertEqual(args_in, args_out)

    def test_arg_parse_str(self):
        parser = NCMethodParser(MyBlueprint.method_str)
        method_args = parser.get_method_args()

        value = 'test'
        parsed_args = []
        args_array = json.loads(f'["{value}"]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], value)

    def test_arg_parse_bytes(self):
        parser = NCMethodParser(MyBlueprint.method_bytes)
        method_args = parser.get_method_args()

        value = '01'
        parsed_args = []
        args_array = json.loads(f'["{value}"]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], b'\x01')

    def test_arg_parse_int(self):
        parser = NCMethodParser(MyBlueprint.method_int)
        method_args = parser.get_method_args()

        value = 1
        parsed_args = []
        args_array = json.loads(f'[{value}]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], value)

    def test_arg_parse_bool(self):
        parser = NCMethodParser(MyBlueprint.method_bool)
        method_args = parser.get_method_args()

        parsed_args = []
        args_array = json.loads('[false]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], False)

    def test_arg_parse_optional(self):
        parser = NCMethodParser(MyBlueprint.method_with_optional)
        method_args = parser.get_method_args()

        # If optional is None
        parsed_args = []
        args_array = json.loads('[null]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], None)

        # If optional has str value
        value = 'test'
        parsed_args = []
        args_array = json.loads(f'["{value}"]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], value)

    def test_arg_parse_tuple(self):
        parser = NCMethodParser(MyBlueprint.method_with_tuple)
        method_args = parser.get_method_args()

        parsed_args = []
        args_array = json.loads('[["test", 1, 2]]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], ('test', 1, 2))

    def test_arg_parse_signed_data(self):
        parser = NCMethodParser(MyBlueprint.method_signed_str)
        method_args = parser.get_method_args()

        parsed_args = []
        args_array = json.loads('[["test", "1234"]]')

        for (_, arg_type), arg_value in zip(method_args, args_array):
            parsed_args.append(parse_arg(arg_value, arg_type))

        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], SignedData('test', bytes.fromhex('1234')))
