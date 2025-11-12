import json
from collections.abc import Callable
from typing import Any, Optional, TypeVar

import pytest

from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail, NCSerializationArgTooLong
from hathor.nanocontracts.method import MAX_BYTES_SERIALIZED_ARG, Method
from hathor.nanocontracts.types import SignedData, public
from hathor_tests import unittest

T = TypeVar('T')


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
    def method_with_optional(self, ctx: Context, x: Optional[str]) -> None:
        pass

    @public
    def method_with_tuple(self, ctx: Context, x: tuple[str, int, int]) -> None:
        pass


class NCBlueprintTestCase(unittest.TestCase):
    def _run_test(self, method: Callable[[Any, T], None], data: T) -> None:
        parser = Method.from_callable(method)
        self._run_test_parser(parser, data)

    def _run_test_parser(self, method_parser: Method, data: T) -> None:
        # Then, check serialization and deserialization.
        args_in = (data,)
        serialized_args_in = method_parser.serialize_args_bytes(args_in)
        args_out = method_parser.deserialize_args_bytes(serialized_args_in)
        self.assertEqual(args_in, args_out)

        # Also check that types match (they don't necessarily always match)
        self.assertEqual(type(args_in), type(args_out))

    def test_type_str_wrong_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self._run_test(MyBlueprint.method_str, b'')
        assert isinstance(e.value.__cause__, TypeError)

    def test_type_str_empty(self) -> None:
        self._run_test(MyBlueprint.method_str, '')

    def test_type_str_small(self) -> None:
        self._run_test(MyBlueprint.method_str, 'a')

    def test_type_str_long(self) -> None:
        # there are 3 bytes of overhead when serializing
        # 1 byte for the number of arguments in method_bytes
        # 2 bytes for the length of the byte sequence that follows (because its length exceeds 63 bytes)
        # since utf-8 encoding for 'a' doesn't change it, it works as if it was bytes
        overhead = 3
        length = MAX_BYTES_SERIALIZED_ARG - overhead
        self._run_test(MyBlueprint.method_str, 'a' * length)

    def test_type_str_too_long(self) -> None:
        with self.assertRaises(NCSerializationArgTooLong):
            length = MAX_BYTES_SERIALIZED_ARG + 1
            self._run_test(MyBlueprint.method_str, 'a' * length)

    def test_type_str_accents(self) -> None:
        self._run_test(MyBlueprint.method_str, 'áéíóú')

    def test_type_bytes_empty(self) -> None:
        self._run_test(MyBlueprint.method_bytes, b'')

    def test_type_bytes_small(self) -> None:
        self._run_test(MyBlueprint.method_bytes, b'a')

    def test_type_bytes_long(self) -> None:
        # there are 3 bytes of overhead when serializing
        # 1 byte for the number of arguments in method_bytes
        # 2 bytes for the length of the byte sequence that follows (because its length exceeds 63 bytes)
        overhead = 3
        length = MAX_BYTES_SERIALIZED_ARG - overhead
        self._run_test(MyBlueprint.method_bytes, b'a' * length)

    def test_type_bytes_too_long(self) -> None:
        with self.assertRaises(NCSerializationArgTooLong):
            length = MAX_BYTES_SERIALIZED_ARG + 1
            self._run_test(MyBlueprint.method_bytes, b'a' * length)

    def test_type_bytes_even_longer(self) -> None:
        class Foo:
            def bar(self, data: bytes) -> None:
                pass
        parser = Method.from_callable(Foo.bar)
        parser.args._max_bytes = 2**32  # more than long enough to test a single bytes write
        max_write_length = 2**16 - 3
        self._run_test_parser(parser, b'a' * max_write_length)  # largest valid write
        with self.assertRaises(NCSerializationArgTooLong):
            self._run_test_parser(parser, b'a' * (max_write_length + 1))  # smallest invalid write

    def test_type_int_negative(self) -> None:
        self._run_test(MyBlueprint.method_int, -100)

    def test_type_int_zero(self) -> None:
        self._run_test(MyBlueprint.method_int, 0)

    def test_type_int_positive(self) -> None:
        self._run_test(MyBlueprint.method_int, 100)

    def test_type_int_too_big(self) -> None:
        with pytest.raises(NCFail) as e:
            self._run_test(MyBlueprint.method_int, 2**223)
        assert isinstance(e.value.__cause__, ValueError)

    def test_type_int_too_small(self) -> None:
        with pytest.raises(NCFail) as e:
            self._run_test(MyBlueprint.method_int, -2**223 - 1)
        assert isinstance(e.value.__cause__, ValueError)

    def test_type_int_wrong_type(self) -> None:
        with pytest.raises(NCFail) as e:
            self._run_test(MyBlueprint.method_int, 1.)
        assert isinstance(e.value.__cause__, TypeError)

    def test_type_int(self) -> None:
        class Foo:
            def bar(self, i: int) -> None:
                pass

        valid_values = [
            0,
            1,
            -1,
            2**31,
            -2**31,
            # edge valid values for 32 bytes of signed leb128 with 4 bytes
            2**223 - 1,
            -2**223,
        ]
        for valid_value in valid_values:
            self._run_test(Foo.bar, valid_value)

        invalid_values = [
            2**223,
            -2**223 - 1,
            2**223 + 1,
            2**224,
            -2**223 - 2,
            -2**224,
        ]
        for invalid_value in invalid_values:
            with pytest.raises(NCFail) as e:
                self._run_test(Foo.bar, invalid_value)
            assert isinstance(e.value.__cause__, ValueError)

    def test_type_bool_false(self) -> None:
        self._run_test(MyBlueprint.method_bool, False)

    def test_type_bool_true(self) -> None:
        self._run_test(MyBlueprint.method_bool, True)

    def test_type_optional_str_none(self) -> None:
        self._run_test(MyBlueprint.method_with_optional, None)

    def test_type_optional_str_empty(self) -> None:
        self._run_test(MyBlueprint.method_with_optional, '')

    def test_type_optional_str(self) -> None:
        self._run_test(MyBlueprint.method_with_optional, 'hathor')

    def test_type_tuple(self) -> None:
        self._run_test(MyBlueprint.method_with_tuple, ('x', 1, 2))

    def test_type_signed_str(self) -> None:
        x: SignedData[str] = SignedData[str]('áéíóú', b'here-goes-the-signature')
        self._run_test(MyBlueprint.method_signed_str, x)

    def test_basic_types(self) -> None:
        parser = Method.from_callable(MyBlueprint.initialize)

        # Then, check serialization and deserialization.
        args_in = ('a', b'b', 1, True)
        serialized_args_in = parser.serialize_args_bytes(args_in)
        args_out = parser.deserialize_args_bytes(serialized_args_in)
        self.assertEqual(args_in, args_out)

    def test_arg_parse_str(self) -> None:
        parser = Method.from_callable(MyBlueprint.method_str)

        value = 'test'
        args_json = json.loads(f'["{value}"]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], value)

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json((value,))
        self.assertEqual(args_json, args_json2)

    def test_arg_parse_bytes(self) -> None:
        parser = Method.from_callable(MyBlueprint.method_bytes)

        value = b'\x01'
        args_json = json.loads(f'["{value.hex()}"]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], value)

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json((value,))
        self.assertEqual(args_json, args_json2)

    def test_arg_parse_int(self) -> None:
        parser = Method.from_callable(MyBlueprint.method_int)

        value = 1
        args_json = json.loads(f'[{value}]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], value)

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json((value,))
        self.assertEqual(args_json, args_json2)

    def test_arg_parse_bool(self) -> None:
        parser = Method.from_callable(MyBlueprint.method_bool)

        args_json = json.loads('[false]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], False)

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json((False,))
        self.assertEqual(args_json, args_json2)

    def test_arg_parse_optional_none(self) -> None:
        parser = Method.from_callable(MyBlueprint.method_with_optional)

        # If optional is None
        args_json = json.loads('[null]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], None)

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json((None,))
        self.assertEqual(args_json, args_json2)

    def test_arg_parse_optional_some(self) -> None:
        parser = Method.from_callable(MyBlueprint.method_with_optional)

        # If optional has str value
        value = 'test'
        args_json = json.loads(f'["{value}"]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], value)

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json(('test',))
        self.assertEqual(args_json, args_json2)

    def test_arg_parse_tuple(self):
        parser = Method.from_callable(MyBlueprint.method_with_tuple)

        args_json = json.loads('[["test", 1, 2]]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], ('test', 1, 2))

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json((('test', 1, 2),))
        self.assertEqual(args_json, args_json2)

    def test_arg_parse_signed_data(self) -> None:
        parser = Method.from_callable(MyBlueprint.method_signed_str)

        args_json = json.loads('[["test", "1234"]]')
        parsed_args = parser.args.json_to_value(args_json)

        # test that it parsed back the original value
        self.assertEqual(len(parsed_args), 1)
        self.assertEqual(parsed_args[0], SignedData[str]('test', bytes.fromhex('1234')))

        # also test that it can generate the same JSON representation
        args_json2 = parser.args.value_to_json((SignedData[str]('test', bytes.fromhex('1234')),))
        self.assertEqual(args_json, args_json2)
