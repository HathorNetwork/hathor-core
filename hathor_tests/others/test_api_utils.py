# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import unittest

from hathor.api_util import APIVersion, parse_args
from hathorlib.token_amount import UnsignedAmount


class APIVersionAmountTestCase(unittest.TestCase):
    """Pin the on-the-wire encoding of token amounts for each API version.

    Decimal places are configured globally by the test conftest (V1 = 2, V2 = 18).
    """

    def test_to_response_v1a_is_v1_int(self) -> None:
        self.assertEqual(APIVersion.V1A.unsigned_amount_to_response(UnsignedAmount.zero()), 0)
        self.assertEqual(APIVersion.V1A.unsigned_amount_to_response(UnsignedAmount.from_v1(12345)), 12345)

    def test_to_response_v2_is_18_decimal_string(self) -> None:
        self.assertEqual(APIVersion.V2.unsigned_amount_to_response(UnsignedAmount.zero()), '0.0')
        self.assertEqual(APIVersion.V2.unsigned_amount_to_response(UnsignedAmount.from_v1(12345)), '123.45')

    def test_from_request_v1a_reads_v1_int(self) -> None:
        self.assertEqual(APIVersion.V1A.unsigned_amount_from_request('12345'), UnsignedAmount.from_v1(12345))

    def test_from_request_v2_reads_decimal_string(self) -> None:
        self.assertEqual(
            APIVersion.V2.unsigned_amount_from_request('123.45'),
            UnsignedAmount.from_v1(12345),
        )


class ApiUtilsTestCase(unittest.TestCase):
    def test_parse_get_arguments(self):
        params = {
            b'arg1': [b'value1'],
            b'arg2': [b'value2'],
            b'arg3': [b'value3'],
        }

        # missing param
        expected = ['arg1', 'arg2', 'arg3', 'arg4']
        self.assertFalse(parse_args(params, expected)['success'])

        # we can have more params than expected; that's ok
        expected = ['arg1', 'arg2']
        self.assertTrue(parse_args(params, expected)['success'])

        # check return dict
        expected = ['arg1', 'arg2', 'arg3']
        ret = parse_args(params, expected)
        self.assertTrue(ret['success'])
        args = ret['args']
        for arg in expected:
            returned_value = args.get(arg)
            expected_value = (params.get(arg.encode('utf-8'))[0]).decode('utf-8')
            self.assertEqual(returned_value, expected_value)
