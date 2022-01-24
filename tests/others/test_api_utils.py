import unittest

from hathor.api_util import parse_args


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
