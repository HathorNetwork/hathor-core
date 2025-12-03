import unittest
from json import JSONDecodeError

from hathor.util import json_loadb


class UtilsTest(unittest.TestCase):
    def test_invalid_json_valid_utf8(self):
        message = b'a'
        message.decode('utf-8')
        self.assertRaises(JSONDecodeError, json_loadb, message)

    def test_valid_json_invalid_utf8(self):
        message = b'\xc3\x28'
        self.assertRaises(UnicodeDecodeError, message.decode, 'utf-8')
        self.assertRaises(JSONDecodeError, json_loadb, message)

    def test_valid_json_valid_utf8(self):
        message = b'{}'
        message.decode('utf-8')
        self.assertEqual({}, json_loadb(message))
