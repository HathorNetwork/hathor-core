# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

r"""
This module implements utf-8 string encoding with a length prefix.

It works exactly like bytes-encoding but the encoded byte-sequence is utf-8 and it takes/returns a `str`.

>>> se = Serializer.build_bytes_serializer()
>>> encode_utf8(se, 'foobar')  # writes 06666f6f626172
>>> encode_utf8(se, 'ハトホル')  # writes 0ce3838fe38388e3839be383ab
>>> encode_utf8(se, '😎')  # writes 04f09f988e
>>> bytes(se.finalize()).hex()
'06666f6f6261720ce3838fe38388e3839be383ab04f09f988e'

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('06666f6f6261720ce3838fe38388e3839be383ab04f09f988e'))
>>> decode_utf8(de)  # reads 06666f6f626172
'foobar'
>>> decode_utf8(de)  # reads 0ce3838fe38388e3839be383ab
'ハトホル'
>>> decode_utf8(de)  # reads 04f09f988e
'😎'
>>> de.finalize()
"""

from hathorlib.serialization import Deserializer, Serializer

from .bytes import decode_bytes, encode_bytes


def encode_utf8(serializer: Serializer, value: str) -> None:
    """ Encodes a string using UTF-8 and adding a length prefix.

    This modules's docstring has more details and examples.
    """
    assert isinstance(value, str)
    data = value.encode('utf-8')
    encode_bytes(serializer, data)


def decode_utf8(deserializer: Deserializer) -> str:
    """ Decodes a UTF-8 string with a length prefix.

    This modules's docstring has more details and examples.
    """
    data = decode_bytes(deserializer)
    return data.decode('utf-8')
