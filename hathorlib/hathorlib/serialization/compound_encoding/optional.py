# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

r"""
An optional type is encoded the same way as a collection with max length of 1.

Layout:

    [0x00] when None
    [0x01][value] when not None

>>> from hathorlib.serialization.encoding.utf8 import encode_utf8, decode_utf8
>>> se = Serializer.build_bytes_serializer()
>>> encode_optional(se, 'foobar', encode_utf8)
>>> bytes(se.finalize()).hex()
'0106666f6f626172'

>>> se = Serializer.build_bytes_serializer()
>>> encode_optional(se, None, encode_utf8)
>>> bytes(se.finalize()).hex()
'00'

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('0106666f6f626172'))
>>> decode_optional(de, decode_utf8)
'foobar'
>>> de.finalize()

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('00'))
>>> str(decode_optional(de, decode_utf8))
'None'
>>> de.finalize()
"""

from typing import Optional, TypeVar

from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.bool import decode_bool, encode_bool

from . import Decoder, Encoder

T = TypeVar('T')


def encode_optional(serializer: Serializer, value: Optional[T], encoder: Encoder[T]) -> None:
    if value is None:
        encode_bool(serializer, False)
    else:
        encode_bool(serializer, True)
        encoder(serializer, value)


def decode_optional(deserializer: Deserializer, decoder: Decoder[T]) -> Optional[T]:
    has_value = decode_bool(deserializer)
    if has_value:
        return decoder(deserializer)
    else:
        return None
