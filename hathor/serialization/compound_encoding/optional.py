#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

r"""
An optional type is encoded the same way as a collection with max length of 1.

Layout:

    [0x00] when None
    [0x01][value] when not None

>>> from hathor.serialization.encoding.utf8 import encode_utf8, decode_utf8
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

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.bool import decode_bool, encode_bool

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
