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
Encoding a mapping is equivalent to encoding a collection of 2-tuples.

Layout: [N: unsigned leb128][key_0][value_0]...[key_N][value_N]

>>> from hathor.serialization.encoding.utf8 import encode_utf8, decode_utf8
>>> from hathor.serialization.encoding.bool import encode_bool, decode_bool
>>> se = Serializer.build_bytes_serializer()
>>> value = {
...     'foo': False,
...     'bar': True,
...     'foobar': True,
...     'baz': False,
... }
>>> encode_mapping(se, value, encode_utf8, encode_bool)
>>> bytes(se.finalize()).hex()
'0403666f6f00036261720106666f6f626172010362617a00'

Breakdown of the result:

    04: 4 in leb128, the total length
    03666f6f: 'foo' with length prefix
    00: False
    03626172: 'bar' with length prefix
    01: True
    06666f6f626172: 'foobar' with length prefix
    01: True
    0362617a: 'baz' with length prefix
    00: False

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('0403666f6f00036261720106666f6f626172010362617a00'))
>>> decode_mapping(de, decode_utf8, decode_bool, dict)
{'foo': False, 'bar': True, 'foobar': True, 'baz': False}
>>> de.finalize()
"""

from collections.abc import Iterable, Mapping
from typing import Callable, TypeVar

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.leb128 import decode_leb128, encode_leb128

from . import Decoder, Encoder

KT = TypeVar('KT')
VT = TypeVar('VT')
R = TypeVar('R', bound=Mapping)


def encode_mapping(
    serializer: Serializer,
    values_mapping: Mapping[KT, VT],
    key_encoder: Encoder[KT],
    value_encoder: Encoder[VT],
) -> None:
    encode_leb128(serializer, len(values_mapping), signed=False)
    for key, value in values_mapping.items():
        key_encoder(serializer, key)
        value_encoder(serializer, value)


def decode_mapping(
    deserializer: Deserializer,
    key_decoder: Decoder[KT],
    value_decoder: Decoder[VT],
    mapping_builder: Callable[[Iterable[tuple[KT, VT]]], R],
) -> R:
    size = decode_leb128(deserializer, signed=False)
    return mapping_builder(
        (key_decoder(deserializer), value_decoder(deserializer))
        for _ in range(size)
    )
