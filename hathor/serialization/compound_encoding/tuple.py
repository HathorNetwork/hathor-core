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
In Python a tuple type can be used in annotations in 2 different ways:

1. `tuple[A, B, C]`: known fixed length and heterogeneous types
2. `tuple[X, ...]`: variable length and homogeneous type

This module only implements encoding of the first case, the second case can be encoded using the collection encoder.

There actually isn't a "format" per-se, the encoding of `tuple[A, B, C]` is just the encoding of A concatenated with B
concatenated with C. So this compound encoder is basically a shortcut that can be used by cases that already have a
tuple of values and a matching tuple of encoders of those values.

>>> from hathor.serialization.encoding.utf8 import encode_utf8, decode_utf8
>>> from hathor.serialization.encoding.bool import encode_bool, decode_bool
>>> from hathor.serialization.encoding.bytes import decode_bytes, encode_bytes
>>> se = Serializer.build_bytes_serializer()
>>> values = ('foobar', False, b'test')
>>> encode_tuple(se, values, (encode_utf8, encode_bool, encode_bytes))
>>> bytes(se.finalize()).hex()
'06666f6f626172000474657374'

Breakdown of the result:

    06666f6f626172: 'foobar'
    00: False
    0474657374: b'test'

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('06666f6f626172000474657374'))
>>> decode_tuple(de, (decode_utf8, decode_bool, decode_bytes))
('foobar', False, b'test')
"""

from typing import Any

from typing_extensions import TypeVarTuple, Unpack

from hathor.serialization import Deserializer, Serializer

from . import Decoder, Encoder

Ts = TypeVarTuple('Ts')


def encode_tuple(serializer: Serializer, values: tuple[Unpack[Ts]], encoders: tuple[Encoder[Any], ...]) -> None:
    assert len(values) == len(encoders)
    # mypy can't track tuple element-wise mapping yet — safe due to length check above
    for value, encoder in zip(values, encoders):  # type: ignore
        encoder(serializer, value)


def decode_tuple(deserializer: Deserializer, decoders: tuple[Decoder[Any], ...]) -> tuple[Unpack[Ts]]:
    return tuple(decoder(deserializer) for decoder in decoders)
