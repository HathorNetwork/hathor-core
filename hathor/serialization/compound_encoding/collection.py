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
A collection is basically any value that has a known size and is iterable.

Layout: [N: unsigned leb128][value_0]...[value_N]

>>> from hathor.serialization.encoding.utf8 import encode_utf8, decode_utf8
>>> se = Serializer.build_bytes_serializer()
>>> value = ['foobar', 'π', '😎', 'test']
>>> encode_collection(se, value, encode_utf8)
>>> bytes(se.finalize()).hex()
'0406666f6f62617202cf8004f09f988e0474657374'

Breakdown of the result:

    04: 4 in leb128, the total length
    06666f6f626172: 'foobar' with length prefix)
    02cf80: 'π' (with length prefix)
    04f09f988e: '😎' (with length prefix)
    0474657374: 'test' (with length prefix)

When decoding, the builder can be any compabile collection, in the previous example a `list` was encoded, but when
decoding a `tuple` could be used, it only matters that the collection can be initialized with an `Iterable[T]`.

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('0406666f6f62617202cf8004f09f988e0474657374'))
>>> decode_collection(de, decode_utf8, tuple)
('foobar', 'π', '😎', 'test')
>>> de.finalize()
"""

from collections.abc import Collection, Iterable
from typing import Callable, TypeVar

from hathor.serialization import Deserializer, SerializationError, Serializer
from hathor.serialization.encoding.leb128 import decode_leb128, encode_leb128

from ...utils.result import Ok, Result, propagate_result
from . import Decoder, Encoder

T = TypeVar('T')
R = TypeVar('R', bound=Collection)


def encode_collection(serializer: Serializer, values: Collection[T], encoder: Encoder[T]) -> None:
    encode_leb128(serializer, len(values), signed=False)
    for value in values:
        encoder(serializer, value)


@propagate_result
def decode_collection(
    deserializer: Deserializer,
    decoder: Decoder[T],
    builder: Callable[[Iterable[T]], R],
) -> Result[R, SerializationError]:
    length = decode_leb128(deserializer, signed=False).unwrap_or_propagate()
    return Ok(builder(decoder(deserializer) for _ in range(length)))
