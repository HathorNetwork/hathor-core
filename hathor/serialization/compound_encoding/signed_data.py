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
A `SignedData[T]` value is encoded the same way as a `tuple[T, bytes]`.

Layout: [value_T][script_bytes].

>>> from hathor.serialization.encoding.utf8 import encode_utf8, decode_utf8
>>> se = Serializer.build_bytes_serializer()
>>> value = SignedData[str]('😎', b'foobar')  # foobar is not a valid script but it doesn't matter
>>> encode_signed_data(se, value, encode_utf8)
>>> bytes(se.finalize()).hex()
'04f09f988e06666f6f626172'

Breakdown of the result:

    04f09f988e: '😎'
    06666f6f626172: b'foobar'

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('04f09f988e06666f6f626172'))
>>> decode_signed_data(de, decode_utf8, str)
SignedData[str](data='😎', script_input=b'foobar')
>>> de.finalize()
"""

from typing import TypeVar

from hathor.nanocontracts.types import SignedData
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.bytes import decode_bytes, encode_bytes

from . import Decoder, Encoder

T = TypeVar('T')


def encode_signed_data(serializer: Serializer, value: SignedData[T], encoder: Encoder[T]) -> None:
    assert isinstance(value, SignedData)
    encoder(serializer, value.data)
    encode_bytes(serializer, value.script_input)


def decode_signed_data(deserializer: Deserializer, decoder: Decoder[T], inner_type: type[T]) -> SignedData[T]:
    data = decoder(deserializer)
    script_input = decode_bytes(deserializer)
    # XXX: ignore valid-type because mypy doesn't recognize dynamic type annotations, but it's correct
    return SignedData[inner_type](data, script_input)  # type: ignore[valid-type]
