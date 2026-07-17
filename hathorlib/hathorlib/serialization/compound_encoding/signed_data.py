# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

r"""
A `SignedData[T]` value is encoded the same way as a `tuple[T, bytes]`.

Layout: [value_T][script_bytes].

The wire format is identical for every concrete `SignedData` subclass; the decoder constructs the
`signed_data_type` it is given, which determines the payload-signing version of the result.

>>> from hathorlib.nanocontracts.types import SignedDataV1
>>> from hathorlib.serialization.encoding.utf8 import encode_utf8, decode_utf8
>>> se = Serializer.build_bytes_serializer()
>>> value = SignedDataV1[str]('😎', b'foobar')  # foobar is not a valid script but it doesn't matter
>>> encode_signed_data(se, value, encode_utf8)
>>> bytes(se.finalize()).hex()
'04f09f988e06666f6f626172'

Breakdown of the result:

    04f09f988e: '😎'
    06666f6f626172: b'foobar'

>>> de = Deserializer.build_bytes_deserializer(bytes.fromhex('04f09f988e06666f6f626172'))
>>> decode_signed_data(de, decode_utf8, SignedDataV1[str])
SignedDataV1[str](data='😎', script_input=b'foobar')
>>> de.finalize()
"""

from typing import TypeVar

from hathorlib.nanocontracts.types import SignedData
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.bytes import decode_bytes, encode_bytes

from . import Decoder, Encoder

T = TypeVar('T')


def encode_signed_data(serializer: Serializer, value: SignedData[T], encoder: Encoder[T]) -> None:
    assert isinstance(value, SignedData)
    encoder(serializer, value.data)
    encode_bytes(serializer, value.script_input)


def decode_signed_data(
    deserializer: Deserializer,
    decoder: Decoder[T],
    signed_data_type: type[SignedData[T]],
) -> SignedData[T]:
    data = decoder(deserializer)
    script_input = decode_bytes(deserializer)
    return signed_data_type(data, script_input)
