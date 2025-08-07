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
This modules implements encoding of byte sequence by prefixing it with the length of the sequence encoded as a LEB128
unsigned integer.

>>> se = Serializer.build_bytes_serializer()
>>> encode_bytes(se, b'test')  # will prepend b'\x04' before writing b'test'
>>> bytes(se.finalize()).hex()
'0474657374'

>>> se = Serializer.build_bytes_serializer()
>>> raw_data = b'test' * 32
>>> len(raw_data)
128
>>> encode_bytes(se, raw_data)  # prepends b'\x80\x01' before raw_data
>>> encoded_data = bytes(se.finalize())
>>> len(encoded_data)
130
>>> encoded_data[:10].hex()
'80017465737474657374'

>>> de = Deserializer.build_bytes_deserializer(encoded_data)  # that we encoded before
>>> decoded_data = decode_bytes(de)
>>> de.finalize()  # called to assert we've consumed everything
>>> decoded_data == raw_data
True
>>> decoded_data[:8]
b'testtest'

>>> de = Deserializer.build_bytes_deserializer(b'\x04test')
>>> decode_bytes(de)
b'test'
>>> de.finalize()

>>> de = Deserializer.build_bytes_deserializer(b'\x04testfoo')
>>> _ = decode_bytes(de)
>>> try:
...     de.finalize()
... except ValueError as e:
...     print(*e.args)
trailing data

>>> de = Deserializer.build_bytes_deserializer(b'\x04testfoo')
>>> _ = decode_bytes(de)
>>> bytes(de.read_all())
b'foo'
"""

from hathor.serialization import Deserializer, Serializer

from .leb128 import decode_leb128, encode_leb128


def encode_bytes(serializer: Serializer, data: bytes) -> None:
    """ Encodes a byte-sequence adding a length prefix.

    This modules's docstring has more details and examples.
    """
    assert isinstance(data, bytes)
    encode_leb128(serializer, len(data), signed=False)
    serializer.write_bytes(data)


def decode_bytes(deserializer: Deserializer) -> bytes:
    """ Decodes a byte-sequnce with a length prefix.

    This modules's docstring has more details and examples.
    """
    size = decode_leb128(deserializer, signed=False)
    return bytes(deserializer.read_bytes(size))
