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
This module implements encoding a boolean value using 1 byte.

The format is trivial and extremely simple:

- `False` maps to `b'\x00'`
- `True` maps to `b'\x01'`
- any other byte value is invalid

>>> se = Serializer.build_bytes_serializer()
>>> encode_bool(se, False)
>>> bytes(se.finalize())
b'\x00'

>>> se = Serializer.build_bytes_serializer()
>>> encode_bool(se, True)
>>> bytes(se.finalize())
b'\x01'

>>> de = Deserializer.build_bytes_deserializer(b'\x00')
>>> decode_bool(de)
False
>>> de.finalize()

>>> de = Deserializer.build_bytes_deserializer(b'\x01')
>>> decode_bool(de)
True
>>> de.finalize()

>>> de = Deserializer.build_bytes_deserializer(b'\x02')
>>> try:
...     decode_bool(de)
... except ValueError as e:
...     print(*e.args)
b'\x02' is not a valid boolean

>>> de = Deserializer.build_bytes_deserializer(b'\x01test')
>>> decode_bool(de)
True
>>> bytes(de.read_all())
b'test'
"""

from hathor.serialization import Deserializer, Serializer


def encode_bool(serializer: Serializer, value: bool) -> None:
    """ Encodes a boolean value using 1 byte.
    """
    assert isinstance(value, bool)
    serializer.write_byte(0x01 if value else 0x00)


def decode_bool(deserializer: Deserializer) -> bool:
    """ Decodes a boolean value from 1 byte.
    """
    i = deserializer.read_byte()
    if i == 0:
        return False
    elif i == 1:
        return True
    else:
        raw = bytes([i])
        raise ValueError(f'{raw!r} is not a valid boolean')
