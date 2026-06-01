# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import NewType, TypeAlias

# XXX: All of these types already have an equivalent NewType available on `hathor.nanoconracts.types`, the next step is
#      to refactor the places which use `hathor.types`, which is still a lot. Some of these would also benefit from
#      using custom classes like `Hash` for better str/repr.

Address: TypeAlias = bytes         # NewType('Address', bytes)
AddressB58: TypeAlias = str
Amount: TypeAlias = int            # NewType('Amount', int)
Timestamp: TypeAlias = int         # NewType('Timestamp', int)
TxOutputScript: TypeAlias = bytes  # NewType('TxOutputScript', bytes)
VertexId: TypeAlias = bytes        # NewType('VertexId', bytes)
BlockId = NewType('BlockId', VertexId)
TransactionId = NewType('TransactionId', VertexId)
TokenUid: TypeAlias = VertexId     # NewType('TokenUid', VertexId)


class Hash:
    r""" A type for easily representing a 32-byte hash, it is not meant to be used directly.

    Instead it is meant to be used to make new-types that also happen to be a hash. This class will provide convenient
    methods for parsing and representing it.

    Examples:

    >>> x = Hash('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc')
    >>> bytes(x)
    b'\x00\x00\x06\xcb\x938[\x8b\x87\xa5E\xa1\xcb\xb6\x19~l\xaf\xf6\x00\xc1,\xc1/\xc5BP\xd3\x9c\x80\x88\xfc'

    >>> Hash(b'\x00\x00\x06\xcb\x938[\x8b\x87\xa5E\xa1\xcb\xb6\x19~l\xaf\xf6\x00\xc1,\xc1/\xc5BP\xd3\x9c\x80\x88\xfc')
    Hash('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc')

    >>> str(x)
    '000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc'

    >>> repr(x)
    "Hash('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc')"

    >>> {x}
    {Hash('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc')}

    >>> class Foo(Hash):
    ...     pass
    >>> y = Foo('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc')
    >>> repr(y)
    "Foo('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc')"

    >>> x == y
    True

    >>> {x: 123}[y]
    123

    >>> Hash('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc34')
    Traceback (most recent call last):
    ...
    ValueError: expected 32 bytes, got 33 bytes

    >>> Hash('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088')
    Traceback (most recent call last):
    ...
    ValueError: expected 32 bytes, got 31 bytes

    >>> Hash('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088f')
    Traceback (most recent call last):
    ...
    ValueError: non-hexadecimal number found in fromhex() arg at position 63

    >>> Hash(123)
    Traceback (most recent call last):
    ...
    TypeError: expected a bytes or str instance, got a <class 'int'> instead
    """
    __slots__ = ('_inner',)
    _inner: bytes

    def __init__(self, inner: bytes | str) -> None:
        if isinstance(inner, str):
            inner = bytes.fromhex(inner)
        if not isinstance(inner, bytes):
            raise TypeError(f'expected a bytes or str instance, got a {repr(type(inner))} instead')
        if len(inner) != 32:
            raise ValueError(f'expected 32 bytes, got {len(inner)} bytes')
        self._inner = inner

    def __bytes__(self):
        return self._inner

    def __str__(self):
        return self._inner.hex()

    def __repr__(self):
        return f"{type(self).__name__}('{self}')"

    def __hash__(self):
        return hash(self._inner)

    def __eq__(self, other):
        return self._inner.__eq__(other._inner)
