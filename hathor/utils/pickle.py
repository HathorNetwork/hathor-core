#  Copyright 2024 Hathor Labs
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

import io
import pickle
from typing import Callable, TypeVar

T = TypeVar('T')


def dumps(obj: object) -> bytes:
    """Like pickle.dumps, but using the custom Hathor pickler."""
    f = io.BytesIO()
    _HathorPickler(f).dump(obj)
    return f.getvalue()


def loads(data: bytes) -> object:
    """Like pickle.loads, but using the custom Hathor pickler."""
    # We can actually use the Python unpickler itself because the unpickle function is embedded in the data,
    # so this is just an alias for convenience.
    return pickle.loads(data)


class _HathorPickler(pickle.Pickler):
    """
    Custom pickler for Hathor types.
    We have to use it instead of the global Python pickler because Twisted breaks the global one.
    """
    dispatch_table = {}


def register_custom_pickler(
    type_: type[T],
    /,
    *,
    serializer: Callable[[T], bytes],
    deserializer: Callable[[bytes], T],
) -> None:
    """Register a custom (de)serializer for a type in the Hathor pickler."""
    def pickler(obj: T) -> tuple[Callable[[bytes], T], tuple[bytes]]:
        return deserializer, (serializer(obj),)

    _HathorPickler.dispatch_table[type_] = pickler
