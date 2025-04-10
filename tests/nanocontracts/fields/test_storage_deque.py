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

from collections import deque
from typing import Any

import pytest

from hathor.nanocontracts.fields.deque_field import StorageDeque, _StorageDequeMetadata
from hathor.nanocontracts.storage import NCStorage
from hathor.nanocontracts.storage.types import _NOT_PROVIDED


class MockNCStorage(NCStorage):
    __slots__ = ('store',)

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    def get(self, key: str, default: Any = _NOT_PROVIDED) -> Any:
        if item := self.store.get(key, default):
            return item
        if default is _NOT_PROVIDED:
            raise KeyError
        return default

    def put(self, key: str, value: Any) -> None:
        self.store[key] = value

    def delete(self, key: str) -> None:
        del self.store[key]


def test_basic() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')

    assert storage.store == {}
    assert list(dq) == []
    assert dq.maxlen is None


def test_append() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')

    dq.append('a')
    dq.append('b')

    assert storage.store == {
        'dq:0': 'a',
        'dq:1': 'b',
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=2, reversed=False),
    }
    assert list(dq) == ['a', 'b']

    dq.reverse()
    dq.append('c')

    assert storage.store == {
        'dq:-1': 'c',
        'dq:0': 'a',
        'dq:1': 'b',
        'dq:__metadata__': _StorageDequeMetadata(first_index=-1, length=3, reversed=True),
    }
    assert list(dq) == ['b', 'a', 'c']


def test_appendleft() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')

    dq.appendleft('a')
    dq.appendleft('b')

    assert storage.store == {
        'dq:-2': 'b',
        'dq:-1': 'a',
        'dq:__metadata__': _StorageDequeMetadata(first_index=-2, length=2, reversed=False),
    }
    assert list(dq) == ['b', 'a']

    dq.reverse()
    dq.appendleft('c')

    assert storage.store == {
        'dq:-2': 'b',
        'dq:-1': 'a',
        'dq:0': 'c',
        'dq:__metadata__': _StorageDequeMetadata(first_index=-2, length=3, reversed=True),
    }
    assert list(dq) == ['c', 'a', 'b']


def test_extend() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')

    dq.extend([1, 2, 3])

    assert storage.store == {
        'dq:0': 1,
        'dq:1': 2,
        'dq:2': 3,
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=3, reversed=False),
    }
    assert list(dq) == [1, 2, 3]

    dq.reverse()
    dq.extend([4, 5])

    assert storage.store == {
        'dq:-2': 5,
        'dq:-1': 4,
        'dq:0': 1,
        'dq:1': 2,
        'dq:2': 3,
        'dq:__metadata__': _StorageDequeMetadata(first_index=-2, length=5, reversed=True),
    }
    assert list(dq) == [3, 2, 1, 4, 5]

    py_dq: deque[int] = deque()
    py_dq.extend([1, 2, 3])
    py_dq.reverse()
    py_dq.extend([4, 5])
    assert list(py_dq) == list(dq)


def test_extendleft() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')

    dq.extendleft([1, 2, 3])

    assert storage.store == {
        'dq:-3': 3,
        'dq:-2': 2,
        'dq:-1': 1,
        'dq:__metadata__': _StorageDequeMetadata(first_index=-3, length=3, reversed=False),
    }
    assert list(dq) == [3, 2, 1]

    dq.reverse()
    dq.extendleft([4, 5])

    assert storage.store == {
        'dq:-3': 3,
        'dq:-2': 2,
        'dq:-1': 1,
        'dq:0': 4,
        'dq:1': 5,
        'dq:__metadata__': _StorageDequeMetadata(first_index=-3, length=5, reversed=True),
    }
    assert list(dq) == [5, 4, 1, 2, 3]

    py_dq: deque[int] = deque()
    py_dq.extendleft([1, 2, 3])
    py_dq.reverse()
    py_dq.extendleft([4, 5])
    assert list(py_dq) == list(dq)


def test_pop() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')
    dq.extend([1, 2, 3, 4])

    assert dq.pop() == 4
    assert storage.store == {
        'dq:0': 1,
        'dq:1': 2,
        'dq:2': 3,
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=3, reversed=False),
    }

    assert dq.pop() == 3
    assert storage.store == {
        'dq:0': 1,
        'dq:1': 2,
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=2, reversed=False),
    }

    dq.reverse()

    assert dq.pop() == 1
    assert storage.store == {
        'dq:1': 2,
        'dq:__metadata__': _StorageDequeMetadata(first_index=1, length=1, reversed=True),
    }

    # popping the last element resets the deque
    assert dq.pop() == 2
    assert storage.store == {}

    with pytest.raises(IndexError):
        dq.pop()


def test_popleft() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')
    dq.extend([1, 2, 3, 4])

    assert dq.popleft() == 1
    assert storage.store == {
        'dq:1': 2,
        'dq:2': 3,
        'dq:3': 4,
        'dq:__metadata__': _StorageDequeMetadata(first_index=1, length=3, reversed=False),
    }

    assert dq.popleft() == 2
    assert storage.store == {
        'dq:2': 3,
        'dq:3': 4,
        'dq:__metadata__': _StorageDequeMetadata(first_index=2, length=2, reversed=False),
    }

    dq.reverse()

    assert dq.popleft() == 4
    assert storage.store == {
        'dq:2': 3,
        'dq:__metadata__': _StorageDequeMetadata(first_index=2, length=1, reversed=True),
    }

    # popping the last element resets the deque
    assert dq.popleft() == 3
    assert storage.store == {}

    with pytest.raises(IndexError):
        dq.popleft()


def test_reverse() -> None:
    storage = MockNCStorage()

    dq = StorageDeque(storage, 'dq')
    dq.extend(['a', 'b', 'c'])

    assert storage.store == {
        'dq:0': 'a',
        'dq:1': 'b',
        'dq:2': 'c',
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=3, reversed=False),
    }
    assert list(dq) == ['a', 'b', 'c']

    dq.reverse()

    assert storage.store == {
        'dq:0': 'a',
        'dq:1': 'b',
        'dq:2': 'c',
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=3, reversed=True),
    }
    assert list(dq) == ['c', 'b', 'a']


def test_indexing() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')

    dq.extend(['a', 'b', 'c', 'd'])

    assert storage.store == {
        'dq:0': 'a',
        'dq:1': 'b',
        'dq:2': 'c',
        'dq:3': 'd',
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=4, reversed=False),
    }
    assert dq[0] == 'a'
    assert dq[1] == 'b'
    assert dq[2] == 'c'
    assert dq[3] == 'd'

    with pytest.raises(IndexError):
        _ = dq[4]

    assert dq[-1] == 'd'
    assert dq[-2] == 'c'
    assert dq[-3] == 'b'
    assert dq[-4] == 'a'

    with pytest.raises(IndexError):
        _ = dq[-5]

    dq[1] = 'changed1'
    dq[-2] = 'changed2'

    with pytest.raises(IndexError):
        dq[4] = 'error'

    with pytest.raises(IndexError):
        dq[-5] = 'error'

    assert storage.store == {
        'dq:0': 'a',
        'dq:1': 'changed1',
        'dq:2': 'changed2',
        'dq:3': 'd',
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=4, reversed=False),
    }
    assert dq[1] == 'changed1'
    assert dq[-2] == 'changed2'

    with pytest.raises(IndexError):
        dq[4] = 'error'

    with pytest.raises(IndexError):
        dq[-5] = 'error'


def test_indexing_reversed() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')

    dq.extend(['a', 'b', 'c', 'd'])
    dq.reverse()

    assert storage.store == {
        'dq:0': 'a',
        'dq:1': 'b',
        'dq:2': 'c',
        'dq:3': 'd',
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=4, reversed=True),
    }
    assert dq[0] == 'd'
    assert dq[1] == 'c'
    assert dq[2] == 'b'
    assert dq[3] == 'a'

    with pytest.raises(IndexError):
        _ = dq[4]

    assert dq[-1] == 'a'
    assert dq[-2] == 'b'
    assert dq[-3] == 'c'
    assert dq[-4] == 'd'

    with pytest.raises(IndexError):
        _ = dq[-5]

    dq[1] = 'changed1'
    dq[-2] = 'changed2'

    assert storage.store == {
        'dq:0': 'a',
        'dq:1': 'changed2',
        'dq:2': 'changed1',
        'dq:3': 'd',
        'dq:__metadata__': _StorageDequeMetadata(first_index=0, length=4, reversed=True),
    }
    assert dq[1] == 'changed1'
    assert dq[-2] == 'changed2'


def test_len() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')
    assert len(dq) == 0

    dq.append('a')
    assert len(dq) == 1

    dq.append('b')
    assert len(dq) == 2

    dq.reverse()
    assert len(dq) == 2


def test_reverse_empty() -> None:
    storage = MockNCStorage()
    dq = StorageDeque(storage, 'dq')
    assert list(dq) == []
    dq.reverse()
    assert list(dq) == []
