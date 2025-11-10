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

import pytest

from hathor.nanocontracts.fields.container import ContainerLeaf
from hathor.nanocontracts.fields.deque_container import DequeContainer, _DequeMetadata
from hathor.nanocontracts.nc_types import Int32NCType, StrNCType
from hathor_tests.nanocontracts.fields.utils import MockNCStorage

INT_NC_TYPE = Int32NCType()
STR_NC_TYPE = StrNCType()


def test_basic() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, INT_NC_TYPE))
    assert storage.store == {}
    dq.__init_storage__()
    assert storage.store == {b'dq:__metadata__': _DequeMetadata(first_index=0, length=0, reversed=False)}

    assert list(dq) == []
    assert dq.maxlen is None


def test_append() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, STR_NC_TYPE))
    dq.__init_storage__()

    dq.append('a')
    dq.append('b')

    assert storage.store == {
        b'dq:\x00': 'a',
        b'dq:\x01': 'b',
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=2, reversed=False),
    }
    assert list(dq) == ['a', 'b']

    dq.reverse()
    dq.append('c')

    assert storage.store == {
        b'dq:\x7f': 'c',
        b'dq:\x00': 'a',
        b'dq:\x01': 'b',
        b'dq:__metadata__': _DequeMetadata(first_index=-1, length=3, reversed=True),
    }
    assert list(dq) == ['b', 'a', 'c']


def test_appendleft() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, STR_NC_TYPE))
    dq.__init_storage__()

    dq.appendleft('a')
    dq.appendleft('b')

    assert storage.store == {
        b'dq:\x7e': 'b',
        b'dq:\x7f': 'a',
        b'dq:__metadata__': _DequeMetadata(first_index=-2, length=2, reversed=False),
    }
    assert list(dq) == ['b', 'a']

    dq.reverse()
    dq.appendleft('c')

    assert storage.store == {
        b'dq:\x7e': 'b',
        b'dq:\x7f': 'a',
        b'dq:\x00': 'c',
        b'dq:__metadata__': _DequeMetadata(first_index=-2, length=3, reversed=True),
    }
    assert list(dq) == ['c', 'a', 'b']


def test_extend() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, INT_NC_TYPE))
    dq.__init_storage__()

    dq.extend([1, 2, 3])

    assert storage.store == {
        b'dq:\x00': 1,
        b'dq:\x01': 2,
        b'dq:\x02': 3,
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=3, reversed=False),
    }
    assert list(dq) == [1, 2, 3]

    dq.reverse()
    dq.extend([4, 5])

    assert storage.store == {
        b'dq:\x7e': 5,
        b'dq:\x7f': 4,
        b'dq:\x00': 1,
        b'dq:\x01': 2,
        b'dq:\x02': 3,
        b'dq:__metadata__': _DequeMetadata(first_index=-2, length=5, reversed=True),
    }
    assert list(dq) == [3, 2, 1, 4, 5]

    py_dq: deque[int] = deque()
    py_dq.extend([1, 2, 3])
    py_dq.reverse()
    py_dq.extend([4, 5])
    assert list(py_dq) == list(dq)


def test_extendleft() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, INT_NC_TYPE))
    dq.__init_storage__()

    dq.extendleft([1, 2, 3])

    assert storage.store == {
        b'dq:\x7d': 3,
        b'dq:\x7e': 2,
        b'dq:\x7f': 1,
        b'dq:__metadata__': _DequeMetadata(first_index=-3, length=3, reversed=False),
    }
    assert list(dq) == [3, 2, 1]

    dq.reverse()
    dq.extendleft([4, 5])

    assert storage.store == {
        b'dq:\x7d': 3,
        b'dq:\x7e': 2,
        b'dq:\x7f': 1,
        b'dq:\x00': 4,
        b'dq:\x01': 5,
        b'dq:__metadata__': _DequeMetadata(first_index=-3, length=5, reversed=True),
    }
    assert list(dq) == [5, 4, 1, 2, 3]

    py_dq: deque[int] = deque()
    py_dq.extendleft([1, 2, 3])
    py_dq.reverse()
    py_dq.extendleft([4, 5])
    assert list(py_dq) == list(dq)


def test_pop() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, INT_NC_TYPE))
    dq.__init_storage__([1, 2, 3, 4])

    assert dq.pop() == 4
    assert storage.store == {
        b'dq:\x00': 1,
        b'dq:\x01': 2,
        b'dq:\x02': 3,
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=3, reversed=False),
    }

    assert dq.pop() == 3
    assert storage.store == {
        b'dq:\x00': 1,
        b'dq:\x01': 2,
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=2, reversed=False),
    }

    dq.reverse()

    assert dq.pop() == 1
    assert storage.store == {
        b'dq:\x01': 2,
        b'dq:__metadata__': _DequeMetadata(first_index=1, length=1, reversed=True),
    }

    # popping the last element resets the deque
    assert dq.pop() == 2
    assert storage.store == {b'dq:__metadata__': _DequeMetadata(first_index=2, length=0, reversed=True)}

    with pytest.raises(IndexError):
        dq.pop()


def test_popleft() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, INT_NC_TYPE))
    dq.__init_storage__([1, 2, 3, 4])

    assert dq.popleft() == 1
    assert storage.store == {
        b'dq:\x01': 2,
        b'dq:\x02': 3,
        b'dq:\x03': 4,
        b'dq:__metadata__': _DequeMetadata(first_index=1, length=3, reversed=False),
    }

    assert dq.popleft() == 2
    assert storage.store == {
        b'dq:\x02': 3,
        b'dq:\x03': 4,
        b'dq:__metadata__': _DequeMetadata(first_index=2, length=2, reversed=False),
    }

    dq.reverse()

    assert dq.popleft() == 4
    assert storage.store == {
        b'dq:\x02': 3,
        b'dq:__metadata__': _DequeMetadata(first_index=2, length=1, reversed=True),
    }

    # popping the last element resets the deque
    assert dq.popleft() == 3
    assert storage.store == {b'dq:__metadata__': _DequeMetadata(first_index=2, length=0, reversed=True)}

    with pytest.raises(IndexError):
        dq.popleft()


def test_reverse() -> None:
    storage = MockNCStorage()

    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, STR_NC_TYPE))
    dq.__init_storage__(['a', 'b', 'c'])

    assert storage.store == {
        b'dq:\x00': 'a',
        b'dq:\x01': 'b',
        b'dq:\x02': 'c',
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=3, reversed=False),
    }
    assert list(dq) == ['a', 'b', 'c']

    dq.reverse()

    assert storage.store == {
        b'dq:\x00': 'a',
        b'dq:\x01': 'b',
        b'dq:\x02': 'c',
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=3, reversed=True),
    }
    assert list(dq) == ['c', 'b', 'a']


def test_indexing() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, STR_NC_TYPE))
    dq.__init_storage__(['a', 'b', 'c', 'd'])

    assert storage.store == {
        b'dq:\x00': 'a',
        b'dq:\x01': 'b',
        b'dq:\x02': 'c',
        b'dq:\x03': 'd',
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=4, reversed=False),
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
        b'dq:\x00': 'a',
        b'dq:\x01': 'changed1',
        b'dq:\x02': 'changed2',
        b'dq:\x03': 'd',
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=4, reversed=False),
    }
    assert dq[1] == 'changed1'
    assert dq[-2] == 'changed2'

    with pytest.raises(IndexError):
        dq[4] = 'error'

    with pytest.raises(IndexError):
        dq[-5] = 'error'


def test_indexing_reversed() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, STR_NC_TYPE))
    dq.__init_storage__(['a', 'b', 'c', 'd'])

    dq.reverse()

    assert storage.store == {
        b'dq:\x00': 'a',
        b'dq:\x01': 'b',
        b'dq:\x02': 'c',
        b'dq:\x03': 'd',
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=4, reversed=True),
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
        b'dq:\x00': 'a',
        b'dq:\x01': 'changed2',
        b'dq:\x02': 'changed1',
        b'dq:\x03': 'd',
        b'dq:__metadata__': _DequeMetadata(first_index=0, length=4, reversed=True),
    }
    assert dq[1] == 'changed1'
    assert dq[-2] == 'changed2'


def test_len() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, STR_NC_TYPE))
    dq.__init_storage__()
    assert len(dq) == 0

    dq.append('a')
    assert len(dq) == 1

    dq.append('b')
    assert len(dq) == 2

    dq.reverse()
    assert len(dq) == 2


def test_reverse_empty() -> None:
    storage = MockNCStorage()
    dq = DequeContainer(storage, b'dq', ContainerLeaf(storage, INT_NC_TYPE))
    dq.__init_storage__()
    assert list(dq) == []
    dq.reverse()
    assert list(dq) == []
