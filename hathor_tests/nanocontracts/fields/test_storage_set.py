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

from typing import Any

import pytest

from hathor.nanocontracts.fields.container import ContainerLeaf
from hathor.nanocontracts.fields.set_container import SetContainer
from hathor.nanocontracts.nc_types import Int32NCType
from hathor_tests.nanocontracts.fields.utils import MockNCStorage

INT_NC_TYPE = Int32NCType()


def test_basic() -> None:
    storage = MockNCStorage()
    my_set = SetContainer(storage, b'my_set', ContainerLeaf(storage, INT_NC_TYPE))
    my_set.__init_storage__()

    assert storage.store == {b'my_set:__length__': 0}
    assert len(my_set) == 0


def test_add_remove_discard() -> None:
    storage = MockNCStorage()
    my_set = SetContainer(storage, b'my_set', ContainerLeaf(storage, INT_NC_TYPE))
    my_set.__init_storage__()

    my_set.add(1)
    my_set.add(1)
    my_set.add(2)
    assert _get_values(storage) == {1, 2}
    assert len(my_set) == 2

    my_set.remove(1)
    assert _get_values(storage) == {2}
    assert len(my_set) == 1

    my_set.discard(2)
    assert _get_values(storage) == set()
    assert len(my_set) == 0

    my_set.discard(1)
    with pytest.raises(KeyError):
        my_set.remove(1)


def test_updates_and_contains() -> None:
    storage = MockNCStorage()
    my_set = SetContainer(storage, b'my_set', ContainerLeaf(storage, INT_NC_TYPE))
    my_set.__init_storage__()

    my_set.update({1, 2, 3}, [2, 3, 4])
    assert _get_values(storage) == {1, 2, 3, 4}
    assert len(my_set) == 4
    assert 0 not in my_set
    assert 1 in my_set
    assert 2 in my_set
    assert 3 in my_set
    assert 4 in my_set
    assert 5 not in my_set

    my_set.difference_update({1, 3}, [4])
    assert _get_values(storage) == {2}
    assert len(my_set) == 1


def test_isdisjoint() -> None:
    storage = MockNCStorage()
    my_set = SetContainer(storage, b'my_set', ContainerLeaf(storage, INT_NC_TYPE))
    my_set.__init_storage__({1, 2, 3})

    assert my_set.isdisjoint(set())
    assert my_set.isdisjoint({4, 5, 6})
    assert my_set.isdisjoint({0, 10})
    assert not my_set.isdisjoint({0, 1, 10, 20})
    assert not my_set.isdisjoint({3})


def test_issuperset() -> None:
    storage = MockNCStorage()
    my_set = SetContainer(storage, b'my_set', ContainerLeaf(storage, INT_NC_TYPE))
    my_set.__init_storage__({1, 2, 3})

    assert my_set.issuperset({})
    assert my_set.issuperset({1})
    assert my_set.issuperset({1, 2})
    assert my_set.issuperset({1, 2, 3})
    assert not my_set.issuperset({1, 2, 3, 4})


def test_intersection() -> None:
    storage = MockNCStorage()
    my_set = SetContainer(storage, b'my_set', ContainerLeaf(storage, INT_NC_TYPE))
    my_set.__init_storage__({1, 2, 3})

    assert my_set.intersection(set()) == set()
    assert my_set.intersection({1}) == {1}
    assert my_set.intersection({1, 2}) == {1, 2}
    assert my_set.intersection({1, 2, 3}) == {1, 2, 3}
    assert my_set.intersection({1, 2, 3, 4}) == {1, 2, 3}


def _get_values(storage: MockNCStorage) -> set[Any]:
    return set(value for key, value in storage.store.items() if key != b'my_set:__length__')
