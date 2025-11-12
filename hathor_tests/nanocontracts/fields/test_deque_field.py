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
from typing import cast

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.nc_types import VarInt32NCType
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder

INT_NC_TYPE = VarInt32NCType()


def _test1(dq: deque[int]) -> None:
    assert list(dq) == []
    dq.append(1)
    dq.appendleft(2)
    dq.extend([3, 4])
    dq.extendleft([5, 6])
    assert list(dq) == [6, 5, 2, 1, 3, 4]
    assert dq.pop() == 4
    assert dq.popleft() == 6
    assert list(dq) == [5, 2, 1, 3]
    assert len(dq) == 4
    dq[1] = 22
    dq[-2] = 11
    assert dq[1] == 22
    assert dq[-2] == 11
    assert list(dq) == [5, 22, 11, 3]


def _test2(dq: deque[int]) -> None:
    assert list(dq) == [5, 22, 11, 3]
    dq.reverse()
    assert list(dq) == [3, 11, 22, 5]
    dq.append(111)
    dq.appendleft(222)
    dq.extend([333, 444])
    dq.extendleft([555, 666])
    assert list(dq) == [666, 555, 222, 3, 11, 22, 5, 111, 333, 444]
    assert dq.pop() == 444
    assert dq.popleft() == 666
    assert list(dq) == [555, 222, 3, 11, 22, 5, 111, 333]
    assert len(dq) == 8
    dq[1] = 2222
    dq[-2] = 1111
    assert dq[1] == 2222
    assert dq[-2] == 1111
    assert list(dq) == [555, 2222, 3, 11, 22, 5, 1111, 333]


class BlueprintWithDeque(Blueprint):
    dq: deque[int]

    @public
    def initialize(self, ctx: Context) -> None:
        self.dq = deque()
        _test1(self.dq)

    @public
    def test(self, ctx: Context) -> None:
        _test2(self.dq)


class BlueprintWithList(Blueprint):
    dq: list[int]

    @public
    def initialize(self, ctx: Context) -> None:
        self.dq = []
        _test1(cast(deque, self.dq))

    @public
    def test(self, ctx: Context) -> None:
        _test2(cast(deque, self.dq))


class TestDequeField(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.bp_deque = b'1' * 32
        self.bp_list = b'2' * 32
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            self.bp_deque: BlueprintWithDeque,
            self.bp_list: BlueprintWithList,
        })

    def _test_deque_field(self, bp_id: bytes) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{bp_id.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = test()

            nc1 <-- b11
            nc1 <-- nc2 <-- b12
        ''')
        artifacts.propagate_with(self.manager)

        b11, b12 = artifacts.get_typed_vertices(['b11', 'b12'], Block)
        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)

        assert b11.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().first_block == b11.hash

        b11_storage = self.manager.get_nc_storage(b11, nc1.hash)

        with self.assertRaises(KeyError):
            b11_storage.get_obj(b'dq:\x7d', INT_NC_TYPE)
        assert b11_storage.get_obj(b'dq:\x7e', INT_NC_TYPE) == 5
        assert b11_storage.get_obj(b'dq:\x7f', INT_NC_TYPE) == 22
        assert b11_storage.get_obj(b'dq:\x00', INT_NC_TYPE) == 11
        assert b11_storage.get_obj(b'dq:\x01', INT_NC_TYPE) == 3
        with self.assertRaises(KeyError):
            b11_storage.get_obj(b'dq:\x02', INT_NC_TYPE)

        assert b12.get_metadata().voided_by is None
        assert nc2.get_metadata().voided_by is None
        assert nc2.get_metadata().first_block == b12.hash

        b12_storage = self.manager.get_nc_storage(b12, nc1.hash)

        with self.assertRaises(KeyError):
            b12_storage.get_obj(b'dq:\x7b', INT_NC_TYPE)
        assert b12_storage.get_obj(b'dq:\x7c', INT_NC_TYPE) == 333
        assert b12_storage.get_obj(b'dq:\x7d', INT_NC_TYPE) == 1111
        assert b12_storage.get_obj(b'dq:\x7e', INT_NC_TYPE) == 5
        assert b12_storage.get_obj(b'dq:\x7f', INT_NC_TYPE) == 22
        assert b12_storage.get_obj(b'dq:\x00', INT_NC_TYPE) == 11
        assert b12_storage.get_obj(b'dq:\x01', INT_NC_TYPE) == 3
        assert b12_storage.get_obj(b'dq:\x02', INT_NC_TYPE) == 2222
        assert b12_storage.get_obj(b'dq:\x03', INT_NC_TYPE) == 555
        with self.assertRaises(KeyError):
            b12_storage.get_obj(b'dq:\x04', INT_NC_TYPE)

    def test_deque_field_with_deque(self) -> None:
        self._test_deque_field(self.bp_deque)

    def test_deque_field_with_list(self) -> None:
        self._test_deque_field(self.bp_list)
