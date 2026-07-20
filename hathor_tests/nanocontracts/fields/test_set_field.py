# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.nc_types import VarInt32NCType
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.utils import set_force_legacy_fields

INT_NC_TYPE = VarInt32NCType()


class MyBlueprint(Blueprint):
    my_set: set[int]

    @public
    def initialize(self, ctx: Context) -> None:
        self.my_set = set()
        assert len(self.my_set) == 0
        self.my_set.add(1)
        self.my_set.add(1)
        self.my_set.update({1, 2, 3, 4, 5})
        assert len(self.my_set) == 5
        assert 1 in self.my_set
        assert 5 in self.my_set

    @public
    def test1(self, ctx: Context) -> None:
        self.my_set.discard(1)
        self.my_set.remove(5)
        assert 1 not in self.my_set
        assert 5 not in self.my_set


class TestDequeField(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        # These tests assert raw storage keys/values with legacy (V1) encodings, so pin the
        # global storage serialization to legacy for their duration.
        set_force_legacy_fields(self, True)
        self.manager = self.create_peer('unittests')
        self.bp_id = b'x' * 32
        self.manager.blueprint_service.register_blueprint(self.bp_id, MyBlueprint)

    def test_set_field(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{self.bp_id.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = test1()

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

        for i in range(1, 6):
            assert b11_storage.get_obj(self._get_key(i), INT_NC_TYPE) == i

        for i in (0, 6):
            assert not b11_storage.has_obj(self._get_key(i))

        assert b12.get_metadata().voided_by is None
        assert nc2.get_metadata().voided_by is None
        assert nc2.get_metadata().first_block == b12.hash

        b12_storage = self.manager.get_nc_storage(b12, nc1.hash)

        for i in range(2, 5):
            assert b12_storage.get_obj(self._get_key(i), INT_NC_TYPE) == i

        for i in (1, 5):
            assert not b12_storage.has_obj(self._get_key(i))

    @staticmethod
    def _get_key(n: int) -> bytes:
        return 'my_set:'.encode() + INT_NC_TYPE.to_bytes(n)
