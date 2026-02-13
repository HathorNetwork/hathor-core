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

from hathor import Blueprint, Context, public
from hathor.nanocontracts.resources.nc_creation import NCCreationResource
from hathor.nanocontracts.types import BlueprintId, VertexId
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts import test_blueprints
from hathor_tests.nanocontracts.test_blueprints.bet import Bet
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import get_genesis_key


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def create_child(self, ctx: Context) -> None:
        self.syscall.setup_new_contract(self.syscall.get_blueprint_id(), salt=b'1').initialize()


class NCCreationResourceTest(_BaseResourceTest._ResourceTest):

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer(
            'unittests',
            nc_indexes=True,
        )
        self.web = StubSite(NCCreationResource(self.manager))
        self.genesis_private_key = get_genesis_key()
        self.builtin_bet_blueprint_id = BlueprintId(self.manager.rng.randbytes(32))
        self.manager.tx_storage.nc_catalog.blueprints[self.builtin_bet_blueprint_id] = Bet

    def prepare_ncs(self) -> tuple[Transaction, Transaction, Transaction, Transaction, Transaction]:
        bet_code = load_builtin_blueprint_for_ocb('bet.py', 'Bet', test_blueprints)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"

            ocb2.ocb_private_key = "{private_key}"
            ocb2.ocb_password = "{password}"

            nc1.nc_id = ocb2
            nc1.nc_method = initialize()

            nc2.nc_id = "{self.builtin_bet_blueprint_id.hex()}"
            nc2.nc_method = initialize("00", "00", 0)

            nc3.nc_id = ocb2
            nc3.nc_method = initialize()

            nc4.nc_id = ocb1
            nc4.nc_method = initialize("00", "00", 0)

            nc5.nc_id = "{self.builtin_bet_blueprint_id.hex()}"
            nc5.nc_method = initialize("00", "00", 0)

            ocb1 <-- ocb2 <-- b11
            b11 < nc1 < nc2 < nc3 < nc4 < nc5

            nc1 <-- nc2 <-- nc3 <-- nc4 <-- nc5 <-- b12

            ocb1.ocb_code = "{bet_code.encode().hex()}"
            ocb2.ocb_code = ```
                from hathor import Blueprint, Context, export, public
                @export
                class MyBlueprint(Blueprint):
                    @public
                    def initialize(self, ctx: Context) -> None:
                        pass
            ```
        ''')

        artifacts.propagate_with(self.manager)
        nc1, nc2, nc3, nc4, nc5 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3', 'nc4', 'nc5'], Transaction)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()
        assert nc4.is_nano_contract()
        assert nc5.is_nano_contract()
        return nc1, nc2, nc3, nc4, nc5

    def nc_to_response_item(self, nc: Transaction) -> dict[str, Any]:
        assert nc.storage is not None
        assert nc.is_nano_contract()
        nano_header = nc.get_nano_header()
        blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
        blueprint_class = nc.storage.get_blueprint_class(blueprint_id)
        return dict(
            nano_contract_id=nc.hash_hex,
            blueprint_id=blueprint_id.hex(),
            blueprint_name=blueprint_class.__name__,
            last_tx_timestamp=nc.timestamp,
            total_txs=1,
            created_at=nc.timestamp,
        )

    async def test_success(self) -> None:
        nc1, nc2, nc3, nc4, nc5 = self.prepare_ncs()
        response = await self.web.get('creation')
        data = response.json_value()

        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc5),
                self.nc_to_response_item(nc4),
                self.nc_to_response_item(nc3),
                self.nc_to_response_item(nc2),
                self.nc_to_response_item(nc1),
            ],
        )

    async def test_tx_aggregation(self) -> None:
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = test_blueprint1.py, TestBlueprint1

            ocb2.ocb_private_key = "{private_key}"
            ocb2.ocb_password = "{password}"
            ocb2.ocb_code = test_blueprint1.py, TestBlueprint1

            nc1.nc_id = ocb1
            nc1.nc_method = initialize(0)

            nc2.nc_id = ocb2
            nc2.nc_method = initialize(0)

            nc3.nc_id = nc2
            nc3.nc_method = create_child_contract()

            nc4.nc_id = nc1
            nc4.nc_method = nop()

            nc5.nc_id = nc2
            nc5.nc_method = nop()

            nc6.nc_id = nc2
            nc6.nc_method = nop()

            nc7.nc_id = nc1
            nc7.nc_method = nop()

            ocb1 <-- ocb2 <-- b11
            b11 < nc1 < nc2 < nc3 < nc4 < nc5 < nc6 < nc7

            nc1 <-- nc2 <-- nc3 <-- b12
        ''')

        artifacts.propagate_with(self.manager)
        nc1, nc2, nc6, nc7 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc6', 'nc7'], Transaction)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc6.is_nano_contract()
        assert nc7.is_nano_contract()
        response = await self.web.get('creation')
        data = response.json_value()

        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[
                dict(
                    nano_contract_id=nc2.hash_hex,
                    blueprint_id=nc2.get_nano_header().nc_id.hex(),
                    blueprint_name='TestBlueprint1',
                    last_tx_timestamp=nc6.timestamp,
                    total_txs=4,
                    created_at=nc2.timestamp,
                ),
                dict(
                    nano_contract_id=nc1.hash_hex,
                    blueprint_id=nc1.get_nano_header().nc_id.hex(),
                    blueprint_name='TestBlueprint1',
                    last_tx_timestamp=nc7.timestamp,
                    total_txs=3,
                    created_at=nc1.timestamp,
                )
            ],
        )

    async def test_pagination(self) -> None:
        nc1, nc2, nc3, nc4, nc5 = self.prepare_ncs()
        response = await self.web.get('creation', {
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=2,
            has_more=True,
            nc_creation_txs=[
                self.nc_to_response_item(nc5),
                self.nc_to_response_item(nc4),
            ],
        )

        response = await self.web.get('creation', {
            b'after': nc4.hash_hex.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=nc4.hash_hex,
            count=2,
            has_more=True,
            nc_creation_txs=[
                self.nc_to_response_item(nc3),
                self.nc_to_response_item(nc2),
            ],
        )

        response = await self.web.get('creation', {
            b'after': nc2.hash_hex.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=nc2.hash_hex,
            count=2,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc1),
            ],
        )

        response = await self.web.get('creation', {
            b'after': nc1.hash_hex.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=nc1.hash_hex,
            count=2,
            has_more=False,
            nc_creation_txs=[],
        )

        response = await self.web.get('creation', {
            b'before': nc1.hash_hex.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=nc1.hash_hex,
            after=None,
            count=2,
            has_more=True,
            nc_creation_txs=[
                self.nc_to_response_item(nc2),
                self.nc_to_response_item(nc3),
            ],
        )

        response = await self.web.get('creation', {
            b'before': nc3.hash_hex.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=nc3.hash_hex,
            after=None,
            count=2,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc4),
                self.nc_to_response_item(nc5),
            ],
        )

    async def test_pagination_asc(self) -> None:
        nc1, nc2, nc3, nc4, nc5 = self.prepare_ncs()
        response = await self.web.get('creation', {
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=2,
            has_more=True,
            nc_creation_txs=[
                self.nc_to_response_item(nc1),
                self.nc_to_response_item(nc2),
            ],
        )

        response = await self.web.get('creation', {
            b'after': nc2.hash_hex.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=nc2.hash_hex,
            count=2,
            has_more=True,
            nc_creation_txs=[
                self.nc_to_response_item(nc3),
                self.nc_to_response_item(nc4),
            ],
        )

        response = await self.web.get('creation', {
            b'after': nc4.hash_hex.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=nc4.hash_hex,
            count=2,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc5),
            ],
        )

        response = await self.web.get('creation', {
            b'after': nc5.hash_hex.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=nc5.hash_hex,
            count=2,
            has_more=False,
            nc_creation_txs=[],
        )

        response = await self.web.get('creation', {
            b'before': nc5.hash_hex.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=nc5.hash_hex,
            after=None,
            count=2,
            has_more=True,
            nc_creation_txs=[
                self.nc_to_response_item(nc4),
                self.nc_to_response_item(nc3),
            ],
        )

        response = await self.web.get('creation', {
            b'before': nc3.hash_hex.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=nc3.hash_hex,
            after=None,
            count=2,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc2),
                self.nc_to_response_item(nc1),
            ],
        )

    async def test_search_by_nc_id(self) -> None:
        nc1, nc2, nc3, nc4, nc5 = self.prepare_ncs()
        response = await self.web.get('on_chain', {
            b'search': nc3.hash_hex.encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc3),
            ],
        )

    async def test_search_by_blueprint_id(self) -> None:
        nc1, nc2, nc3, nc4, nc5 = self.prepare_ncs()
        response = await self.web.get('on_chain', {
            b'search': nc1.get_nano_header().nc_id.hex().encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc3),
                self.nc_to_response_item(nc1),
            ],
        )

        response = await self.web.get('on_chain', {
            b'search': nc2.get_nano_header().nc_id.hex().encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc5),
                self.nc_to_response_item(nc2),
            ],
        )

        response = await self.web.get('on_chain', {
            b'search': nc4.get_nano_header().nc_id.hex().encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc4),
            ],
        )

    async def test_search_by_blueprint_id_with_pagination(self) -> None:
        nc1, nc2, nc3, nc4, nc5 = self.prepare_ncs()
        nc1_nano_header = nc1.get_nano_header()
        response = await self.web.get('on_chain', {
            b'search': nc1_nano_header.nc_id.hex().encode(),
            b'count': b'1',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=1,
            has_more=True,
            nc_creation_txs=[
                self.nc_to_response_item(nc3),
            ],
        )

        response = await self.web.get('on_chain', {
            b'search': nc1_nano_header.nc_id.hex().encode(),
            b'count': b'1',
            b'after': nc3.hash_hex.encode()
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=nc3.hash_hex,
            count=1,
            has_more=False,
            nc_creation_txs=[
                self.nc_to_response_item(nc1),
            ],
        )

    async def test_search_non_existent(self) -> None:
        self.prepare_ncs()
        response = await self.web.get('on_chain', {
            b'search': self._settings.GENESIS_BLOCK_HASH.hex().encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[],
        )

        response = await self.web.get('on_chain', {
            b'search': b'fe' * 32,
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[],
        )

    async def test_search_non_hex(self) -> None:
        self.prepare_ncs()
        response = await self.web.get('builtin', {
            b'search': b'abc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            count=10,
            before=None,
            after=None,
            has_more=False,
            nc_creation_txs=[],
        )

    async def test_non_hex_pagination(self) -> None:
        self.prepare_ncs()
        response = await self.web.get('creation', {
            b'after': b'abc',
            b'count': b'2',
        })
        data = response.json_value()
        assert response.responseCode == 400
        assert data == dict(
            success=False,
            error='Invalid "before" or "after": abc'
        )

    async def test_contract_create_contract(self) -> None:
        blueprint_id = BlueprintId(self.rng.randbytes(32))
        self.manager.tx_storage.nc_catalog.blueprints[blueprint_id] = MyBlueprint

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1 <-- b11

            nc2.nc_id = nc1
            nc2.nc_method = create_child()
            nc2 <-- b12
        ''')

        artifacts.propagate_with(self.manager)
        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        nc1, nc2, = artifacts.get_typed_vertices(('nc1', 'nc2'), Transaction)

        assert nc1.get_metadata().first_block == b11.hash
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc2.get_metadata().first_block == b12.hash
        assert nc2.get_metadata().nc_execution == NCExecutionState.SUCCESS

        response = await self.web.get('creation')
        data = response.json_value()

        # Contracts created by contracts are currently not supported by the API and are simply omitted.
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            nc_creation_txs=[
                dict(
                    nano_contract_id=nc1.hash_hex,
                    blueprint_id=blueprint_id.hex(),
                    blueprint_name='MyBlueprint',
                    last_tx_timestamp=nc2.timestamp,
                    total_txs=2,
                    created_at=nc1.timestamp,
                ),
            ],
        )
