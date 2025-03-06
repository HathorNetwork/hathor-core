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

from hathor.nanocontracts import NanoContract
from hathor.nanocontracts.resources.nc_creation import NCCreationResource
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import get_genesis_key


class NCCreationResourceTest(_BaseResourceTest._ResourceTest):
    use_memory_storage = False

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer(
            'testnet',
            nc_indices=True,
            use_memory_storage=self.use_memory_storage,
            use_memory_index=self.use_memory_storage,
        )
        self.web = StubSite(NCCreationResource(self.manager))
        self.genesis_private_key = get_genesis_key()

    def prepare_ncs(self) -> tuple[NanoContract, NanoContract, NanoContract, NanoContract, NanoContract]:
        bet_code = load_builtin_blueprint_for_ocb('bet.py', 'Bet')
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        dag_builder = self.get_dag_builder(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"

            ocb2.ocb_private_key = "{private_key}"
            ocb2.ocb_password = "{password}"

            nc1.nc_id = ocb2
            nc1.nc_method = initialize()

            nc2.nc_id = "3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595"
            nc2.nc_method = initialize("00", "00", 0)

            nc3.nc_id = ocb2
            nc3.nc_method = initialize()

            nc4.nc_id = ocb1
            nc4.nc_method = initialize("00", "00", 0)

            nc5.nc_id = "3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595"
            nc5.nc_method = initialize("00", "00", 0)

            ocb1 <-- ocb2 <-- b11
            b11 < nc1 < nc2 < nc3 < nc4 < nc5

            ocb1.ocb_code = "{bet_code.encode().hex()}"
            ocb2.ocb_code = ```
                from hathor.nanocontracts import Blueprint
                from hathor.nanocontracts.context import Context
                from hathor.nanocontracts.types import public
                class MyBlueprint(Blueprint):
                    @public
                    def initialize(self, ctx: Context) -> None:
                        pass
                __blueprint__ = MyBlueprint
            ```
        ''')

        artifacts.propagate_with(self.manager)
        nc1, nc2, nc3, nc4, nc5 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3', 'nc4', 'nc5'], NanoContract)
        return nc1, nc2, nc3, nc4, nc5

    def nc_to_response_item(self, nc: NanoContract) -> dict[str, Any]:
        return dict(
            nano_contract_id=nc.hash_hex,
            blueprint_id=nc.get_blueprint_id().hex(),
            blueprint_name=nc.get_blueprint_class().__name__,
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
        dag_builder = self.get_dag_builder(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
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
            nc3.nc_method = nop()

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
        ''')

        artifacts.propagate_with(self.manager)
        nc1, nc2, nc6, nc7 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc6', 'nc7'], NanoContract)
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
                    blueprint_id=nc2.get_blueprint_id().hex(),
                    blueprint_name='TestBlueprint1',
                    last_tx_timestamp=nc6.timestamp,
                    total_txs=4,
                    created_at=nc2.timestamp,
                ),
                dict(
                    nano_contract_id=nc1.hash_hex,
                    blueprint_id=nc1.get_blueprint_id().hex(),
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
            b'search': nc1.get_blueprint_id().hex().encode(),
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
            b'search': nc2.get_blueprint_id().hex().encode(),
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
            b'search': nc4.get_blueprint_id().hex().encode(),
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
