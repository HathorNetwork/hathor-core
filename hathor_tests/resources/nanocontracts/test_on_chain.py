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

from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.resources.on_chain import BlueprintOnChainResource
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts import test_blueprints
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class BlueprintOnChainResourceTest(_BaseResourceTest._ResourceTest):

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer(
            'unittests',
            nc_indexes=True,
        )
        self.web = StubSite(BlueprintOnChainResource(self.manager))
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def propagate_ocbs(self) -> list[OnChainBlueprint]:
        bet_code = load_builtin_blueprint_for_ocb('bet.py', 'Bet', test_blueprints)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb2.ocb_private_key = "{private_key}"
            ocb3.ocb_private_key = "{private_key}"
            ocb4.ocb_private_key = "{private_key}"
            ocb5.ocb_private_key = "{private_key}"

            ocb1.ocb_password = "{password}"
            ocb2.ocb_password = "{password}"
            ocb3.ocb_password = "{password}"
            ocb4.ocb_password = "{password}"
            ocb5.ocb_password = "{password}"

            ocb1.ocb_code = "{bet_code.encode().hex()}"
            ocb2.ocb_code = "{bet_code.encode().hex()}"
            ocb3.ocb_code = "{bet_code.encode().hex()}"
            ocb4.ocb_code = "{bet_code.encode().hex()}"
            ocb5.ocb_code = "{bet_code.encode().hex()}"

            ocb1 <-- ocb2 <-- ocb3 <-- ocb4 <-- ocb5 <-- b11
        """)

        artifacts.propagate_with(self.manager)
        return artifacts.get_typed_vertices(['ocb1', 'ocb2', 'ocb3', 'ocb4', 'ocb5'], OnChainBlueprint)

    def blueprint_tx_to_response(self, bp_tx: OnChainBlueprint, *, name: str = 'Bet') -> dict[str, Any]:
        return dict(
            id=bp_tx.blueprint_id().hex(),
            name=name,
            created_at=bp_tx.timestamp
        )

    async def test_success(self) -> None:
        # test when there are no OCBs
        response = await self.web.get('on_chain')
        data = response.json_value()

        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[],
        )

        ocbs = self.propagate_ocbs()
        response = await self.web.get('on_chain')
        data = response.json_value()
        expected_bps = [self.blueprint_tx_to_response(ocb)for ocb in reversed(ocbs)]

        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=expected_bps,
        )

    async def test_ocb_not_confirmed(self) -> None:
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = test_blueprint1.py, TestBlueprint1

            ocb2.ocb_private_key = "{private_key}"
            ocb2.ocb_password = "{password}"
            ocb2.ocb_code = test_blueprint1.py, TestBlueprint1

            ocb1 <-- b11
        """)

        artifacts.propagate_with(self.manager)
        ocb1 = artifacts.get_typed_vertex('ocb1', OnChainBlueprint)

        response = await self.web.get('on_chain')
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[
                self.blueprint_tx_to_response(ocb1, name='TestBlueprint1')
            ],
        )

    async def test_pagination(self) -> None:
        ocbs = self.propagate_ocbs()
        response = await self.web.get('on_chain', {
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=2,
            has_more=True,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[4]),
                self.blueprint_tx_to_response(ocbs[3]),
            ],
        )

        after = ocbs[3].hash_hex
        response = await self.web.get('on_chain', {
            b'after': after.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=after,
            count=2,
            has_more=True,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[2]),
                self.blueprint_tx_to_response(ocbs[1]),
            ],
        )

        after = ocbs[1].hash_hex
        response = await self.web.get('on_chain', {
            b'after': after.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=after,
            count=2,
            has_more=False,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[0]),
            ],
        )

        after = ocbs[0].hash_hex
        response = await self.web.get('on_chain', {
            b'after': after.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=after,
            count=2,
            has_more=False,
            blueprints=[],
        )

        before = ocbs[0].hash_hex
        response = await self.web.get('on_chain', {
            b'before': before.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=before,
            after=None,
            count=2,
            has_more=True,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[1]),
                self.blueprint_tx_to_response(ocbs[2]),
            ],
        )

        before = ocbs[2].hash_hex
        response = await self.web.get('on_chain', {
            b'before': before.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=before,
            after=None,
            count=2,
            has_more=False,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[3]),
                self.blueprint_tx_to_response(ocbs[4]),
            ],
        )

        before = ocbs[4].hash_hex
        response = await self.web.get('on_chain', {
            b'before': before.encode(),
            b'count': b'2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=before,
            after=None,
            count=2,
            has_more=False,
            blueprints=[],
        )

    async def test_pagination_asc(self) -> None:
        ocbs = self.propagate_ocbs()
        response = await self.web.get('on_chain', {
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
            blueprints=[
                self.blueprint_tx_to_response(ocbs[0]),
                self.blueprint_tx_to_response(ocbs[1]),
            ],
        )

        after = ocbs[1].hash_hex
        response = await self.web.get('on_chain', {
            b'after': after.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=after,
            count=2,
            has_more=True,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[2]),
                self.blueprint_tx_to_response(ocbs[3]),
            ],
        )

        after = ocbs[3].hash_hex
        response = await self.web.get('on_chain', {
            b'after': after.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=after,
            count=2,
            has_more=False,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[4]),
            ],
        )

        after = ocbs[4].hash_hex
        response = await self.web.get('on_chain', {
            b'after': after.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=after,
            count=2,
            has_more=False,
            blueprints=[],
        )

        before = ocbs[4].hash_hex
        response = await self.web.get('on_chain', {
            b'before': before.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=before,
            after=None,
            count=2,
            has_more=True,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[3]),
                self.blueprint_tx_to_response(ocbs[2]),
            ],
        )

        before = ocbs[2].hash_hex
        response = await self.web.get('on_chain', {
            b'before': before.encode(),
            b'count': b'2',
            b'order': b'asc',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=before,
            after=None,
            count=2,
            has_more=False,
            blueprints=[
                self.blueprint_tx_to_response(ocbs[1]),
                self.blueprint_tx_to_response(ocbs[0]),
            ],
        )

    async def test_search_by_bp_id(self) -> None:
        ocbs = self.propagate_ocbs()
        some_bp_tx = ocbs[2]
        response = await self.web.get('on_chain', {
            b'search': some_bp_tx.hash_hex.encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[
                self.blueprint_tx_to_response(some_bp_tx),
            ],
        )

        # tx exists but is not a blueprint
        bp_id = self._settings.GENESIS_TX1_HASH.hex()
        response = await self.web.get('builtin', {
            b'search': bp_id.encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[],
        )

        response = await self.web.get('on_chain', {
            b'search': b'ff' * 32,
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[],
        )

    async def test_search_by_name(self) -> None:
        response = await self.web.get('builtin', {
            b'search': b'Bet',
        })
        data = response.json_value()
        # it's not implemented so it returns empty
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[],
        )
