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

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.resources.builtin import BlueprintBuiltinResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class MyBlueprint1(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass


class MyBlueprint2(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass


class BlueprintBuiltinResourceTest(_BaseResourceTest._ResourceTest):

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer(
            'unittests',
            nc_indexes=True,
        )
        self.web = StubSite(BlueprintBuiltinResource(self.manager))

        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            (b'\x11' * 32): MyBlueprint1,
            (b'\x22' * 32): MyBlueprint2,
            (b'\x33' * 32): MyBlueprint2,
            (b'\x44' * 32): MyBlueprint2,
            (b'\x55' * 32): MyBlueprint2,
        })

    async def test_success(self) -> None:
        response = await self.web.get('builtin')
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[
                dict(id='11' * 32, name='MyBlueprint1'),
                dict(id='22' * 32, name='MyBlueprint2'),
                dict(id='33' * 32, name='MyBlueprint2'),
                dict(id='44' * 32, name='MyBlueprint2'),
                dict(id='55' * 32, name='MyBlueprint2'),
            ],
        )

    async def test_pagination(self) -> None:
        response = await self.web.get('builtin', {
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
                dict(id='11' * 32, name='MyBlueprint1'),
                dict(id='22' * 32, name='MyBlueprint2'),
            ],
        )

        after = '22' * 32
        response = await self.web.get('builtin', {
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
                dict(id='33' * 32, name='MyBlueprint2'),
                dict(id='44' * 32, name='MyBlueprint2'),
            ],
        )

        after = '44' * 32
        response = await self.web.get('builtin', {
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
                dict(id='55' * 32, name='MyBlueprint2'),
            ],
        )

        after = '55' * 32
        response = await self.web.get('builtin', {
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

        before = '55' * 32
        response = await self.web.get('builtin', {
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
                dict(id='44' * 32, name='MyBlueprint2'),
                dict(id='33' * 32, name='MyBlueprint2'),
            ],
        )

        before = '33' * 32
        response = await self.web.get('builtin', {
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
                dict(id='22' * 32, name='MyBlueprint2'),
                dict(id='11' * 32, name='MyBlueprint1'),
            ],
        )

        before = '11' * 32
        response = await self.web.get('builtin', {
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

    async def test_search_by_id(self) -> None:
        bp_id = '33' * 32
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
            blueprints=[
                dict(id=bp_id, name='MyBlueprint2'),
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

        response = await self.web.get('builtin', {
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
            b'search': b'myblueprint1',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[
                dict(id='11' * 32, name='MyBlueprint1'),
            ],
        )

        response = await self.web.get('builtin', {
            b'search': b'MyBlueprint2',
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            before=None,
            after=None,
            count=10,
            has_more=False,
            blueprints=[
                dict(id='22' * 32, name='MyBlueprint2'),
                dict(id='33' * 32, name='MyBlueprint2'),
                dict(id='44' * 32, name='MyBlueprint2'),
                dict(id='55' * 32, name='MyBlueprint2'),
            ],
        )

        response = await self.web.get('builtin', {
            b'search': b'Unknown',
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
