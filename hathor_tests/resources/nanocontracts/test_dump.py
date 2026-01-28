# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import gzip
import textwrap

from hathor import __version__
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.resources import NanoContractDumpResource
from hathor.transaction import Block, Transaction
from hathor.util import not_none
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class MyBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context, value: int) -> None:
        self.value = value


class NanoContractDumpTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.blueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.blueprint_id: MyBlueprint
        })

        self.manager = self.create_peer('unittests', unlock_wallet=True)
        self.manager.tx_storage.nc_catalog = self.catalog
        self.web = StubSite(NanoContractDumpResource(self.manager))
        dag_builder = TestDAGBuilder.from_manager(self.manager)

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize(123)
            nc1 <-- b11
        ''')

        artifacts.propagate_with(self.manager)
        self.b11 = artifacts.get_typed_vertex('b11', Block)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)

        nc_address = nc1.get_nano_header().nc_address
        b11_root_id = not_none(self.b11.get_metadata().nc_block_root_id)

        metadata_value = '01207878787878787878787878787878787878787878787878787878787878787878'
        self.expected = textwrap.dedent(f'''\
            HATHOR_NCDUMP
            VERSION: {__version__}
            NETWORK: unittests
            ---
            HEIGHT: 11
            BLOCK: {self.b11.hash.hex()}
            - BLOCK ROOT: {b11_root_id.hex()}
              02{nc_address.hex()}: 00
              00{nc1.hash.hex()}: 59fa1541822b08da50ad9c0efee0f0f33026f8e3bbd9cbab88e7710d2b907068
            - CONTRACT ROOT: 59fa1541822b08da50ad9c0efee0f0f33026f8e3bbd9cbab88e7710d2b907068
              02689aec5873ee7f0004e05ab78cbf6507e400939f316d137d472c1aeca5515bf7: {metadata_value}
              00cd42404d52ad55ccfa9aca4adc828aa5800ad9d385a0671fbcbf724118320619: 01fb00
        ''')

    async def test_dump_complete(self) -> None:
        response = await self.web.get('dump')
        assert response.responseCode == 200

        content = b''.join(response.written)
        decompressed = gzip.decompress(content).decode('utf-8')

        assert decompressed == self.expected

    async def test_dump_until_height(self) -> None:
        response = await self.web.get('dump', {
            b'until_height': b'11',
        })
        assert response.responseCode == 200

        content = b''.join(response.written)
        decompressed = gzip.decompress(content).decode('utf-8')

        assert decompressed == self.expected

    async def test_dump_until_block(self) -> None:
        response = await self.web.get('dump', {
            b'until_block': self.b11.hash_hex.encode('ascii'),
        })
        assert response.responseCode == 200

        content = b''.join(response.written)
        decompressed = gzip.decompress(content).decode('utf-8')

        assert decompressed == self.expected

    async def test_dump_mutual_exclusive_params(self) -> None:
        response = await self.web.get('dump', {
            b'until_block': b'01' * 32,
            b'until_height': b'100',
        })
        assert response.responseCode == 400
        data = response.json_value()
        assert not data['success']
        assert data['error'] == 'Parameters until_block and until_height cannot be used together.'

    async def test_dump_invalid_block_hash(self) -> None:
        response = await self.web.get('dump', {
            b'until_block': b'invalid_hex',
        })
        assert response.responseCode == 400
        data = response.json_value()
        assert not data['success']
        assert data['error'] == 'Invalid block hash: invalid_hex'

    async def test_dump_height_exceeds_best(self) -> None:
        response = await self.web.get('dump', {
            b'until_height': b'999',
        })
        assert response.responseCode == 400
        data = response.json_value()
        assert not data['success']
        assert data['error'] == 'Height 999 exceeds best block height 11'

    async def test_dump_block_not_found(self) -> None:
        fake_hash = '01' * 32
        response = await self.web.get('dump', {
            b'until_block': fake_hash.encode('ascii'),
        })
        assert response.responseCode == 404
        data = response.json_value()
        assert not data['success']
        assert data['error'] == f'Block not found: {fake_hash}'

    async def test_dump_with_start_block(self) -> None:
        response = await self.web.get('dump', {
            b'start_block': self.b11.hash_hex.encode('ascii'),
        })
        assert response.responseCode == 200

        content = b''.join(response.written)
        decompressed = gzip.decompress(content).decode('utf-8')

        assert decompressed == self.expected

    async def test_dump_start_block_not_found(self) -> None:
        fake_hash = '01' * 32
        response = await self.web.get('dump', {
            b'start_block': fake_hash.encode('ascii'),
        })
        assert response.responseCode == 404
        data = response.json_value()
        assert not data['success']
        assert data['error'] == f'Start block not found: {fake_hash}'

    async def test_dump_start_block_invalid_hex(self) -> None:
        response = await self.web.get('dump', {
            b'start_block': b'invalid_hex',
        })
        assert response.responseCode == 400
        data = response.json_value()
        assert not data['success']
        assert data['error'] == 'Invalid start_block hash: invalid_hex'
