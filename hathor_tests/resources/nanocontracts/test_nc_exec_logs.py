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

from unittest.mock import ANY

from hathor.nanocontracts.resources.nc_exec_logs import NCExecLogsResource
from hathor.transaction import Block, Transaction
from hathor_tests.nanocontracts.test_nc_exec_logs import MY_BLUEPRINT1_ID, BaseNCExecLogs
from hathor_tests.resources.base_resource import StubSite


class NCExecLogsResourceTest(BaseNCExecLogs):
    __test__ = True

    def setUp(self):
        super().setUp()
        self._prepare()
        self.web = StubSite(NCExecLogsResource(self.manager))
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            blockchain b1 a[2..3]
            b1 < dummy
            b2 < a2

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc1 <-- b2
            nc1 <-- a2
        """)

        for _, vertex in artifacts.list:
            assert self.manager.on_new_tx(vertex)

        self.nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        assert self.nc1.is_nano_contract()
        self.b2, self.a2 = artifacts.get_typed_vertices(['b2', 'a2'], Block)

    async def test_missing_id(self) -> None:
        response = await self.web.get('logs')
        data = response.json_value()
        assert response.responseCode == 400
        assert not data['success']

    async def test_invalid_id(self) -> None:
        response = await self.web.get('logs', {
            b'id': b'a',
        })
        data = response.json_value()
        assert response.responseCode == 400
        assert data == dict(
            success=False,
            error='Invalid id: a'
        )

    async def test_tx_not_found(self) -> None:
        response = await self.web.get('logs', {
            b'id': b'aa',
        })
        data = response.json_value()
        assert response.responseCode == 404
        assert data == dict(
            success=False,
            error='NC "aa" not found.'
        )

    async def test_nc_not_found(self) -> None:
        genesis_hash = self._settings.GENESIS_TX1_HASH.hex()
        response = await self.web.get('logs', {
            b'id': genesis_hash.encode()
        })
        data = response.json_value()
        assert response.responseCode == 404
        assert data == dict(
            success=False,
            error=f'NC "{genesis_hash}" not found.'
        )

    async def test_invalid_log_level(self) -> None:
        response = await self.web.get('logs', {
            b'id': self.nc1.hash_hex.encode(),
            b'log_level': b'UNKNOWN'
        })
        data = response.json_value()
        assert response.responseCode == 400
        assert data == dict(
            success=False,
            error='Invalid log level: UNKNOWN'
        )

    async def test_success(self) -> None:
        response = await self.web.get('logs', {
            b'id': self.nc1.hash_hex.encode(),
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            nc_id=self.nc1.get_nano_header().get_contract_id().hex(),
            nc_execution='success',
            logs={
                self.a2.hash_hex: [
                    dict(
                        error_traceback=None,
                        logs=[
                            dict(
                                type='CALL_BEGIN',
                                level='DEBUG',
                                nc_id=self.nc1.hash_hex,
                                call_type='public',
                                method_name='initialize',
                                str_args='()',
                                timestamp=ANY,
                                actions=[],
                            ),
                            dict(
                                type='LOG',
                                level='INFO',
                                message='initialize() called on MyBlueprint1',
                                key_values={},
                                timestamp=ANY,
                            ),
                            dict(
                                type='CALL_END',
                                level='DEBUG',
                                timestamp=ANY,
                                sandbox_counters=ANY,
                            )
                        ],
                    ),
                ],
            },
        )

    async def test_all_execs(self) -> None:
        response = await self.web.get('logs', {
            b'id': self.nc1.hash_hex.encode(),
            b'all_execs': b'true'
        })
        data = response.json_value()

        expected_initialize_call_logs = [
            dict(
                type='CALL_BEGIN',
                level='DEBUG',
                nc_id=self.nc1.hash_hex,
                call_type='public',
                method_name='initialize',
                str_args='()',
                timestamp=ANY,
                actions=[],
            ),
            dict(
                type='LOG',
                level='INFO',
                message='initialize() called on MyBlueprint1',
                key_values={},
                timestamp=ANY,
            ),
            dict(
                type='CALL_END',
                level='DEBUG',
                timestamp=ANY,
                sandbox_counters=ANY,
            )
        ]

        assert data == dict(
            success=True,
            nc_id=self.nc1.get_nano_header().get_contract_id().hex(),
            nc_execution='success',
            logs={
                self.b2.hash_hex: [
                    dict(
                        error_traceback=None,
                        logs=expected_initialize_call_logs,
                    ),
                ],
                self.a2.hash_hex: [
                    dict(
                        error_traceback=None,
                        logs=expected_initialize_call_logs,
                    ),
                ],
            },
        )

    async def test_filter_log_level(self) -> None:
        response = await self.web.get('logs', {
            b'id': self.nc1.hash_hex.encode(),
            b'log_level': b'ERROR'
        })
        data = response.json_value()
        assert data == dict(
            success=True,
            nc_id=self.nc1.get_nano_header().get_contract_id().hex(),
            nc_execution='success',
            logs={
                self.a2.hash_hex: [
                    dict(
                        error_traceback=None,
                        logs=[],
                    ),
                ],
            },
        )
