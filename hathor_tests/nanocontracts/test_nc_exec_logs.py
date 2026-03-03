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

from textwrap import dedent
from unittest.mock import ANY

from hathor.nanocontracts import Blueprint, Context, NCFail, public
from hathor.nanocontracts.nc_exec_logs import (
    NCCallBeginEntry,
    NCCallEndEntry,
    NCExecEntry,
    NCLogConfig,
    NCLogEntry,
    NCLogLevel,
)
from hathor.nanocontracts.runner import CallType
from hathor.nanocontracts.types import ContractId, NCDepositAction, TokenUid, view
from hathor.transaction import Block, Transaction
from hathor.util import not_none
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder

MY_BLUEPRINT1_ID: bytes = b'\x11' * 32
MY_BLUEPRINT2_ID: bytes = b'\x22' * 32


class MyBlueprint1(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        self.log.info('initialize() called on MyBlueprint1')

    @public
    def log_levels(self, ctx: Context) -> None:
        msg = 'log_levels() called'
        self.log.debug(msg, test1=1)
        self.log.info(msg, test2=2)
        self.log.warn(msg, test3=3)
        self.log.error(msg, test4=4)

    @public
    def fail(self, ctx: Context) -> None:
        self.log.warn('fail() called')
        raise NCFail('some fail')

    @public
    def value_error(self, ctx: Context) -> None:
        self.log.warn('value_error() called')
        raise ValueError('some value error')

    @public(allow_deposit=True)
    def call_another_public(self, ctx: Context, contract_id: ContractId) -> None:
        self.log.debug('call_another_public() called on MyBlueprint1', contract_id=contract_id)
        action = NCDepositAction(token_uid=TokenUid(b'\x00'), amount=5)
        result1 = self.syscall.get_contract(contract_id, blueprint_id=None).public(action).sum(1, 2)
        result2 = self.syscall.get_contract(contract_id, blueprint_id=None).view().hello_world()
        self.log.debug('results on MyBlueprint1', result1=result1, result2=result2)


class MyBlueprint2(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        self.log.info('initialize() called on MyBlueprint2')

    @public(allow_deposit=True)
    def sum(self, ctx: Context, a: int, b: int) -> int:
        self.log.debug('sum() called on MyBlueprint2', a=a, b=b)
        return a + b

    @view
    def hello_world(self) -> str:
        self.log.debug('hello_world() called on MyBlueprint2')
        return 'hello world'


class BaseNCExecLogs(unittest.TestCase):
    __test__ = False

    def _get_initialize_entries(self, tx: Transaction) -> list[NCCallBeginEntry | NCLogEntry | NCCallEndEntry]:
        assert tx.is_nano_contract()
        nano_header = tx.get_nano_header()
        assert self.manager.tx_storage.nc_catalog is not None
        blueprint_class = self.manager.tx_storage.nc_catalog.blueprints[nano_header.nc_id]
        return [
            NCCallBeginEntry.model_construct(
                nc_id=ContractId(tx.hash),
                call_type=CallType.PUBLIC,
                method_name='initialize',
                timestamp=ANY,
                actions=[],
            ),
            NCLogEntry.model_construct(
                level=NCLogLevel.INFO,
                message=f'initialize() called on {blueprint_class.__name__}',
                timestamp=ANY,
            ),
            NCCallEndEntry.model_construct(timestamp=ANY, sandbox_counters=ANY),
        ]

    def _prepare(self, nc_log_config: NCLogConfig = NCLogConfig.ALL) -> None:
        settings = self._settings.model_copy(update={
            'REWARD_SPEND_MIN_BLOCKS': 1,  # to make tests quicker
        })
        artifacts = self.get_builder() \
            .set_settings(settings) \
            .set_nc_log_config(nc_log_config) \
            .build()

        self.nc_log_storage = not_none(artifacts.consensus.block_algorithm_factory.nc_log_storage)
        self.manager = artifacts.manager
        assert self.manager.tx_storage.nc_catalog is not None
        self.manager.tx_storage.nc_catalog.blueprints = {
            MY_BLUEPRINT1_ID: MyBlueprint1,
            MY_BLUEPRINT2_ID: MyBlueprint2,
        }
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)


class TestNCExecLogs(BaseNCExecLogs):
    __test__ = True

    def test_config_all(self) -> None:
        self._prepare(nc_log_config=NCLogConfig.ALL)
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = fail()

            nc3.nc_id = nc1
            nc3.nc_method = value_error()

            nc1 <-- nc2 <-- nc3 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)
        b2 = artifacts.get_typed_vertex('b2', Block)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }

        assert len(not_none(self.nc_log_storage.get_logs(nc2.hash)).entries[b2.hash]) > 0
        assert len(not_none(self.nc_log_storage.get_logs(nc3.hash)).entries[b2.hash]) > 0

    def test_config_none(self) -> None:
        self._prepare(nc_log_config=NCLogConfig.NONE)
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = fail()

            nc3.nc_id = nc1
            nc3.nc_method = value_error()

            nc1 <-- nc2 <-- nc3 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        assert self.nc_log_storage.get_logs(nc1.hash) is None
        assert self.nc_log_storage.get_logs(nc2.hash) is None
        assert self.nc_log_storage.get_logs(nc3.hash) is None

    def test_config_failed(self) -> None:
        self._prepare(nc_log_config=NCLogConfig.FAILED)
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = fail()

            nc3.nc_id = nc1
            nc3.nc_method = value_error()

            nc1 <-- nc2 <-- nc3 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)
        b2 = artifacts.get_typed_vertex('b2', Block)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        assert self.nc_log_storage.get_logs(nc1.hash) is None
        assert len(not_none(self.nc_log_storage.get_logs(nc2.hash)).entries[b2.hash]) > 0
        assert len(not_none(self.nc_log_storage.get_logs(nc3.hash)).entries[b2.hash]) > 0

    def test_config_failed_unhandled(self) -> None:
        self._prepare(nc_log_config=NCLogConfig.FAILED_UNHANDLED)
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = fail()

            nc3.nc_id = nc1
            nc3.nc_method = value_error()

            nc1 <-- nc2 <-- nc3 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)
        b2 = artifacts.get_typed_vertex('b2', Block)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        assert self.nc_log_storage.get_logs(nc1.hash) is None
        assert self.nc_log_storage.get_logs(nc2.hash) is None
        assert len(not_none(self.nc_log_storage.get_logs(nc3.hash)).entries[b2.hash]) > 0

    def test_log_levels_and_key_values(self) -> None:
        self._prepare()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = log_levels()

            nc1 <-- nc2 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)
        b2 = artifacts.get_typed_vertex('b2', Block)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()

        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }

        assert not_none(self.nc_log_storage.get_logs(nc2.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=[
                    NCCallBeginEntry.model_construct(
                        nc_id=ContractId(nc1.hash),
                        call_type=CallType.PUBLIC,
                        method_name='log_levels',
                        timestamp=ANY,
                        actions=[],
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.DEBUG,
                        message='log_levels() called',
                        key_values=dict(test1='1'),
                        timestamp=ANY,
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.INFO,
                        message='log_levels() called',
                        key_values=dict(test2='2'),
                        timestamp=ANY,
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.WARN,
                        message='log_levels() called',
                        key_values=dict(test3='3'),
                        timestamp=ANY,
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.ERROR,
                        message='log_levels() called',
                        key_values=dict(test4='4'),
                        timestamp=ANY,
                    ),
                    NCCallEndEntry.model_construct(timestamp=ANY, sandbox_counters=ANY),
                ],
            )],
        }

        # test log level filter
        assert not_none(self.nc_log_storage.get_logs(nc2.hash, log_level=NCLogLevel.WARN)).entries == {
            b2.hash: [NCExecEntry(
                logs=[
                    NCLogEntry.model_construct(
                        level=NCLogLevel.WARN,
                        message='log_levels() called',
                        key_values=dict(test3='3'),
                        timestamp=ANY,
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.ERROR,
                        message='log_levels() called',
                        key_values=dict(test4='4'),
                        timestamp=ANY,
                    ),
                ],
            )],
        }

    def test_nc_fail(self) -> None:
        self._prepare()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = fail()

            nc1 <-- nc2 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)
        b2 = artifacts.get_typed_vertex('b2', Block)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()

        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }

        result = not_none(self.nc_log_storage.get_logs(nc2.hash))
        assert result.entries == {
            b2.hash: [NCExecEntry.model_construct(
                error_traceback=ANY,
                logs=[
                    NCCallBeginEntry.model_construct(
                        nc_id=ContractId(nc1.hash),
                        call_type=CallType.PUBLIC,
                        method_name='fail',
                        timestamp=ANY,
                        actions=[],
                    ),
                    NCLogEntry.model_construct(level=NCLogLevel.WARN, message='fail() called', timestamp=ANY),
                ],
            )],
        }

        error_tb = result.entries[b2.hash][0].error_traceback
        assert error_tb is not None
        assert error_tb.startswith('Traceback (most recent call last):')
        assert error_tb.endswith('hathor.nanocontracts.exception.NCFail: some fail\n')

    def test_value_error(self) -> None:
        self._prepare()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = value_error()

            nc1 <-- nc2 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)
        b2 = artifacts.get_typed_vertex('b2', Block)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()

        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }

        result = not_none(self.nc_log_storage.get_logs(nc2.hash))
        assert result.entries == {
            b2.hash: [NCExecEntry.model_construct(
                error_traceback=ANY,
                logs=[
                    NCCallBeginEntry.model_construct(
                        nc_id=ContractId(nc1.hash),
                        call_type=CallType.PUBLIC,
                        method_name='value_error',
                        timestamp=ANY,
                        actions=[],
                    ),
                    NCLogEntry.model_construct(level=NCLogLevel.WARN, message='value_error() called', timestamp=ANY),
                ],
            )],
        }

        error_tb = result.entries[b2.hash][0].error_traceback
        assert error_tb is not None
        assert error_tb.startswith('Traceback (most recent call last):')
        assert dedent("""
            ValueError: some value error\n
            The above exception was the direct cause of the following exception:\n
            Traceback (most recent call last):
        """) in error_tb
        expected_suffix = 'hathor.nanocontracts.exception.NCFail: Execution failed: ValueError: some value error\n'
        assert error_tb.endswith(expected_suffix)

    def test_reexecution_on_reorgs(self) -> None:
        self._prepare()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..4]
            blockchain b1 a[2..3]
            b1 < dummy
            b2 < a2 < a3 < b3 < b4

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc1 <-- b2
            nc1 <-- a2
        """)

        nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        b2, a2 = artifacts.get_typed_vertices(['b2', 'a2'], Block)
        assert nc1.is_nano_contract()

        # 2 reorgs happen, so nc1.initialize() gets executed 3 times, once in block a2 and twice in block b2
        artifacts.propagate_with(self.manager, up_to='b2')
        assert nc1.get_metadata().first_block == b2.hash
        assert b2.get_metadata().voided_by is None
        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }

        artifacts.propagate_with(self.manager, up_to='a3')
        assert nc1.get_metadata().first_block == a2.hash
        assert b2.get_metadata().voided_by == {b2.hash}
        assert a2.get_metadata().voided_by is None
        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
            a2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }

        artifacts.propagate_with(self.manager)
        assert nc1.get_metadata().first_block == b2.hash
        assert b2.get_metadata().voided_by is None
        assert a2.get_metadata().voided_by == {a2.hash}
        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [
                NCExecEntry(
                    logs=self._get_initialize_entries(nc1),
                ),
                NCExecEntry(
                    logs=self._get_initialize_entries(nc1),
                ),
            ],
            a2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }

    def test_call_another_contract_public(self) -> None:
        self._prepare()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..2]
            b1 < dummy

            nc1.nc_id = "{MY_BLUEPRINT1_ID.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = "{MY_BLUEPRINT2_ID.hex()}"
            nc2.nc_method = initialize()

            nc3.nc_id = nc1
            nc3.nc_deposit = 10 HTR
            nc3.nc_method = call_another_public(`nc2`)

            nc1.out[0] <<< nc2
            nc2.out[0] <<< nc3
            nc3 <-- b2
        """)
        artifacts.propagate_with(self.manager)

        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)
        b2 = artifacts.get_typed_vertex('b2', Block)
        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        assert not_none(self.nc_log_storage.get_logs(nc1.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc1),
            )],
        }
        assert not_none(self.nc_log_storage.get_logs(nc2.hash)).entries == {
            b2.hash: [NCExecEntry(
                logs=self._get_initialize_entries(nc2),
            )],
        }

        assert not_none(self.nc_log_storage.get_logs(nc3.hash)).entries == {
            b2.hash: [NCExecEntry(
                error_traceback=None,
                logs=[
                    NCCallBeginEntry.model_construct(
                        nc_id=ContractId(nc1.hash),
                        call_type=CallType.PUBLIC,
                        method_name='call_another_public',
                        str_args=str((nc2.hash,)),
                        timestamp=ANY,
                        actions=[
                            dict(
                                type='deposit',
                                token_uid='00',
                                amount=10,
                            )
                        ],
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.DEBUG,
                        message='call_another_public() called on MyBlueprint1',
                        key_values=dict(contract_id=nc2.hash_hex),
                        timestamp=ANY,
                    ),
                    NCCallBeginEntry.model_construct(
                        nc_id=ContractId(nc2.hash),
                        call_type=CallType.PUBLIC,
                        method_name='sum',
                        str_args=str((1, 2)),
                        timestamp=ANY,
                        actions=[
                            dict(
                                type='deposit',
                                token_uid='00',
                                amount=5,
                            )
                        ],
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.DEBUG,
                        message='sum() called on MyBlueprint2',
                        key_values=dict(a='1', b='2'),
                        timestamp=ANY
                    ),
                    NCCallEndEntry.model_construct(timestamp=ANY, sandbox_counters=ANY),
                    NCCallBeginEntry.model_construct(
                        nc_id=ContractId(nc2.hash),
                        call_type=CallType.VIEW,
                        method_name='hello_world',
                        timestamp=ANY,
                        actions=None,
                    ),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.DEBUG,
                        message='hello_world() called on MyBlueprint2',
                        timestamp=ANY,
                    ),
                    NCCallEndEntry.model_construct(timestamp=ANY, sandbox_counters=ANY),
                    NCLogEntry.model_construct(
                        level=NCLogLevel.DEBUG,
                        message='results on MyBlueprint1',
                        key_values=dict(result1='3', result2='hello world'),
                        timestamp=ANY
                    ),
                    NCCallEndEntry.model_construct(timestamp=ANY, sandbox_counters=ANY),
                ],
            )],
        }
