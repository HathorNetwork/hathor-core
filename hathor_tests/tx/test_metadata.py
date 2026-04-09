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

from unittest.mock import Mock

from hathor import BlueprintId, ContractId, TokenUid
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.nanocontracts.runner.index_records import (
    CreateContractRecord,
    CreateTokenRecord,
    IndexRecordType,
    UpdateAuthoritiesRecord,
    UpdateTokenBalanceRecord,
)
from hathor.transaction import TransactionMetadata
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.token_info import TokenVersion
from hathor.transaction.types import MetaNCCallRecord
from hathor.transaction.validation_state import ValidationState
from hathor.util import not_none
from hathor_tests import unittest


class TestMetadata(unittest.TestCase):
    def test_round_trip(self) -> None:
        meta = TransactionMetadata()
        meta._tx_ref = Mock()
        meta.hash = b'abc'
        meta.spent_outputs = {0: [b'1', b'2'], 10: [b'3']}
        meta.conflict_with = [b'1', b'2']
        meta.voided_by = {b'1', b'2'}
        meta.received_by = [1, 2, 3]
        meta.twins = [b'1', b'2']
        meta.accumulated_weight = 123
        meta.score = 456
        meta.first_block = b'123'
        meta.validation = ValidationState.FULL
        meta.nc_block_root_id = b'456'
        meta.nc_execution = NCExecutionState.SUCCESS
        meta.nc_calls = [
            MetaNCCallRecord(
                blueprint_id=b'foo',
                contract_id=b'bar',
                method_name='aaa',
                index_updates=[
                    CreateContractRecord(
                        blueprint_id=BlueprintId(b'bbb'),
                        contract_id=ContractId(b'ccc'),
                    ),
                    CreateTokenRecord(
                        token_uid=TokenUid(b'ttt'),
                        amount=123,
                        token_symbol='s',
                        token_name='n',
                        token_version=TokenVersion.FEE,
                    ),
                    UpdateTokenBalanceRecord(
                        token_uid=TokenUid(b'ttt'),
                        amount=123,
                    ),
                    UpdateAuthoritiesRecord(
                        type=IndexRecordType.REVOKE_AUTHORITIES,
                        token_uid=TokenUid(b'ttt'),
                        mint=True,
                        melt=True,
                    ),
                ],
            ),
        ]
        meta.nc_events = [
            (b'a', b'b'),
            (b'c', b'd'),
        ]
        meta.feature_states = {
            Feature.NOP_FEATURE_1: FeatureState.FAILED,
            Feature.NOP_FEATURE_2: FeatureState.ACTIVE,
        }

        storage_json = meta.to_storage_json()
        meta2 = TransactionMetadata.create_from_json(storage_json)
        meta3 = TransactionMetadata.from_bytes(meta.to_bytes())

        assert meta.hash == meta2.hash and meta.hash == meta3.hash
        assert meta.spent_outputs == meta2.spent_outputs and meta.spent_outputs == meta3.spent_outputs
        assert (
            set(not_none(meta.conflict_with)) == set(not_none(meta2.conflict_with))
            and set(not_none(meta.conflict_with)) == set(not_none(meta3.conflict_with))
        )
        assert meta.voided_by == meta2.voided_by and meta.voided_by == meta3.voided_by
        assert meta.received_by == meta2.received_by and meta.received_by == meta3.received_by
        assert meta.twins == meta2.twins and meta.twins == meta3.twins
        assert (
            meta.accumulated_weight == meta2.accumulated_weight and meta.accumulated_weight == meta3.accumulated_weight
        )
        assert meta.score == meta2.score and meta.score == meta3.score
        assert meta.first_block == meta2.first_block and meta.first_block == meta3.first_block
        assert meta.validation == meta2.validation and meta.validation == meta3.validation
        assert meta.nc_block_root_id == meta2.nc_block_root_id and meta.nc_block_root_id == meta3.nc_block_root_id
        assert meta.nc_execution == meta2.nc_execution and meta.nc_execution == meta3.nc_execution
        assert meta.nc_calls == meta2.nc_calls and meta.nc_calls == meta3.nc_calls
        assert meta.nc_events == meta2.nc_events and meta.nc_events == meta3.nc_events
        assert meta.feature_states == meta2.feature_states and meta.feature_states == meta3.feature_states
