#  Copyright 2023 Hathor Labs
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

import pytest
from pydantic import ValidationError

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_data import ReorgData
from hathor.event.model.event_type import EventType
from tests.utils import EventMocker


@pytest.mark.parametrize('event_id', [0, 1, 1000])
@pytest.mark.parametrize('group_id', [None, 0, 1, 1000])
def test_create_base_event(event_id, group_id):
    event = BaseEvent(
        id=event_id,
        timestamp=123.3,
        type=EventType.VERTEX_METADATA_CHANGED,
        data=EventMocker.tx_data,
        group_id=group_id
    )

    expected = dict(
        id=event_id,
        timestamp=123.3,
        type='VERTEX_METADATA_CHANGED',
        data=dict(
            hash='abc',
            nonce=123,
            timestamp=456,
            version=1,
            weight=10.0,
            inputs=[],
            outputs=[],
            parents=[],
            token_name=None,
            token_symbol=None,
            tokens=[],
            aux_pow=None,
            metadata=dict(
                hash='abc',
                spent_outputs=[],
                conflict_with=[],
                first_block=None,
                voided_by=[],
                received_by=[],
                children=[],
                twins=[],
                accumulated_weight=1024,
                score=1048576,
                height=100,
                validation='validation'
            )
        ),
        group_id=group_id
    )

    assert event.dict() == expected


@pytest.mark.parametrize('event_id', [None, -1, -1000])
def test_create_base_event_fail_id(event_id):
    with pytest.raises(ValidationError):
        BaseEvent(
            id=event_id,
            timestamp=123.3,
            type=EventType.VERTEX_METADATA_CHANGED,
            data=EventMocker.tx_data,
        )


@pytest.mark.parametrize('group_id', [-1, -1000])
def test_create_base_event_fail_group_id(group_id):
    with pytest.raises(ValidationError):
        BaseEvent(
            id=0,
            timestamp=123.3,
            type=EventType.VERTEX_METADATA_CHANGED,
            data=EventMocker.tx_data,
            group_id=group_id
        )


def test_create_base_event_fail_data_type():
    with pytest.raises(ValidationError):
        BaseEvent(
            id=0,
            timestamp=123.3,
            type=EventType.VERTEX_METADATA_CHANGED,
            data=ReorgData(
                reorg_size=10,
                previous_best_block='a',
                new_best_block='b',
                common_block='c'
            ),
        )
