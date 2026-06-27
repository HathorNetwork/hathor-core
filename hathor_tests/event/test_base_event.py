# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import pytest
from pydantic import ValidationError

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_data import ReorgData
from hathor.event.model.event_type import EventType
from hathor_tests.utils import EventMocker


@pytest.mark.parametrize('event_id', [0, 1, 1000])
@pytest.mark.parametrize('group_id', [None, 0, 1, 1000])
def test_create_base_event(event_id: int, group_id: int | None) -> None:
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
            name='tx name',
            nonce=123,
            timestamp=456,
            signal_bits=0,
            version=1,
            weight=10.0,
            headers=[],
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
                twins=[],
                accumulated_weight=10.0,
                score=20.0,
                accumulated_weight_raw="1024",
                score_raw="1048576",
                height=100,
                validation='validation',
                nc_execution=None,
            )
        ),
        group_id=group_id
    )

    assert event.model_dump() == expected


@pytest.mark.parametrize('event_id', [-1, -1000])
def test_create_base_event_fail_id(event_id: int) -> None:
    with pytest.raises(ValidationError):
        BaseEvent(
            id=event_id,
            timestamp=123.3,
            type=EventType.VERTEX_METADATA_CHANGED,
            data=EventMocker.tx_data,
        )


@pytest.mark.parametrize('group_id', [-1, -1000])
def test_create_base_event_fail_group_id(group_id: int) -> None:
    with pytest.raises(ValidationError):
        BaseEvent(
            id=0,
            timestamp=123.3,
            type=EventType.VERTEX_METADATA_CHANGED,
            data=EventMocker.tx_data,
            group_id=group_id
        )


def test_create_base_event_fail_data_type() -> None:
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
