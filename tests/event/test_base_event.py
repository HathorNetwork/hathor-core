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

from hathor.event import BaseEvent


@pytest.mark.parametrize('event_id', [0, 1, 1000])
@pytest.mark.parametrize('group_id', [None, 0, 1, 1000])
def test_create_base_event(event_id, group_id):
    event = BaseEvent(
        peer_id='some_peer',
        id=event_id,
        timestamp=123.3,
        type='some_type',
        data=dict(some_data='some_value'),
        group_id=group_id
    )

    expected = dict(
        peer_id='some_peer',
        id=event_id,
        timestamp=123.3,
        type='some_type',
        data=dict(some_data='some_value'),
        group_id=group_id
    )

    assert event.dict() == expected


@pytest.mark.parametrize('event_id', [None, -1, -1000])
def test_create_base_event_fail_id(event_id):
    with pytest.raises(ValidationError):
        BaseEvent(
            peer_id='some_peer',
            id=event_id,
            timestamp=123.3,
            type='some_type',
            data=dict(some_data='some_value')
        )


@pytest.mark.parametrize('group_id', [-1, -1000])
def test_create_base_event_fail_group_id(group_id):
    with pytest.raises(ValidationError):
        BaseEvent(
            peer_id='some_peer',
            id=0,
            timestamp=123.3,
            type='some_type',
            data=dict(some_data='some_value'),
            group_id=group_id
        )
