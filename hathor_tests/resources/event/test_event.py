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

from unittest.mock import Mock

import pytest

from hathor.event import EventManager
from hathor.event.resources.event import EventResource
from hathor.event.storage import EventRocksDBStorage
from hathor.storage import RocksDBStorage
from hathor_tests.resources.base_resource import StubSite
from hathor_tests.utils import EventMocker


@pytest.fixture
def web():
    event_storage = EventRocksDBStorage(
        rocksdb_storage=RocksDBStorage.create_temp(),
    )

    for i in range(3):
        event = EventMocker.create_event(i)
        event_storage.save_event(event)

    event_manager = Mock(spec_set=EventManager)
    event_manager.event_storage = event_storage

    return StubSite(EventResource(event_manager))


@pytest.fixture
def data():
    return EventMocker.tx_data.dict()


def test_get_events(web, data):
    response = web.get('event').result
    result = response.json_value()
    expected = dict(
        latest_event_id=2,
        events=[
            dict(id=0, timestamp=123456.0, type='VERTEX_METADATA_CHANGED', data=data, group_id=None),
            dict(id=1, timestamp=123456.0, type='VERTEX_METADATA_CHANGED', data=data, group_id=None),
            dict(id=2, timestamp=123456.0, type='VERTEX_METADATA_CHANGED', data=data, group_id=None),
        ],
    )

    assert result == expected


def test_get_events_with_size(web, data):
    response = web.get('event', {b'size': b'1'})
    result = response.result.json_value()
    expected = dict(
        latest_event_id=2,
        events=[
            dict(id=0, timestamp=123456.0, type='VERTEX_METADATA_CHANGED', data=data, group_id=None),
        ],
    )

    assert result == expected


def test_get_events_with_last_ack_event_id(web, data):
    response = web.get('event', {b'last_ack_event_id': b'0'})
    result = response.result.json_value()
    expected = dict(
        latest_event_id=2,
        events=[
            dict(id=1, timestamp=123456.0, type='VERTEX_METADATA_CHANGED', data=data, group_id=None),
            dict(id=2, timestamp=123456.0, type='VERTEX_METADATA_CHANGED', data=data, group_id=None),
        ],
    )

    assert result == expected


def test_get_events_with_size_and_last_ack_event_id(web, data):
    response = web.get('event', {b'last_ack_event_id': b'0', b'size': b'1'})
    result = response.result.json_value()
    expected = dict(
        latest_event_id=2,
        events=[
            dict(id=1, timestamp=123456.0, type='VERTEX_METADATA_CHANGED', data=data, group_id=None),
        ],
    )

    assert result == expected
