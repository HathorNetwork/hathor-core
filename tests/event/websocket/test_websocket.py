import tempfile
from json import JSONDecodeError
from uuid import uuid4

import pytest
from twisted.internet.testing import StringTransport

from hathor.event.storage.event_storage import EventStorage
from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.event.storage.rocksdb_storage import EventRocksDBStorage
from hathor.event.websocket.event_streaming import EventStreaming
from hathor.event.websocket.factory import EventWebsocketFactory
from hathor.event.websocket.protocol import HathorEventWebsocketProtocol
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.util import json_loadb
from tests import unittest
from tests.resources.base_resource import _BaseResourceTest
from tests.utils import HAS_ROCKSDB, EventMocker


class BaseWebsocketTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self) -> None:
        super().setUp()
        self.event_mocker = EventMocker(self.rng)
        self.factory = EventWebsocketFactory(self.event_storage)
        self.factory.openHandshakeTimeout = 0
        self.protocol = self.factory.buildProtocol(uuid4())
        self.transport = StringTransport()
        self.protocol.makeConnection(self.transport)

    def set_storage(self, event_storage: EventStorage) -> None:
        self.event_storage = event_storage

    def test_get_from_storage_and_send(self):
        self._setup_event_streaming(0)

        for i in range(10):
            self.event_storage.save_event(self.event_mocker.generate_mocked_event(i))

        self.factory._send_events_to_subscribed_clients()
        expected_last_event = {
            'type': 'event',
            'data': {'id': 9, 'type': 'network:best_block_found', 'data': {'data': 'test'}}
        }
        actual_last_event = self._decode_value(self.transport.value())

        assert expected_last_event['type'] == actual_last_event['type']
        assert expected_last_event['data']['id'] == actual_last_event['data']['id']
        assert expected_last_event['data']['type'] == actual_last_event['data']['type']
        assert expected_last_event['data']['data'] == actual_last_event['data']['data']

    def test_subscribe_with_too_high_event_id(self):
        # User wants to stream from event 15, but only 10 events will be created in the storage
        self._setup_event_streaming(15)

        for i in range(10):
            self.event_storage.save_event(self.event_mocker.generate_mocked_event(i))

        self.factory._send_events_to_subscribed_clients()
        assert self.transport.value() == b''

    def test_subscribe_with_negative_event_id(self):
        for i in range(5):
            self.event_storage.save_event(self.event_mocker.generate_mocked_event(i))

        self.protocol.state = HathorEventWebsocketProtocol.STATE_OPEN
        self.factory.handle_message(self.protocol, b'{"type": "start_streaming_events", "event_id": "-5"}')
        result = self._decode_value(self.transport.value())

        assert result['type'] == 'start_streaming_events'
        assert result['success'] is False
        assert result['reason'] == 'event_id must be a positive integer number'

    def _setup_event_streaming(self, last_event):
        event_streaming = EventStreaming(self.protocol, last_event)

        connection_map = {
           self.protocol.id: event_streaming
        }

        self.factory.connections_to_stream_events = connection_map
        self.factory.connections.add(self.protocol)
        self.protocol.state = HathorEventWebsocketProtocol.STATE_OPEN

    def _decode_value(self, value):
        ret = None
        while value:
            try:
                ret = json_loadb(value)
                break
            except (UnicodeDecodeError, JSONDecodeError):
                value = value[1:]

        return ret


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class BaseRocksDBTest(BaseWebsocketTest):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        rocksdb_storage = RocksDBStorage(path=self.directory)
        self.set_storage(EventRocksDBStorage(rocksdb_storage))
        return super().setUp()


class BaseMemoryTest(BaseWebsocketTest):
    def setUp(self):
        self.set_storage(EventMemoryStorage())
        return super().setUp()


class RocksDBTestSy1ncV2(unittest.SyncV2Params, BaseRocksDBTest):
    __test__ = True


class MemoryStorageTestSyncV2(unittest.SyncV2Params, BaseMemoryTest):
    __test__ = True


class RocksDBTestSyncV1(unittest.SyncV1Params, BaseRocksDBTest):
    __test__ = True


class MemoryStorageTestSyncV1(unittest.SyncV1Params, BaseMemoryTest):
    __test__ = True
