# Copyright 2022 Hathor Labs
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

from typing import Callable, Dict, Optional, Type

from structlog import get_logger

from hathor.event.base_event import BaseEvent, BaseEventData, EmptyData, ReorgData, TxData
from hathor.event.storage import EventStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor.util import Reactor

logger = get_logger()

_GROUP_START_EVENTS = {
    HathorEvents.REORG_STARTED,
}

_GROUP_END_EVENTS = {
    HathorEvents.REORG_FINISHED,
}

_SUBSCRIBE_EVENTS = [
    HathorEvents.NETWORK_NEW_TX_ACCEPTED,
    HathorEvents.NETWORK_BEST_BLOCK_FOUND,
    HathorEvents.NETWORK_ORPHAN_BLOCK_FOUND,
    HathorEvents.LOAD_STARTED,
    HathorEvents.LOAD_FINISHED,
    HathorEvents.REORG_STARTED,
    HathorEvents.REORG_FINISHED,
    HathorEvents.VERTEX_METADATA_CHANGED,
    HathorEvents.CONSENSUS_TX_UPDATE,
    HathorEvents.CONSENSUS_TX_REMOVED,
]

_EVENT_CONVERTER = {
    HathorEvents.CONSENSUS_TX_UPDATE: HathorEvents.VERTEX_METADATA_CHANGED
}


_EVENT_EXTRACT_MAP: Dict[HathorEvents, Type[BaseEventData]] = {
    HathorEvents.LOAD_STARTED: EmptyData,
    HathorEvents.LOAD_FINISHED: EmptyData,
    HathorEvents.NETWORK_NEW_TX_ACCEPTED: TxData,
    HathorEvents.NETWORK_BEST_BLOCK_FOUND: TxData,
    HathorEvents.NETWORK_ORPHAN_BLOCK_FOUND: TxData,
    HathorEvents.REORG_STARTED: ReorgData,
    HathorEvents.REORG_FINISHED: EmptyData,
    HathorEvents.VERTEX_METADATA_CHANGED: TxData,
    HathorEvents.CONSENSUS_TX_UPDATE: TxData,
    HathorEvents.CONSENSUS_TX_REMOVED: TxData,
}


class EventManager:
    """Class that manages integration events.

    Events are received from PubSub, persisted on the storage and sent to WebSocket clients.
    """

    _peer_id: str

    @property
    def event_storage(self) -> EventStorage:
        return self._event_storage

    def __init__(
        self,
        event_storage: EventStorage,
        event_ws_factory: EventWebsocketFactory,
        pubsub: PubSubManager,
        reactor: Reactor
    ):
        self.log = logger.new()

        self._clock = reactor
        self._event_storage = event_storage
        self._event_ws_factory = event_ws_factory
        self._pubsub = pubsub

        self._last_event = self._event_storage.get_last_event()
        self._last_existing_group_id = self._event_storage.get_last_group_id()

        self._assert_closed_event_group()
        self._subscribe_events()

    def start(self, peer_id: str) -> None:
        self._peer_id = peer_id
        self._event_ws_factory.start()

    def stop(self):
        self._event_ws_factory.stop()

    def _assert_closed_event_group(self):
        # XXX: we must check that the last event either does not belong to an event group or that it just closed an
        #      event group, because we cannot resume an open group of events that wasn't properly closed before exit
        assert (
            self._event_group_is_closed()
        ), 'an unclosed event group was detected, which indicates the node crashed, cannot resume'

    def _event_group_is_closed(self):
        return (
            self._last_event is None or
            self._last_event.group_id is None or
            HathorEvents(self._last_event.type) in _GROUP_END_EVENTS
        )

    def _subscribe_events(self):
        """ Subscribe to defined events for the pubsub received
        """
        for event in _SUBSCRIBE_EVENTS:
            self._pubsub.subscribe(event, self._handle_event)

    def _handle_event(self, event_type: HathorEvents, event_args: EventArguments) -> None:
        create_event_fn: Callable[[HathorEvents, EventArguments], BaseEvent]
        event_type = _EVENT_CONVERTER.get(event_type, event_type)

        if event_type in _GROUP_START_EVENTS:
            create_event_fn = self._create_group_start_event
        elif event_type in _GROUP_END_EVENTS:
            create_event_fn = self._create_group_end_event
        else:
            create_event_fn = self._create_non_group_edge_event

        event = create_event_fn(event_type, event_args)

        self._event_storage.save_event(event)
        self._event_ws_factory.broadcast_event(event)

        self._last_event = event

    def _create_group_start_event(self, event_type: HathorEvents, event_args: EventArguments) -> BaseEvent:
        assert self._event_group_is_closed(), 'A new event group cannot be started as one is already in progress.'

        new_group_id = 0 if self._last_existing_group_id is None else self._last_existing_group_id + 1

        self._last_existing_group_id = new_group_id

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=new_group_id,
        )

    def _create_group_end_event(self, event_type: HathorEvents, event_args: EventArguments) -> BaseEvent:
        assert self._last_event is not None, 'Cannot end event group if there are no events.'
        assert not self._event_group_is_closed(), 'Cannot end event group as none is in progress.'

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=self._last_event.group_id,
        )

    def _create_non_group_edge_event(self, event_type: HathorEvents, event_args: EventArguments) -> BaseEvent:
        group_id = None

        if not self._event_group_is_closed():
            assert self._last_event is not None, 'Cannot continue event group if there are no events.'
            group_id = self._last_event.group_id

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=group_id,
        )

    def _create_event(
        self,
        event_type: HathorEvents,
        event_args: EventArguments,
        group_id: Optional[int],
    ) -> BaseEvent:
        event_data_type = _EVENT_EXTRACT_MAP.get(event_type)

        if event_data_type is None:
            raise ValueError(f'The given event type ({event_type}) is not a supported event')

        return BaseEvent(
            id=0 if self._last_event is None else self._last_event.id + 1,
            peer_id=self._peer_id,
            timestamp=self._clock.seconds(),
            type=event_type.value,
            data=event_data_type.from_event_arguments(event_args),
            group_id=group_id,
        )
