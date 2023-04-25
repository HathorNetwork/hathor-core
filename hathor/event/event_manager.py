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

from typing import Callable, Optional

from structlog import get_logger

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_type import EventType
from hathor.event.storage import EventStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor.util import Reactor

logger = get_logger()

_GROUP_START_EVENTS = {
    EventType.REORG_STARTED,
}

_GROUP_END_EVENTS = {
    EventType.REORG_FINISHED,
}

_SUBSCRIBE_EVENTS = [
    HathorEvents.MANAGER_ON_START,
    HathorEvents.LOAD_FINISHED,
    HathorEvents.NETWORK_NEW_TX_ACCEPTED,
    HathorEvents.REORG_STARTED,
    HathorEvents.REORG_FINISHED,
    HathorEvents.CONSENSUS_TX_UPDATE,
]


class EventManager:
    """Class that manages integration events.

    Events are received from PubSub, persisted on the storage and sent to WebSocket clients.
    """

    _peer_id: str
    _is_running: bool = False
    _load_finished: bool = False

    @property
    def event_storage(self) -> EventStorage:
        return self._event_storage

    def __init__(
        self,
        event_storage: EventStorage,
        event_ws_factory: EventWebsocketFactory,
        pubsub: PubSubManager,
        reactor: Reactor,
        emit_load_events: bool = False
    ):
        self.log = logger.new()

        self._clock = reactor
        self._event_storage = event_storage
        self._event_ws_factory = event_ws_factory
        self._pubsub = pubsub
        self.emit_load_events = emit_load_events

        self._last_event = self._event_storage.get_last_event()
        self._last_existing_group_id = self._event_storage.get_last_group_id()

        self._assert_closed_event_group()
        self._subscribe_events()

    def start(self, peer_id: str) -> None:
        assert self._is_running is False, 'Cannot start, EventManager is already running'

        self._peer_id = peer_id
        self._event_ws_factory.start()
        self._is_running = True

    def stop(self):
        assert self._is_running is True, 'Cannot stop, EventManager is not running'

        self._event_ws_factory.stop()
        self._is_running = False

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
            EventType(self._last_event.type) in _GROUP_END_EVENTS
        )

    def _subscribe_events(self):
        """ Subscribe to defined events for the pubsub received
        """
        for event in _SUBSCRIBE_EVENTS:
            self._pubsub.subscribe(event, self._handle_event)

    def _handle_event(self, hathor_event: HathorEvents, event_args: EventArguments) -> None:
        assert self._is_running, 'Cannot handle event, EventManager is not started.'

        event_type = EventType.from_hathor_event(hathor_event)
        event_specific_handlers = {
            EventType.LOAD_FINISHED: self._handle_load_finished
        }

        if event_specific_handler := event_specific_handlers.get(event_type):
            event_specific_handler()

        if not self._load_finished and not self.emit_load_events:
            return

        self._handle_event_creation(event_type, event_args)

    def _handle_event_creation(self, event_type: EventType, event_args: EventArguments) -> None:
        create_event_fn: Callable[[EventType, EventArguments], BaseEvent]

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

    def _create_group_start_event(self, event_type: EventType, event_args: EventArguments) -> BaseEvent:
        assert self._event_group_is_closed(), 'A new event group cannot be started as one is already in progress.'

        new_group_id = 0 if self._last_existing_group_id is None else self._last_existing_group_id + 1

        self._last_existing_group_id = new_group_id

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=new_group_id,
        )

    def _create_group_end_event(self, event_type: EventType, event_args: EventArguments) -> BaseEvent:
        assert self._last_event is not None, 'Cannot end event group if there are no events.'
        assert not self._event_group_is_closed(), 'Cannot end event group as none is in progress.'

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=self._last_event.group_id,
        )

    def _create_non_group_edge_event(self, event_type: EventType, event_args: EventArguments) -> BaseEvent:
        group_id = None

        if not self._event_group_is_closed():
            assert self._last_event is not None, 'Cannot continue event group if there are no events.'
            group_id = self._last_event.group_id

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=group_id,
        )

    def _handle_load_finished(self):
        self._load_finished = True

    def _create_event(
        self,
        event_type: EventType,
        event_args: EventArguments,
        group_id: Optional[int],
    ) -> BaseEvent:
        return BaseEvent.from_event_arguments(
            event_id=0 if self._last_event is None else self._last_event.id + 1,
            peer_id=self._peer_id,
            timestamp=self._clock.seconds(),
            event_type=event_type,
            event_args=event_args,
            group_id=group_id,
        )
