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

from typing import Any, Callable, Dict, Optional

from structlog import get_logger

from hathor.event.base_event import BaseEvent
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
    HathorEvents.NETWORK_NEW_TX_VOIDED,
    HathorEvents.NETWORK_BEST_BLOCK_FOUND,
    HathorEvents.NETWORK_ORPHAN_BLOCK_FOUND,
    HathorEvents.LOAD_STARTED,
    HathorEvents.LOAD_FINISHED,
    HathorEvents.REORG_STARTED,
    HathorEvents.REORG_FINISHED,
    HathorEvents.TX_METADATA_CHANGED,
    HathorEvents.BLOCK_METADATA_CHANGED,
    HathorEvents.CONSENSUS_TX_UPDATE,
    HathorEvents.CONSENSUS_TX_REMOVED,
]


def _todo(args: EventArguments) -> Dict[str, Any]:
    raise NotImplementedError('TODO')


def _empty(args: EventArguments) -> Dict[str, Any]:
    return {}


def _extract_tx(args: EventArguments) -> Dict[str, Any]:
    return {
        'hash': args.tx.hash_hex,
        # TODO: other fields haven't been implemented, but will be before this feature is rolled out
    }


def _extract_reorg(args: EventArguments) -> Dict[str, Any]:
    return {
        'reorg_size': args.reorg_size,
        'previous_best_block': args.old_best_block.hash_hex,
        'new_best_block': args.new_best_block.hash_hex,
        'common_block': args.common_block.hash_hex,
    }


_EVENT_EXTRACT_MAP: Dict[HathorEvents, Callable[[EventArguments], Dict[str, Any]]] = {
    HathorEvents.LOAD_STARTED: _empty,
    HathorEvents.LOAD_FINISHED: _empty,
    HathorEvents.NETWORK_NEW_TX_ACCEPTED: _extract_tx,
    HathorEvents.NETWORK_NEW_TX_VOIDED: _extract_tx,
    HathorEvents.NETWORK_BEST_BLOCK_FOUND: _extract_tx,
    HathorEvents.NETWORK_ORPHAN_BLOCK_FOUND: _extract_tx,
    HathorEvents.REORG_STARTED: _extract_reorg,
    HathorEvents.REORG_FINISHED: _empty,
    HathorEvents.TX_METADATA_CHANGED: _todo,  # XXX: I'm considering removing this event
    HathorEvents.BLOCK_METADATA_CHANGED: _todo,  # XXX: I'm considering removing this event
    HathorEvents.CONSENSUS_TX_UPDATE: _extract_tx,
    HathorEvents.CONSENSUS_TX_REMOVED: _extract_tx,
}


def _build_event_data(event_type: HathorEvents, event_args: EventArguments) -> Dict[str, Any]:
    """Extract and build event data from event_args for a given event type."""
    event_extract_fn = _EVENT_EXTRACT_MAP.get(event_type)
    if event_extract_fn is None:
        raise ValueError(f'The given event type ({event_type}) is not a supported event')
    return event_extract_fn(event_args)


class EventManager:
    def __init__(
        self,
        event_storage: EventStorage,
        event_ws_factory: EventWebsocketFactory,
        pubsub: PubSubManager,
        reactor: Reactor,
        peer_id: str
    ):
        self.log = logger.new()

        self._clock = reactor
        self._event_storage = event_storage
        self._event_ws_factory = event_ws_factory
        self._pubsub = pubsub
        self._peer_id = peer_id

        self._last_event = self._event_storage.get_last_event()
        self._last_existing_group_id = self._event_storage.get_last_group_id()

        self._assert_closed_event_group()
        self._subscribe_events()

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
        return BaseEvent(
            id=0 if self._last_event is None else self._last_event.id + 1,
            peer_id=self._peer_id,
            timestamp=self._clock.seconds(),
            type=event_type.value,
            data=_build_event_data(event_type, event_args),
            group_id=group_id,
        )
