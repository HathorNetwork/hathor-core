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


def _build_event_data(event: HathorEvents, event_args: EventArguments) -> Dict[str, Any]:
    """Extract and build event data from event_args for a given event type."""
    event_extract_fn = _EVENT_EXTRACT_MAP.get(event)
    if event_extract_fn is None:
        raise ValueError(f'The given event type ({event}) is not a supported event')
    return event_extract_fn(event_args)


def _assert_unclosed_event_group(last_event: BaseEvent):
    last_event_type = HathorEvents(last_event.type) if last_event is not None else None
    # XXX: we must check that the last event either does not belong to an event group or that it just closed an
    #      event group, because we cannot resume an open group of events that wasn't properly closed before exit
    assert (
        last_event is None or
        last_event.group_id is None or
        last_event_type in _GROUP_END_EVENTS
    ), 'an unclosed event group was detected, which indicates the node crashed, cannot resume'


class EventManager:
    def __init__(
        self,
        event_storage: EventStorage,
        event_ws_factory: EventWebsocketFactory,
        reactor: Reactor,
        peer_id: str
    ):
        self.log = logger.new()
        self.clock = reactor
        self.event_storage = event_storage
        self.event_ws_factory = event_ws_factory

        last_event = self.event_storage.get_last_event()
        last_group_id = self.event_storage.get_last_group_id()

        _assert_unclosed_event_group(last_event)

        self._next_event_id = 0 if last_event is None else last_event.id + 1
        self._next_group_id = 0 if last_group_id is None else last_group_id + 1
        self._current_group_id: Optional[int] = None
        self._peer_id = peer_id

    def subscribe(self, pubsub: PubSubManager) -> None:
        """ Subscribe to defined events for the pubsub received
        """
        for event in _SUBSCRIBE_EVENTS:
            pubsub.subscribe(event, self._handle_event)

    def _handle_event(self, event: HathorEvents, event_args: EventArguments) -> None:
        event_id = self._next_event_id
        group_id = self._current_group_id

        if event in _GROUP_START_EVENTS:
            assert self._current_group_id is None, 'A new event group cannot be started as one is already in progress.'
            group_id = self._next_group_id

        elif event in _GROUP_END_EVENTS:
            assert self._current_group_id is not None, 'Cannot end event group as none is in progress.'
            self._current_group_id = None

        base_event = BaseEvent(
            id=event_id,
            peer_id=self._peer_id,
            timestamp=self.clock.seconds(),
            type=event.value,
            data=_build_event_data(event, event_args),
            group_id=group_id,
        )

        self._persist_event(base_event)
        self._broadcast_event(base_event)

        self._next_event_id += 1

        if event in _GROUP_START_EVENTS:
            self._current_group_id = self._next_group_id
            self._next_group_id += 1

    def _persist_event(self, event: BaseEvent) -> None:
        self.event_storage.save_event(event)

    def _broadcast_event(self, event: BaseEvent) -> None:
        self.event_ws_factory.broadcast_event(event)
