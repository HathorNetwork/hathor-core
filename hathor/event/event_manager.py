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

from typing import Callable, Iterator, Optional
from uuid import uuid4

from structlog import get_logger

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_type import EventType
from hathor.event.model.node_state import NodeState
from hathor.event.storage import EventStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.execution_manager import ExecutionManager
from hathor.nanocontracts.runner.index_records import CreateTokenRecord
from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import not_none, progress
from hathor.utils.iter import batch_iterator

logger = get_logger()

N_LOAD_EVENTS_PER_BATCH = 10_000

_GROUP_START_EVENTS = {
    EventType.REORG_STARTED,
}

_GROUP_END_EVENTS = {
    EventType.REORG_FINISHED,
}

_SUBSCRIBE_EVENTS = [
    HathorEvents.NETWORK_NEW_TX_ACCEPTED,
    HathorEvents.REORG_STARTED,
    HathorEvents.REORG_FINISHED,
    HathorEvents.CONSENSUS_TX_UPDATE,
    HathorEvents.CONSENSUS_TX_REMOVED,
    HathorEvents.NC_EVENT,
    HathorEvents.NC_EXEC_SUCCESS,
]


class EventManager:
    """Class that manages integration events.

    Events are received from PubSub, persisted on the storage and sent to WebSocket clients.
    """

    _peer_id: str
    _is_running: bool = False
    _previous_node_state: Optional[NodeState] = None
    _stream_id: Optional[str] = None
    _last_event: Optional[BaseEvent] = None
    _last_existing_group_id: Optional[int] = None

    @property
    def event_storage(self) -> EventStorage:
        return self._event_storage

    def __init__(
        self,
        event_storage: EventStorage,
        pubsub: PubSubManager,
        reactor: Reactor,
        execution_manager: ExecutionManager,
        event_ws_factory: Optional[EventWebsocketFactory] = None,
    ) -> None:
        self.log = logger.new()

        self._reactor = reactor
        self._event_storage = event_storage
        self._event_ws_factory = event_ws_factory
        self._pubsub = pubsub
        self._execution_manager = execution_manager

    def start(self, peer_id: str) -> None:
        """Starts the EventManager."""
        assert self._is_running is False, 'Cannot start, EventManager is already running'
        assert self._event_ws_factory is not None, 'Cannot start, EventWebsocketFactory is not set'
        assert self.get_event_queue_state() is True, 'Cannot start, event queue feature is disabled'

        self._execution_manager.register_on_crash_callback(self.on_full_node_crash)
        self._previous_node_state = self._event_storage.get_node_state()

        if self._should_reload_events():
            self._event_storage.reset_events()
            self._stream_id = str(uuid4())
            self._event_storage.save_stream_id(self._stream_id)
        else:
            self._last_event = self._event_storage.get_last_event()
            self._last_existing_group_id = self._event_storage.get_last_group_id()
            self._stream_id = not_none(self._event_storage.get_stream_id())

        self._assert_closed_event_group()
        self._subscribe_events()

        self._peer_id = peer_id
        self._event_ws_factory.start(stream_id=not_none(self._stream_id))
        self._is_running = True
        self.log.info('Starting Event Manager', stream_id=self._stream_id)

    def stop(self) -> None:
        """Stops the EventManager."""
        assert self._is_running is True, 'Cannot stop, EventManager is not running'
        assert self._event_ws_factory is not None

        self._event_ws_factory.stop()
        self._is_running = False

    def _assert_closed_event_group(self) -> None:
        # XXX: we must check that the last event either does not belong to an event group or that it just closed an
        #      event group, because we cannot resume an open group of events that wasn't properly closed before exit
        assert self._event_group_is_closed(), (
            'an unclosed event group was detected, which indicates the node crashed, cannot resume'
        )

    def _event_group_is_closed(self) -> bool:
        """Returns whether the previous event group was properly closed, if there's one."""
        return (
            self._last_event is None or
            self._last_event.group_id is None or
            EventType(self._last_event.type) in _GROUP_END_EVENTS
        )

    def _subscribe_events(self) -> None:
        """ Subscribe to defined events for the pubsub received
        """
        for event in _SUBSCRIBE_EVENTS:
            self._pubsub.subscribe(event, self._handle_hathor_event)

    def load_started(self) -> None:
        if not self._is_running:
            return

        self._handle_event(
            event_type=EventType.LOAD_STARTED,
            event_args=EventArguments(),
        )
        self._event_storage.save_node_state(NodeState.LOAD)

    def load_finished(self) -> None:
        if not self._is_running:
            return

        self._handle_event(
            event_type=EventType.LOAD_FINISHED,
            event_args=EventArguments(),
        )
        self._event_storage.save_node_state(NodeState.SYNC)

    def on_full_node_crash(self) -> None:
        if not self._is_running:
            return

        self._handle_event(
            event_type=EventType.FULL_NODE_CRASHED,
            event_args=EventArguments(),
        )

    def _handle_hathor_event(self, hathor_event: HathorEvents, event_args: EventArguments) -> None:
        """Handles a PubSub 'HathorEvents' event."""

        event_type = EventType.from_hathor_event(hathor_event)
        if event_type is not None:
            self._handle_event(event_type, event_args)

        if hathor_event == HathorEvents.NETWORK_NEW_TX_ACCEPTED:
            self._handle_token_creation_events(event_args)
        elif hathor_event == HathorEvents.NC_EXEC_SUCCESS:
            self._handle_nc_token_creation_events(event_args)

    def _handle_event(self, event_type: EventType, event_args: EventArguments) -> None:
        """Handles an Event Queue feature 'EventType' event."""
        assert self._is_running, 'Cannot handle event, EventManager is not started.'
        assert self._event_ws_factory is not None

        event = self._handle_event_creation(event_type, event_args)

        self._event_storage.save_event(event)
        self._event_ws_factory.broadcast_event(event)

        self._last_event = event

    def _handle_event_creation(self, event_type: EventType, event_args: EventArguments) -> BaseEvent:
        """Handles the creation of an event from PubSub's EventArguments, according to its EventType."""
        create_event_fn: Callable[[EventType, EventArguments], BaseEvent]

        if event_type in _GROUP_START_EVENTS:
            create_event_fn = self._create_group_start_event
        elif event_type in _GROUP_END_EVENTS:
            create_event_fn = self._create_group_end_event
        else:
            create_event_fn = self._create_non_group_edge_event

        event = create_event_fn(event_type, event_args)

        return event

    def _create_group_start_event(self, event_type: EventType, event_args: EventArguments) -> BaseEvent:
        """Creates a group start event."""
        assert self._event_group_is_closed(), 'A new event group cannot be started as one is already in progress.'

        new_group_id = 0 if self._last_existing_group_id is None else self._last_existing_group_id + 1

        self._last_existing_group_id = new_group_id

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=new_group_id,
        )

    def _create_group_end_event(self, event_type: EventType, event_args: EventArguments) -> BaseEvent:
        """Creates a group end event."""
        assert self._last_event is not None, 'Cannot end event group if there are no events.'
        assert not self._event_group_is_closed(), 'Cannot end event group as none is in progress.'

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=self._last_event.group_id,
        )

    def _create_non_group_edge_event(self, event_type: EventType, event_args: EventArguments) -> BaseEvent:
        """Creates an event that neither a start nor an end event."""
        group_id = None

        if not self._event_group_is_closed():
            assert self._last_event is not None, 'Cannot continue event group if there are no events.'
            group_id = self._last_event.group_id

        return self._create_event(
            event_type=event_type,
            event_args=event_args,
            group_id=group_id,
        )

    def _handle_token_creation_events(self, event_args: EventArguments) -> None:
        """Emit token-related events for accepted transactions."""
        tx = getattr(event_args, 'tx', None)
        if isinstance(tx, TokenCreationTransaction):
            assert tx.hash is not None
            token_event_args = EventArguments(
                tx=tx,
                token_uid=tx.hash_hex,
                token_name=tx.token_name,
                token_symbol=tx.token_symbol,
                token_version=tx.token_version,
                nc_exec_info=None,
            )

            self._handle_event(EventType.TOKEN_CREATED, token_event_args)

    def _handle_nc_token_creation_events(self, event_args: EventArguments) -> None:
        """Emit NC token-created events when a contract execution succeeds."""
        tx = getattr(event_args, 'tx', None)
        assert isinstance(tx, Transaction)
        assert tx.is_nano_contract()
        meta = tx.get_metadata()
        assert meta.nc_execution == NCExecutionState.SUCCESS
        self._emit_nc_token_created_events(tx, meta)

    def _emit_nc_token_created_events(
        self,
        tx: Transaction,
        meta: TransactionMetadata,
    ) -> None:
        if not meta.nc_calls:
            return
        assert tx.hash is not None
        tx_hash_hex = tx.hash_hex
        assert meta.first_block is not None
        first_block_hex = meta.first_block.hex()
        for call in meta.nc_calls:
            for record in call.index_updates:
                if not isinstance(record, CreateTokenRecord):
                    continue
                token_event_args = EventArguments(
                    tx=tx,
                    token_uid=record.token_uid.hex(),
                    token_name=record.token_name,
                    token_symbol=record.token_symbol,
                    token_version=record.token_version,
                    nc_exec_info={
                        'nc_tx': tx_hash_hex,
                        'nc_block': first_block_hex,
                    },
                )
                self._handle_event(EventType.TOKEN_CREATED, token_event_args)

    def _create_event(
        self,
        event_type: EventType,
        event_args: EventArguments,
        group_id: Optional[int],
    ) -> BaseEvent:
        """Actually creates a BaseEvent."""
        return BaseEvent.from_event_arguments(
            event_id=0 if self._last_event is None else self._last_event.id + 1,
            timestamp=self._reactor.seconds(),
            event_type=event_type,
            event_args=event_args,
            group_id=group_id,
        )

    def _should_reload_events(self) -> bool:
        """Returns whether events should be reloaded or not."""
        return self._previous_node_state in [None, NodeState.LOAD]

    def get_event_queue_state(self) -> bool:
        """Get whether the event queue feature is enabled from the storage."""
        return self._event_storage.get_event_queue_state()

    def save_event_queue_state(self, state: bool) -> None:
        """Saves whether the event queue feature is enabled from the storage."""
        self._event_storage.save_event_queue_state(state)

    def handle_load_phase_vertices(
        self,
        *,
        topological_iterator: Iterator[BaseTransaction],
        total_vertices: int
    ) -> None:
        """
        Either generates load phase events or not, depending on previous node state.
        Does so asynchronously so events generated here are not processed before normal event handling.
        """
        assert self._is_running, 'Cannot handle load phase events, EventManager is not started.'

        if not self._should_reload_events():
            return

        self.log.info('Started creating events from existing database...')
        event_iterator = self._create_event_iterator(topological_iterator, total_vertices)
        event_batches = batch_iterator(event_iterator, N_LOAD_EVENTS_PER_BATCH)

        for batch in event_batches:
            self._event_storage.save_events(batch)

        self.log.info('Finished creating events from existing database.')

    def _create_event_iterator(
        self,
        topological_iterator: Iterator[BaseTransaction],
        total_vertices: int
    ) -> Iterator[BaseEvent]:
        """Given a topological iterator of txs, create an iterator of events while also tracking progress and
        broadcasting them."""
        assert self._event_ws_factory is not None

        for vertex in progress(topological_iterator, log=self.log, total=total_vertices):
            event = self._handle_event_creation(
                event_type=EventType.NEW_VERTEX_ACCEPTED,
                event_args=EventArguments(tx=vertex)
            )

            yield event
            self._event_ws_factory.broadcast_event(event)
            self._last_event = event
