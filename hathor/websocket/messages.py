# Copyright 2024 Hathor Labs
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

"""Pydantic models for Admin WebSocket messages.

This module defines all message types for the Admin WebSocket endpoint (/ws).
Messages are split into client commands (requests) and server events (responses).
"""

from typing import Annotated, Any, Literal, Optional, Union

from pydantic import Discriminator, Field, NonNegativeInt, RootModel, Tag

from hathor.utils.pydantic import BaseModel


# =============================================================================
# Base Classes
# =============================================================================


class WebSocketMessage(BaseModel):
    """Base class for all WebSocket messages."""
    pass


class WebSocketClientCommand(WebSocketMessage):
    """Base class for client-to-server commands."""
    pass


class WebSocketServerEvent(WebSocketMessage):
    """Base class for server-to-client events."""
    pass


# =============================================================================
# Client Commands (Requests)
# =============================================================================


class PingCommand(WebSocketClientCommand):
    """Ping command for connection keepalive.

    The server responds with a PongEvent.
    """
    type: Literal['ping'] = 'ping'


class SubscribeAddressCommand(WebSocketClientCommand):
    """Subscribe to receive notifications for a specific address.

    When subscribed, the client receives wallet:address_history, wallet:element_winner,
    and wallet:element_voided events for transactions involving this address.
    """
    type: Literal['subscribe_address'] = 'subscribe_address'
    address: str = Field(description='The address to subscribe to (base58 format)')


class UnsubscribeAddressCommand(WebSocketClientCommand):
    """Unsubscribe from address notifications."""
    type: Literal['unsubscribe_address'] = 'unsubscribe_address'
    address: str = Field(description='The address to unsubscribe from')


class HistoryXpubCommand(WebSocketClientCommand):
    """Request transaction history for an extended public key (xpub).

    Uses BIP44 derivation to generate addresses and streams their transaction history.
    """
    type: Literal['request:history:xpub'] = 'request:history:xpub'
    id: str = Field(description='Unique identifier for this history stream request')
    xpub: str = Field(description='Extended public key (BIP32)')
    gap_limit: Optional[NonNegativeInt] = Field(
        default=None,
        alias='gap-limit',
        description='Number of consecutive unused addresses before stopping derivation'
    )
    first_index: Optional[NonNegativeInt] = Field(
        default=None,
        alias='first-index',
        description='Starting address index for derivation'
    )
    window_size: Optional[NonNegativeInt] = Field(
        default=None,
        alias='window-size',
        description='Flow control window size (max pending items)'
    )


class HistoryManualCommand(WebSocketClientCommand):
    """Request transaction history for a list of addresses.

    Streams transaction history for the specified addresses.
    """
    type: Literal['request:history:manual'] = 'request:history:manual'
    id: str = Field(description='Unique identifier for this history stream request')
    addresses: list[str] = Field(description='List of addresses to get history for')
    first: Optional[bool] = Field(
        default=None,
        description='If true, include first unused address'
    )
    last: Optional[bool] = Field(
        default=None,
        description='If true, include last unused address'
    )
    gap_limit: Optional[NonNegativeInt] = Field(
        default=None,
        alias='gap-limit',
        description='Number of consecutive unused addresses before stopping'
    )
    window_size: Optional[NonNegativeInt] = Field(
        default=None,
        alias='window-size',
        description='Flow control window size'
    )


class HistoryStopCommand(WebSocketClientCommand):
    """Stop an active history streaming request."""
    type: Literal['request:history:stop'] = 'request:history:stop'
    id: str = Field(description='ID of the history stream to stop')


class HistoryAckCommand(WebSocketClientCommand):
    """Acknowledge received history items and adjust the sliding window.

    Used for flow control in history streaming.
    """
    type: Literal['request:history:ack'] = 'request:history:ack'
    id: str = Field(description='ID of the history stream')
    ack: Optional[NonNegativeInt] = Field(
        default=None,
        description='Sequence number of the last acknowledged item'
    )
    window: Optional[NonNegativeInt] = Field(
        default=None,
        description='New window size'
    )


# Discriminated union for all client commands
ClientCommand = Annotated[
    Union[
        Annotated[PingCommand, Tag('ping')],
        Annotated[SubscribeAddressCommand, Tag('subscribe_address')],
        Annotated[UnsubscribeAddressCommand, Tag('unsubscribe_address')],
        Annotated[HistoryXpubCommand, Tag('request:history:xpub')],
        Annotated[HistoryManualCommand, Tag('request:history:manual')],
        Annotated[HistoryStopCommand, Tag('request:history:stop')],
        Annotated[HistoryAckCommand, Tag('request:history:ack')],
    ],
    Discriminator('type')
]


class ClientCommandWrapper(RootModel[ClientCommand]):
    """Wrapper for parsing client commands."""

    @classmethod
    def parse_raw_command(cls, raw: bytes) -> ClientCommand:
        return cls.model_validate_json(raw).root


# =============================================================================
# Server Events (Responses)
# =============================================================================


class PongEvent(WebSocketServerEvent):
    """Response to a ping command."""
    type: Literal['pong'] = 'pong'


class WebSocketErrorMessage(WebSocketServerEvent):
    """Error message sent when a command fails."""
    type: Literal['error'] = 'error'
    success: Literal[False] = False
    errmsg: str = Field(description='Error message describing what went wrong')


class CapabilitiesMessage(WebSocketServerEvent):
    """Sent on connection to indicate server capabilities.

    Currently supported capabilities:
    - 'history-streaming': Server supports the request:history:* commands
    """
    type: Literal['capabilities'] = 'capabilities'
    capabilities: list[str] = Field(description='List of supported capability identifiers')


class SubscribeAddressResponse(WebSocketServerEvent):
    """Response to a subscribe_address command."""
    type: Literal['subscribe_address'] = 'subscribe_address'
    address: str = Field(description='The address that was subscribed to')
    success: bool = Field(description='Whether the subscription was successful')
    message: Optional[str] = Field(default=None, description='Optional status message')


class UnsubscribeAddressResponse(WebSocketServerEvent):
    """Response to an unsubscribe_address command."""
    type: Literal['unsubscribe_address'] = 'unsubscribe_address'
    success: bool = Field(description='Whether the unsubscription was successful')


# =============================================================================
# Dashboard Metrics Event
# =============================================================================


class DashboardMetricsEvent(WebSocketServerEvent):
    """Periodic broadcast of dashboard metrics to all connected clients.

    Sent every WS_SEND_METRICS_INTERVAL (default: 1 second).
    """
    type: Literal['dashboard:metrics'] = 'dashboard:metrics'
    transactions: int = Field(description='Total number of transactions')
    blocks: int = Field(description='Total number of blocks')
    best_block_height: int = Field(description='Height of the best block')
    hash_rate: float = Field(description='Current network hash rate')
    peers: int = Field(description='Number of connected peers')
    time: float = Field(description='Unix timestamp of the metrics')


# =============================================================================
# Network Events
# =============================================================================


class NetworkNewTxEvent(WebSocketServerEvent):
    """Broadcast when a new transaction or block is accepted by the network."""
    type: Literal['network:new_tx_accepted'] = 'network:new_tx_accepted'
    tx_id: str = Field(description='Transaction ID (hex)')
    timestamp: int = Field(description='Transaction timestamp')
    version: int = Field(description='Transaction version')
    weight: float = Field(description='Transaction weight')
    parents: list[str] = Field(description='Parent transaction IDs')
    inputs: list[dict[str, Any]] = Field(description='Transaction inputs')
    outputs: list[dict[str, Any]] = Field(description='Transaction outputs')
    tokens: list[str] = Field(default_factory=list, description='Token UIDs involved')
    is_block: bool = Field(description='Whether this is a block')
    first_block: Optional[str] = Field(default=None, description='First block that confirmed this tx')


# =============================================================================
# Wallet Events
# =============================================================================


class WalletOutputReceivedEvent(WebSocketServerEvent):
    """Sent when an output is received in the wallet."""
    type: Literal['wallet:output_received'] = 'wallet:output_received'
    output: dict[str, Any] = Field(description='The received output details')


class WalletInputSpentEvent(WebSocketServerEvent):
    """Sent when an output from the wallet is spent."""
    type: Literal['wallet:output_spent'] = 'wallet:output_spent'
    output_spent: dict[str, Any] = Field(description='The spent output details')


class WalletBalanceUpdatedEvent(WebSocketServerEvent):
    """Sent when the wallet balance changes."""
    type: Literal['wallet:balance_updated'] = 'wallet:balance_updated'
    balance: dict[str, int] = Field(
        description='Balance with available and locked amounts'
    )


class WalletAddressHistoryEvent(WebSocketServerEvent):
    """Sent to subscribed addresses when their history changes."""
    type: Literal['wallet:address_history'] = 'wallet:address_history'
    address: str = Field(description='The address whose history changed')
    history: list[dict[str, Any]] = Field(description='Updated history entries')


class WalletElementWinnerEvent(WebSocketServerEvent):
    """Sent when a transaction becomes the winner in a conflict."""
    type: Literal['wallet:element_winner'] = 'wallet:element_winner'
    tx_id: str = Field(description='Transaction ID that became winner')
    address: str = Field(description='Affected address')


class WalletElementVoidedEvent(WebSocketServerEvent):
    """Sent when a transaction is voided."""
    type: Literal['wallet:element_voided'] = 'wallet:element_voided'
    tx_id: str = Field(description='Transaction ID that was voided')
    address: str = Field(description='Affected address')


# =============================================================================
# History Streaming Messages
# =============================================================================


class StreamBase(WebSocketServerEvent):
    """Base class for history streaming messages."""
    pass


class StreamErrorMessage(StreamBase):
    """Sent when an error occurs during history streaming."""
    type: Literal['stream:history:error'] = 'stream:history:error'
    id: str = Field(description='Stream request ID')
    errmsg: str = Field(description='Error description')


class StreamBeginMessage(StreamBase):
    """Marks the beginning of a history stream."""
    type: Literal['stream:history:begin'] = 'stream:history:begin'
    id: str = Field(description='Stream request ID')
    seq: int = Field(description='Sequence number')
    window_size: Optional[int] = Field(
        default=None,
        description='Current window size for flow control'
    )


class StreamEndMessage(StreamBase):
    """Marks the end of a history stream."""
    type: Literal['stream:history:end'] = 'stream:history:end'
    id: str = Field(description='Stream request ID')
    seq: int = Field(description='Final sequence number')


class StreamVertexMessage(StreamBase):
    """Contains a transaction/block in the history stream."""
    type: Literal['stream:history:vertex'] = 'stream:history:vertex'
    id: str = Field(description='Stream request ID')
    seq: int = Field(description='Sequence number')
    data: dict[str, Any] = Field(description='Transaction data in JSON format')


class StreamAddressMessage(StreamBase):
    """Marks the beginning of history for a new address in the stream.

    Also implicitly marks the end of the previous address's history.
    """
    type: Literal['stream:history:address'] = 'stream:history:address'
    id: str = Field(description='Stream request ID')
    seq: int = Field(description='Sequence number')
    index: int = Field(description='Address index in the derivation/list')
    address: str = Field(description='The address (base58)')
    subscribed: bool = Field(description='Whether auto-subscribed to this address')
