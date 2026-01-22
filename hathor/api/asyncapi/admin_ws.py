#  Copyright 2026 Hathor Labs
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

"""AsyncAPI channel definition for Admin WebSocket (/ws).

The Admin WebSocket provides:
- Real-time dashboard metrics
- Address subscription for wallet notifications
- Transaction history streaming (xpub and manual address lists)
- Network events (new transactions/blocks)

Protocol: Custom JSON messages over WebSocket
Path: /ws
"""

from hathor.api.asyncapi.generator import ChannelDefinition, MessageDefinition, MessageDirection
from hathor.websocket.messages import (
    CapabilitiesMessage,
    DashboardMetricsEvent,
    HistoryAckCommand,
    HistoryManualCommand,
    HistoryStopCommand,
    HistoryXpubCommand,
    NetworkNewTxEvent,
    PingCommand,
    PongEvent,
    StreamAddressMessage,
    StreamBeginMessage,
    StreamEndMessage,
    StreamErrorMessage,
    StreamVertexMessage,
    SubscribeAddressCommand,
    SubscribeAddressResponse,
    UnsubscribeAddressCommand,
    UnsubscribeAddressResponse,
    WalletAddressHistoryEvent,
    WalletBalanceUpdatedEvent,
    WalletElementVoidedEvent,
    WalletElementWinnerEvent,
    WalletInputSpentEvent,
    WalletOutputReceivedEvent,
    WebSocketErrorMessage,
)


def get_admin_ws_channel() -> ChannelDefinition:
    """Get the channel definition for the Admin WebSocket.

    Returns:
        ChannelDefinition with all client commands and server events.
    """
    return ChannelDefinition(
        channel_id='adminWs',
        address='/ws',
        title='Admin WebSocket',
        description='''
The Admin WebSocket provides real-time data streaming for:

- **Dashboard Metrics**: Periodic broadcasts of network statistics
- **Address Subscriptions**: Subscribe to wallet notifications for specific addresses
- **History Streaming**: Stream transaction history for xpub keys or address lists
- **Network Events**: Real-time notifications for new transactions and blocks

## Connection Flow

1. Connect to `ws://<host>:<port>/ws`
2. Server sends `capabilities` message listing supported features
3. Client can send commands and receive events

## Capabilities

- `history-streaming`: Indicates support for `request:history:*` commands

## Flow Control (History Streaming)

History streaming uses a sliding window for flow control:
1. Client sends `request:history:xpub` or `request:history:manual` with `window-size`
2. Server sends items up to the window size
3. Client sends `request:history:ack` to acknowledge items and adjust window
4. Client can send `request:history:stop` to cancel the stream
''',
        tags=['websocket', 'admin', 'realtime'],
        messages=[
            # =====================================================================
            # Client Commands (Receive from client)
            # =====================================================================
            MessageDefinition(
                name='ping',
                model=PingCommand,
                direction=MessageDirection.RECEIVE,
                summary='Connection keepalive ping',
                description='Send to check connection liveness. Server responds with pong.',
                tags=['keepalive'],
            ),
            MessageDefinition(
                name='subscribeAddress',
                model=SubscribeAddressCommand,
                direction=MessageDirection.RECEIVE,
                summary='Subscribe to address notifications',
                description='Subscribe to receive wallet events for a specific address.',
                tags=['subscription'],
            ),
            MessageDefinition(
                name='unsubscribeAddress',
                model=UnsubscribeAddressCommand,
                direction=MessageDirection.RECEIVE,
                summary='Unsubscribe from address notifications',
                description='Stop receiving wallet events for a specific address.',
                tags=['subscription'],
            ),
            MessageDefinition(
                name='historyXpub',
                model=HistoryXpubCommand,
                direction=MessageDirection.RECEIVE,
                summary='Request history for xpub key',
                description='Stream transaction history for addresses derived from an extended public key.',
                tags=['history-streaming'],
            ),
            MessageDefinition(
                name='historyManual',
                model=HistoryManualCommand,
                direction=MessageDirection.RECEIVE,
                summary='Request history for address list',
                description='Stream transaction history for a manually specified list of addresses.',
                tags=['history-streaming'],
            ),
            MessageDefinition(
                name='historyStop',
                model=HistoryStopCommand,
                direction=MessageDirection.RECEIVE,
                summary='Stop history streaming',
                description='Cancel an active history streaming request.',
                tags=['history-streaming'],
            ),
            MessageDefinition(
                name='historyAck',
                model=HistoryAckCommand,
                direction=MessageDirection.RECEIVE,
                summary='Acknowledge history items',
                description='Acknowledge received items and optionally adjust the flow control window.',
                tags=['history-streaming'],
            ),

            # =====================================================================
            # Server Events (Send to client)
            # =====================================================================
            MessageDefinition(
                name='pong',
                model=PongEvent,
                direction=MessageDirection.SEND,
                summary='Connection keepalive pong',
                description='Response to a ping command.',
                tags=['keepalive'],
            ),
            MessageDefinition(
                name='error',
                model=WebSocketErrorMessage,
                direction=MessageDirection.SEND,
                summary='Error message',
                description='Sent when a command fails or an error occurs.',
                tags=['error'],
            ),
            MessageDefinition(
                name='capabilities',
                model=CapabilitiesMessage,
                direction=MessageDirection.SEND,
                summary='Server capabilities',
                description='Sent on connection to indicate supported features.',
                tags=['connection'],
            ),
            MessageDefinition(
                name='subscribeAddressResponse',
                model=SubscribeAddressResponse,
                direction=MessageDirection.SEND,
                summary='Subscription response',
                description='Response to a subscribe_address command.',
                tags=['subscription'],
            ),
            MessageDefinition(
                name='unsubscribeAddressResponse',
                model=UnsubscribeAddressResponse,
                direction=MessageDirection.SEND,
                summary='Unsubscription response',
                description='Response to an unsubscribe_address command.',
                tags=['subscription'],
            ),

            # Dashboard Metrics
            MessageDefinition(
                name='dashboardMetrics',
                model=DashboardMetricsEvent,
                direction=MessageDirection.SEND,
                summary='Dashboard metrics broadcast',
                description='Periodic broadcast of network statistics to all connected clients.',
                tags=['metrics', 'broadcast'],
            ),

            # Network Events
            MessageDefinition(
                name='networkNewTx',
                model=NetworkNewTxEvent,
                direction=MessageDirection.SEND,
                summary='New transaction/block accepted',
                description='Broadcast when a new transaction or block is accepted by the network.',
                tags=['network', 'broadcast'],
            ),

            # Wallet Events
            MessageDefinition(
                name='walletOutputReceived',
                model=WalletOutputReceivedEvent,
                direction=MessageDirection.SEND,
                summary='Wallet output received',
                description='Sent when an output is received in the wallet.',
                tags=['wallet'],
            ),
            MessageDefinition(
                name='walletInputSpent',
                model=WalletInputSpentEvent,
                direction=MessageDirection.SEND,
                summary='Wallet output spent',
                description='Sent when an output from the wallet is spent.',
                tags=['wallet'],
            ),
            MessageDefinition(
                name='walletBalanceUpdated',
                model=WalletBalanceUpdatedEvent,
                direction=MessageDirection.SEND,
                summary='Wallet balance changed',
                description='Sent when the wallet balance changes.',
                tags=['wallet'],
            ),
            MessageDefinition(
                name='walletAddressHistory',
                model=WalletAddressHistoryEvent,
                direction=MessageDirection.SEND,
                summary='Address history updated',
                description='Sent to subscribed addresses when their history changes.',
                tags=['wallet', 'subscription'],
            ),
            MessageDefinition(
                name='walletElementWinner',
                model=WalletElementWinnerEvent,
                direction=MessageDirection.SEND,
                summary='Transaction became winner',
                description='Sent when a transaction becomes the winner in a conflict.',
                tags=['wallet', 'subscription'],
            ),
            MessageDefinition(
                name='walletElementVoided',
                model=WalletElementVoidedEvent,
                direction=MessageDirection.SEND,
                summary='Transaction voided',
                description='Sent when a transaction is voided.',
                tags=['wallet', 'subscription'],
            ),

            # History Streaming Events
            MessageDefinition(
                name='streamBegin',
                model=StreamBeginMessage,
                direction=MessageDirection.SEND,
                summary='History stream started',
                description='Marks the beginning of a history stream.',
                tags=['history-streaming'],
            ),
            MessageDefinition(
                name='streamEnd',
                model=StreamEndMessage,
                direction=MessageDirection.SEND,
                summary='History stream ended',
                description='Marks the end of a history stream.',
                tags=['history-streaming'],
            ),
            MessageDefinition(
                name='streamAddress',
                model=StreamAddressMessage,
                direction=MessageDirection.SEND,
                summary='New address in stream',
                description='Marks the beginning of history for a new address in the stream.',
                tags=['history-streaming'],
            ),
            MessageDefinition(
                name='streamVertex',
                model=StreamVertexMessage,
                direction=MessageDirection.SEND,
                summary='Transaction in stream',
                description='Contains a transaction or block in the history stream.',
                tags=['history-streaming'],
            ),
            MessageDefinition(
                name='streamError',
                model=StreamErrorMessage,
                direction=MessageDirection.SEND,
                summary='Stream error',
                description='Sent when an error occurs during history streaming.',
                tags=['history-streaming', 'error'],
            ),
        ],
    )
