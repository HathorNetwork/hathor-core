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

from hathor.api.asyncapi.generator import ChannelDefinition
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
            # Client Commands (Receive from client)
            PingCommand,
            SubscribeAddressCommand,
            UnsubscribeAddressCommand,
            HistoryXpubCommand,
            HistoryManualCommand,
            HistoryStopCommand,
            HistoryAckCommand,
            # Server Events (Send to client)
            PongEvent,
            WebSocketErrorMessage,
            CapabilitiesMessage,
            SubscribeAddressResponse,
            UnsubscribeAddressResponse,
            DashboardMetricsEvent,
            NetworkNewTxEvent,
            WalletOutputReceivedEvent,
            WalletInputSpentEvent,
            WalletBalanceUpdatedEvent,
            WalletAddressHistoryEvent,
            WalletElementWinnerEvent,
            WalletElementVoidedEvent,
            StreamBeginMessage,
            StreamEndMessage,
            StreamAddressMessage,
            StreamVertexMessage,
            StreamErrorMessage,
        ],
    )
