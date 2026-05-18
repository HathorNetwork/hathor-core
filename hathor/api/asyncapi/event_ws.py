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

"""AsyncAPI channel definition for Event WebSocket (/event_ws).

The Event WebSocket provides:
- Reliable event streaming with flow control
- Full node events (transactions, blocks, reorgs, nano contracts)
- Event persistence and replay from a specific event ID

Protocol: Custom JSON messages over WebSocket with sliding window flow control
Path: /event_ws
"""

from hathor.api.asyncapi.generator import ChannelDefinition
from hathor.event.websocket.request import AckRequest, StartStreamRequest, StopStreamRequest
from hathor.event.websocket.response import EventResponse, InvalidRequestResponse


def get_event_ws_channel() -> ChannelDefinition:
    """Get the channel definition for the Event WebSocket.

    Returns:
        ChannelDefinition with all client commands and server events.
    """
    return ChannelDefinition(
        channel_id='eventWs',
        address='/event_ws',
        title='Event WebSocket',
        description='''
The Event WebSocket provides reliable event streaming with flow control.

## Event Types

Events are typed and include full transaction/block data:

- `LOAD_STARTED` / `LOAD_FINISHED`: Node loading lifecycle
- `NEW_VERTEX_ACCEPTED`: New transaction or block accepted
- `VERTEX_METADATA_CHANGED`: Transaction metadata updated (confirmations, etc.)
- `VERTEX_REMOVED`: Transaction removed from DAG
- `REORG_STARTED` / `REORG_FINISHED`: Chain reorganization events
- `NC_EVENT`: Nano contract event emitted
- `TOKEN_CREATED`: New token created
- `FULL_NODE_CRASHED`: Node crash notification

## Connection Flow

1. Connect to `ws://<host>:<port>/event_ws`
2. Send `START_STREAM` with `last_ack_event_id` (or null for beginning) and `window_size`
3. Receive `EVENT` messages up to the window size
4. Send `ACK` to acknowledge events and adjust window
5. Send `STOP_STREAM` to pause streaming

## Flow Control

The sliding window mechanism ensures reliable delivery:

1. **window_size**: Maximum pending (unacknowledged) events
2. **ack_event_id**: Last event ID successfully processed by client
3. Server won't send more events until client ACKs, keeping pending <= window_size

## Event Ordering

Events are assigned sequential IDs (`event.id`) that determine total order.
Events may be grouped (`group_id`) for related events (e.g., reorg events).

## Replay

To resume from a previous position, send `START_STREAM` with `last_ack_event_id`
set to the last successfully processed event ID.
''',
        tags=['websocket', 'events', 'streaming'],
        messages=[
            # Client Commands (Receive from client)
            StartStreamRequest,
            AckRequest,
            StopStreamRequest,
            # Server Events (Send to client)
            EventResponse,
            InvalidRequestResponse,
        ],
    )
