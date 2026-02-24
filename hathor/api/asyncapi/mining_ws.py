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

"""AsyncAPI channel definition and Pydantic models for Mining WebSocket.

The Mining WebSocket uses JSON-RPC 2.0 protocol for:
- Getting block templates for mining
- Submitting mined blocks
- Receiving notifications when new templates are available

Protocol: JSON-RPC 2.0 over WebSocket
"""

from typing import Any, Literal, Optional, Union

from pydantic import Field

from hathor.api.asyncapi.decorators import ws_message
from hathor.api.asyncapi.generator import ChannelDefinition, MessageDirection
from hathor.utils.pydantic import BaseModel


# =============================================================================
# JSON-RPC 2.0 Base Types
# =============================================================================


JsonRpcId = Union[str, int, float, None]


class JsonRpcRequest(BaseModel):
    """Base class for JSON-RPC 2.0 requests."""
    jsonrpc: Literal['2.0'] = '2.0'
    id: JsonRpcId = Field(description='Request identifier (null for notifications)')
    method: str = Field(description='Method name to call')


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 error object."""
    code: int = Field(description='Error code')
    message: str = Field(description='Error message')
    data: Optional[Any] = Field(default=None, description='Additional error data')


@ws_message(
    name='jsonRpcError',
    direction=MessageDirection.SEND,
    summary='JSON-RPC error response',
    description='Error response for failed requests.',
    tags=['error'],
)
class JsonRpcResponse(BaseModel):
    """JSON-RPC 2.0 response."""
    id: JsonRpcId = Field(description='Request identifier this is responding to')
    result: Optional[Any] = Field(default=None, description='Result on success')
    error: Optional[JsonRpcError] = Field(default=None, description='Error on failure')


class JsonRpcNotification(BaseModel):
    """JSON-RPC 2.0 notification (server-initiated, no id)."""
    id: Literal[None] = None
    method: str = Field(description='Notification method name')
    params: Optional[Any] = Field(default=None, description='Notification parameters')


# =============================================================================
# Block Template Schema
# =============================================================================


class BlockTemplateSchema(BaseModel):
    """Block template for mining.

    Contains all information needed to construct and mine a valid block.
    """
    data: str = Field(
        description='Hex-encoded serialized block without nonce (ready for mining)'
    )
    versions: list[int] = Field(
        description='Supported block versions'
    )
    reward: int = Field(
        description='Mining reward in smallest unit (1 HTR = 100 units)'
    )
    weight: float = Field(
        description='Target weight for the block (from DAA)'
    )
    timestamp_now: int = Field(
        description='Reference timestamp when template was generated'
    )
    timestamp_min: int = Field(
        description='Minimum valid timestamp for the block'
    )
    timestamp_max: int = Field(
        description='Maximum valid timestamp for the block'
    )
    parents: list[str] = Field(
        description='Required parent transaction/block IDs (hex)'
    )
    parents_any: list[str] = Field(
        description='Optional additional parents to choose from (hex)'
    )
    height: int = Field(
        description='Block height'
    )
    score: int = Field(
        description='Block score'
    )
    signal_bits: int = Field(
        description='Signal bits for feature activation'
    )


# =============================================================================
# Mining Request/Response Models
# =============================================================================


@ws_message(
    name='miningRefresh',
    direction=MessageDirection.RECEIVE,
    summary='Get current block templates',
    description='Request the current block template(s) for mining.',
    tags=['mining', 'request'],
)
class MiningRefreshRequest(JsonRpcRequest):
    """Request current block template(s) for mining.

    The server responds with a list of BlockTemplate objects.
    If the node is still syncing, returns an empty list.
    """
    method: Literal['mining.refresh'] = 'mining.refresh'
    params: list[Any] = Field(default_factory=list, description='Empty params list')


@ws_message(
    name='miningRefreshResponse',
    direction=MessageDirection.SEND,
    summary='Block templates response',
    description='Response containing current block template(s).',
    tags=['mining', 'response'],
)
class MiningRefreshResponse(JsonRpcResponse):
    """Response to mining.refresh request."""
    result: Optional[list[BlockTemplateSchema]] = Field(
        default=None,
        description='List of block templates (empty if node is syncing)'
    )


class MiningSubmitParams(BaseModel):
    """Parameters for mining.submit request."""
    hexdata: str = Field(description='Hex-encoded mined block')
    optimistic: bool = Field(
        default=False,
        description='If true, return new template immediately on success'
    )


@ws_message(
    name='miningSubmit',
    direction=MessageDirection.RECEIVE,
    summary='Submit mined block',
    description='Submit a mined block to the network.',
    tags=['mining', 'request'],
)
class MiningSubmitRequest(JsonRpcRequest):
    """Submit a mined block to the network.

    On success:
    - If `optimistic=false`: Returns `true`
    - If `optimistic=true`: Returns a new BlockTemplate based on the submitted block

    On failure: Returns `false` or an error
    """
    method: Literal['mining.submit'] = 'mining.submit'
    params: MiningSubmitParams


@ws_message(
    name='miningSubmitResponse',
    direction=MessageDirection.SEND,
    summary='Block submission result',
    description='Response indicating success/failure of block submission.',
    tags=['mining', 'response'],
)
class MiningSubmitResponse(JsonRpcResponse):
    """Response to mining.submit request."""
    result: Optional[Union[bool, BlockTemplateSchema]] = Field(
        default=None,
        description='True on success, or new template if optimistic=true'
    )


# =============================================================================
# Mining Notification Models
# =============================================================================


@ws_message(
    name='miningNotify',
    direction=MessageDirection.SEND,
    summary='New templates notification',
    description='Notification sent when new block templates are available.',
    tags=['mining', 'notification'],
)
class MiningNotifyNotification(JsonRpcNotification):
    """Server notification when new block templates are available.

    Sent to all connected miners when:
    - A new transaction/block is accepted
    - The template changes for any reason

    Miners should update their work to mine the new template.
    """
    method: Literal['mining.notify'] = 'mining.notify'
    params: list[BlockTemplateSchema] = Field(
        description='List of new block templates'
    )


# =============================================================================
# JSON-RPC Error Codes
# =============================================================================


class JsonRpcErrorCodes:
    """Standard JSON-RPC 2.0 error codes."""
    PARSE_ERROR = -32700  # Invalid JSON
    INVALID_REQUEST = -32600  # Not a valid request object
    METHOD_NOT_FOUND = -32601  # Method does not exist
    INVALID_PARAMS = -32602  # Invalid method parameters
    INTERNAL_ERROR = -32603  # Internal server error


# =============================================================================
# Channel Definition
# =============================================================================


def get_mining_ws_channel() -> ChannelDefinition:
    """Get the channel definition for the Mining WebSocket.

    Returns:
        ChannelDefinition with JSON-RPC 2.0 request/response messages.
    """
    return ChannelDefinition(
        channel_id='miningWs',
        address='/mining',
        title='Mining WebSocket',
        description='''
The Mining WebSocket implements a JSON-RPC 2.0 protocol for cryptocurrency mining.

## Protocol

All messages follow the JSON-RPC 2.0 specification:

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "<unique_id>",
  "method": "<method_name>",
  "params": <params>
}
```

**Response:**
```json
{
  "id": "<request_id>",
  "result": <result_value>,
  "error": null
}
```

**Notification (server-initiated):**
```json
{
  "id": null,
  "method": "<method_name>",
  "params": <params>
}
```

## Connection Flow

1. Connect to the mining WebSocket endpoint
2. If node is synced, server sends `mining.notify` notification with initial templates
3. Call `mining.refresh` to get current templates at any time
4. Receive `mining.notify` notifications when templates change
5. Call `mining.submit` to submit mined blocks

## Block Template

The block template contains:
- `data`: Pre-serialized block ready for nonce mining (hex)
- `weight`: Target difficulty from the DAA
- `timestamp_*`: Valid timestamp range
- `parents`: Required parent references
- `reward`: Mining reward amount

## Optimistic Mode

When submitting with `optimistic=true`, the response includes a new block
template based on the submitted block, allowing immediate continuation of mining.

## Error Handling

Standard JSON-RPC 2.0 error codes:
- `-32700`: Parse error (invalid JSON)
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error

Fatal errors will close the connection after sending the error response.
''',
        tags=['websocket', 'mining', 'json-rpc'],
        messages=[
            # Client Requests (Receive from client)
            MiningRefreshRequest,
            MiningSubmitRequest,
            # Server Responses/Notifications (Send to client)
            MiningRefreshResponse,
            MiningSubmitResponse,
            MiningNotifyNotification,
            JsonRpcResponse,
        ],
    )
