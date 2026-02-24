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

"""AsyncAPI 3.0 specification generator from Pydantic models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Union

from pydantic import BaseModel

from hathor.api.schema_utils import SchemaRegistryMixin


class MessageDirection(Enum):
    """Direction of a WebSocket message."""
    RECEIVE = 'receive'  # Client -> Server
    SEND = 'send'  # Server -> Client


@dataclass
class MessageDefinition:
    """Definition of a WebSocket message."""
    name: str
    model: type[BaseModel]
    direction: MessageDirection
    summary: str
    description: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class ChannelDefinition:
    """Definition of a WebSocket channel (endpoint).

    The ``messages`` list can contain either:
    - ``MessageDefinition`` instances (explicit metadata), or
    - Pydantic model classes decorated with ``@ws_message`` (metadata read from decorator).
    """
    channel_id: str
    address: str
    title: str
    description: str
    messages: list[Union[MessageDefinition, type[BaseModel]]] = field(default_factory=list)
    protocol: str = 'ws'
    tags: list[str] = field(default_factory=list)


class AsyncAPIGenerator(SchemaRegistryMixin):
    """Generates AsyncAPI 3.0 specification from channel definitions.

    This generator collects channel and message definitions and produces
    a complete AsyncAPI 3.0 specification for WebSocket APIs.
    """

    def __init__(
        self,
        title: str = 'Hathor WebSocket API',
        version: str = '0.69.0',
        description: str = 'WebSocket APIs for Hathor full node',
    ) -> None:
        self.title = title
        self.version = version
        self.description = description
        self._channels: list[ChannelDefinition] = []
        self._schemas: dict[str, Any] = {}

    def add_channel(self, channel: ChannelDefinition) -> None:
        """Register a channel definition."""
        self._channels.append(channel)

    @staticmethod
    def _resolve_message(entry: MessageDefinition | type[BaseModel]) -> MessageDefinition:
        """Convert a channel message entry to a MessageDefinition.

        If the entry is already a MessageDefinition, return it as-is.
        If it's a model class decorated with @ws_message, build a MessageDefinition from its metadata.
        """
        if isinstance(entry, MessageDefinition):
            return entry

        from hathor.api.asyncapi.decorators import get_ws_message_meta

        meta = get_ws_message_meta(entry)
        if meta is None:
            raise ValueError(
                f"Model class {entry.__name__} passed to ChannelDefinition.messages "
                f"but is not decorated with @ws_message"
            )
        return MessageDefinition(
            name=meta.name,
            model=entry,
            direction=meta.direction,
            summary=meta.summary,
            description=meta.description,
            tags=list(meta.tags),
        )

    def _build_message(self, msg: MessageDefinition) -> dict[str, Any]:
        """Build an AsyncAPI message object."""
        message: dict[str, Any] = {
            'name': msg.name,
            'summary': msg.summary,
            'payload': self._get_schema_ref(msg.model),
        }
        if msg.description:
            message['description'] = msg.description
        if msg.tags:
            message['tags'] = [{'name': tag} for tag in msg.tags]
        return message

    def _build_channel(self, channel: ChannelDefinition) -> tuple[dict[str, Any], list[MessageDefinition]]:
        """Build an AsyncAPI channel object.

        Returns:
            Tuple of (channel_obj, resolved_messages).
        """
        channel_obj: dict[str, Any] = {
            'address': channel.address,
            'title': channel.title,
            'description': channel.description,
            'messages': {},
        }

        resolved: list[MessageDefinition] = []
        for entry in channel.messages:
            msg = self._resolve_message(entry)
            resolved.append(msg)
            channel_obj['messages'][msg.name] = self._build_message(msg)

        if channel.tags:
            channel_obj['tags'] = [{'name': tag} for tag in channel.tags]

        return channel_obj, resolved

    def _build_operations(self, channel: ChannelDefinition, messages: list[MessageDefinition]) -> dict[str, Any]:
        """Build AsyncAPI operations for a channel."""
        operations: dict[str, Any] = {}

        # Group messages by direction
        receive_msgs = [m for m in messages if m.direction == MessageDirection.RECEIVE]
        send_msgs = [m for m in messages if m.direction == MessageDirection.SEND]

        if receive_msgs:
            operations[f'{channel.channel_id}Receive'] = {
                'action': 'receive',
                'channel': {'$ref': f'#/channels/{channel.channel_id}'},
                'summary': f'Receive messages from client on {channel.title}',
                'messages': [
                    {'$ref': f'#/channels/{channel.channel_id}/messages/{m.name}'}
                    for m in receive_msgs
                ],
            }

        if send_msgs:
            operations[f'{channel.channel_id}Send'] = {
                'action': 'send',
                'channel': {'$ref': f'#/channels/{channel.channel_id}'},
                'summary': f'Send messages to client on {channel.title}',
                'messages': [
                    {'$ref': f'#/channels/{channel.channel_id}/messages/{m.name}'}
                    for m in send_msgs
                ],
            }

        return operations

    def generate(self) -> dict[str, Any]:
        """Generate the complete AsyncAPI specification.

        Returns:
            AsyncAPI 3.0 specification as a dictionary.
        """
        # Reset schemas for fresh generation
        self._schemas = {}

        # Build channels
        channels: dict[str, Any] = {}
        operations: dict[str, Any] = {}

        for channel in self._channels:
            channel_obj, resolved_msgs = self._build_channel(channel)
            channels[channel.channel_id] = channel_obj
            operations.update(self._build_operations(channel, resolved_msgs))

        # Build complete spec
        spec: dict[str, Any] = {
            'asyncapi': '3.0.0',
            'info': {
                'title': self.title,
                'version': self.version,
                'description': self.description,
            },
            'channels': channels,
            'operations': operations,
        }

        # Add components/schemas if any were registered
        if self._schemas:
            spec['components'] = {'schemas': self._flatten_schemas()}

        return spec


def create_hathor_asyncapi_generator() -> AsyncAPIGenerator:
    """Create and configure an AsyncAPIGenerator with all Hathor WebSocket channels.

    Returns:
        Configured AsyncAPIGenerator with admin, event, and mining channels.
    """
    from hathor.api.asyncapi.admin_ws import get_admin_ws_channel
    from hathor.api.asyncapi.event_ws import get_event_ws_channel
    from hathor.api.asyncapi.mining_ws import get_mining_ws_channel

    generator = AsyncAPIGenerator()
    generator.add_channel(get_admin_ws_channel())
    generator.add_channel(get_event_ws_channel())
    generator.add_channel(get_mining_ws_channel())

    return generator
