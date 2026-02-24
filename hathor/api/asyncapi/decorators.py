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

"""Decorator for annotating WebSocket message models with AsyncAPI metadata."""

from dataclasses import dataclass, field
from typing import Callable, TypeVar

from pydantic import BaseModel

from hathor.api.asyncapi.generator import MessageDirection

T = TypeVar('T', bound=type[BaseModel])


@dataclass(frozen=True)
class WsMessageMetadata:
    """Metadata for a WebSocket message model, stored by @ws_message."""
    name: str
    direction: MessageDirection
    summary: str
    description: str | None = None
    tags: list[str] = field(default_factory=list)


def ws_message(
    *,
    name: str,
    direction: MessageDirection,
    summary: str,
    description: str | None = None,
    tags: list[str] | None = None,
) -> Callable[[T], T]:
    """Decorator to attach AsyncAPI message metadata to a Pydantic model class.

    The metadata is stored as a ``_ws_message_meta`` class attribute and can be
    retrieved with :func:`get_ws_message_meta`.

    Args:
        name: Message name used in the AsyncAPI spec (e.g. 'ping', 'streamBegin').
        direction: Whether the message is sent or received (from the server's perspective).
        summary: Short summary of the message.
        description: Longer description (optional).
        tags: List of tag names (optional).
    """
    def decorator(cls: T) -> T:
        cls._ws_message_meta = WsMessageMetadata(  # type: ignore[attr-defined]
            name=name,
            direction=direction,
            summary=summary,
            description=description,
            tags=tags or [],
        )
        return cls

    return decorator  # type: ignore[return-value]


def get_ws_message_meta(cls: type[BaseModel]) -> WsMessageMetadata | None:
    """Retrieve the WsMessageMetadata attached by @ws_message, or None."""
    return getattr(cls, '_ws_message_meta', None)
