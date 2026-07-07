# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""AsyncAPI specification generator for WebSocket APIs.

This module provides tools for generating AsyncAPI 3.0 specifications
from Pydantic models, documenting the three WebSocket endpoints:

- Admin WebSocket (/ws): Dashboard metrics, address subscriptions, history streaming
- Event WebSocket (/event_ws): Event streaming with flow control
- Mining WebSocket: JSON-RPC 2.0 mining protocol

Usage:
    from hathor.api.asyncapi import AsyncAPIGenerator

    generator = AsyncAPIGenerator()
    spec = generator.generate()
"""

from hathor.api.asyncapi.generator import AsyncAPIGenerator

__all__ = ['AsyncAPIGenerator']
