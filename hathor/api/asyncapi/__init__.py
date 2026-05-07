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
