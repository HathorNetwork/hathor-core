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

"""OpenAPI specification generation utilities."""

from hathor.api.openapi.decorators import api_endpoint, clear_endpoint_registry, get_endpoint_registry
from hathor.api.openapi.generator import OpenAPIGenerator

__all__ = [
    'api_endpoint',
    'clear_endpoint_registry',
    'get_endpoint_registry',
    'OpenAPIGenerator',
]
