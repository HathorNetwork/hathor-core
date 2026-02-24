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

"""OpenAPI 3.1 specification generator from Pydantic models."""

import typing
from collections import defaultdict
from typing import Any

from pydantic import BaseModel

from hathor.api.openapi.decorators import EndpointMetadata, get_endpoint_registry
from hathor.api.schema_utils import SchemaRegistryMixin


class OpenAPIGenerator(SchemaRegistryMixin):
    """Generates OpenAPI 3.1 specification from registered endpoints.

    This generator collects metadata from @api_endpoint decorated methods
    and generates a complete OpenAPI specification.
    """

    def __init__(
        self,
        title: str = 'Hathor Core API',
        version: str = '0.69.0',
        description: str = 'REST API for Hathor full node',
    ) -> None:
        self.title = title
        self.version = version
        self.description = description
        self._schemas: dict[str, Any] = {}

    def _build_parameters(self, metadata: EndpointMetadata) -> list[dict[str, Any]]:
        """Build OpenAPI parameters from query params model and path params."""
        parameters: list[dict[str, Any]] = []

        # Add path parameters from path_params_regex
        for param_name, regex in metadata.path_params_regex.items():
            param: dict[str, Any] = {
                'name': param_name,
                'in': 'path',
                'required': True,
                'schema': {'type': 'string', 'pattern': regex},
            }
            if param_name in metadata.path_params_descriptions:
                param['description'] = metadata.path_params_descriptions[param_name]
            parameters.append(param)

        # Add query parameters from Pydantic model
        if metadata.query_params_model:
            schema = metadata.query_params_model.model_json_schema()
            properties = schema.get('properties', {})
            required_fields = set(schema.get('required', []))

            for field_name, field_schema in properties.items():
                query_param: dict[str, Any] = {
                    'name': field_name,
                    'in': 'query',
                    'required': field_name in required_fields,
                    'schema': field_schema,
                }
                if 'description' in field_schema:
                    query_param['description'] = field_schema['description']
                parameters.append(query_param)

        return parameters

    def _build_request_body(self, metadata: EndpointMetadata) -> dict[str, Any] | None:
        """Build OpenAPI requestBody from request model."""
        if not metadata.request_model:
            return None

        return {
            'required': True,
            'content': {
                'application/json': {
                    'schema': self._get_schema_ref(metadata.request_model),
                },
            },
        }

    def _get_response_models(self, metadata: EndpointMetadata) -> list[type[BaseModel]]:
        """Extract individual response models from response_model (handles Union types)."""
        if metadata.response_model is None:
            return []

        # Check if it's a Union type
        args = typing.get_args(metadata.response_model)
        if args:
            return list(args)

        # Single model
        return [metadata.response_model]

    def _build_responses(self, metadata: EndpointMetadata) -> dict[str, Any]:
        """Build OpenAPI responses section.

        Reads http_status_code from each response model's ClassVar and groups
        by status code. If multiple models share a status code, uses oneOf.
        """
        models = self._get_response_models(metadata)

        if not models:
            return {'200': {'description': 'Success'}}

        # Group models by their http_status_code
        by_status: dict[int, list[type[BaseModel]]] = defaultdict(list)
        for model in models:
            status_code = getattr(model, 'http_status_code', 200)
            by_status[status_code].append(model)

        responses: dict[str, Any] = {}
        for status_code, status_models in sorted(by_status.items()):
            if len(status_models) == 1:
                schema = self._get_schema_ref(status_models[0])
            else:
                schema = {
                    'oneOf': [self._get_schema_ref(m) for m in status_models],
                }

            # Use response_description from the first model that has one, else default
            description: str | None = None
            examples: dict[str, Any] = {}
            for model in status_models:
                model_desc = getattr(model, 'response_description', None)
                if description is None and model_desc:
                    description = model_desc
                model_examples = getattr(model, 'openapi_examples', None)
                if model_examples:
                    for name, example in model_examples.items():
                        examples[name] = {
                            'summary': example.summary,
                            'value': example.value.model_dump(mode='json'),
                        }

            if description is None:
                description = 'Success' if status_code == 200 else 'Error'

            media_type: dict[str, Any] = {'schema': schema}
            if examples:
                media_type['examples'] = examples

            responses[str(status_code)] = {
                'description': description,
                'content': {
                    'application/json': media_type,
                },
            }

        return responses

    def _build_operation(self, metadata: EndpointMetadata) -> dict[str, Any]:
        """Build an OpenAPI operation object."""
        operation: dict[str, Any] = {
            'operationId': metadata.operation_id,
            'summary': metadata.summary,
        }

        if metadata.description:
            operation['description'] = metadata.description

        if metadata.tags:
            operation['tags'] = metadata.tags

        if metadata.deprecated:
            operation['deprecated'] = True

        # Parameters
        parameters = self._build_parameters(metadata)
        if parameters:
            operation['parameters'] = parameters

        # Request body
        request_body = self._build_request_body(metadata)
        if request_body:
            operation['requestBody'] = request_body

        # Responses
        operation['responses'] = self._build_responses(metadata)

        return operation

    def _build_path_item(self, metadata: EndpointMetadata) -> dict[str, Any]:
        """Build an OpenAPI path item with extensions."""
        path_item: dict[str, Any] = {}

        # Add visibility extension
        path_item['x-visibility'] = metadata.visibility

        # Add rate limit extension
        if metadata.rate_limit_global or metadata.rate_limit_per_ip:
            rate_limit: dict[str, Any] = {}
            if metadata.rate_limit_global:
                rate_limit['global'] = [
                    {'rate': rl.rate, 'burst': rl.burst, 'delay': rl.delay}
                    for rl in metadata.rate_limit_global
                ]
            if metadata.rate_limit_per_ip:
                rate_limit['per-ip'] = [
                    {'rate': rl.rate, 'burst': rl.burst, 'delay': rl.delay}
                    for rl in metadata.rate_limit_per_ip
                ]
            path_item['x-rate-limit'] = rate_limit

        # Add path params regex extension
        if metadata.path_params_regex:
            path_item['x-path-params-regex'] = metadata.path_params_regex

        # Add the operation
        path_item[metadata.method.lower()] = self._build_operation(metadata)

        return path_item

    def generate(self) -> dict[str, Any]:
        """Generate the complete OpenAPI specification.

        Returns:
            OpenAPI 3.1 specification as a dictionary.

        Raises:
            ValueError: If duplicate method+path combinations are detected.
        """
        # Reset schemas for fresh generation
        self._schemas = {}

        # Build paths from registered endpoints
        paths: dict[str, Any] = {}
        seen_operations: set[tuple[str, str]] = set()

        for metadata in get_endpoint_registry():
            key = (metadata.path, metadata.method)
            if key in seen_operations:
                raise ValueError(
                    f"Duplicate operation: {metadata.method} {metadata.path} "
                    f"(operation_id: {metadata.operation_id})"
                )
            seen_operations.add(key)

            if metadata.path in paths:
                # Merge with existing path item (multiple methods on same path)
                existing = paths[metadata.path]
                existing[metadata.method.lower()] = self._build_operation(metadata)
            else:
                paths[metadata.path] = self._build_path_item(metadata)

        # Build complete spec
        spec: dict[str, Any] = {
            'openapi': '3.1.0',
            'info': {
                'title': self.title,
                'version': self.version,
                'description': self.description,
            },
            'paths': paths,
        }

        # Add components/schemas if any were registered
        if self._schemas:
            spec['components'] = {'schemas': self._flatten_schemas()}

        return spec
