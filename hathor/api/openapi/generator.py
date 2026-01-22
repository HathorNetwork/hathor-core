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

from typing import Any

from pydantic import BaseModel

from hathor.api.openapi.decorators import EndpointMetadata, get_endpoint_registry


class OpenAPIGenerator:
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

    def _get_schema_ref(self, model: type[BaseModel]) -> dict[str, str]:
        """Get a $ref to a schema, registering it if needed."""
        schema_name = model.__name__
        if schema_name not in self._schemas:
            self._schemas[schema_name] = model.model_json_schema(
                ref_template='#/components/schemas/{model}'
            )
        return {'$ref': f'#/components/schemas/{schema_name}'}

    def _build_parameters(self, metadata: EndpointMetadata) -> list[dict[str, Any]]:
        """Build OpenAPI parameters from query params model and path params."""
        parameters: list[dict[str, Any]] = []

        # Add path parameters from path_params_regex
        for param_name, regex in metadata.path_params_regex.items():
            parameters.append({
                'name': param_name,
                'in': 'path',
                'required': True,
                'schema': {'type': 'string', 'pattern': regex},
            })

        # Add query parameters from Pydantic model
        if metadata.query_params_model:
            schema = metadata.query_params_model.model_json_schema()
            properties = schema.get('properties', {})
            required_fields = set(schema.get('required', []))

            for field_name, field_schema in properties.items():
                param: dict[str, Any] = {
                    'name': field_name,
                    'in': 'query',
                    'required': field_name in required_fields,
                    'schema': field_schema,
                }
                if 'description' in field_schema:
                    param['description'] = field_schema['description']
                parameters.append(param)

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

    def _build_responses(self, metadata: EndpointMetadata) -> dict[str, Any]:
        """Build OpenAPI responses section."""
        responses: dict[str, Any] = {}

        # Success response
        if metadata.response_model:
            responses['200'] = {
                'description': 'Success',
                'content': {
                    'application/json': {
                        'schema': self._get_schema_ref(metadata.response_model),
                    },
                },
            }
        else:
            responses['200'] = {'description': 'Success'}

        # Error responses
        for error_model in metadata.error_responses:
            # Default to 400 for error responses, could be enhanced
            responses['400'] = {
                'description': 'Error',
                'content': {
                    'application/json': {
                        'schema': self._get_schema_ref(error_model),
                    },
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
        """
        # Reset schemas for fresh generation
        self._schemas = {}

        # Build paths from registered endpoints
        paths: dict[str, Any] = {}
        for metadata in get_endpoint_registry():
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
            # Process schemas to handle nested $defs
            components_schemas: dict[str, Any] = {}
            for name, schema in self._schemas.items():
                # Extract $defs to top-level schemas
                if '$defs' in schema:
                    for def_name, def_schema in schema['$defs'].items():
                        components_schemas[def_name] = def_schema
                    del schema['$defs']
                components_schemas[name] = schema

            spec['components'] = {'schemas': components_schemas}

        return spec
