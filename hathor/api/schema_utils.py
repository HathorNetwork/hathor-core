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

"""Shared schema utilities for OpenAPI and AsyncAPI generators."""

from typing import Any

from pydantic import BaseModel


class SchemaRegistryMixin:
    """Mixin providing shared Pydantic schema registration and $defs flattening.

    Both OpenAPIGenerator and AsyncAPIGenerator use identical logic to:
    1. Register a Pydantic model's JSON schema and return a $ref
    2. Flatten nested $defs into top-level component schemas

    This mixin extracts that shared code.
    """

    _schemas: dict[str, Any]

    def _get_schema_ref(self, model: type[BaseModel]) -> dict[str, str]:
        """Get a $ref to a schema, registering it if needed."""
        schema_name = model.__name__
        if schema_name not in self._schemas:
            self._schemas[schema_name] = model.model_json_schema(
                ref_template='#/components/schemas/{model}'
            )
        return {'$ref': f'#/components/schemas/{schema_name}'}

    def _flatten_schemas(self) -> dict[str, Any]:
        """Flatten nested $defs into top-level component schemas.

        Returns:
            A dict of schema_name -> schema suitable for components/schemas.
        """
        components_schemas: dict[str, Any] = {}
        for name, schema in self._schemas.items():
            if '$defs' in schema:
                for def_name, def_schema in schema['$defs'].items():
                    components_schemas[def_name] = def_schema
                del schema['$defs']
            components_schemas[name] = schema
        return components_schemas
