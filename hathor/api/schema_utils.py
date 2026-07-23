# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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

        Raises:
            ValueError: If two different schemas share the same $def name.
        """
        components_schemas: dict[str, Any] = {}
        for name, schema in self._schemas.items():
            if '$defs' in schema:
                for def_name, def_schema in schema['$defs'].items():
                    if def_name in components_schemas and components_schemas[def_name] != def_schema:
                        raise ValueError(
                            f"Conflicting schema definitions for '{def_name}': "
                            f"found different schemas with the same name"
                        )
                    components_schemas[def_name] = def_schema
                del schema['$defs']
            components_schemas[name] = schema
        return components_schemas
