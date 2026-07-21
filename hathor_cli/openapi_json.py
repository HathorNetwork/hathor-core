# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
from typing import Any


def get_base_path() -> Path:
    from hathor import _openapi as openapi_module
    return Path(openapi_module.__file__).parent


def get_default_output_path() -> Path:
    return get_base_path().joinpath('openapi.json')


def get_base() -> dict[str, Any]:
    """ Returns the base configuration from OpenAPI json
    """
    with open(get_base_path().joinpath('openapi_base.json'), 'r') as f:
        return json.load(f)


def get_components() -> dict[str, Any]:
    """ Returns the components from OpenAPI json
    """
    with open(get_base_path().joinpath('openapi_components.json'), 'r') as f:
        return json.load(f)


def get_openapi_dict() -> dict[str, Any]:
    """ Returns the generated OpenAPI dict

    This function merges OpenAPI specs from two sources:
    1. Legacy: Manual `resource.openapi` class attributes
    2. Modern: `@api_endpoint` decorator with Pydantic models

    The modern approach takes precedence for any overlapping paths.
    """
    from hathor._openapi.register import get_registered_resources
    from hathor.api.openapi import OpenAPIGenerator

    openapi = get_base()
    components = get_components()
    openapi['components'] = components['components']

    # 1. Add paths from legacy manual openapi attributes
    for resource in get_registered_resources():
        if hasattr(resource, 'openapi'):
            for path, path_item in resource.openapi.items():
                if path in openapi['paths']:
                    openapi['paths'][path].update(path_item)
                else:
                    openapi['paths'][path] = path_item

    # 2. Add/override paths from modern @api_endpoint decorator
    generator = OpenAPIGenerator()
    modern_spec = generator.generate()

    # Merge paths at method level (modern takes precedence for overlapping methods)
    for path, path_item in modern_spec.get('paths', {}).items():
        if path in openapi['paths']:
            openapi['paths'][path].update(path_item)
        else:
            openapi['paths'][path] = path_item

    # Merge schemas into components
    modern_schemas = modern_spec.get('components', {}).get('schemas', {})
    if modern_schemas:
        if 'schemas' not in openapi['components']:
            openapi['components']['schemas'] = {}
        openapi['components']['schemas'].update(modern_schemas)

    return openapi


def main():
    import argparse

    from hathor_cli.util import create_parser

    parser = create_parser()
    parser.add_argument('--indent', type=int, default=None, help='Number of spaces to use for indentation')
    parser.add_argument('out', type=argparse.FileType('w', encoding='UTF-8'), default=get_default_output_path(),
                        nargs='?', help='Output file where OpenAPI json will be written')
    args = parser.parse_args()

    from hathor.api.openapi.versioning import prefix_unversioned_paths

    openapi = prefix_unversioned_paths(get_openapi_dict())
    json.dump(openapi, args.out, indent=args.indent)
