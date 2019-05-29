import json
import os
from typing import Any, Dict

from hathor.cli.openapi_files.register import get_registered_resources

BASE_PATH = os.path.join(os.path.dirname(__file__), 'openapi_files')
DEFAULT_OUTPUT_PATH = os.path.join(BASE_PATH, 'openapi.json')


def get_base() -> Dict[str, Any]:
    """ Returns the base configuration from OpenAPI json
    """
    with open(os.path.join(BASE_PATH, 'openapi_base.json'), 'r') as f:
        return json.load(f)


def get_components() -> Dict[str, Any]:
    """ Returns the components from OpenAPI json
    """
    with open(os.path.join(BASE_PATH, 'openapi_components.json'), 'r') as f:
        return json.load(f)


def get_openapi_dict() -> Dict[str, Any]:
    """ Returns the generated OpenAPI dict
    """
    openapi = get_base()
    components = get_components()
    openapi['components'] = components['components']
    for resource in get_registered_resources():
        openapi['paths'].update(resource.openapi)
    return openapi


def main():
    import argparse

    from hathor.cli.util import create_parser

    parser = create_parser()
    parser.add_argument('--indent', type=int, default=None, help='Number of spaces to use for indentation')
    parser.add_argument('out', type=argparse.FileType('w', encoding='UTF-8'), default=DEFAULT_OUTPUT_PATH, nargs='?',
                        help='Output file where OpenSPI json will be written')
    args = parser.parse_args()

    openapi = get_openapi_dict()
    json.dump(openapi, args.out, indent=args.indent)
