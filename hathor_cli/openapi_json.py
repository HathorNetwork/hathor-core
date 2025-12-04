# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from typing import Any
from pathlib import Path


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
    """
    from hathor._openapi.register import get_registered_resources
    openapi = get_base()
    components = get_components()
    openapi['components'] = components['components']
    for resource in get_registered_resources():
        openapi['paths'].update(resource.openapi)
    return openapi


def main():
    import argparse

    from hathor_cli.util import create_parser

    parser = create_parser()
    parser.add_argument('--indent', type=int, default=None, help='Number of spaces to use for indentation')
    parser.add_argument('out', type=argparse.FileType('w', encoding='UTF-8'), default=get_default_output_path(),
                        nargs='?', help='Output file where OpenSPI json will be written')
    args = parser.parse_args()

    openapi = get_openapi_dict()
    json.dump(openapi, args.out, indent=args.indent)
