import json
import os
from typing import Any, Dict

from hathor.cli.openapi_files.register import get_registered_resources

FILENAME = 'openapi.json'
PATH = 'hathor/cli/openapi_files/'
FILE_PATH = os.path.join(PATH, FILENAME)


def get_base() -> Dict[str, Any]:
    """ Returns the base configuration from openapi json
    """
    with open(os.path.join(PATH, 'openapi_base.json'), 'r') as f:
        return json.loads(f.read())


def get_components() -> Dict[str, Any]:
    """ Returns the components from openapi json
    """
    with open(os.path.join(PATH, 'openapi_components.json'), 'r') as f:
        return json.loads(f.read())


def execute() -> None:
    openapi = get_base()
    components = get_components()
    openapi['components'] = components['components']

    for resource in get_registered_resources():
        openapi['paths'].update(resource.openapi)

    with open(FILE_PATH, 'w') as f:
        f.write(json.dumps(openapi))


def main():
    execute()
