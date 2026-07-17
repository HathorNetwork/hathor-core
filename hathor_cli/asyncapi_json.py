# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""CLI command to generate AsyncAPI specification for WebSocket APIs.

This generates an AsyncAPI 3.0 specification documenting:
- Admin WebSocket (/ws): Dashboard metrics, address subscriptions, history streaming
- Event WebSocket (/event_ws): Event streaming with flow control
- Mining WebSocket: JSON-RPC 2.0 mining protocol

Usage:
    hathor-cli generate_asyncapi_json [--indent N] [output_file]

The generated specification can be used with:
- AsyncAPI Studio: https://studio.asyncapi.com/
- AsyncAPI Generator: https://github.com/asyncapi/generator
- Documentation renderers
"""

import json
from typing import Any


def get_asyncapi_dict() -> dict[str, Any]:
    """Generate the complete AsyncAPI specification.

    Returns:
        AsyncAPI 3.0 specification as a dictionary.
    """
    from hathor.api.asyncapi.generator import create_hathor_asyncapi_generator

    generator = create_hathor_asyncapi_generator()
    return generator.generate()


def main():
    import argparse

    from hathor_cli.util import create_parser

    parser = create_parser()
    parser.add_argument(
        '--indent',
        type=int,
        default=None,
        help='Number of spaces to use for indentation'
    )
    parser.add_argument(
        'out',
        type=argparse.FileType('w', encoding='UTF-8'),
        default='-',
        nargs='?',
        help='Output file where AsyncAPI JSON will be written (default: stdout)'
    )
    args = parser.parse_args()

    asyncapi = get_asyncapi_dict()
    json.dump(asyncapi, args.out, indent=args.indent)
