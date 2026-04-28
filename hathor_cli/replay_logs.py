# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from json import JSONDecodeError


def main():
    import argparse
    import sys

    from hathor_cli.util import ConsoleRenderer, create_parser
    from hathor.util import json_loads

    parser = create_parser()
    parser.add_argument('input', type=argparse.FileType('r', encoding='UTF-8'), default=sys.stdin, nargs='?',
                        help='Where to read json logs from, defaults to stdin.')
    parser.add_argument('output', type=argparse.FileType('w', encoding='UTF-8'), default=sys.stdout, nargs='?',
                        help='Where to write pretty logs to, defaults to stdout.')
    parser.add_argument('--color', action='store_true')
    args = parser.parse_args()

    renderer = ConsoleRenderer(colors=args.color or args.output.isatty())

    while True:
        line_with_break = args.input.readline()
        if not line_with_break:
            break
        line = line_with_break.strip()
        if line.startswith('#'):
            pass  # ignore
        elif line.startswith('--'):
            print('...', file=args.output, flush=True)
        else:
            try:
                log_dict = json_loads(line)
                print(renderer(None, '', log_dict), file=args.output, flush=True)
            except JSONDecodeError:
                print('!!!', line, file=args.output, flush=True)
