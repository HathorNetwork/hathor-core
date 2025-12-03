# Copyright 2022 Hathor Labs
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
