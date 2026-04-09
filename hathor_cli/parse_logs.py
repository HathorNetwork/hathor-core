# Copyright 2024 Hathor Labs
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
import re
import sys
from argparse import FileType
from io import TextIOWrapper
from typing import Iterator


def main() -> None:
    """
    Parse logs from a dump file (either as json or plain logs) into a file with only vertex hex bytes.
    The logs must be generated with --log-vertex-bytes. Then, use load-from-logs to run a full node from this file.
    """
    from hathor_cli.util import create_parser
    parser = create_parser()
    file_args = parser.add_mutually_exclusive_group(required=True)
    file_args.add_argument(
        '--json-logs-file',
        type=FileType('r', encoding='UTF-8'),
        help='Where to read json logs from.',
    )
    file_args.add_argument(
        '--plain-logs-file',
        type=FileType('r', encoding='UTF-8'),
        help='Where to read plain logs from.',
    )
    parser.add_argument(
        '--output-file',
        type=FileType('w', encoding='UTF-8'),
        required=True,
        help='Output file.',
    )
    args = parser.parse_args(sys.argv[1:])
    assert isinstance(args.output_file, TextIOWrapper)

    vertex_iter: Iterator[str]
    if args.json_logs_file is not None:
        assert isinstance(args.json_logs_file, TextIOWrapper)
        print('parsing json logs file...')
        vertex_iter = _parse_json_logs(args.json_logs_file)
    else:
        assert isinstance(args.plain_logs_file, TextIOWrapper)
        print('parsing plain logs file...')
        vertex_iter = _parse_plain_logs(args.plain_logs_file)

    print('writing to output file...')
    for vertex in vertex_iter:
        args.output_file.write(vertex + '\n')
    print('done')


def _parse_json_logs(file: TextIOWrapper) -> Iterator[str]:
    while True:
        line = file.readline()
        if not line:
            break

        json_dict = json.loads(line)
        event = json_dict.get('event')
        if not event:
            return

        if event in ('new block', 'new tx'):
            vertex_bytes = json_dict.get('bytes')
            assert vertex_bytes is not None, 'logs should be generated with --log-vertex-bytes'
            yield vertex_bytes


def _parse_plain_logs(file: TextIOWrapper) -> Iterator[str]:
    pattern = r'new (tx|block)    .*bytes=([^ ]*) '
    compiled_pattern = re.compile(pattern)

    while True:
        line_with_break = file.readline()
        if not line_with_break:
            break
        line = line_with_break.strip()

        matches = compiled_pattern.findall(line)
        if len(matches) == 0:
            continue

        assert len(matches) == 1
        _, vertex_bytes_hex = matches[0]
        yield vertex_bytes_hex
