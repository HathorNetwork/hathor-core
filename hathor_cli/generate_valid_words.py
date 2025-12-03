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

from argparse import ArgumentParser, Namespace


def generate_words(language: str = 'english', count: int = 24) -> str:
    from mnemonic import Mnemonic
    mnemonic = Mnemonic(language)
    return mnemonic.generate(strength=int(count * 10.67))


def create_parser() -> ArgumentParser:
    from hathor_cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--language', help='Words language')
    parser.add_argument('--count', type=int, help='Word count')
    return parser


def execute(args: Namespace) -> None:
    kwargs = {}

    if args.language:
        kwargs['language'] = args.language
    if args.count:
        kwargs['count'] = args.count

    print(generate_words(**kwargs))


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
