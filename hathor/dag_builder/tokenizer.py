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

import re
from enum import Enum, auto
from typing import Any, Iterator

"""
A domain specific language to describe DAGs.

Syntax:

    blockchain genesis a[2..5]  # create blocks a2, a3, a4, and a5 where a2's parent is the genesis block
    blockchain pi a[5..7]       # create blocks a5, a6, and a7 where a5's parent is pi
    a <-- b <-- c               # a is a parent of b which is a parent of c
    a --> b --> c               # c is a parent of b which is a parent of a
    a.out[i] <<< b c d          # b, c, and d spend the i-th output of a
    a < b < c                   # a must be created before b and b must be created before c
    a > b > c                   # a must be created after b and b must be creater after c
    a.attr = value              # set value of attribute attr to a

Special attributes:
    a.out[i] = 100 HTR          # set that the i-th output of a holds 100 HTR
    a.out[i] = 100 TOKEN        # set that the i-th output of a holds 100 TOKEN where TOKEN is a custom token
    a.weight = 50               # set vertex weight


Example:

    blockchain genesis a[0..300]
    blockchain a300 b[0..20]
    blockchain b4 c[0..10]

    # reward lock
    a300 < dummy

    b11 --> tx1
    b11 --> tx2

    b14 --> tx1
    b14 --> tx3

    c3 --> tx1
    c3 --> tx2

    tx1 <-- tx2 <-- tx3

    tx3 --> tx5 --> tx6

    tx1.out[0] <<< tx2 tx3
    tx1.out[0] <<< tx4

    a0.out[0] <<< tx1

    tx1.out[0] = 100 HTR [wallet1]
    tx1.out[1] = 50 TK1  [wallet2]
    tx2.out[0] = 75 USDC [wallet1]

    USDC.out[0] = 100000 HTR

    b5 < c0 < c10 < b20
    b6 < tx3
    b16 < tx4
"""


class TokenType(Enum):
    BLOCKCHAIN = auto()
    ATTRIBUTE = auto()
    PARENT = auto()
    SPEND = auto()
    OUTPUT = auto()
    ORDER_BEFORE = auto()


Token = tuple[TokenType, tuple[Any, ...]]


def collect_pairs(parts: list[str], expected_sep: str) -> Iterator[tuple[str, str]]:
    """Pair all parts two by two checking the separator."""
    n = len(parts)
    if n < 3:
        raise SyntaxError
    if n % 2 == 0:
        raise SyntaxError

    k = (n - 1) // 2
    for i in range(k):
        first = parts[2 * i]
        sep = parts[2 * i + 1]
        second = parts[2 * i + 2]
        if parts[2 * i + 1] != expected_sep:
            raise SyntaxError(f'inconsistent separator; got {sep} but expecting {expected_sep}')
        yield (first, second)


def tokenize(content: str) -> Iterator[Token]:
    """Parse content and generate tokens.
    """
    blockchain_re = re.compile(r'^([a-zA-Z][a-zA-Z0-9-_]*)\[([0-9]+)..([0-9]+)\]$')
    first_parent: str | None
    for line in content.split('\n'):
        line, _, _ = line.partition('#')
        line = line.strip()
        if not line:
            continue

        # split() trims on both sides and remove empty parts
        parts = line.split()

        if parts[0] == 'blockchain':
            if len(parts) != 3:
                raise SyntaxError
            first_parent = parts[1]
            if first_parent == 'genesis':
                first_parent = None
            match = blockchain_re.match(parts[2])
            if not match:
                raise SyntaxError(f'invalid blockchain format: {line}')
            name, begin, end = match.groups()
            yield (TokenType.BLOCKCHAIN, (name, first_parent, int(begin), int(end)))

        elif parts[1] == '=':
            name, key = parts[0].split('.', 1)
            if key.startswith('out[') and key[-1] == ']':
                index = int(key[4:-1])
                amount = int(parts[2])
                token = parts[3]
                attrs = parts[4:]
                yield (TokenType.OUTPUT, (name, index, amount, token, attrs))
            else:
                yield (TokenType.ATTRIBUTE, (name, key, ' '.join(parts[2:])))

        elif parts[1] == '<--':
            for _to, _from in collect_pairs(parts, '<--'):
                yield (TokenType.PARENT, (_from, _to))

        elif parts[1] == '-->':
            for _from, _to in collect_pairs(parts, '-->'):
                yield (TokenType.PARENT, (_from, _to))

        elif parts[1] == '<<<':
            _to, _out = parts[0].split('.', 1)
            if not _out.startswith('out['):
                raise SyntaxError
            if _out[-1] != ']':
                raise SyntaxError
            _txout_index = int(_out[4:-1])
            for _from in parts[2:]:
                yield (TokenType.SPEND, (_from, _to, _txout_index))

        elif parts[1] == '<':
            for _a, _b in collect_pairs(parts, '<'):
                yield (TokenType.ORDER_BEFORE, (_b, _a))

        elif parts[1] == '>':
            for _a, _b in collect_pairs(parts, '>'):
                yield (TokenType.ORDER_BEFORE, (_a, _b))

        else:
            raise SyntaxError(line)
