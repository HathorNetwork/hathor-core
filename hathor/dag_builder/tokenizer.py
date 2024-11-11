import re
from enum import Enum, auto
from typing import Any, Iterator


class Token(Enum):
    BLOCKCHAIN = auto()
    ATTRIBUTE = auto()
    PARENT = auto()
    SPEND = auto()
    OUTPUT = auto()
    ORDER_BEFORE = auto()


def collect_pairs(parts: list[str], expected_sep: str) -> Iterator[tuple[str, str]]:
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


def parse_file(filename: str) -> Iterator[tuple[Token, Any, ...]]:
    fp = open(filename, 'r')
    content = fp.readlines()
    yield from parse_string(content)


def parse_string(content) -> Iterator:
    blockchain_re = re.compile(r'^([a-zA-Z][a-zA-Z0-9-_]*)\[([0-9]+)..([0-9]+)\]$')
    for line in content:
        line = line.strip()
        if not line:
            continue

        if line[0] == '#':
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
            yield (Token.BLOCKCHAIN, name, first_parent, int(begin), int(end))

        elif parts[1] == '=':
            name, key = parts[0].split('.', 1)
            if key.startswith('out[') and key[-1] == ']':
                index = int(key[4:-1])
                amount = int(parts[2])
                token = parts[3]
                attrs = parts[4:]
                yield (Token.OUTPUT, name, index, amount, token, attrs)
            else:
                yield (Token.ATTRIBUTE, name, key, parts[2:])

        elif parts[1] == '<--':
            for _to, _from in collect_pairs(parts, '<--'):
                yield (Token.PARENT, _from, _to)

        elif parts[1] == '-->':
            for _from, _to in collect_pairs(parts, '-->'):
                yield (Token.PARENT, _from, _to)

        elif parts[1] == '<<<':
            _to, _out = parts[0].split('.', 1)
            if not _out.startswith('out['):
                raise SyntaxError
            if _out[-1] != ']':
                raise SyntaxError
            _txout_index = int(_out[4:-1])
            for _from in parts[2:]:
                yield (Token.SPEND, _from, _to, _txout_index)

        elif parts[1] == '<':
            for _a, _b in collect_pairs(parts, '<'):
                yield (Token.ORDER_BEFORE, _b, _a)

        else:
            raise SyntaxError(line)
