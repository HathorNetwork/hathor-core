#!/usr/bin/env python3

# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Summarize repeated file-level diff patterns."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass

DEFAULT_DIFF_ARGS = ['origin/master...HEAD']
DEFAULT_EXAMPLES = 8
DEFAULT_MAX_LINES = 160
COLOR_MODES = {'auto', 'always', 'never'}
COLOR_RESET = '\033[0m'
COLORS = {
    'bold': '\033[1m',
    'cyan': '\033[36m',
    'dim': '\033[2m',
    'green': '\033[32m',
    'red': '\033[31m',
}
YEAR_RE = re.compile(r'\b(?:19|20)\d{2}(?:-(?:19|20)\d{2})?\b')


@dataclass(frozen=True)
class FileDiff:
    path: str
    pattern_lines: tuple[str, ...]


@dataclass(frozen=True)
class Options:
    diff_args: list[str]
    examples: int
    max_lines: int
    normalize_years: bool
    color: bool


def print_usage() -> None:
    print(
        """usage: tools/summarize-diff-patterns.py [options] [git-diff-args...]

Group repeated file-level diffs after removing file-specific diff metadata.
By default, it runs:

  git diff --no-color --no-ext-diff --unified=0 origin/master...HEAD

Options:
  --examples N            Number of example paths per group. Default: 8.
  --max-lines N           Max pattern lines printed per group. Use 0 for all.
                           Default: 160.
  --color MODE            Color output: auto, always, never. Default: auto.
  --no-color              Same as --color never.
  --no-normalize-years    Do not replace copyright years with <YEAR>.
  -h, --help              Show this help.

Example:
  tools/summarize-diff-patterns.py origin/master...origin/chore/reuse-tool -- \\
    . ':(exclude)REUSE.toml' ':(exclude)LICENSES/Apache-2.0.txt'
""",
    )


def parse_options(argv: list[str]) -> Options:
    examples = DEFAULT_EXAMPLES
    max_lines = DEFAULT_MAX_LINES
    normalize_years = True
    color_mode = 'auto'
    index = 0

    while index < len(argv):
        arg = argv[index]
        if arg == '--':
            index += 1
            break
        if arg in ('-h', '--help'):
            print_usage()
            raise SystemExit(0)
        if arg == '--examples':
            if index + 1 >= len(argv):
                print('error: --examples requires a value', file=sys.stderr)
                raise SystemExit(2)
            examples = parse_non_negative_int('--examples', argv[index + 1])
            index += 2
            continue
        if arg == '--max-lines':
            if index + 1 >= len(argv):
                print('error: --max-lines requires a value', file=sys.stderr)
                raise SystemExit(2)
            max_lines = parse_non_negative_int('--max-lines', argv[index + 1])
            index += 2
            continue
        if arg == '--color':
            if index + 1 >= len(argv):
                print('error: --color requires a value', file=sys.stderr)
                raise SystemExit(2)
            color_mode = parse_color_mode(argv[index + 1])
            index += 2
            continue
        if arg.startswith('--color='):
            color_mode = parse_color_mode(arg.partition('=')[2])
            index += 1
            continue
        if arg == '--no-color':
            color_mode = 'never'
            index += 1
            continue
        if arg == '--no-normalize-years':
            normalize_years = False
            index += 1
            continue
        break

    diff_args = argv[index:] or DEFAULT_DIFF_ARGS
    return Options(
        diff_args=diff_args,
        examples=examples,
        max_lines=max_lines,
        normalize_years=normalize_years,
        color=should_color(color_mode),
    )


def parse_non_negative_int(option: str, value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        print(f'error: {option} must be an integer', file=sys.stderr)
        raise SystemExit(2) from None
    if parsed < 0:
        print(f'error: {option} must be non-negative', file=sys.stderr)
        raise SystemExit(2)
    return parsed


def parse_color_mode(value: str) -> str:
    if value not in COLOR_MODES:
        modes = ', '.join(sorted(COLOR_MODES))
        print(f'error: --color must be one of: {modes}', file=sys.stderr)
        raise SystemExit(2)
    return value


def should_color(mode: str) -> bool:
    return mode == 'always' or (
        mode == 'auto'
        and sys.stdout.isatty()
        and 'NO_COLOR' not in os.environ
    )


def run_git_diff(diff_args: list[str]) -> str:
    command = [
        'git',
        'diff',
        '--no-color',
        '--no-ext-diff',
        '--unified=0',
        *diff_args,
    ]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode not in (0, 1):
        print(result.stderr, file=sys.stderr, end='')
        raise SystemExit(result.returncode)
    return result.stdout


def path_from_diff_git(line: str) -> str:
    parts = line.split()
    if len(parts) < 4:
        return '<unknown>'
    path = parts[3]
    if path.startswith('b/'):
        return path[2:]
    return path


def path_from_file_header(line: str) -> str | None:
    path = line[4:]
    if path == '/dev/null':
        return None
    if path.startswith('a/') or path.startswith('b/'):
        return path[2:]
    return path


def normalize_line(line: str, *, normalize_years: bool) -> str:
    for prefix in ('rename from ', 'rename to ', 'copy from ', 'copy to '):
        if line.startswith(prefix):
            return f'{prefix}<PATH>'

    if line.startswith('Binary files '):
        return 'Binary files differ'

    if normalize_years and 'Copyright' in line:
        line = YEAR_RE.sub('<YEAR>', line)

    return line


def parse_diff(diff_text: str, *, normalize_years: bool) -> list[FileDiff]:
    files: list[FileDiff] = []
    current_path: str | None = None
    current_lines: list[str] = []

    def flush_current() -> None:
        nonlocal current_path, current_lines
        if current_path is not None:
            files.append(FileDiff(current_path, tuple(current_lines)))
        current_path = None
        current_lines = []

    for line in diff_text.splitlines():
        if line.startswith('diff --git '):
            flush_current()
            current_path = path_from_diff_git(line)
            continue

        if current_path is None:
            continue

        if line.startswith('index '):
            continue
        if line.startswith('--- '):
            continue
        if line.startswith('+++ '):
            path = path_from_file_header(line)
            if path is not None:
                current_path = path
            continue
        if line.startswith('@@ '):
            continue

        current_lines.append(normalize_line(line, normalize_years=normalize_years))

    flush_current()
    return files


def colorize(text: str, color: str, *, enabled: bool) -> str:
    if not enabled:
        return text
    return f'{COLORS[color]}{text}{COLOR_RESET}'


def colorize_diff_line(line: str, *, enabled: bool) -> str:
    if line.startswith('+'):
        return colorize(line, 'green', enabled=enabled)
    if line.startswith('-'):
        return colorize(line, 'red', enabled=enabled)
    return line


def print_group(
    *,
    index: int,
    paths: list[str],
    pattern_lines: tuple[str, ...],
    examples: int,
    max_lines: int,
    color: bool,
) -> None:
    title = f'## Pattern {index}: {len(paths)} file(s)'
    print(colorize(title, 'cyan', enabled=color))
    print(colorize('Examples:', 'bold', enabled=color))
    for path in sorted(paths)[:examples]:
        print(f'  {path}')
    remaining = len(paths) - examples
    if remaining > 0:
        print(f'  ... {remaining} more')
    print()

    lines_to_print = pattern_lines
    truncated = False
    if max_lines and len(pattern_lines) > max_lines:
        lines_to_print = pattern_lines[:max_lines]
        truncated = True

    print(colorize('Diff pattern:', 'bold', enabled=color))
    for line in lines_to_print:
        print(colorize_diff_line(line, enabled=color))
    if truncated:
        message = f'... {len(pattern_lines) - max_lines} more diff line(s)'
        print(colorize(message, 'dim', enabled=color))
    print()


def main() -> int:
    options = parse_options(sys.argv[1:])
    files = parse_diff(
        run_git_diff(options.diff_args),
        normalize_years=options.normalize_years,
    )

    groups: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for file_diff in files:
        groups[file_diff.pattern_lines].append(file_diff.path)

    sorted_groups = sorted(
        groups.items(),
        key=lambda item: (-len(item[1]), item[1][0], item[0]),
    )

    print(f'Git diff args: {" ".join(options.diff_args)}')
    print(f'Files with diffs: {len(files)}')
    print(f'Unique diff patterns: {len(sorted_groups)}')
    print()

    for index, (pattern_lines, paths) in enumerate(sorted_groups, start=1):
        print_group(
            index=index,
            paths=paths,
            pattern_lines=pattern_lines,
            examples=options.examples,
            max_lines=options.max_lines,
            color=options.color,
        )

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
