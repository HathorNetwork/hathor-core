#!/usr/bin/env python3

# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Fix source files that need short REUSE SPDX headers (Python and Rust)."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

COPYRIGHT = 'Hathor Labs'
LICENSE = 'Apache-2.0'
# The tag is assembled from two pieces so this file does not contain a verbatim license-identifier
# line that `reuse lint` would otherwise pick up as a spurious declaration.
SPDX_LICENSE_TAG = 'SPDX-License-' + 'Identifier'

CODING_RE = re.compile(r'^#.*coding[:=]\s*[-\w.]+')


@dataclass(frozen=True)
class Language:
    """A source language for which we know how to normalize REUSE headers."""
    name: str
    suffixes: tuple[str, ...]
    comment: str  # line-comment prefix, e.g. '#' or '//'
    has_preamble: bool  # whether a shebang/coding preamble may precede the header


PYTHON = Language('Python', ('.py',), '#', has_preamble=True)
RUST = Language('Rust', ('.rs',), '//', has_preamble=False)
LANGUAGES = (PYTHON, RUST)
SUFFIX_TO_LANGUAGE = {suffix: lang for lang in LANGUAGES for suffix in lang.suffixes}


def _line_comment_apache_re(comment: str) -> re.Pattern[str]:
    """Build a regex matching the legacy line-comment Apache header for the given comment prefix."""
    c = re.escape(comment)
    return re.compile(
        r'\A(?:[ \t]*\n)*'
        rf'{c}[ \t]*Copyright [^\n]*Hathor Labs\n'
        rf'{c}[ \t]*\n'
        rf'{c}[ \t]*Licensed under the Apache License, Version 2\.0 \(the "License"\);\n'
        rf'{c}[ \t]*you may not use this file except in compliance with the License\.\n'
        rf'{c}[ \t]*You may obtain a copy of the License at\n'
        rf'{c}[ \t]*\n'
        rf'{c}[ \t]*http://www\.apache\.org/licenses/LICENSE-2\.0\n'
        rf'{c}[ \t]*\n'
        rf'{c}[ \t]*Unless required by applicable law or agreed to in writing, software\n'
        rf'{c}[ \t]*distributed under the License is distributed on an "AS IS" BASIS,\n'
        rf'{c}[ \t]*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.\n'
        rf'{c}[ \t]*See the License for the specific language governing permissions and\n'
        rf'{c}[ \t]*limitations under the License\.\n'
        r'(?:\n)?'
    )


LEGACY_LINE_COMMENT_RE = {lang: _line_comment_apache_re(lang.comment) for lang in LANGUAGES}

DOCSTRING_APACHE_RE = re.compile(
    r'\A(?:[ \t]*\n)*(?P<quote>"""|\'\'\')\n'
    r'Copyright [^\n]*Hathor Labs\n'
    r'\n'
    r'Licensed under the Apache License, Version 2\.0 \(the "License"\);\n'
    r'you may not use this file except in compliance with the License\.\n'
    r'You may obtain a copy of the License at\n'
    r'\n'
    r'[ \t]*http://www\.apache\.org/licenses/LICENSE-2\.0\n'
    r'\n'
    r'Unless required by applicable law or agreed to in writing, software\n'
    r'distributed under the License is distributed on an "AS IS" BASIS,\n'
    r'WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.\n'
    r'See the License for the specific language governing permissions and\n'
    r'limitations under the License\.\n'
    r'(?P=quote)\n'
    r'(?:\n)?'
)


def run_reuse_lint() -> dict:
    result = subprocess.run(
        ['reuse', 'lint', '--json'],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode not in (0, 1):
        print(result.stderr, file=sys.stderr, end='')
        raise SystemExit(result.returncode)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print('Could not parse `reuse lint --json` output.', file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        raise SystemExit(2) from exc


def files_with_reuse_issues(report: dict) -> set[Path]:
    paths: set[Path] = set()
    for file_info in report.get('files', []):
        path = Path(file_info.get('path', ''))
        if path.suffix not in SUFFIX_TO_LANGUAGE:
            continue
        if not file_info.get('copyrights') or not file_info.get('spdx_expressions'):
            paths.add(path)
    return paths


def split_preamble(text: str, lang: Language) -> tuple[str, str]:
    """Split off any leading lines (shebang/coding) that must stay above the header."""
    if not lang.has_preamble:
        return '', text

    lines = text.splitlines(keepends=True)
    prefix: list[str] = []
    index = 0

    if lines and lines[0].startswith('#!'):
        prefix.append(lines[0])
        index = 1

    if index < len(lines) and CODING_RE.match(lines[index]):
        prefix.append(lines[index])
        index += 1

    return ''.join(prefix), ''.join(lines[index:])


def remove_known_legacy_header(path: Path, lang: Language) -> bool:
    text = path.read_text(encoding='utf-8')
    prefix, rest = split_preamble(text, lang)
    fixed = LEGACY_LINE_COMMENT_RE[lang].sub('', rest, count=1)
    if lang is PYTHON:
        fixed = DOCSTRING_APACHE_RE.sub('', fixed, count=1)
    new_text = prefix + fixed
    if new_text == text:
        return False
    path.write_text(new_text, encoding='utf-8', newline='')
    return True


def normalize_reuse_header(path: Path, lang: Language) -> bool:
    """Drop the blank comment line `reuse annotate` inserts between the two SPDX tags."""
    text = path.read_text(encoding='utf-8')
    copyright_header = f'{lang.comment} SPDX-FileCopyrightText: {COPYRIGHT}'
    license_header = f'{lang.comment} {SPDX_LICENSE_TAG}: {LICENSE}'
    fixed = text.replace(
        f'{copyright_header}\n{lang.comment}\n{license_header}',
        f'{copyright_header}\n{license_header}',
        1,
    )
    if fixed == text:
        return False
    path.write_text(fixed, encoding='utf-8', newline='')
    return True


def annotate(path: Path) -> bool:
    result = subprocess.run(
        [
            'reuse',
            'annotate',
            '--copyright',
            COPYRIGHT,
            '--license',
            LICENSE,
            '--exclude-year',
            str(path),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        print(result.stdout, end='')
        print(result.stderr, file=sys.stderr, end='')
        return False
    return True


def existing_source_paths(paths: list[str]) -> set[Path]:
    result: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if path.suffix in SUFFIX_TO_LANGUAGE and path.exists():
            result.add(path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Fix Python and Rust files with missing REUSE SPDX headers.',
    )
    parser.add_argument(
        'paths',
        nargs='*',
        help='Optional Python/Rust files to fix. Defaults to files reported by `reuse lint`.',
    )
    args = parser.parse_args()

    if args.paths:
        candidates = existing_source_paths(args.paths)
    else:
        candidates = files_with_reuse_issues(run_reuse_lint())

    if not candidates:
        print('No REUSE header fixes needed.')
        return 0

    failures: list[Path] = []
    for path in sorted(candidates):
        lang = SUFFIX_TO_LANGUAGE[path.suffix]
        remove_known_legacy_header(path, lang)
        if not annotate(path):
            failures.append(path)
            continue
        normalize_reuse_header(path, lang)

    remaining = files_with_reuse_issues(run_reuse_lint())
    remaining = {path for path in remaining if path in candidates}

    if failures or remaining:
        print('Some headers still need manual fixes:', file=sys.stderr)
        for path in sorted(set(failures) | remaining):
            print(f'  {path}', file=sys.stderr)
        return 1

    print(f'Fixed REUSE headers in {len(candidates)} file(s).')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
