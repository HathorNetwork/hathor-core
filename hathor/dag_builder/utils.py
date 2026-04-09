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

from hathor.dag_builder.tokenizer import MULTILINE_DELIMITER

TEXT_DELIMITER = '"'
LITERAL_DELIMITERS = [TEXT_DELIMITER, MULTILINE_DELIMITER]


def is_literal(value: str) -> bool:
    """Return true if the value is a literal."""
    return _get_literal_delimiter(value) is not None


def get_literal(value: str) -> str:
    """Return the content of the literal."""
    delimiter = _get_literal_delimiter(value)
    assert delimiter is not None
    n = len(delimiter)
    return value[n:-n]


def _get_literal_delimiter(value: str) -> str | None:
    """Return the delimiter if value is a literal, None otherwise."""
    for delimiter in LITERAL_DELIMITERS:
        if value.startswith(delimiter) and value.endswith(delimiter):
            return delimiter
    return None


def parse_amount_token(value: str) -> tuple[str, int, list[str]]:
    """Parse the format "[amount] [token_symbol] [args]"."""
    parts = value.split()
    token = parts[1]
    amount = int(parts[0])
    args = parts[2:]
    return (token, amount, args)
