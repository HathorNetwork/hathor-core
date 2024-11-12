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

def is_literal(value: str) -> bool:
    """Return true if the value is a literal."""
    if value[0] == '"' and value[-1] == '"':
        return True
    return False


def get_literal(value: str) -> str:
    """Return the content of the literal."""
    assert value[0] == value[-1] and value[0] == '"'
    return value[1:-1]


def parse_amount_token(value: str) -> tuple[str, int, list[str]]:
    """Parse the format "[amount] [token_symbol] [args]"."""
    parts = value.split()
    token = parts[1]
    amount = int(parts[0])
    args = parts[2:]
    return (token, amount, args)
