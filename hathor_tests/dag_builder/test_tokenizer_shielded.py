#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.dag_builder.tokenizer import TokenType, tokenize


def test_tokenize_shielded_output_default_mode() -> None:
    tokens = list(tokenize('tx1.sout[0] = 30 HTR [wallet1]'))
    assert tokens == [(TokenType.SHIELDED_OUTPUT, ('tx1', 0, 30, 'HTR', ['[wallet1]']))]


def test_tokenize_shielded_output_full_mode() -> None:
    tokens = list(tokenize('tx1.sout[2] = 10 HTR [wallet1] [full-shielded]'))
    assert tokens == [
        (TokenType.SHIELDED_OUTPUT, ('tx1', 2, 10, 'HTR', ['[wallet1]', '[full-shielded]'])),
    ]


def test_tokenize_transparent_output_still_works() -> None:
    tokens = list(tokenize('tx1.out[0] = 100 HTR [wallet1]'))
    assert tokens == [(TokenType.OUTPUT, ('tx1', 0, 100, 'HTR', ['[wallet1]']))]
