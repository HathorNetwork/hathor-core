#  Copyright 2023 Hathor Labs
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

import hashlib
from unittest.mock import Mock

import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import ScriptError
from hathor.transaction.scripts.script_context import ScriptContext
from hathor.transaction.scripts.sighash import SighashAll, SighashBitmask


@pytest.mark.parametrize(['max_num_outputs'], [(99,), (255,)])
def test_defaults(max_num_outputs: int) -> None:
    settings = Mock(spec_set=HathorSettings)
    settings.MAX_NUM_OUTPUTS = max_num_outputs

    context = ScriptContext(settings=settings, stack=Mock(), logs=[], extras=Mock())

    tx = Transaction(
        inputs=[
            TxInput(tx_id=b'tx1', index=0, data=b''),
            TxInput(tx_id=b'tx2', index=1, data=b''),
        ],
        outputs=[
            TxOutput(value=11, script=b''),
            TxOutput(value=22, script=b''),
        ]
    )

    assert context._sighash == SighashAll()
    assert context.get_tx_sighash_data(tx) == tx.get_sighash_all_data()
    assert context.get_selected_outputs() == set(range(max_num_outputs))


def test_set_sighash() -> None:
    context = ScriptContext(settings=Mock(), stack=Mock(), logs=[], extras=Mock())

    sighash = SighashBitmask(inputs=0b111, outputs=0b101)
    context.set_sighash(sighash)
    assert context._sighash == sighash

    with pytest.raises(ScriptError):
        context.set_sighash(sighash)


@pytest.mark.parametrize(
    ['outputs_bitmask', 'selected_outputs'],
    [
        (0b00, set()),
        (0b01, {0}),
        (0b10, {1}),
        (0b11, {0, 1}),
    ]
)
def test_sighash_bitmask(outputs_bitmask: int, selected_outputs: set[int]) -> None:
    settings = Mock()
    settings.MAX_NUM_INPUTS = 88
    settings.MAX_NUM_OUTPUTS = 99

    context = ScriptContext(settings=settings, stack=Mock(), logs=[], extras=Mock())
    tx = Transaction(
        inputs=[
            TxInput(tx_id=b'tx1', index=0, data=b''),
            TxInput(tx_id=b'tx2', index=1, data=b''),
        ],
        outputs=[
            TxOutput(value=11, script=b''),
            TxOutput(value=22, script=b''),
        ]
    )

    sighash_bitmask = SighashBitmask(inputs=0b11, outputs=outputs_bitmask)
    context.set_sighash(sighash_bitmask)

    data = tx.get_custom_sighash_data(sighash_bitmask)
    assert context.get_tx_sighash_data(tx) == hashlib.sha256(data).digest()

    with pytest.raises(ScriptError) as e:
        context.set_sighash(Mock())

    assert str(e.value) == 'Cannot modify sighash after it is already set.'
    assert context.get_selected_outputs() == selected_outputs
