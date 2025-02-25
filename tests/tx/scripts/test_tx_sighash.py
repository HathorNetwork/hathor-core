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

from unittest.mock import patch

from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts.sighash import SighashBitmask


def test_get_sighash_bitmask() -> None:
    inputs = [
        TxInput(tx_id=b'tx1', index=0, data=b''),
        TxInput(tx_id=b'tx2', index=1, data=b''),
        TxInput(tx_id=b'tx3', index=1, data=b''),
        TxInput(tx_id=b'tx4', index=1, data=b''),
        TxInput(tx_id=b'tx5', index=1, data=b''),
        TxInput(tx_id=b'tx6', index=1, data=b''),
        TxInput(tx_id=b'tx7', index=1, data=b''),
        TxInput(tx_id=b'tx8', index=1, data=b''),
    ]
    outputs = [
        TxOutput(value=11, script=b''),
        TxOutput(value=22, script=b''),
        TxOutput(value=33, script=b''),
        TxOutput(value=44, script=b''),
        TxOutput(value=55, script=b''),
        TxOutput(value=66, script=b''),
        TxOutput(value=77, script=b''),
        TxOutput(value=88, script=b''),
    ]
    tx = Transaction(inputs=inputs, outputs=outputs)

    with patch.object(tx, '_get_sighash') as mock:
        tx.get_custom_sighash_data(SighashBitmask(inputs=0b0000_0001, outputs=0b0000_0000))
        mock.assert_called_once_with(inputs=inputs[0:1], outputs=[])
        mock.reset_mock()

        tx.get_custom_sighash_data(SighashBitmask(inputs=0b0000_0011, outputs=0b0000_0001))
        mock.assert_called_once_with(inputs=inputs[0:2], outputs=outputs[0:1])
        mock.reset_mock()

        tx.get_custom_sighash_data(SighashBitmask(inputs=0b0000_1111, outputs=0b0000_1111))
        mock.assert_called_once_with(inputs=inputs[0:4], outputs=outputs[0:4])
        mock.reset_mock()

        tx.get_custom_sighash_data(SighashBitmask(inputs=0b1110_0000, outputs=0b0111_0000))
        mock.assert_called_once_with(inputs=inputs[5:8], outputs=outputs[4:7])
        mock.reset_mock()

        tx.get_custom_sighash_data(SighashBitmask(inputs=0b1101_1010, outputs=0b1110_0010))
        mock.assert_called_once_with(
            inputs=[
                inputs[1],
                inputs[3],
                inputs[4],
                inputs[6],
                inputs[7],
            ],
            outputs=[
                outputs[1],
                outputs[5],
                outputs[6],
                outputs[7],
            ]
        )
        mock.reset_mock()
