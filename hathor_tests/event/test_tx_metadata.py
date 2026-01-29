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

from hathor.event.model.event_data import SpentOutput, TxMetadata


def test_from_spent_output_instance() -> None:
    spent_outputs = [
        SpentOutput(index=0, tx_ids=['a', 'b']),
        SpentOutput(index=1, tx_ids=['c', 'd']),
    ]
    metadata = TxMetadata(
        hash='some_hash',
        spent_outputs=spent_outputs,
        conflict_with=[],
        voided_by=[],
        received_by=[],
        twins=[],
        accumulated_weight=0.0,
        score=0.0,
        accumulated_weight_raw="0",
        score_raw="0",
        first_block=None,
        height=0,
        validation='some_validation'
    )

    assert metadata.spent_outputs == spent_outputs


def test_from_spent_output_list() -> None:
    spent_outputs = [
        SpentOutput(index=0, tx_ids=['a', 'b']),
        SpentOutput(index=1, tx_ids=['c', 'd']),
    ]
    metadata = TxMetadata.model_validate(
        dict(
            hash='some_hash',
            spent_outputs=[
                [0, ['a', 'b']],
                [1, ['c', 'd']]
            ],
            conflict_with=[],
            voided_by=[],
            received_by=[],
            children=[],
            twins=[],
            accumulated_weight=0.0,
            score=0.0,
            accumulated_weight_raw="0",
            score_raw="0",
            first_block=None,
            height=0,
            validation='some_validation'
        )
    )

    assert metadata.spent_outputs == spent_outputs


def test_from_spent_output_dict() -> None:
    spent_outputs = [
        SpentOutput(index=0, tx_ids=['a', 'b']),
        SpentOutput(index=1, tx_ids=['c', 'd']),
    ]
    metadata = TxMetadata.model_validate(
        dict(
            hash='some_hash',
            spent_outputs=[
                dict(index=0, tx_ids=['a', 'b']),
                dict(index=1, tx_ids=['c', 'd'])
            ],
            conflict_with=[],
            voided_by=[],
            received_by=[],
            children=[],
            twins=[],
            accumulated_weight=0.0,
            score=0.0,
            accumulated_weight_raw="0",
            score_raw="0",
            first_block=None,
            height=0,
            validation='some_validation'
        )
    )

    assert metadata.spent_outputs == spent_outputs
