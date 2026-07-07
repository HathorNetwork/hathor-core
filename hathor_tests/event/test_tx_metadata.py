# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
