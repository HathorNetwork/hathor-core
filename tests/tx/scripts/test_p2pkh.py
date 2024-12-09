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

from hathor.transaction.scripts import P2PKH, Opcode
from hathor.transaction.scripts.sighash import InputsOutputsLimit, SighashAll, SighashBitmask, SighashRange


def test_create_input_data_simple() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    data = P2PKH.create_input_data(public_key_bytes=pub_key, signature=signature)

    assert data == bytes([
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])


def test_create_input_data_with_sighash_all() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    data = P2PKH.create_input_data(public_key_bytes=pub_key, signature=signature, sighash=SighashAll())

    assert data == bytes([
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])


def test_create_input_data_with_sighash_bitmask() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    inputs_bitmask = 0b111
    outputs_bitmask = 0b101
    sighash = SighashBitmask(inputs=inputs_bitmask, outputs=outputs_bitmask)
    data = P2PKH.create_input_data(public_key_bytes=pub_key, signature=signature, sighash=sighash)

    assert data == bytes([
        1,
        inputs_bitmask,
        1,
        outputs_bitmask,
        Opcode.OP_SIGHASH_BITMASK,
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])


def test_create_input_data_with_sighash_range() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    input_start = 123
    input_end = 145
    output_start = 10
    output_end = 20
    sighash = SighashRange(
        input_start=input_start,
        input_end=input_end,
        output_start=output_start,
        output_end=output_end,
    )
    data = P2PKH.create_input_data(public_key_bytes=pub_key, signature=signature, sighash=sighash)

    assert data == bytes([
        1,
        input_start,
        1,
        input_end,
        1,
        output_start,
        1,
        output_end,
        Opcode.OP_SIGHASH_RANGE,
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])


def test_create_input_data_with_inputs_outputs_limit() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    max_inputs = 2
    max_outputs = 3
    limit = InputsOutputsLimit(max_inputs=max_inputs, max_outputs=max_outputs)
    data = P2PKH.create_input_data(public_key_bytes=pub_key, signature=signature, inputs_outputs_limit=limit)

    assert data == bytes([
        1,
        max_inputs,
        1,
        max_outputs,
        Opcode.OP_MAX_INPUTS_OUTPUTS,
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])


def test_create_input_data_with_max_sighash_subsets() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    max_subsets = 7
    data = P2PKH.create_input_data(public_key_bytes=pub_key, signature=signature, max_sighash_subsets=max_subsets)

    assert data == bytes([
        1,
        max_subsets,
        Opcode.OP_MAX_SIGHASH_SUBSETS,
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])


def test_create_input_data_with_sighash_bitmask_and_inputs_outputs_limit() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    inputs_bitmask = 0b111
    outputs_bitmask = 0b101
    max_inputs = 2
    max_outputs = 3
    sighash = SighashBitmask(inputs=inputs_bitmask, outputs=outputs_bitmask)
    limit = InputsOutputsLimit(max_inputs=max_inputs, max_outputs=max_outputs)
    data = P2PKH.create_input_data(
        public_key_bytes=pub_key,
        signature=signature,
        sighash=sighash,
        inputs_outputs_limit=limit
    )

    assert data == bytes([
        1,
        inputs_bitmask,
        1,
        outputs_bitmask,
        Opcode.OP_SIGHASH_BITMASK,
        1,
        max_inputs,
        1,
        max_outputs,
        Opcode.OP_MAX_INPUTS_OUTPUTS,
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])


def test_create_input_data_with_sighash_range_and_inputs_outputs_limit() -> None:
    pub_key = b'my_pub_key'
    signature = b'my_signature'
    input_start = 123
    input_end = 145
    output_start = 10
    output_end = 20
    max_inputs = 2
    max_outputs = 3
    sighash = SighashRange(
        input_start=input_start,
        input_end=input_end,
        output_start=output_start,
        output_end=output_end,
    )
    limit = InputsOutputsLimit(max_inputs=max_inputs, max_outputs=max_outputs)
    data = P2PKH.create_input_data(
        public_key_bytes=pub_key,
        signature=signature,
        sighash=sighash,
        inputs_outputs_limit=limit
    )

    assert data == bytes([
        1,
        input_start,
        1,
        input_end,
        1,
        output_start,
        1,
        output_end,
        Opcode.OP_SIGHASH_RANGE,
        1,
        max_inputs,
        1,
        max_outputs,
        Opcode.OP_MAX_INPUTS_OUTPUTS,
        len(signature),
        *signature,
        len(pub_key),
        *pub_key
    ])
