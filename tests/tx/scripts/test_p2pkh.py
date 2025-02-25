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
from hathor.transaction.scripts.sighash import InputsOutputsLimit, SighashBitmask


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
