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

import struct
from typing import Union

from typing_extensions import assert_never

from hathor.transaction.scripts.opcode import Opcode
from hathor.transaction.scripts.sighash import (
    InputsOutputsLimit,
    SighashAll,
    SighashBitmask,
    SighashRange,
    SighashType,
)


class HathorScript:
    """This class is supposed to be help build scripts abstracting some corner cases.

    For example, when pushing data to the stack, we may or may not have to use OP_PUSHDATA.
    This is the sequence we have to add to the script:
    - len(data) <= 75: [len(data) data]
    - len(data) > 75: [OP_PUSHDATA1 len(data) data]

    pushData abstracts this differences and presents an unique interface.
    """
    def __init__(self) -> None:
        self.data = b''

    def addOpcode(self, opcode: Opcode) -> None:
        self.data += bytes([opcode])

    def pushData(self, data: Union[int, bytes]) -> None:
        if isinstance(data, int):
            if data > 4294967295:
                n = struct.pack('!Q', data)
            elif data > 65535:
                n = struct.pack('!I', data)
            elif data > 255:
                n = struct.pack('!H', data)
            else:
                n = struct.pack('!B', data)
            data = n
        if len(data) <= 75:
            self.data += (bytes([len(data)]) + data)
        else:
            self.data += (bytes([Opcode.OP_PUSHDATA1]) + bytes([len(data)]) + data)

    def push_sighash(self, sighash: SighashType) -> None:
        """Push a custom sighash to the script."""
        match sighash:
            case SighashAll():
                pass
            case SighashBitmask():
                self.pushData(sighash.inputs)
                self.pushData(sighash.outputs)
                self.addOpcode(Opcode.OP_SIGHASH_BITMASK)
            case SighashRange():
                self.pushData(sighash.input_start)
                self.pushData(sighash.input_end)
                self.pushData(sighash.output_start)
                self.pushData(sighash.output_end)
                self.addOpcode(Opcode.OP_SIGHASH_RANGE)
            case _:
                assert_never(sighash)

    def push_max_sighash_subsets(self, max_subsets: int | None) -> None:
        """Push a maximum limit for custom sighash subsets."""
        if max_subsets is None:
            return

        self.pushData(max_subsets)
        self.addOpcode(Opcode.OP_MAX_SIGHASH_SUBSETS)

    def push_inputs_outputs_limit(self, limit: InputsOutputsLimit | None) -> None:
        """Push a custom inputs and outputs limit to the script."""
        if not limit:
            return

        self.pushData(limit.max_inputs)
        self.pushData(limit.max_outputs)
        self.addOpcode(Opcode.OP_MAX_INPUTS_OUTPUTS)
