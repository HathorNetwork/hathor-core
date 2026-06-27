# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import struct
from typing import Union

from hathor.transaction.scripts.opcode import Opcode


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
