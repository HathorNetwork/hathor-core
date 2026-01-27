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
from typing import Any, Optional

from hathorlib.utils import decode_address, get_address_b58_from_redeem_script_hash
from hathorlib.scripts.base_script import BaseScript
from hathorlib.scripts.construct import get_pushdata, re_compile
from hathorlib.scripts.execute import Stack, get_script_op
from hathorlib.scripts.hathor_script import HathorScript
from hathorlib.scripts.opcode import Opcode, op_pushdata, op_pushdata1


class MultiSig(BaseScript):
    re_match = re_compile('^(?:(DATA_4) OP_GREATERTHAN_TIMESTAMP)? ' 'OP_HASH160 (DATA_20) OP_EQUAL$')

    def __init__(self, address: str, timelock: Optional[Any] = None) -> None:
        """This class represents the multi signature script (MultiSig). It enables the group of persons
        who has the corresponding private keys of the address to spend the tokens.

        This script validates the signatures and public keys on the corresponding input
        data.

        Output script and the corresponding input data are usually represented like:
        output script: OP_HASH160 <redeemScriptHash> OP_EQUAL
        input data: <sig1> ... <sigM> <redeemScript>

        :param address: address to send tokens
        :type address: string(base58)

        :param timelock: timestamp until when it's locked
        :type timelock: int
        """
        self.address = address
        self.timelock = timelock

    def to_human_readable(self) -> dict[str, Any]:
        """ Decode MultiSig class to dict with its type and data

            :return: dict with MultiSig info
            :rtype: dict[str:]
        """
        ret: dict[str, Any] = {}
        ret['type'] = self.get_type()
        ret['address'] = self.address
        ret['timelock'] = self.timelock
        return ret

    def get_type(self) -> str:
        return 'MultiSig'

    def get_script(self) -> bytes:
        return MultiSig.create_output_script(decode_address(self.address), self.timelock)

    def get_address(self) -> str:
        return self.address

    def get_timelock(self) -> Optional[int]:
        return self.timelock

    @classmethod
    def get_multisig_redeem_script_pos(cls, input_data: bytes) -> int:
        """ Get the position of the opcode that pushed the redeem_script on the stack

        :param input_data: data from the input being evaluated
        :type input_data: bytes

        :return: position of pushdata for redeem_script
        :rtype: int
        """
        pos = 0
        last_pos = 0
        data_len = len(input_data)
        while pos < data_len:
            last_pos = pos
            _, pos = get_script_op(pos, input_data)
        return last_pos

    @classmethod
    def create_output_script(cls, address: bytes, timelock: Optional[Any] = None) -> bytes:
        """
        :param address: address to send tokens
        :type address: bytes

        :param timelock: timestamp until when the output is locked
        :type timelock: bytes

        :rtype: bytes
        """
        assert len(address) == 25
        redeem_script_hash = address[1:-4]
        s = HathorScript()
        if timelock:
            s.pushData(timelock)
            s.addOpcode(Opcode.OP_GREATERTHAN_TIMESTAMP)
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(redeem_script_hash)
        s.addOpcode(Opcode.OP_EQUAL)
        return s.data

    @classmethod
    def create_input_data(cls, redeem_script: bytes, signatures: list[bytes]) -> bytes:
        """
        :param redeem_script: script to redeem the tokens: <M> <pubkey1> ... <pubkeyN> <N> <OP_CHECKMULTISIG>
        :type redeem_script: bytes

        :param signatures: array of signatures to validate the input and redeem the tokens
        :type signagures: list[bytes]

        :rtype: bytes
        """
        s = HathorScript()
        for signature in signatures:
            s.pushData(signature)
        s.pushData(redeem_script)
        return s.data

    @classmethod
    def parse_script(cls, script: bytes) -> Optional['MultiSig']:
        """Checks if the given script is of type multisig. If it is, returns the MultiSig object.
        Otherwise, returns None.

        :param script: script to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.MultiSig` or None
        """
        match = cls.re_match.search(script)
        if match:
            groups = match.groups()
            timelock = None
            pushdata_timelock = groups[0]
            if pushdata_timelock:
                timelock_bytes = get_pushdata(pushdata_timelock)
                timelock = struct.unpack('!I', timelock_bytes)[0]
            redeem_script_hash = get_pushdata(groups[1])
            address_b58 = get_address_b58_from_redeem_script_hash(redeem_script_hash)
            return cls(address_b58, timelock)
        return None

    @classmethod
    def get_multisig_data(cls, input_data: bytes) -> bytes:
        """ Input data has many signatures and a block with the redeem script
            In the second part of the script eval we need to evaluate the redeem script
            so we need to get the redeem script without the block, to evaluate the elements on it

            This method removes the (possible) OP_PUSHDATA1 byte and the redeem script length,
            so it can be evaluated as any normal script

            :param input_data: data from the input being evaluated
            :type input_data: bytes

            :return: data ready to be evaluated. The signatures and the redeem script
            :rtype: bytes
        """
        pos = 0
        last_pos = 0
        stack: Stack = []
        data_len = len(input_data)
        while pos < data_len:
            last_pos = pos
            opcode = input_data[pos]
            if (opcode >= 1 and opcode <= 75):
                pos = op_pushdata(pos, input_data, stack)
            elif opcode == Opcode.OP_PUSHDATA1:
                pos = op_pushdata1(pos, input_data, stack)
            else:
                pos += 1

        redeem_script = stack[-1]
        assert isinstance(redeem_script, bytes)
        return input_data[:last_pos] + redeem_script
