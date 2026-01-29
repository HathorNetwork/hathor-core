"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""
from hathor.transaction.scripts.construct import get_pushdata

from typing import Any, Dict, Optional

from hathorlib.scripts.base_script import BaseScript
from hathorlib.scripts.hathor_script import HathorScript
from hathorlib.scripts.opcode import Opcode


class DataScript(BaseScript):
    def __init__(self, data: str) -> None:
        """This class represents a data script usually used by NFT transactions.
        The script has a data field and ends with an OP_CHECKSIG so it can't be spent.

        The script format is: <DATA_N> <OP_CHECKSIG>

        :param data: data string to be stored in the script
        :type data: string
        """
        self.data = data

    def to_human_readable(self) -> Dict[str, Any]:
        """ Decode DataScript class with type and data

            :return: Dict with ScriptData info
            :rtype: Dict[str:]
        """
        ret: Dict[str, Any] = {}
        ret['type'] = self.get_type()
        ret['data'] = self.data
        return ret

    def get_type(self) -> str:
        return 'Data'

    def get_script(self) -> bytes:
        return DataScript.create_output_script(self.data)

    @classmethod
    def create_output_script(cls, data: str) -> bytes:
        """
        :param data: Data to be stored in the script
        :type data: string

        :rtype: bytes
        """
        s = HathorScript()
        s.pushData(data.encode('utf-8'))
        s.addOpcode(Opcode.OP_CHECKSIG)
        return s.data

    @classmethod
    def parse_script(cls, script: bytes) -> Optional['DataScript']:
        """Checks if the given script is of type data script. If it is, returns the DataScript object.
        Otherwise, returns None.

        :param script: script to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.DataScript` or None
        """
        if len(script) < 2:
            # At least 1 byte for len data and 1 byte for OP_CHECKSIG
            return None

        # The expected len will be at least 2 bytes
        # 1 for the script len and 1 for the OP_CHECKSIG in the end
        expected_script_len = 2

        if script[0] == Opcode.OP_PUSHDATA1:
            expected_script_len += 1
            data_bytes_len = script[1]
        else:
            data_bytes_len = script[0]

        expected_script_len += data_bytes_len

        if expected_script_len != len(script):
            # Script is not a DataScript
            return None

        if script[-1] != Opcode.OP_CHECKSIG:
            # Last script byte must be an OP_CHECKSIG
            return None

        # Get the data from the script
        data = get_pushdata(script)

        try:
            decoded_str = data.decode('utf-8')
            return cls(decoded_str)
        except UnicodeDecodeError:
            return None


