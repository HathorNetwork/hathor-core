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

from hathorlib.utils import decode_address, get_address_b58_from_public_key_hash
from hathorlib.scripts.base_script import BaseScript
from hathorlib.scripts.construct import get_pushdata, re_compile
from hathorlib.scripts.hathor_script import HathorScript
from hathorlib.scripts.opcode import Opcode


class P2PKH(BaseScript):
    re_match = re_compile('^(?:(DATA_4) OP_GREATERTHAN_TIMESTAMP)? '
                          'OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKSIG$')

    def __init__(self, address: str, timelock: Optional[int] = None) -> None:
        """This class represents the pay to public hash key script. It enables the person
        who has the corresponding private key of the address to spend the tokens.

        This script validates the signature and public key on the corresponding input
        data. The public key is first checked against the script address and then the
        signature is verified, which means the sender owns the corresponding private key.

        Output script and the corresponding input data are usually represented like:
        input data: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        output script: <sig> <pubKey>

        :param address: address to send tokens
        :type address: string(base58)

        :param timelock: timestamp until when it's locked
        :type timelock: int
        """
        self.address = address
        self.timelock = timelock

    def to_human_readable(self) -> dict[str, Any]:
        ret: dict[str, Any] = {}
        ret['type'] = self.get_type()
        ret['address'] = self.address
        ret['timelock'] = self.timelock
        return ret

    def get_type(self) -> str:
        return 'P2PKH'

    def get_script(self) -> bytes:
        return P2PKH.create_output_script(decode_address(self.address), self.timelock)

    def get_address(self) -> str:
        return self.address

    def get_timelock(self) -> Optional[int]:
        return self.timelock

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
        public_key_hash = address[1:-4]
        s = HathorScript()
        if timelock:
            s.pushData(timelock)
            s.addOpcode(Opcode.OP_GREATERTHAN_TIMESTAMP)
        s.addOpcode(Opcode.OP_DUP)
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(public_key_hash)
        s.addOpcode(Opcode.OP_EQUALVERIFY)
        s.addOpcode(Opcode.OP_CHECKSIG)
        return s.data

    @classmethod
    def create_input_data(cls, public_key_bytes: bytes, signature: bytes) -> bytes:
        """
        :param private_key: key corresponding to the address we want to spend tokens from
        :type private_key: :py:class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`

        :rtype: bytes
        """
        s = HathorScript()
        s.pushData(signature)
        s.pushData(public_key_bytes)
        return s.data

    @classmethod
    def parse_script(cls, script: bytes) -> Optional['P2PKH']:
        """Checks if the given script is of type p2pkh. If it is, returns the P2PKH object.
        Otherwise, returns None.

        :param script: script to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.P2PKH` or None
        """
        match = cls.re_match.search(script)
        if match:
            groups = match.groups()
            timelock = None
            pushdata_timelock = groups[0]
            if pushdata_timelock:
                timelock_bytes = get_pushdata(pushdata_timelock)
                timelock = struct.unpack('!I', timelock_bytes)[0]
            pushdata_address = groups[1]
            public_key_hash = get_pushdata(pushdata_address)
            address_b58 = get_address_b58_from_public_key_hash(public_key_hash)
            return cls(address_b58, timelock)
        return None
