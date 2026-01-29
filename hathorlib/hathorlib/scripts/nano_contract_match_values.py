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

import base64
import struct
from typing import Any, Optional

from hathorlib.utils import get_address_b58_from_bytes
from hathorlib.scripts.construct import get_pushdata, re_compile
from hathorlib.scripts.execute import binary_to_int
from hathorlib.scripts.hathor_script import HathorScript
from hathorlib.scripts.opcode import Opcode


# XXX: does it make sense to make this BaseScript too?
class NanoContractMatchValues:
    re_match = re_compile('^OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKDATASIG OP_0 (BLOCK) OP_DATA_STREQUAL '
                          'OP_1 (NUMBER) OP_DATA_GREATERTHAN OP_2 (BLOCK) OP_DATA_MATCH_VALUE OP_FIND_P2PKH$')

    def __init__(self, oracle_pubkey_hash, min_timestamp, oracle_data_id, value_dict, fallback_pubkey_hash=b'\x00'):
        """This class represents a nano contract that tries to match on a single value. The pubKeyHash
        associated with the data given by the oracle will be able to spend the contract tokens.

        :param oracle_pubkey_hash: oracle's public key after being hashed by SHA256 and RIPMD160
        :type oracle_pubkey_hash: bytes

        :param min_timestamp: contract can only be spent after this timestamp. If we don't need it, simply
        pass same timestamp as transaction
        :type min_timestamp: int

        :param oracle_data_id: unique id for the data reported by the oracle. For eg, a oracle that reports
        stock prices can use stock ticker symbols as this id
        :type oracle_data_id: bytes

        :param value_dict: a dictionary with the pubKeyHash and corresponding value ({pubKeyHash, value}).
        The pubkeyHash with value matching the data sent by oracle will be able to spend the contract funds
        :type value_dict: dict[bytes, int]

        :param fallback_pubkey_hash: if none of the values match, this pubkey hash identifies the winner address
        :type fallback_pubkey_hash: bytes
        """
        self.oracle_pubkey_hash = oracle_pubkey_hash
        self.min_timestamp = min_timestamp
        self.oracle_data_id = oracle_data_id
        self.value_dict = value_dict  # dict[bytes, int]
        self.fallback_pubkey_hash = fallback_pubkey_hash

    def to_human_readable(self) -> dict[str, Any]:
        ret: dict[str, Any] = {}
        ret['type'] = 'NanoContractMatchValues'
        ret['oracle_pubkey_hash'] = base64.b64encode(self.oracle_pubkey_hash).decode('utf-8')
        ret['min_timestamp'] = self.min_timestamp
        ret['oracle_data_id'] = self.oracle_data_id.decode('utf-8')
        ret['value_dict'] = {get_address_b58_from_bytes(k): v for k, v in self.value_dict.items()}
        try:
            if len(self.fallback_pubkey_hash) == 1:
                ret['fallback_pubkey_hash'] = None
            else:
                ret['fallback_pubkey_hash'] = get_address_b58_from_bytes(self.fallback_pubkey_hash)
        except TypeError:
            ret['fallback_pubkey_hash'] = None
        return ret

    def create_output_script(self) -> bytes:
        """
        :return: the output script in binary
        :rtype: bytes
        """
        s = HathorScript()
        s.addOpcode(Opcode.OP_DUP)
        s.addOpcode(Opcode.OP_HASH160)
        s.pushData(self.oracle_pubkey_hash)
        s.addOpcode(Opcode.OP_EQUALVERIFY)
        s.addOpcode(Opcode.OP_CHECKDATASIG)
        # compare first value from data with oracle_data_id
        s.addOpcode(Opcode.OP_0)
        s.pushData(self.oracle_data_id)
        s.addOpcode(Opcode.OP_DATA_STREQUAL)
        # compare second value from data with min_timestamp
        s.addOpcode(Opcode.OP_1)
        s.pushData(struct.pack('!I', self.min_timestamp))
        s.addOpcode(Opcode.OP_DATA_GREATERTHAN)
        # finally, compare third value with values on dict
        s.addOpcode(Opcode.OP_2)
        s.pushData(self.fallback_pubkey_hash)
        for pubkey_hash, value in self.value_dict.items():
            s.pushData(value)
            s.pushData(pubkey_hash)
        # we use int as bytes because it may be greater than 16
        # TODO should we limit it to 16?
        s.pushData(len(self.value_dict))
        s.addOpcode(Opcode.OP_DATA_MATCH_VALUE)
        # pubkey left on stack should be on outputs
        s.addOpcode(Opcode.OP_FIND_P2PKH)
        return s.data

    @classmethod
    def create_input_data(cls, data: bytes, oracle_sig: bytes, oracle_pubkey: bytes) -> bytes:
        """
        :param data: data from the oracle
        :type data: bytes

        :param oracle_sig: the data signed by the oracle, with its private key
        :type oracle_sig: bytes

        :param oracle_pubkey: the oracle's public key
        :type oracle_pubkey: bytes

        :rtype: bytes
        """
        s = HathorScript()
        s.pushData(data)
        s.pushData(oracle_sig)
        s.pushData(oracle_pubkey)
        return s.data

    @classmethod
    def parse_script(cls, script: bytes) -> Optional['NanoContractMatchValues']:
        """Checks if the given script is of type NanoContractMatchValues. If it is, returns the corresponding object.
        Otherwise, returns None.

        :param script: script to check
        :type script: bytes

        :rtype: :py:class:`hathor.transaction.scripts.NanoContractMatchValues` or None
        """
        # regex for this is a bit tricky, as some data has variable length. We first match the base regex for this
        # script and later manually parse variable length fields
        match = cls.re_match.search(script)
        if match:
            groups = match.groups()
            # oracle pubkey hash
            oracle_pubkey_hash = get_pushdata(groups[0])
            # oracle data id
            oracle_data_id = get_pushdata(groups[1])
            # timestamp
            timestamp = groups[2]
            min_timestamp = binary_to_int(timestamp[1:])

            # variable length data. We'll parse it manually. It should have the following format:
            # fallback_pubkey_hash, [valueN, pubkey_hash_N], N
            extra_data = groups[3]

            fallback_pubkey_len = extra_data[0]
            if len(extra_data) < fallback_pubkey_len + 2:
                # extra data has at least the fallback_pubkey length (1 byte) and number of
                # values (N, after values and pubkeys). That's why we use fallback_pubkey_len + 2
                return None
            fallback_pubkey = extra_data[1] if fallback_pubkey_len == 1 else extra_data[1:fallback_pubkey_len]
            n_values = extra_data[-1]

            values_pubkeys = extra_data[(fallback_pubkey_len + 1):-2]
            value_dict = {}
            pos = 0
            for i in range(n_values):
                if len(values_pubkeys[pos:]) < 1:
                    return None
                value_len = values_pubkeys[pos]
                pos += 1
                if len(values_pubkeys[pos:]) < value_len:
                    return None
                value = values_pubkeys[pos] if value_len == 1 else binary_to_int(values_pubkeys[pos:(pos + value_len)])
                pos += value_len
                if len(values_pubkeys[pos:]) < 1:
                    return None
                pubkey_len = values_pubkeys[pos]
                pos += 1
                if len(values_pubkeys[pos:]) < pubkey_len:
                    return None
                pubkey = values_pubkeys[pos:(pos + pubkey_len)]
                pos += pubkey_len
                value_dict[pubkey] = value

            if len(values_pubkeys[pos:]) > 0:
                # shouldn't have data left
                return None

            return NanoContractMatchValues(oracle_pubkey_hash, min_timestamp, oracle_data_id, value_dict,
                                           fallback_pubkey)
        return None
