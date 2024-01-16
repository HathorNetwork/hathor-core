# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
from typing import TYPE_CHECKING, Any, Generator, NamedTuple, Optional, Pattern, Union

from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import decode_address
from hathor.transaction.exceptions import ScriptError
from hathor.transaction.scripts.base_script import BaseScript

if TYPE_CHECKING:
    from hathor.transaction.scripts import P2PKH, MultiSig, Opcode


def re_compile(pattern: str) -> Pattern[bytes]:
    """ Transform a given script pattern into a regular expression.

    The script pattern is like a regular expression, but you may include five
    special symbols:
      (i) OP_DUP, OP_HASH160, and all other opcodes;
     (ii) DATA_<length>: data with the specified length;
    (iii) NUMBER: a 4-byte integer;
     (iv) BLOCK: a variable length block, to be parsed later

    Example:
    >>> r = re_compile(
    ...     '^(?:DATA_4 OP_GREATERTHAN_TIMESTAMP)? '
    ...     'OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKSIG$'
    ... )

    :return: A compiled regular expression matcher
    :rtype: :py:class:`re.Pattern`
    """

    def _to_byte_pattern(m):
        x = m.group().decode('ascii').strip()
        if x.startswith('OP_'):
            from hathor.transaction.scripts.opcode import Opcode
            return bytes([Opcode[x]])
        elif x.startswith('DATA_'):
            length = int(m.group()[5:])
            return _re_pushdata(length)
        elif x.startswith('NUMBER'):
            return b'.{5}'
        elif x.startswith('BLOCK'):
            return b'.*'
        else:
            raise ValueError('Invalid opcode: {}'.format(x))

    p = pattern.encode('ascii')
    p = re.sub(rb'\s*([A-Z0-9_]+)\s*', _to_byte_pattern, p)
    return re.compile(p, re.DOTALL)


def _re_pushdata(length: int) -> bytes:
    """ Create a regular expression that matches a data block with a given length.

    :return: A non-compiled regular expression
    :rtype: bytes
    """
    from hathor.transaction.scripts.opcode import Opcode
    ret = [bytes([Opcode.OP_PUSHDATA1]), bytes([length]), b'.{', str(length).encode('ascii'), b'}']

    if length <= 75:
        # for now, we accept <= 75 bytes with OP_PUSHDATA1. It's optional
        ret.insert(1, b'?')

    return b''.join(ret)


def create_base_script(address: str, timelock: Optional[Any] = None) -> BaseScript:
    """ Verifies if address is P2PKH or Multisig and return the corresponding BaseScript implementation.
    """
    from hathor.transaction.scripts.execute import binary_to_int
    settings = get_global_settings()
    baddress = decode_address(address)
    if baddress[0] == binary_to_int(settings.P2PKH_VERSION_BYTE):
        from hathor.transaction.scripts import P2PKH
        return P2PKH(address, timelock)
    elif baddress[0] == binary_to_int(settings.MULTISIG_VERSION_BYTE):
        from hathor.transaction.scripts import MultiSig
        return MultiSig(address, timelock)
    else:
        raise ScriptError('The address is not valid')


def create_output_script(address: bytes, timelock: Optional[Any] = None) -> bytes:
    """ Verifies if address is P2PKH or Multisig and create correct output script

        :param address: address to send tokens
        :type address: bytes

        :param timelock: timestamp until when the output is locked
        :type timelock: bytes

        :raises ScriptError: if address is not from one of the possible options

        :rtype: bytes
    """
    from hathor.transaction.scripts.execute import binary_to_int
    settings = get_global_settings()
    # XXX: if the address class can somehow be simplified create_base_script could be used here
    if address[0] == binary_to_int(settings.P2PKH_VERSION_BYTE):
        from hathor.transaction.scripts import P2PKH
        return P2PKH.create_output_script(address, timelock)
    elif address[0] == binary_to_int(settings.MULTISIG_VERSION_BYTE):
        from hathor.transaction.scripts import MultiSig
        return MultiSig.create_output_script(address, timelock)
    else:
        raise ScriptError('The address is not valid')


def parse_address_script(script: bytes) -> Optional[Union['P2PKH', 'MultiSig']]:
    """ Verifies if address is P2PKH or Multisig and calls correct parse_script method

        :param script: script to decode
        :type script: bytes

        :return: P2PKH or MultiSig class or None
        :rtype: class or None
    """
    from hathor.transaction.scripts import P2PKH, MultiSig
    script_classes: list[type[Union[P2PKH, MultiSig]]] = [P2PKH, MultiSig]
    # Each class verifies its script
    for script_class in script_classes:
        if script_class.re_match.search(script):
            return script_class.parse_script(script)
    return None


class _ScriptOperation(NamedTuple):
    opcode: Union['Opcode', int]
    position: int
    data: Union[None, bytes, int, str]


def parse_script_ops(data: bytes) -> Generator[_ScriptOperation, None, None]:
    """ Parse script yielding each operation on the script
        this is an utility function to make scripts human readable for debugging and dev

        :param data: script to parse that contains data and opcodes
        :type data: bytes

        :return: generator for operations on script
        :rtype: Generator[_ScriptOperation, None, None]
    """
    from hathor.transaction.scripts import Opcode
    from hathor.transaction.scripts.execute import Stack, get_script_op
    op: Union[Opcode, int]

    pos = 0
    last_pos = 0
    data_len = len(data)
    stack: Stack = []
    while pos < data_len:
        last_pos = pos
        opcode, pos = get_script_op(pos, data, stack)
        try:
            op = Opcode(opcode)
        except ValueError:
            op = opcode
        if len(stack) != 0:
            yield _ScriptOperation(opcode=op, position=last_pos, data=stack.pop())
        else:
            yield _ScriptOperation(opcode=op, position=last_pos, data=None)


def count_sigops(data: bytes) -> int:
    """ Count number of signature operations on the script

        :param data: script to parse that contains data and opcodes
        :type data: bytes

        :raises OutOfData: when trying to read out of script
        :raises InvalidScriptError: when an invalid opcode is found
        :raises InvalidScriptError: when the previous opcode to an
                OP_CHECKMULTISIG is not an integer (number of operations to execute)

        :return: number of signature operations the script would do if it was executed
        :rtype: int
    """
    from hathor.transaction.scripts import Opcode
    from hathor.transaction.scripts.execute import decode_opn, get_script_op
    settings = get_global_settings()
    n_ops: int = 0
    data_len: int = len(data)
    pos: int = 0
    last_opcode: Union[int, None] = None

    while pos < data_len:
        opcode, pos = get_script_op(pos, data)

        if opcode == Opcode.OP_CHECKSIG:
            n_ops += 1
        elif opcode == Opcode.OP_CHECKMULTISIG:
            assert isinstance(last_opcode, int)
            if Opcode.OP_0 <= last_opcode <= Opcode.OP_16:
                # Conventional OP_CHECKMULTISIG: <sign_1>...<sign_m> <m> <pubkey_1>...<pubkey_n> <n> <checkmultisig>
                # this function will run op_checksig with each pair (sign_x, pubkey_y) until all signatures
                # are verified so the worst case scenario is n op_checksig and the best m op_checksig
                # we know m <= n, so for now we are counting n operations (the upper limit)
                n_ops += decode_opn(last_opcode)
            else:
                # Unconventional OP_CHECKMULTISIG:
                # We count the limit for PUBKEYS, since this is also the upper limit on signature operations
                # that any op_checkmultisig would run
                n_ops += settings.MAX_MULTISIG_PUBKEYS
        last_opcode = opcode
    return n_ops


def get_sigops_count(data: bytes, output_script: Optional[bytes] = None) -> int:
    """ Count number of signature operations on the script, if it's an input script and the spent output is passed
        check the spent output for MultiSig and count operations on redeem_script too

        :param data: script to parse with opcodes
        :type data: bytes

        :param output_script: spent output script if data was from an TxIn
        :type output_script: Union[None, bytes]

        :raises OutOfData: when trying to read out of script
        :raises InvalidScriptError: when an invalid opcode is found

        :return: number of signature operations the script would do if it was executed
        :rtype: int
    """
    # If validating an input, should check the spent_tx for MultiSig
    if output_script is not None:
        # If it's multisig we have to validate the redeem_script sigop count
        from hathor.transaction.scripts import MultiSig
        if MultiSig.re_match.search(output_script):
            multisig_data = MultiSig.get_multisig_data(data)
            # input_script + redeem_script
            return count_sigops(multisig_data)

    return count_sigops(data)


def get_pushdata(data: bytes) -> bytes:
    if data[0] > 75:
        length = data[1]
        start = 2
    else:
        length = data[0]
        start = 1
    return data[start:(start + length)]
