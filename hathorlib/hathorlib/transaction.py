"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

from __future__ import annotations

import struct
from collections import namedtuple
from struct import pack
from typing import TYPE_CHECKING, List, TypeVar

from hathorlib.base_transaction import TX_HASH_SIZE, BaseTransaction, TxInput, TxOutput
from hathorlib.conf import HathorSettings
from hathorlib.exceptions import InvalidOutputValue, InvalidToken
from hathorlib.headers import VertexBaseHeader
from hathorlib.utils import unpack, unpack_len

if TYPE_CHECKING:
    from hathorlib.headers import FeeHeader, NanoHeader

T = TypeVar('T', bound=VertexBaseHeader)

settings = HathorSettings()

# Signal bits (B), version (B), token uids len (B) and inputs len (B), outputs len (B).
_FUNDS_FORMAT_STRING = '!BBBBB'

# Signal bits (B), version (B), inputs len (B), and outputs len (B), token uids len (B).
_SIGHASH_ALL_FORMAT_STRING = '!BBBBB'

TokenInfo = namedtuple('TokenInfo', 'amount can_mint can_melt')


class Transaction(BaseTransaction):
    __slots__ = ('tokens',)

    SERIALIZATION_NONCE_SIZE = 4

    def __init__(self) -> None:
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__()
        self.tokens: List[bytes] = []

    @property
    def is_block(self) -> bool:
        """Returns true if this is a block"""
        return False

    @property
    def is_transaction(self) -> bool:
        """Returns true if this is a transaction"""
        return True

    def is_nano_contract(self) -> bool:
        try:
            self.get_nano_header()
        except ValueError:
            return False
        else:
            return True

    def has_fees(self) -> bool:
        """Returns true if this transaction has a fee header"""
        try:
            self.get_fee_header()
        except ValueError:
            return False
        else:
            return True

    def get_nano_header(self) -> NanoHeader:
        from hathorlib.headers import NanoHeader
        """Return the NanoHeader or raise ValueError."""
        return self._get_header(NanoHeader)

    def get_fee_header(self) -> FeeHeader:
        from hathorlib.headers import FeeHeader
        """Return the FeeHeader or raise ValueError."""
        return self._get_header(FeeHeader)

    def _get_header(self, header_type: type[T]) -> T:
        """Return the header of the given type or raise ValueError."""
        for header in self.headers:
            if isinstance(header, header_type):
                return header
        raise ValueError(f'{header_type.__name__.lower()} not found')

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes) -> 'Transaction':
        try:
            tx = cls()
            buf = tx.get_fields_from_struct(struct_bytes)

            if len(buf) < cls.SERIALIZATION_NONCE_SIZE:
                raise ValueError('Invalid sequence of bytes')

            [tx.nonce, ], buf = unpack('!I', buf)

            while buf:
                buf = tx.get_header_from_bytes(buf)
        except struct.error:
            raise ValueError('Invalid sequence of bytes')

        tx.update_hash()
        return tx

    def calculate_height(self) -> int:
        # XXX: transactions don't have height, using 0 as a placeholder
        return 0

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        """ Gets all funds fields for a transaction from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.signal_bits, self.version, tokens_len, inputs_len, outputs_len), buf = unpack(
            _FUNDS_FORMAT_STRING,
            buf
        )

        for _ in range(tokens_len):
            token_uid, buf = unpack_len(TX_HASH_SIZE, buf)
            self.tokens.append(token_uid)

        for _ in range(inputs_len):
            txin, buf = TxInput.create_from_bytes(buf)
            self.inputs.append(txin)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf)
            self.outputs.append(txout)

        return buf

    def get_funds_struct(self) -> bytes:
        """Return the funds data serialization of the transaction

        :return: funds data serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = pack(
            _FUNDS_FORMAT_STRING,
            self.signal_bits,
            self.version,
            len(self.tokens),
            len(self.inputs),
            len(self.outputs)
        )

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for tx_input in self.inputs:
            struct_bytes += bytes(tx_input)

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        return struct_bytes

    def get_sighash_all(self, clear_input_data: bool = True) -> bytes:
        """Return a serialization of the inputs, outputs and tokens without including any other field

        :return: Serialization of the inputs, outputs and tokens
        :rtype: bytes
        """
        struct_bytes = bytearray(
            pack(
                _SIGHASH_ALL_FORMAT_STRING,
                self.signal_bits,
                self.version,
                len(self.tokens),
                len(self.inputs),
                len(self.outputs)
            )
        )

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for tx_input in self.inputs:
            struct_bytes += tx_input.get_sighash_bytes(clear_input_data)

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        for header in self.headers:
            struct_bytes += header.get_sighash_bytes()

        ret = bytes(struct_bytes)
        return ret

    def get_token_uid(self, index: int) -> bytes:
        """Returns the token uid with corresponding index from the tx token uid list.

        Hathor always has index 0, but we don't include it in the token uid list, so other tokens are
        always 1-off. This means that token with index 1 is the first in the list.

        :param index: token index on the token uid list
        :type index: int

        :return: the token uid
        :rtype: bytes
        """
        if index == 0:
            return settings.HATHOR_TOKEN_UID
        return self.tokens[index - 1]

    def verify_without_storage(self) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_outputs()

    def verify_outputs(self) -> None:
        """Verify outputs reference an existing token uid in the tx list and there are no hathor
        authority UTXOs

        :raises InvalidToken: output references non existent token uid or when there's a hathor authority utxo
        """
        for index, output in enumerate(self.outputs):
            # check index is valid
            if output.get_token_index() > len(self.tokens):
                raise InvalidToken('token uid index not available: index {}'.format(output.get_token_index()))

            # no hathor authority UTXO
            if (output.get_token_index() == 0) and output.is_token_authority():
                raise InvalidToken('Cannot have authority UTXO for hathor tokens: {}'.format(
                    output.to_human_readable()))

            # output value must be positive
            if output.value <= 0:
                raise InvalidOutputValue('Output value must be a positive integer. Value: {} and index: {}'.format(
                    output.value, index))
