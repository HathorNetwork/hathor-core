"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

from struct import pack
from typing import Dict

from hathorlib.base_transaction import BaseTransaction, TxOutput
from hathorlib.utils import int_to_bytes, unpack, unpack_len

# Signal bits (B), version (B), outputs len (B)
_FUNDS_FORMAT_STRING = '!BBB'

# Signal bits (B), version (B), inputs len (B) and outputs len (B)
_SIGHASH_ALL_FORMAT_STRING = '!BBBB'


class Block(BaseTransaction):
    SERIALIZATION_NONCE_SIZE = 16

    @property
    def is_block(self) -> bool:
        """Returns true if this is a block"""
        return True

    @property
    def is_transaction(self) -> bool:
        """Returns true if this is a transaction"""
        return False

    def _get_formatted_fields_dict(self, short: bool = True) -> Dict[str, str]:
        d = super()._get_formatted_fields_dict(short)
        if not short:
            d.update(data=self.data.hex())
        return d

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes) -> 'Block':
        blc = cls()
        buf = blc.get_fields_from_struct(struct_bytes)

        if len(buf) < cls.SERIALIZATION_NONCE_SIZE:
            raise ValueError('Invalid sequence of bytes')

        blc.nonce = int.from_bytes(buf[:cls.SERIALIZATION_NONCE_SIZE], byteorder='big')
        buf = buf[cls.SERIALIZATION_NONCE_SIZE:]

        while buf:
            buf = blc.get_header_from_bytes(buf)

        blc.hash = blc.calculate_hash()

        return blc

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        """ Gets all funds fields for a block from a buffer.

        :param buf: Bytes of a serialized block
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.signal_bits, self.version, outputs_len), buf = unpack(_FUNDS_FORMAT_STRING, buf)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf)
            self.outputs.append(txout)

        return buf

    def get_graph_fields_from_struct(self, buf: bytes) -> bytes:
        """ Gets graph fields for a block from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        buf = super().get_graph_fields_from_struct(buf)
        (data_bytes,), buf = unpack('!B', buf)
        self.data, buf = unpack_len(data_bytes, buf)
        return buf

    def get_funds_struct(self) -> bytes:
        """Return the funds data serialization of the block

        :return: funds data serialization of the block
        :rtype: bytes
        """
        struct_bytes = pack(_FUNDS_FORMAT_STRING, self.signal_bits, self.version, len(self.outputs))

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        return struct_bytes

    def get_graph_struct(self) -> bytes:
        """Return the graph data serialization of the block, without including the nonce field

        :return: graph data serialization of the transaction
        :rtype: bytes
        """
        struct_bytes_without_data = super().get_graph_struct()
        data_bytes = int_to_bytes(len(self.data), 1)
        return struct_bytes_without_data + data_bytes + self.data
