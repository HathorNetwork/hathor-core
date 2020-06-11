"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import base64
from struct import pack
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from hathor import protos
from hathor.conf import HathorSettings
from hathor.transaction import BaseTransaction, TxOutput, TxVersion
from hathor.transaction.exceptions import BlockWithInputs, BlockWithTokensError, TransactionDataError
from hathor.transaction.util import int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

settings = HathorSettings()

# Version (H), outputs len (B)
_FUNDS_FORMAT_STRING = '!HB'

# Version (H), inputs len (B) and outputs len (B)
_SIGHASH_ALL_FORMAT_STRING = '!HBB'


class Block(BaseTransaction):
    SERIALIZATION_NONCE_SIZE = 16

    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 version: int = TxVersion.REGULAR_BLOCK,
                 weight: float = 0,
                 outputs: Optional[List[TxOutput]] = None,
                 parents: Optional[List[bytes]] = None,
                 hash: Optional[bytes] = None,
                 data: bytes = b'',
                 storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight,
                         outputs=outputs or [], parents=parents or [], hash=hash, storage=storage)
        self.data = data

    def _get_formatted_fields_dict(self, short: bool = True) -> Dict[str, str]:
        d = super()._get_formatted_fields_dict(short)
        if not short:
            d.update(data=self.data.hex())
        return d

    @property
    def is_block(self) -> bool:
        """Returns true if this is a block"""
        return True

    @property
    def is_transaction(self) -> bool:
        """Returns true if this is a transaction"""
        return False

    def to_proto(self, include_metadata: bool = True) -> protos.BaseTransaction:
        tx_proto = protos.Block(
            version=self.version,
            weight=self.weight,
            timestamp=self.timestamp,
            parents=self.parents,
            outputs=map(TxOutput.to_proto, self.outputs),
            hash=self.hash,
            data=self.data
        )
        tx_proto.nonce = int_to_bytes(self.nonce, 16)
        if include_metadata:
            tx_proto.metadata.CopyFrom(self.get_metadata().to_proto())
        return protos.BaseTransaction(block=tx_proto)

    @classmethod
    def create_from_proto(cls, tx_proto: protos.BaseTransaction,
                          storage: Optional['TransactionStorage'] = None) -> 'Block':
        block_proto = tx_proto.block
        tx = cls(
            version=block_proto.version,
            weight=block_proto.weight,
            timestamp=block_proto.timestamp,
            hash=block_proto.hash or None,
            parents=list(block_proto.parents),
            outputs=list(map(TxOutput.create_from_proto, block_proto.outputs)),
            storage=storage,
            data=block_proto.data
        )
        tx.nonce = int.from_bytes(block_proto.nonce, 'big')
        if block_proto.HasField('metadata'):
            from hathor.transaction import TransactionMetadata

            # make sure hash is not empty
            tx.hash = tx.hash or tx.calculate_hash()
            tx._metadata = TransactionMetadata.create_from_proto(tx.hash, block_proto.metadata)
        return tx

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes,
                           storage: Optional['TransactionStorage'] = None) -> 'Block':
        blc = cls()
        buf = blc.get_fields_from_struct(struct_bytes)

        blc.nonce = int.from_bytes(buf, byteorder='big')
        if len(buf) != cls.SERIALIZATION_NONCE_SIZE:
            raise ValueError('Invalid sequence of bytes')

        blc.hash = blc.calculate_hash()
        blc.storage = storage

        return blc

    def calculate_height(self) -> int:
        """Return the height of the block, i.e., the number of blocks since genesis"""
        if self.is_genesis:
            return 0
        assert self.storage is not None
        parent_block = self.get_block_parent()
        return parent_block.get_metadata().height + 1

    def get_block_parent_hash(self) -> bytes:
        """ Return the hash of the parent block.
        """
        return self.parents[0]

    def get_block_parent(self) -> 'Block':
        """Return the parent block.
        """
        assert self.storage is not None
        block_parent = self.storage.get_transaction(self.get_block_parent_hash())
        assert isinstance(block_parent, Block)
        return block_parent

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        """ Gets all funds fields for a block from a buffer.

        :param buf: Bytes of a serialized block
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.version, outputs_len), buf = unpack(_FUNDS_FORMAT_STRING, buf)

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
        struct_bytes = pack(_FUNDS_FORMAT_STRING, self.version, len(self.outputs))

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

    def get_token_uid(self, index: int) -> bytes:
        """Returns the token uid with corresponding index from the tx token uid list.

        Blocks can only have HTR tokens

        :param index: token index on the token uid list
        :type index: int

        :return: the token uid
        :rtype: bytes
        """
        assert index == 0
        return settings.HATHOR_TOKEN_UID

    # TODO: maybe introduce convention on serialization methods names (e.g. to_json vs get_struct)
    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> Dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['tokens'] = []
        json['data'] = base64.b64encode(self.data).decode('utf-8')
        return json

    def to_json_extended(self) -> Dict[str, Any]:
        json = super().to_json_extended()
        json['height'] = self.get_metadata().height

        return json

    def verify_no_inputs(self) -> None:
        inputs = getattr(self, 'inputs', None)
        if inputs:
            raise BlockWithInputs('number of inputs {}'.format(len(inputs)))

    def verify_outputs(self) -> None:
        super().verify_outputs()
        for output in self.outputs:
            if output.get_token_index() > 0:
                raise BlockWithTokensError('in output: {}'.format(output.to_human_readable()))

    def verify_data(self) -> None:
        if len(self.data) > settings.BLOCK_DATA_MAX_SIZE:
            raise TransactionDataError('block data has {} bytes'.format(len(self.data)))

    def verify_without_storage(self) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_no_inputs()
        self.verify_outputs()
        self.verify_data()

    def get_base_hash(self) -> bytes:
        from hathor.merged_mining.bitcoin import sha256d_hash
        return sha256d_hash(self.get_header_without_nonce())

    def verify(self) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
        """
        # TODO Should we validate a limit of outputs?
        if self.is_genesis:
            # TODO do genesis validation
            return

        self.verify_without_storage()

        # (1) and (4)
        self.verify_parents()
