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

import base64
from itertools import starmap, zip_longest
from operator import add
from struct import pack
from typing import TYPE_CHECKING, Any, Optional

from hathor import daa
from hathor.checkpoint import Checkpoint
from hathor.conf import get_settings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, TxOutput, TxVersion
from hathor.transaction.exceptions import (
    BlockWithInputs,
    BlockWithTokensError,
    CheckpointError,
    InvalidBlockReward,
    RewardLocked,
    TransactionDataError,
    WeightError,
)
from hathor.transaction.util import VerboseCallback, int_to_bytes, unpack, unpack_len
from hathor.util import not_none
from hathor.utils.int import get_bit_list

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

settings = get_settings()
cpu = get_cpu_profiler()

# Signal bits (B), version (B), outputs len (B)
_FUNDS_FORMAT_STRING = '!BBB'

# Signal bits (B), version (B), inputs len (B) and outputs len (B)
_SIGHASH_ALL_FORMAT_STRING = '!BBBB'


class Block(BaseTransaction):
    SERIALIZATION_NONCE_SIZE = 16

    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 signal_bits: int = 0,
                 version: int = TxVersion.REGULAR_BLOCK,
                 weight: float = 0,
                 outputs: Optional[list[TxOutput]] = None,
                 parents: Optional[list[bytes]] = None,
                 hash: Optional[bytes] = None,
                 data: bytes = b'',
                 storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, signal_bits=signal_bits, version=version, weight=weight,
                         outputs=outputs or [], parents=parents or [], hash=hash, storage=storage)
        self.data = data

    def _get_formatted_fields_dict(self, short: bool = True) -> dict[str, str]:
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

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes, storage: Optional['TransactionStorage'] = None,
                           *, verbose: VerboseCallback = None) -> 'Block':
        blc = cls()
        buf = blc.get_fields_from_struct(struct_bytes, verbose=verbose)

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
        return parent_block.get_height() + 1

    def calculate_min_height(self) -> int:
        """The minimum height the next block needs to have, basically the maximum min-height of this block's parents.
        """
        assert self.storage is not None
        # maximum min-height of any parent tx
        min_height = 0
        for tx_hash in self.get_tx_parents():
            tx = self.storage.get_transaction(tx_hash)
            tx_min_height = tx.get_metadata().min_height
            min_height = max(min_height, not_none(tx_min_height))

        return min_height

    def calculate_feature_activation_bit_counts(self) -> list[int]:
        """
        Calculates the feature_activation_bit_counts metadata attribute, which is a list of feature activation bit
        counts.

        Each list index corresponds to a bit position, and its respective value is the rolling count of active bits
        from the previous boundary block up to this block, including it. LSB is on the left.
        """
        previous_counts = self._get_previous_feature_activation_bit_counts()
        bit_list = self._get_feature_activation_bit_list()

        count_and_bit_pairs = zip_longest(previous_counts, bit_list, fillvalue=0)
        updated_counts = starmap(add, count_and_bit_pairs)

        return list(updated_counts)

    def _get_previous_feature_activation_bit_counts(self) -> list[int]:
        """
        Returns the feature_activation_bit_counts metadata attribute from the parent block,
        or no previous counts if this is a boundary block.
        """
        evaluation_interval = settings.FEATURE_ACTIVATION.evaluation_interval
        is_boundary_block = self.calculate_height() % evaluation_interval == 0

        if is_boundary_block:
            return []

        parent_block = self.get_block_parent()

        return parent_block.get_feature_activation_bit_counts()

    def get_next_block_best_chain_hash(self) -> Optional[bytes]:
        """Return the hash of the next block in the best blockchain. The blockchain is
        written from left-to-righ (->), meaning the next block has a greater height.
        In a timeline, the parent block (left) comes first of the child (right).

             +-----------+       +-----------+       +-----------+
         --->| height: 1 |------>| height: 2 |------>| height: 3 |--->
             |  parent   |       |  current  |       |   child   |
             +-----------+       +-----------+       +-----------+
                 left                                    right
                 past                                   future

                                "left-to-right"
        """
        assert self.storage is not None
        meta = self.get_metadata()
        assert not meta.voided_by

        candidates = []
        for h in meta.children:
            blk = self.storage.get_transaction(h)
            assert blk.is_block
            blk_meta = blk.get_metadata()
            if blk_meta.voided_by:
                continue
            candidates.append(h)

        if len(candidates) == 0:
            return None
        assert len(candidates) == 1
        return candidates[0]

    def get_next_block_best_chain(self) -> Optional['Block']:
        """Return the next block in the best blockchain. The blockchain is written
        from left-to-righ (->), meaning the next block has a greater height.
        In a timeline, the parent block (left) comes first of the child (right).

             +-----------+       +-----------+       +-----------+
         --->| height: 1 |------>| height: 2 |------>| height: 3 |--->
             |  parent   |       |  current  |       |   child   |
             +-----------+       +-----------+       +-----------+
                 left                                    right
                 past                                   future

                                "left-to-right"
        """
        assert self.storage is not None
        h = self.get_next_block_best_chain_hash()
        if h is None:
            return None
        tx = self.storage.get_transaction(h)
        assert isinstance(tx, Block)
        return tx

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

    def get_funds_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        """ Gets all funds fields for a block from a buffer.

        :param buf: Bytes of a serialized block
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.signal_bits, self.version, outputs_len), buf = unpack(_FUNDS_FORMAT_STRING, buf)
        if verbose:
            verbose('signal_bits', self.signal_bits)
            verbose('version', self.version)
            verbose('outputs_len', outputs_len)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf, verbose=verbose)
            self.outputs.append(txout)

        return buf

    def get_graph_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        """ Gets graph fields for a block from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        buf = super().get_graph_fields_from_struct(buf, verbose=verbose)
        (data_bytes,), buf = unpack('!B', buf)
        if verbose:
            verbose('data_len', data_bytes)
        self.data, buf = unpack_len(data_bytes, buf)
        if verbose:
            verbose('data', self.data.hex())
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
    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['tokens'] = []
        json['data'] = base64.b64encode(self.data).decode('utf-8')
        return json

    def to_json_extended(self) -> dict[str, Any]:
        json = super().to_json_extended()
        json['height'] = self.get_metadata().height

        return json

    def has_basic_block_parent(self) -> bool:
        """Whether all block parent is in storage and is at least basic-valid."""
        assert self.storage is not None
        parent_block_hash = self.parents[0]
        if not self.storage.transaction_exists(parent_block_hash):
            return False
        metadata = self.storage.get_metadata(parent_block_hash)
        if metadata is None:
            return False
        return metadata.validation.is_at_least_basic()

    def verify_basic(self, skip_block_weight_verification: bool = False) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if not skip_block_weight_verification:
            self.verify_weight()
        self.verify_reward()

    def verify_checkpoint(self, checkpoints: list[Checkpoint]) -> None:
        assert self.hash is not None
        assert self.storage is not None
        height = self.get_height()  # TODO: use "soft height" when sync-checkpoint is added
        # find checkpoint with our height:
        checkpoint: Optional[Checkpoint] = None
        for cp in checkpoints:
            if cp.height == height:
                checkpoint = cp
                break
        if checkpoint is not None and checkpoint.hash != self.hash:
            raise CheckpointError(f'Invalid new block {self.hash_hex}: checkpoint hash does not match')
        else:
            # TODO: check whether self is a parent of any checkpoint-valid block, this is left for a future PR
            pass

    def verify_weight(self) -> None:
        """Validate minimum block difficulty."""
        block_weight = daa.calculate_block_difficulty(self)
        if self.weight < block_weight - settings.WEIGHT_TOL:
            raise WeightError(f'Invalid new block {self.hash_hex}: weight ({self.weight}) is '
                              f'smaller than the minimum weight ({block_weight})')

    def verify_height(self) -> None:
        """Validate that the block height is enough to confirm all transactions being confirmed."""
        meta = self.get_metadata()
        assert meta.height is not None
        assert meta.min_height is not None
        if meta.height < meta.min_height:
            raise RewardLocked(f'Block needs {meta.min_height} height but has {meta.height}')

    def verify_reward(self) -> None:
        """Validate reward amount."""
        parent_block = self.get_block_parent()
        tokens_issued_per_block = daa.get_tokens_issued_per_block(parent_block.get_height() + 1)
        if self.sum_outputs != tokens_issued_per_block:
            raise InvalidBlockReward(
                f'Invalid number of issued tokens tag=invalid_issued_tokens tx.hash={self.hash_hex} '
                f'issued={self.sum_outputs} allowed={tokens_issued_per_block}'
            )

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
        self.verify_sigops_output()

    def get_base_hash(self) -> bytes:
        from hathor.merged_mining.bitcoin import sha256d_hash
        return sha256d_hash(self.get_header_without_nonce())

    @cpu.profiler(key=lambda self: 'block-verify!{}'.format(self.hash.hex()))
    def verify(self, reject_locked_reward: bool = True) -> None:
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

        self.verify_height()

    def get_height(self) -> int:
        """Returns the block's height."""
        meta = self.get_metadata()
        assert meta.height is not None
        return meta.height

    def get_feature_activation_bit_counts(self) -> list[int]:
        """Returns the block's feature_activation_bit_counts metadata attribute."""
        metadata = self.get_metadata()
        assert metadata.feature_activation_bit_counts is not None, 'Blocks must always have this attribute set.'

        return metadata.feature_activation_bit_counts

    def _get_feature_activation_bit_list(self) -> list[int]:
        """
        Extracts feature activation bits from the signal bits, as a list where each index corresponds to the bit
        position. LSB is on the left.
        """
        assert self.signal_bits <= 0xFF, 'signal_bits must be one byte at most'

        bitmask = self._get_feature_activation_bitmask()
        bits = self.signal_bits & bitmask

        bit_list = get_bit_list(bits, min_size=settings.FEATURE_ACTIVATION.max_signal_bits)

        return bit_list

    @classmethod
    def _get_feature_activation_bitmask(cls) -> int:
        """Returns the bitmask that gets feature activation bits from signal bits."""
        bitmask = (1 << settings.FEATURE_ACTIVATION.max_signal_bits) - 1

        return bitmask

    def get_feature_state(self, *, feature: Feature) -> Optional[FeatureState]:
        """Returns the state of a feature from metadata."""
        metadata = self.get_metadata()
        feature_states = metadata.feature_states or {}

        return feature_states.get(feature)

    def update_feature_state(self, *, feature: Feature, state: FeatureState) -> None:
        """Updates the state of a feature in metadata and persists it."""
        assert self.storage is not None
        metadata = self.get_metadata()
        feature_states = metadata.feature_states or {}
        feature_states[feature] = state
        metadata.feature_states = feature_states

        self.storage.save_transaction(self, only_metadata=True)

    def get_feature_activation_bit_value(self, bit: int) -> int:
        """Get the feature activation bit value for a specific bit position."""
        bit_list = self._get_feature_activation_bit_list()

        return bit_list[bit]
