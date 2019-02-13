import base64
import hashlib
from itertools import chain
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set

from _hashlib import HASH
from twisted.logger import Logger

from hathor import protos
from hathor.constants import BLOCK_DATA_MAX_SIZE, BLOCK_NONCE_BYTES as NONCE_BYTES
from hathor.transaction.base_transaction import BaseTransaction, TxOutput, sum_weights
from hathor.transaction.exceptions import BlockDataError, BlockWithInputs, BlockWithTokensError
from hathor.transaction.util import int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


class Block(BaseTransaction):
    log = Logger()

    def __init__(self, nonce: int = 0, timestamp: Optional[int] = None, version: int = 1, weight: float = 0,
                 outputs: Optional[List[TxOutput]] = None, parents: Optional[List[bytes]] = None,
                 hash: Optional[bytes] = None, storage: Optional['TransactionStorage'] = None,
                 data: bytes = b'') -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight,
                         outputs=outputs or [], parents=parents or [], hash=hash, storage=storage, is_block=True)
        self.data = data

    def to_proto(self, include_metadata: bool = True) -> protos.BaseTransaction:
        tx_proto = protos.Block(
            version=self.version,
            weight=self.weight,
            timestamp=self.timestamp,
            parents=self.parents,
            outputs=map(TxOutput.to_proto, self.outputs),
            nonce=int_to_bytes(self.nonce, 16),
            hash=self.hash,
            data=self.data
        )
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
            nonce=int.from_bytes(block_proto.nonce, 'big'),
            hash=block_proto.hash or None,
            parents=list(block_proto.parents),
            outputs=list(map(TxOutput.create_from_proto, block_proto.outputs)),
            storage=storage,
            data=block_proto.data
        )
        if block_proto.HasField('metadata'):
            from hathor.transaction import TransactionMetadata
            # make sure hash is not empty
            tx.hash = tx.hash or tx.calculate_hash()
            tx._metadata = TransactionMetadata.create_from_proto(tx.hash, block_proto.metadata)
        return tx

    def get_block_parent_hash(self) -> bytes:
        """Return the hash of the parent block.
        """
        return self.parents[0]

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes,
                           storage: Optional['TransactionStorage'] = None) -> 'Block':
        blc = cls()
        buf = blc.get_fields_from_struct(struct_bytes)

        [data_bytes, ], buf = unpack('B', buf)
        blc.data, buf = unpack_len(data_bytes, buf)

        blc.nonce = int.from_bytes(buf, byteorder='big')
        if len(buf) != NONCE_BYTES:
            raise ValueError('Invalid sequence of bytes')

        blc.hash = blc.calculate_hash()
        blc.storage = storage

        return blc

    def get_struct_without_nonce(self) -> bytes:
        struct_bytes_without_data = super().get_struct_without_nonce()
        # TODO: should we validate data length here?
        data_bytes = int_to_bytes(len(self.data), 1)
        return struct_bytes_without_data + data_bytes + self.data

    def get_struct(self) -> bytes:
        """Return the complete serialization of the transaction

        :rtype: bytes
        """
        struct_bytes = self.get_struct_without_nonce()
        struct_bytes += int_to_bytes(self.nonce, NONCE_BYTES)
        return struct_bytes

    def calculate_hash2(self, part1: HASH) -> bytes:
        part1.update(int_to_bytes(self.nonce, NONCE_BYTES))
        return hashlib.sha256(part1.digest()).digest()

    # TODO: maybe introduce convention on serialization methods names (e.g. to_json vs get_struct)
    def to_json(self, decode_script: bool = False) -> Dict[str, Any]:
        json = super().to_json(decode_script)
        json['data'] = base64.b64encode(self.data).decode('utf-8')
        return json

    def verify_no_inputs(self) -> None:
        inputs = getattr(self, 'inputs', None)
        if inputs:
            raise BlockWithInputs('number of inputs {}'.format(len(inputs)))

    def verify_outputs(self) -> None:
        # can only contain hathor tokens
        # check there are no tokens in the token uid list
        if len(self.tokens) > 0:
            raise BlockWithTokensError('token list: {}'.format([token_uid.hex() for token_uid in self.tokens]))

        for output in self.outputs:
            if output.get_token_index() > 0:
                raise BlockWithTokensError('in output: {}'.format(output.to_human_readable()))

    def verify_data(self) -> None:
        if len(self.data) > BLOCK_DATA_MAX_SIZE:
            raise BlockDataError('block data has {} bytes'.format(len(self.data)))

    def verify_without_storage(self) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_no_inputs()
        self.verify_outputs()
        self.verify_data()

    def verify(self) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) data field must contain at most 100 bytes
        """
        # TODO Should we validate a limit of outputs?
        if self.is_genesis:
            # TODO do genesis validation
            return

        self.verify_without_storage()

        # (1) and (4)
        self.verify_parents()

    def _score_tx_dfs(self, tx: BaseTransaction, used: Set[bytes],
                      mark_as_best_chain: bool, newest_timestamp: int) -> float:
        """ Internal method to run a DFS. It is used by `calculate_score()`.
        """
        assert self.storage is not None

        assert tx.hash is not None
        assert not tx.is_block
        if tx.hash in used:
            return 0
        used.add(tx.hash)

        meta = tx.get_metadata()
        if meta.first_block:
            block = self.storage.get_transaction(meta.first_block)
            if block.timestamp <= newest_timestamp:
                return 0

        if mark_as_best_chain:
            assert meta.first_block is None
            meta.first_block = self.hash
            self.storage.save_transaction(tx, only_metadata=True)

        score = tx.weight
        for parent in tx.get_parents():
            score = sum_weights(score, self._score_tx_dfs(parent, used, mark_as_best_chain, newest_timestamp))
        return score

    def _score_block_dfs(self, block: BaseTransaction, used: Set[bytes],
                         mark_as_best_chain: bool, newest_timestamp: int) -> float:
        """ Internal method to run a DFS. It is used by `calculate_score()`.
        """
        assert self.storage is not None

        assert block.is_block
        score = block.weight
        for parent in block.get_parents():
            if parent.is_block:
                assert isinstance(parent, Block)
                if parent.timestamp <= newest_timestamp:
                    meta = parent.get_metadata()
                    x = meta.score
                else:
                    x = parent._score_block_dfs(parent, used, mark_as_best_chain, newest_timestamp)
                score = sum_weights(score, x)
            else:
                score = sum_weights(score, self._score_tx_dfs(parent, used, mark_as_best_chain, newest_timestamp))

        # Always save the score when it is calculated.
        meta = block.get_metadata()
        if not meta.score:
            meta.score = score
            self.storage.save_transaction(block, only_metadata=True)
        else:
            # The score of a block is immutable since the sub-DAG behind it is immutable as well.
            # Thus, if we have already calculated it, we just check the consistency of the calculation.
            # Unfortunately we may have to calculate it more than once when a new block arrives in a side
            # side because the `first_block` points only to the best chain.
            assert abs(meta.score - score) < 1e-10

        return score

    def calculate_score(self, *, mark_as_best_chain: bool = False) -> float:
        """ Calculate block's score, which is the accumulated work of the verified transactions and blocks.

        :param: mark_as_best_chain: If `True`, the transactions' will point `meta.first_block` to
                                    the blocks of the chain.
        """
        assert self.storage is not None
        if self.is_genesis:
            if mark_as_best_chain:
                meta = self.get_metadata()
                meta.score = self.weight
                self.storage.save_transaction(self, only_metadata=True)
            return self.weight

        block = self._find_first_parent_in_best_chain()
        newest_timestamp = block.timestamp

        used: Set[bytes] = set()
        return self._score_block_dfs(self, used, mark_as_best_chain, newest_timestamp)

    def _remove_first_block_markers_dfs(self, tx: BaseTransaction, used: Set[bytes]) -> None:
        """ Run a DFS removing the `meta.first_block` pointing to this block. The DFS stops when it finds
        a transaction pointing to another block.
        """
        assert tx.hash is not None
        assert self.storage is not None

        if tx.hash in used:
            return
        used.add(tx.hash)
        assert not tx.is_block

        meta = tx.get_metadata()
        if meta.first_block != self.hash:
            return

        meta.first_block = None
        self.storage.save_transaction(tx, only_metadata=True)

        for parent in tx.get_parents():
            if not parent.is_block:
                self._remove_first_block_markers_dfs(parent, used)

    def remove_first_block_markers(self) -> None:
        """ Remove all `meta.first_block` pointing to this block.
        """
        used: Set[bytes] = set()
        for parent in self.get_parents():
            if not parent.is_block:
                self._remove_first_block_markers_dfs(parent, used)

    def update_score_and_mark_as_the_best_chain(self) -> None:
        """ Update score and mark the chain as the best chain.
        Thus, transactions' first_block will point to the blocks in the chain.
        """
        self.calculate_score(mark_as_best_chain=True)

    def update_voided_info(self) -> None:
        """ This method is called only once when a new block arrives.

        The blockchain part of the DAG is a tree with the genesis block as the root.
        I'll say the a block A is connected to a block B when A verifies B, i.e., B is a parent of A.

        A chain is a sequence of connected blocks starting in a leaf and ending in the root, i.e., any path from a leaf
        to the root is a chain. Given a chain, its head is a leaf in the tree, and its tail is the sub-chain without
        the head.

        The best chain is a chain that has the highest score of all chains.

        The score of a block is calculated as the sum of the weights of all transactions and blocks both direcly and
        indirectly verified by the block. The score of a chain is defined as the score of its head.

        The side chains are the chains whose scores are smaller than the best chain's.
        The head of the side chains are always voided blocks.

        There are two possible states for the block chain:
        (i)  It has a single best chain, i.e., one chain has the highest score
        (ii) It has multiple best chains, i.e., two or more chains have the same score (and this score is the highest
             among the chains)

        When there are multiple best chains, I'll call them best chain candidates.

        The arrived block can be connected in four possible ways:
        (i)   To the head of a best chain
        (ii)  To the tail of the best chain
        (iii) To the head of a side chain
        (iv)  To the tail of a side chain

        Thus, there are eight cases to be handled when a new block arrives, which are:
        (i)    Single best chain, connected to the head of the best chain
        (ii)   Single best chain, connected to the tail of the best chain
        (iii)  Single best chain, connected to the head of a side chain
        (iv)   Single best chain, connected to the tail of a side chain
        (v)    Multiple best chains, connected to the head of a best chain
        (vi)   Multiple best chains, connected to the tail of a best chain
        (vii)  Multiple best chains, connected to the head of a side chain
        (viii) Multiple best chains, connected to the tail of a side chain

        Case (i) is trivial because the single best chain will remain as the best chain. So, just calculate the new
        score and that's it.

        Case (v) is also trivial. As there are multiple best chains and the new block is connected to the head of one
        of them, this will be the new winner. So, the blockchain state will change to a single best chain again.

        In the other cases, we must calculate the score and compare with the best score.

        When there are multiple best chains, all their heads will be voided.
        """
        assert self.weight > 0, 'This algorithm assumes that block\'s weight is always greater than zero'
        if not self.parents:
            assert self.is_genesis is True
            self.update_score_and_mark_as_the_best_chain()
            return

        assert self.storage is not None
        assert self.hash is not None

        parent = self.storage.get_transaction(self.get_block_parent_hash())
        parent_meta = parent.get_metadata()
        assert self.hash in parent_meta.children

        is_connected_to_the_head = bool(len(parent_meta.children) == 1)
        is_connected_to_the_best_chain = bool(not parent_meta.voided_by)

        if is_connected_to_the_head and is_connected_to_the_best_chain:
            # Case (i): Single best chain, connected to the head of the best chain
            self.update_score_and_mark_as_the_best_chain()
            heads = [self.storage.get_transaction(h) for h in self.storage.get_best_block_tips()]
            assert len(heads) == 1

        else:
            # Resolve all other cases, but (i).

            # First, void this block.
            self.mark_as_voided(skip_remove_first_block_markers=True)

            # Get the score of the best chains.
            # We need to void this block first, because otherwise it would always be one of the heads.
            heads = [self.storage.get_transaction(h) for h in self.storage.get_best_block_tips()]
            best_score = None
            for block in heads:
                block_meta = block.get_metadata(force_reload=True)
                if best_score is None:
                    best_score = block_meta.score
                else:
                    # All heads must have the same score.
                    assert abs(best_score - block_meta.score) < 1e-10
            assert isinstance(best_score, float)

            # Calculate the score.
            score = self.calculate_score()

            # Finally, check who the winner is.
            eps = 1e-10
            if score <= best_score - eps:
                # Nothing to do.
                pass

            else:
                # Either eveyone has the same score or there is a winner.

                valid_heads = []
                for block in heads:
                    meta = block.get_metadata()
                    if not meta.voided_by:
                        valid_heads.append(block)

                # We must have at most one valid head.
                # Either we have a single best chain or all chains have already been voided.
                assert len(valid_heads) <= 1, 'We must never have more than one valid head'

                # We need to go through all side chains because there may be non-voided blocks
                # that must be voided.
                # For instance, imagine two chains with intersection with both heads voided.
                # Now, a new chain starting in genesis reaches the same score. Then, the tail
                # of the two chains must be voided.
                first_block = self._find_first_parent_in_best_chain()
                for block in heads:
                    while True:
                        if block.timestamp <= first_block.timestamp:
                            break
                        meta = block.get_metadata()
                        if not meta.voided_by:
                            # Only mark as voided when it is non-voided.
                            block.mark_as_voided()
                        # We have to go through the chain until the first parent in the best
                        # chain because the head may be voided with part of the tail non-voided.
                        block = self.storage.get_transaction(block.get_block_parent_hash())

                if score >= best_score + eps:
                    # We have a new winner.
                    self.update_score_and_mark_as_the_best_chain()
                    self.remove_voided_by_from_chain()

    def mark_as_voided(self, *, skip_remove_first_block_markers: bool = False):
        """ Mark a block as voided. By default, it will remove the first block markers from
        `meta.first_block` of the transactions that point to it.
        """
        if not skip_remove_first_block_markers:
            self.remove_first_block_markers()
        assert self.add_voided_by()

    def add_voided_by(self, voided_hash: Optional[bytes] = None) -> bool:
        """ Add a new hash in its `meta.voided_by`. If `voided_hash` is None, it includes
        the block's own hash.
        """
        assert self.storage is not None
        assert self.hash is not None

        if voided_hash is None:
            voided_hash = self.hash
        assert voided_hash is not None

        meta = self.get_metadata()
        if voided_hash in meta.voided_by:
            return False

        self.log.debug('add_voided_by block={} voided_hash={}'.format(self.hash.hex(), voided_hash.hex()))

        meta.voided_by.add(voided_hash)
        self.storage.save_transaction(self, only_metadata=True)

        spent_by: Iterable[bytes] = chain(*meta.spent_outputs.values())
        for tx_hash in spent_by:
            tx = self.storage.get_transaction(tx_hash)
            assert not tx.is_block
            tx.add_voided_by(voided_hash)
        return True

    def remove_voided_by(self, voided_hash: Optional[bytes] = None) -> bool:
        """ Remove a hash from its `meta.voided_by`. If `voided_hash` is None, it removes
        the block's own hash.
        """
        assert self.storage is not None
        assert self.hash is not None

        if voided_hash is None:
            voided_hash = self.hash

        meta = self.get_metadata()
        if voided_hash not in meta.voided_by:
            return False

        self.log.debug('remove_voided_by block={} voided_hash={}'.format(self.hash.hex(), voided_hash.hex()))

        meta.voided_by.remove(voided_hash)
        self.storage.save_transaction(self, only_metadata=True)

        spent_by: Iterable[bytes] = chain(*meta.spent_outputs.values())
        for tx_hash in spent_by:
            tx = self.storage.get_transaction(tx_hash)
            assert not tx.is_block
            tx.remove_voided_by(voided_hash)
        return True

    def remove_voided_by_from_chain(self):
        """ Remove voided_by from the chain. Now, it is the best chain.

        The blocks are visited from right to left (most recent to least recent).
        """
        block = self
        while True:
            assert block.is_block
            success = block.remove_voided_by()
            if not success:
                break
            block = self.storage.get_transaction(block.get_block_parent_hash())

    def _find_first_parent_in_best_chain(self) -> BaseTransaction:
        """ Find the first block in the side chain that is not voided, i.e., the block where the fork started.

        In the simple schema below, the best chain's blocks are O's, the side chain's blocks are I's, and the first
        valid block is the [O].

        O-O-O-O-[O]-O-O-O-O
                 |
                 +-I-I-I
        """
        assert self.storage is not None
        assert len(self.parents) > 0, 'This should never happen because the genesis is always in the best chain'
        parent_hash = self.get_block_parent_hash()
        while True:
            parent = self.storage.get_transaction(parent_hash)
            parent_meta = parent.get_metadata()
            if not parent_meta.voided_by:
                break
            assert len(parent.parents) > 0, 'This should never happen because the genesis is always in the best chain'
            parent_hash = parent.get_block_parent_hash()
        return parent
