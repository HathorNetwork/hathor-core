from typing import TYPE_CHECKING, List, Optional

from twisted.logger import Logger

from hathor import protos
from hathor.transaction.base_transaction import BaseTransaction, Output
from hathor.transaction.exceptions import BlockHeightError, BlockWithInputs, BlockWithTokensError

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


class Block(BaseTransaction):
    log = Logger()

    def __init__(self, nonce: int = 0, timestamp: Optional[int] = None, version: int = 1, weight: float = 0,
                 height: int = 0, outputs: Optional[List[Output]] = None, parents: Optional[List[bytes]] = None,
                 hash: Optional[bytes] = None, storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, height=height,
                         outputs=outputs or [], parents=parents or [], hash=hash, storage=storage, is_block=True)

    def to_proto(self, include_metadata: bool = True) -> protos.BaseTransaction:
        tx_proto = protos.Block(
            version=self.version,
            weight=self.weight,
            timestamp=self.timestamp,
            height=self.height,
            parents=self.parents,
            outputs=map(Output.to_proto, self.outputs),
            nonce=self.nonce,
            hash=self.hash,
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
            height=block_proto.height,
            nonce=block_proto.nonce,
            hash=block_proto.hash or None,
            parents=list(block_proto.parents),
            outputs=list(map(Output.create_from_proto, block_proto.outputs)),
            storage=storage,
        )
        if block_proto.HasField('metadata'):
            from hathor.transaction import TransactionMetadata
            # make sure hash is not empty
            tx.hash = tx.hash or tx.calculate_hash()
            tx._metadata = TransactionMetadata.create_from_proto(tx.hash, block_proto.metadata)
        return tx

    def verify_height(self) -> None:
        """Verify that the height is correct (should be parent + 1)."""
        error_height_message = 'Invalid height of block'
        if self.is_genesis and self.height != 1:
            raise BlockHeightError(error_height_message)

        # TODO: How to verify parent height stuff without access to storage?
        if not self.storage:
            self.log.warn("WARNING(transaction/block.py): Can't verify block height without transaction storage.")
            return

        # Get all parents.
        parent_blocks = [parent for parent in self.get_parents()]

        if self.is_genesis:
            expected_height = 1
        else:
            expected_height = max(x.height for x in parent_blocks) + 1

        if self.height != expected_height:
            raise BlockHeightError(error_height_message)

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

    def calculate_height(self):
        """ Calculate block height according to its parents

        :return: Block height
        :rtype: int
        """
        if self.is_genesis:
            return 1
        parents_tx = [self.storage.get_transaction(h) for h in self.parents]
        height = max(x.height for x in parents_tx) + 1
        return height

    def verify_without_storage(self) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_no_inputs()
        self.verify_outputs()

    def verify(self) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) height of block == height of previous block + 1
        """
        # TODO Should we validate a limit of outputs?
        if self.is_genesis:
            # TODO do genesis validation
            return

        self.verify_without_storage()

        # (1) and (4)
        self.verify_parents()
        # (5)
        self.verify_height()
