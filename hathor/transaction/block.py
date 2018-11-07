from hathor.transaction.base_transaction import BaseTransaction
from hathor.transaction.exceptions import BlockHeightError, BlockWithInputs

from twisted.logger import Logger

from math import log


class Block(BaseTransaction):
    log = Logger()

    def __init__(self, nonce=0, timestamp=None, version=1, weight=0, height=0,
                 outputs=None, parents=None, hash=None, storage=None):
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            version=version,
            weight=weight,
            height=height,
            outputs=outputs or [],
            parents=parents or [],
            hash=hash,
            storage=storage,
            is_block=True
        )

    def calculate_weight(self, network_hashrate):
        """ Calculate the minimum weight so it is a valid block.
        weight = 7 + log2(hash_rate)
        """
        return 7 + log(network_hashrate, 2)

    def verify_height(self):
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

        if self.height != max(x.height for x in parent_blocks) + 1:
            raise BlockHeightError(error_height_message)

    def verify_no_inputs(self):
        inputs = getattr(self, 'inputs', None)
        if inputs:
            raise BlockWithInputs('number of inputs {}'.format(len(inputs)))

    def calculate_height(self):
        """ Calculate block height according to its parents

        :return: Block height
        :rtype: int
        """
        if self.is_genesis:
            return 1
        parents_tx = [self.storage.get_transaction_by_hash_bytes(h) for h in self.parents]
        height = max(x.height for x in parents_tx) + 1
        return height

    def verify_without_storage(self):
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_height()
        self.verify_no_inputs()

    def verify(self):
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight
            (3) creates the correct amount of tokens in the output
            (4) height of block == height of previous block + 1
            (5) all parents must exist and have timestamp smaller than ours
        """
        # TODO Should we validate a limit of outputs?
        # TODO (1) and (3)
        if self.is_genesis:
            # TODO do genesis validation
            return

        self.verify_without_storage()

        # (5)
        self.verify_parents()
