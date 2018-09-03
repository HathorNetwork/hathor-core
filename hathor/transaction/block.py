from hathor.transaction.base_transaction import BaseTransaction
from math import log


class Block(BaseTransaction):
    def __init__(self, nonce=0, timestamp=None, version=1, weight=0,
                 outputs=None, parents=None, hash=None, storage=None):
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            version=version,
            weight=weight,
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

    def verify(self):
        """
              (i) confirms at least two pending transactions and references last block
             (ii) solves the pow with the correct weight
            (iii) creates the correct amount of tokens in the output
        """
        # TODO Should we validate a limit of outputs?
        # TODO (i) and (iii)
        if self.is_genesis:
            # TODO do genesis validation
            return
        self.verify_pow()
