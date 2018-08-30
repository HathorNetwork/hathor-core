from hathor.transaction.base_transaction import BaseTransaction
from math import log


class Block(BaseTransaction):
    def __init__(self, nonce=0, timestamp=None, version=1, weight=0,
                 outputs=[], parents=[], hash=None, storage=None, network_hashrate=10000):
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            version=version,
            weight=weight,
            outputs=outputs,
            parents=parents,
            hash=hash,
            storage=storage,
            is_block=True
        )
        self.network_hashrate = network_hashrate

    def calculate_weight(self):
        """
            weight = 7 + log2(hash_rate)
        """
        # TODO Get current hash rate from the network
        return 7 + log(self.hash_rate, 2)

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


# TODO add block output
BLOCK_GENESIS = Block(
    hash=b'\x00\x00\x00*\xa1^\x86\x18tZk\x7f\x88\xdbM\r\xb0Bq\xb02.j\x00\x86H6\x9c\x94iH}',
    nonce=2458042,
    timestamp=1533643200,
    weight=24
)
