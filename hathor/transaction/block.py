from hathor.transaction.base_transaction import BaseTransaction, Output
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
        return 7 + log(self.network_hashrate, 2)

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


GENESIS_OUTPUT = Output(1000, b'\x98\xf1+e\x936\xa1\x87M\xdb\xae7\x83\x7f\xa8\xa3\x9ff\xb5=')
BLOCK_GENESIS = Block(
    hash=b'\x00\x00\x08N\x8a\xb4*\xe07!\x06\x90\x85J4R\xbal\x8bL\x0e\x02VqW\x00>\xa4\xa3d\x00\x8a',
    nonce=3508191,
    timestamp=1533643200,
    weight=24,
    outputs=[GENESIS_OUTPUT]
)
