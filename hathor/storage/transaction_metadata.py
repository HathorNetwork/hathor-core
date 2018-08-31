class TransactionMetadata:

    def __init__(self, unspent_outputs=[], hash=None):
        """
            hash: hash of tx
            unspent_outputs: array of indexes (int)
        """
        self.hash = hash
        self.unspent_outputs = unspent_outputs
        self.received_by = set()
