class TransactionMetadata:

    def __init__(self, spent_outputs=[], hash=None):
        """
            hash: hash of tx
            spent_outputs: array of indexes (int)
        """
        self.hash = hash
        self.spent_outputs = spent_outputs
        self.received_by = set()
