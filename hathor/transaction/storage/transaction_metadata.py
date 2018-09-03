class TransactionMetadata:

    def __init__(self, spent_outputs=None, hash=None):
        """
            hash: hash of tx
            spent_outputs: array of indexes (int)
        """
        _spent = spent_outputs or []
        self.hash = hash
        self.spent_outputs = set(_spent)
        self.received_by = set()

    def __eq__(self, other):
        """Override the default Equals behavior"""
        return self.hash == other.hash and self.spent_outputs == other.spent_outputs
