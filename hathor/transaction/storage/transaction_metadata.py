class TransactionMetadata:

    def __init__(self, spent_outputs=None, hash=None):
        """
            hash: hash of tx
            spent_outputs: array of indexes (int)
        """
        # Hash of the transaction.
        self.hash = hash

        # List of transactions which have spent one of its output.
        _spent = spent_outputs or []
        self.spent_outputs = set(_spent)

        # List of peers which have sent this transaction.
        # Store only the peers' id.
        self.received_by = set()

        # List of transactions which have this transaction as parent.
        # Store only the transactions' hash.
        self.children = set()

    def __eq__(self, other):
        """Override the default Equals behavior"""
        return self.hash == other.hash and self.spent_outputs == other.spent_outputs
