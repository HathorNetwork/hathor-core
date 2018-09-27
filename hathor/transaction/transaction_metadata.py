class TransactionMetadata:

    def __init__(self, spent_outputs=None, hash=None, accumulated_weight=0):
        """
        :param hash: hash of tx
        :type hash: bytes

        :param spent_outputs: list of indexes indicating spent outputs of this tx
        :type spent_outputs: Set[int]

        :type accumulated_weight: int
        """
        # Hash of the transaction.
        self.hash = hash

        # List of the tx outputs that have been spent
        _spent = spent_outputs or []
        self.spent_outputs = set(_spent)

        # List of peers which have sent this transaction.
        # Store only the peers' id.
        self.received_by = set()

        # List of transactions which have this transaction as parent.
        # Store only the transactions' hash.
        self.children = set()

        # Accumulated weight
        self.accumulated_weight = accumulated_weight

    def __eq__(self, other):
        """Override the default Equals behavior"""
        return self.hash == other.hash and self.spent_outputs == other.spent_outputs

    def to_json(self):
        data = {}
        data['spent_outputs'] = list(self.spent_outputs)
        data['received_by'] = list(self.received_by)
        data['children'] = list(self.children)
        data['accumulated_weight'] = self.accumulated_weight

        return data
