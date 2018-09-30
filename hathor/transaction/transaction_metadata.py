from collections import defaultdict

from hathor.transaction.base_transaction import TxConflictState


class TransactionMetadata:

    def __init__(self, spent_outputs=None, hash=None, accumulated_weight=0):
        """
        :param hash: hash of tx
        :type hash: bytes

        :param spent_outputs: Spent outputs of this tx
        :type spent_outputs: DefaultDict[int, Set[bytes (hash)]]

        :type accumulated_weight: int
        """
        # Hash of the transaction.
        self.hash = hash

        # Tx outputs that have been spent.
        # The key is the output index, while the value is a set of the transactions which spend the output.
        # DefaultDict[int, Set[bytes(hash)]]
        self.spent_outputs = spent_outputs or defaultdict(set)

        # Indicate whether this transaction is valid.
        self.conflict = TxConflictState.NO_CONFLICT

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
        for field in ['hash', 'spent_outputs', 'conflict', 'received_by', 'children', 'accumulated_weight']:
            if getattr(self, field) != getattr(other, field):
                return False
        return True

    def to_json(self):
        data = {}
        data['hash'] = self.hash.hex()
        data['spent_outputs'] = [(x, list(y)) for x, y in self.spent_outputs.items()]
        data['received_by'] = list(self.received_by)
        data['children'] = list(self.children)
        data['conflict'] = self.conflict.value
        data['accumulated_weight'] = self.accumulated_weight

        return data

    @classmethod
    def create_from_json(cls, data):
        meta = cls()
        meta.hash = bytes.fromhex(data['hash'])
        meta.spent_outputs = defaultdict(set, [(x, set(y)) for x, y in data['spent_outputs']])
        meta.received_by = set(data['received_by'])
        meta.children = set(data['children'])
        meta.conflict = TxConflictState(data['conflict'])
        meta.accumulated_weight = data['accumulated_weight']
        return meta
