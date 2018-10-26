from collections import defaultdict


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
        self.hash = hash  # bytes(hash)

        # Tx outputs that have been spent.
        # The key is the output index, while the value is a set of the transactions which spend the output.
        # DefaultDict[int, Set[bytes(hash)]]
        self.spent_outputs = spent_outputs or defaultdict(set)

        # Hash of the transactions that conflicts with this transaction.
        self.conflict_with = set()  # Set[bytes(hash)]

        # Hash of the transactions that void this transaction.
        # When a transaction has a conflict and is voided because of this conflict, its own hash is added to
        # voided_by. The logic is that the transaction is voiding itself.
        self.voided_by = set()  # Set[bytes(hash)]

        # List of peers which have sent this transaction.
        # Store only the peers' id.
        self.received_by = set()

        # List of transactions which have this transaction as parent.
        # Store only the transactions' hash.
        self.children = set()  # Set[bytes(hash)]

        # Accumulated weight
        self.accumulated_weight = accumulated_weight  # float

    def __eq__(self, other):
        """Override the default Equals behavior"""
        for field in ['hash', 'spent_outputs', 'conflict_with', 'voided_by',
                      'received_by', 'children', 'accumulated_weight']:
            if getattr(self, field) != getattr(other, field):
                return False
        return True

    def to_json(self):
        data = {}
        data['hash'] = self.hash.hex()
        data['spent_outputs'] = []
        for idx, hashes in self.spent_outputs.items():
            data['spent_outputs'].append([idx, [h_bytes.hex() for h_bytes in hashes]])
        data['received_by'] = list(self.received_by)
        data['children'] = [x.hex() for x in self.children]
        data['conflict_with'] = [x.hex() for x in self.conflict_with]
        data['voided_by'] = [x.hex() for x in self.voided_by]
        data['accumulated_weight'] = self.accumulated_weight
        return data

    @classmethod
    def create_from_json(cls, data):
        meta = cls()
        meta.hash = bytes.fromhex(data['hash'])
        for idx, hashes in data['spent_outputs']:
            for h_hex in hashes:
                meta.spent_outputs[idx].add(bytes.fromhex(h_hex))
        meta.received_by = set(data['received_by'])
        meta.children = set(bytes.fromhex(h) for h in data['children'])

        if 'conflict_with' in data:
            meta.conflict_with = set(bytes.fromhex(h) for h in data['conflict_with'])
        else:
            meta.conflict_with = set()

        if 'voided_by' in data:
            meta.voided_by = set(bytes.fromhex(h) for h in data['voided_by'])
        else:
            meta.voided_by = set()

        meta.accumulated_weight = data['accumulated_weight']
        return meta
