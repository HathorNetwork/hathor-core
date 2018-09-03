from hathor.transaction.base_transaction import BaseTransaction, MAX_NUM_INPUTS, MAX_NUM_OUTPUTS
from hathor.transaction.exceptions import InputOutputMismatch, TooManyInputs, TooManyOutputs, DoubleSpend
from hathor.transaction.storage.exceptions import TransactionMetadataDoesNotExist
from hathor.util import validate_signature, validate_script
from math import log


class Transaction(BaseTransaction):
    def __init__(self, nonce=0, timestamp=None, version=1,
                 weight=0, inputs=None, outputs=None, parents=None, hash=None, storage=None):
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            version=version,
            weight=weight,
            inputs=inputs or [],
            outputs=outputs or [],
            parents=parents or [],
            hash=hash,
            storage=storage,
            is_block=False
        )

    def calculate_weight(self):
        """
            Calculate transaction weight
            weight = log2(size) + log2(amount) + 0.5
        """
        size = len(self.get_struct())
        # +1 solves corner case when sum is 0 (genesis)
        amount = self.sum_outputs + 1
        return log(size, 2) + log(amount, 2) + 0.5

    def verify(self):
        """
            We have to do 8 verifications:
               (i) spends only unspent outputs
              (ii) sum of inputs is equal to the sum of outputs
             (iii) number of inputs is at most 256
              (iv) number of outputs is at most 256
               (v) confirms at least two pending transactions
              (vi) solves the pow with the correct weight
             (vii) validates signature of inputs
            (viii) validates public key and output (of the inputs) addresses
        """
        # TODO (i), (v) and (viii)
        if self.is_genesis:
            # TODO do genesis validation
            return
        self.verify_pow()
        self.verify_sum()
        self.verify_inputs()
        self.verify_number_of_inputs()
        self.verify_number_of_outputs()

    def verify_number_of_inputs(self):
        """Verify number of inputs does not exceeds the limit"""
        if len(self.inputs) > MAX_NUM_INPUTS:
            raise TooManyInputs

    def verify_number_of_outputs(self):
        """Verify number of outputs does not exceeds the limit"""
        if len(self.outputs) > MAX_NUM_OUTPUTS:
            raise TooManyOutputs

    def verify_inputs(self):
        """Verify inputs signatures and ownership and unspent outputs"""
        for input_tx in self.inputs:
            self.verify_input_signature(input_tx)
            self.verify_ownership_input(input_tx)
            self.verify_unspent_output(input_tx)

    def verify_input_signature(self, input_tx):
        """
            Verify one input signature
            We validate that this signature can be verified by the public key of the input
        """
        # TODO What should we sign?
        validate_signature(input_tx.data, input_tx.tx_id)

    def verify_sum(self):
        """Verify that the sum of outputs is equal of the sum of inputs"""
        sum_outputs = self.sum_outputs
        sum_inputs = 0
        for input_tx in self.inputs:
            spent_tx = self.get_spent_tx(input_tx)
            sum_inputs += spent_tx.outputs[input_tx.index].value

        if sum_outputs != sum_inputs:
            raise InputOutputMismatch

    def verify_ownership_input(self, input_tx):
        spent_tx = self.get_spent_tx(input_tx)
        script_output = spent_tx.outputs[input_tx.index].script
        validate_script(input_tx.data, script_output)

    def verify_unspent_output(self, input_tx):
        try:
            metadata = self.get_tx_metadata(input_tx)
            if input_tx.index in metadata.spent_outputs:
                raise DoubleSpend
        except TransactionMetadataDoesNotExist:
            # No output was spent in this transaction
            pass

    def get_spent_tx(self, input_tx):
        # TODO Maybe we could use a TransactionCacheStorage in the future to reduce storage hit
        try:
            spent_tx = input_tx._tx
        except AttributeError:
            spent_tx = self.storage.get_transaction_by_hash_bytes(input_tx.tx_id)
            input_tx._tx = spent_tx
        return spent_tx

    def get_tx_metadata(self, input_tx):
        # TODO Maybe we could use a TransactionCacheStorage in the future to reduce storage hit
        try:
            metadata = input_tx._metadata
        except AttributeError:
            metadata = self.storage.get_metadata_by_hash_bytes(input_tx.tx_id)
            input_tx._metadata = metadata
        return metadata

    def execute(self):
        for input_tx in self.inputs:
            try:
                metadata = self.get_tx_metadata(input_tx)
                metadata.spent_outputs.add(input_tx.index)
            except TransactionMetadataDoesNotExist:
                from hathor.transaction.storage.transaction_metadata import TransactionMetadata
                metadata = TransactionMetadata(hash=input_tx.tx_id, spent_outputs=[input_tx.index])

            self.storage.save_metadata(metadata)

        self.storage.save_transaction(self)
