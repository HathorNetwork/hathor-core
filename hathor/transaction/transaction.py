from hathor.transaction.base_transaction import BaseTransaction, MAX_NUM_INPUTS, MAX_NUM_OUTPUTS
from hathor.transaction.exceptions import InputOutputMismatch, TooManyInputs, TooManyOutputs, \
                                          InvalidInputData, TimestampError, InexistentInput, \
                                          ConflictingInputs, ScriptError
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.scripts import script_eval
from math import log


class Transaction(BaseTransaction):
    def __init__(self, nonce=0, timestamp=None, version=1, weight=0, height=0,
                 inputs=None, outputs=None, parents=None, hash=None, storage=None):
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            version=version,
            weight=weight,
            height=height,
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
              (ix) validate that both parents are valid
               (x) validate input's timestamps
        """
        if self.is_genesis:
            # TODO do genesis validation
            return
        self.verify_without_storage()
        self.verify_inputs()        # need to run verify_inputs first to check if all inputs exist
        self.verify_sum()
        self.verify_parents()

    def verify_without_storage(self):
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_number_of_inputs()
        self.verify_number_of_outputs()

    def verify_number_of_inputs(self):
        """Verify number of inputs does not exceeds the limit"""
        if len(self.inputs) > MAX_NUM_INPUTS:
            raise TooManyInputs('Maximum number of inputs exceeded')

    def verify_number_of_outputs(self):
        """Verify number of outputs does not exceeds the limit"""
        if len(self.outputs) > MAX_NUM_OUTPUTS:
            raise TooManyOutputs('Maximum number of outputs exceeded')

    def verify_sum(self):
        """Verify that the sum of outputs is equal of the sum of inputs"""
        sum_outputs = self.sum_outputs
        sum_inputs = 0
        for input_tx in self.inputs:
            spent_tx = self.get_spent_tx(input_tx)
            sum_inputs += spent_tx.outputs[input_tx.index].value
        if sum_outputs != sum_inputs:
            raise InputOutputMismatch('Sum of inputs is different than the sum of outputs')

    def verify_inputs(self):
        """Verify inputs signatures and ownership and all inputs actually exist"""
        spent_outputs = set()  # Set[Tuple[bytes(hash), int]]
        for input_tx in self.inputs:
            try:
                spent_tx = self.get_spent_tx(input_tx)
                if input_tx.index >= len(spent_tx.outputs):
                    raise InexistentInput('Output spent by this input does not exist: {} index {}'
                                          .format(input_tx.tx_id.hex(), input_tx.index))
            except TransactionDoesNotExist:
                raise InexistentInput('Input tx does not exist: {}'.format(input_tx.tx_id.hex()))

            if self.timestamp <= spent_tx.timestamp:
                raise TimestampError('tx={} timestamp={}, parent={} timestamp={}'.format(
                    self.hash.hex(),
                    self.timestamp,
                    spent_tx.hash.hex(),
                    spent_tx.timestamp,
                ))

            self.verify_script(input_tx, spent_tx)

            # check if any other input in this tx is spending the same output
            key = (input_tx.tx_id, input_tx.index)
            if key in spent_outputs:
                raise ConflictingInputs('tx {} inputs spend the same output: {} index {}'
                                        .format(self.hash_hex, input_tx.tx_id.hex(), input_tx.index))
            spent_outputs.add(key)

    def verify_script(self, input_tx, spent_tx):
        """
        :type input_tx: Input
        :type spent_tx: Transaction
        """
        try:
            script_eval(self, input_tx, spent_tx)
        except ScriptError as e:
            raise InvalidInputData from e

    def get_spent_tx(self, input_tx):
        # TODO Maybe we could use a TransactionCacheStorage in the future to reduce storage hit
        try:
            spent_tx = input_tx._tx
        except AttributeError:
            spent_tx = self.storage.get_transaction(input_tx.tx_id)
            input_tx._tx = spent_tx
        return spent_tx
