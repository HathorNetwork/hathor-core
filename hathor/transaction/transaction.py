from hathor.transaction.base_transaction import BaseTransaction, MAX_NUM_INPUTS, MAX_NUM_OUTPUTS
from hathor.transaction.exceptions import InputOutputMismatch, TooManyInputs, TooManyOutputs, InputSignatureError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from math import log


class Transaction(BaseTransaction):
    def __init__(self, nonce=0, timestamp=None, version=1,
                 weight=0, inputs=[], outputs=[], parents=[], hash=None, storage=None):
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            version=version,
            weight=weight,
            inputs=inputs,
            outputs=outputs,
            parents=parents,
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
        # self.verify_inputs_signature()
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

    def verify_inputs_signature(self):
        """Verify inputs signatures"""
        for input_tx in self.inputs:
            self.verify_input(input_tx)

    def verify_input(self, input_tx):
        """
            Verify one input signature
            We validate that this signature can be verified by the public key of the input
        """
        # TODO What should we sign?
        try:
            input_tx.public_key.verify(
                input_tx.signature,
                input_tx.tx_id,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return InputSignatureError

    def verify_sum(self):
        """Verify that the sum of outputs is equal of the sum of inputs"""
        sum_outputs = self.sum_outputs
        sum_inputs = 0
        for input_tx in self.inputs:
            # TODO Maybe we could use a TransactionCacheStorage in the future to reduce storage hit
            tx = self.storage.get_transaction_by_hash_bytes(input_tx.tx_id)
            sum_inputs += tx.outputs[input_tx.index].value

        if sum_outputs != sum_inputs:
            raise InputOutputMismatch


TX_GENESIS1 = Transaction(
    hash=b'\x00\x00\x00\xfc\xa3]%\xc2\xb5u\xbe\xc0T0\x8a\x0c$\xc3\xd0\xb7\x98\xf1&\x8b\xecV.\xc1`\xce\x0fh',
    nonce=17262397,
    timestamp=1533643201,
    weight=24
)

TX_GENESIS2 = Transaction(
    hash=b'\x00\x00\x00@\xec\x1e\xe7\x14\xcc\x1a\x8b^I\xfc\xed\x84\x84\x84\xab\x80\x81\xb9s\x94\xc9=\xa1B\\Nay',
    nonce=15665735,
    timestamp=1533643202,
    weight=24
)
