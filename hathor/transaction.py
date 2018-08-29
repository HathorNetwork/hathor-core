import datetime
import struct
from math import log
from hashlib import sha256
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

MAX_NONCE = 2 ** 32
MAX_NUM_INPUTS = MAX_NUM_OUTPUTS = 256


class Transaction:
    """Hathor transaction"""

    def __init__(self, nonce=0, timestamp=None, version=1, weight=0, inputs=[], outputs=[], parents=[], hash=None, storage=None):
        """
            Nonce: nonce used for the proof-of-work
            Timestamp: moment of creation
            Version: version when it was created
            Weight: calculated as log2(size) + log2(amount) + 0.5
            Inputs: all inputs that are being used (empty in case of a block)
            Outputs: all outputs that are being created
            Parents: transactions you are confirming (2 transactions and 1 block - in case of a block only)
            Some exceptions can happen:
              - first block doesn't have a block to confirm.
              - first two transactions don't have two transactions to confirm.
        """
        self.nonce = nonce
        self.timestamp = timestamp or int(datetime.datetime.now().timestamp())
        self.version = version
        self.weight = weight
        self.inputs = inputs
        self.outputs = outputs
        self.parents = parents
        self.storage = storage
        self.hash = hash

        if not weight:
            # In case of new transactions we need to calculate the weight
            self.weight = self.get_weight()

    @property
    def sum_outputs(self):
        """Sum of the amounts of the outputs"""
        return sum([output.amount for output in self.outputs])

    @property
    def target(self):
        """Target to be achieved in the mining process"""
        return 2 ** (256 - self.weight) - 1

    def get_weight(self):
        """
            Calculate transaction weight
            weight = log2(size) + log2(amount) + 0.5
        """
        size = len(self.get_struct())
        amount = self.sum_outputs
        return log(size, 2) + log(amount, 2) + 0.5

    def get_struct_without_nonce(self):
        """Return the struct of the transaction without the nonce field"""
        # First part is version (H), weight (f), timestamp (I), inputs len (H), outputs len (H) and parents len (H)
        struct_ = struct.pack(
            '!HfIHHH',
            self.version,
            self.weight,
            self.timestamp,
            len(self.inputs),
            len(self.outputs),
            len(self.parents)
        )

        for parent in self.parents:
            struct_ += parent

        for input_ in self.inputs:
            struct_ += input_.tx_id
            struct_ += bytes([input_.index])
            struct_ += input_.signature
            struct_ += input_.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        for output_ in self.outputs:
            struct_ += output_.address
            # amount spent is 4 bytes
            struct_ += output_.amount.to_bytes(4, byteorder='big', signed=False)

        return struct_

    def get_struct(self):
        """Return the full struct of the transaction (with the nonce)"""
        struct_ = self.get_struct_without_nonce()
        struct_ += self.nonce.to_bytes(4, byteorder='big', signed=False)
        return struct_

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
        return self.verify_pow() \
            and self.verify_sum() \
            and self.verify_inputs_signature() \
            and self.verify_number_of_inputs() \
            and self.verify_number_of_outputs()

    def verify_number_of_inputs(self):
        """Verify number of inputs does not exceeds the limit"""
        return len(self.inputs) <= MAX_NUM_INPUTS

    def verify_number_of_outputs(self):
        """Verify number of outputs does not exceeds the limit"""
        return len(self.outputs) <= MAX_NUM_OUTPUTS

    def verify_inputs_signature(self):
        """Verify inputs signatures"""
        for input_ in self.inputs:
            if not self.verify_input(input_):
                return False
        return True

    def verify_input(self, input_):
        """
            Verify one input signature
            We vaidate that this signature can be verified by the public key of the input
        """
        # TODO What should we sign?
        try:
            input_.public_key.verify(
                input_.signature,
                input_.tx_id,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    def verify_pow(self):
        """Verify proof-of-work and that the weight is correct"""
        return self.pow() == self.hash and self.get_weight() == self.weight

    def verify_sum(self):
        """Verify that the sum of outputs is equal of the sum of inputs"""
        sum_outputs = self.sum_outputs
        sum_inputs = 0
        for input_ in self.inputs:
            tx = self.storage.get_transaction_by_hash(input_.tx_id)
            sum_inputs += tx.outputs[input_.index].amount

        print('Sum outputs: ', sum_outputs)
        return sum_outputs == sum_inputs

    def resolve(self):
        """Start mining to achieve the target"""
        hash_ = self.mining()
        if hash_:
            self.hash = hash_
            return True
        else:
            return False

    def pow_part1(self):
        """Returns the fixed part of the pow"""
        pow_part1 = sha256()
        pow_part1.update(self.get_struct_without_nonce())
        return pow_part1

    def pow_part2(self, pow_part1):
        """Returns the full hash of the pow from first part"""
        pow_part1.update(self.nonce.to_bytes(4, byteorder='big', signed=False))
        return sha256(pow_part1.digest()).digest()

    def pow(self):
        """Returns the full hash of the pow"""
        pow_part1 = self.pow_part1()
        return self.pow_part2(pow_part1)

    def mining(self):
        """Starts mining until it solves the problem (finds the nonce that satisfies the conditions)"""
        pow_part1 = self.pow_part1()
        target = self.target
        while self.nonce < MAX_NONCE:
            result = self.pow_part2(pow_part1.copy())

            if int(result.hex(), 16) < target:
                print(result)
                return result
            self.nonce += 1
        return None


class Input:
    def __init__(self, tx_id, index, signature, public_key):
        """
            tx_id: hash of the transaction that contains the output of this input
            index: index of the output you are spending from transaction tx_id
            signature, public_key: attributes that help validating the transaction
        """
        self.tx_id = tx_id                  # bytes
        self.index = index                  # int
        self.signature = signature          # bytes
        self.public_key = public_key        # EllipticCurvePublicKey


class Output:
    def __init__(self, address, amount):
        """
            address: destination of the transfer
            amount: quantity being transferred
        """
        self.address = address              # bytes
        self.amount = amount                # int
